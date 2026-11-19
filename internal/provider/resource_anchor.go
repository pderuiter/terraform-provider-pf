package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pderuiter/terraform-provider-pf/internal/client"
)

var (
	_ resource.Resource                   = &anchorResource{}
	_ resource.ResourceWithConfigure      = &anchorResource{}
	_ resource.ResourceWithImportState    = &anchorResource{}
	_ resource.ResourceWithModifyPlan     = &anchorResource{}
	_ resource.ResourceWithValidateConfig = &anchorResource{}
)

func NewAnchorResource() resource.Resource { return &anchorResource{} }

type anchorResource struct{ d *providerData }

type anchorModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Rules   []ruleModel  `tfsdk:"rules"`
	ETag    types.String `tfsdk:"etag"`
	PFRules types.List   `tfsdk:"pf_rules"`
}

func (r *anchorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_anchor"
}

func (r *anchorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A pf anchor `api/<name>` owned by pfapid. The rules replace the anchor's ruleset as a whole.\n\n" +
			"Every change is applied with commit-confirm: pfapid loads it, the provider confirms it over the same " +
			"connection, and pfapid rolls it back by itself if that confirmation never arrives. `terraform plan` " +
			"runs the rules through `pfctl -n` on the firewall and shows the result in `pf_rules`.\n\n" +
			"If the rules loaded in pf differ from the committed ones (someone ran pfctl by hand), refresh warns and " +
			"the next apply loads the configured rules again.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Anchor name (`api/<name>` in pf). Lower case letters, digits, `-` and `_`, at most 31.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{stringvalidator.RegexMatches(nameRe, "must match "+nameRe.String())},
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "Rules in evaluation order.",
				Required:            true,
				NestedObject:        schema.NestedAttributeObject{Attributes: ruleAttrs()},
			},
			"etag": schema.StringAttribute{
				MarkdownDescription: "Version of the committed anchor; used to refuse changes made on a stale view.",
				Computed:            true,
			},
			"pf_rules": schema.ListAttribute{
				MarkdownDescription: "The rules as pf loads them (`pfctl -nv` output, e.g. one line per port). Computed at plan time.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
	}
}

func (r *anchorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("%T", req.ProviderData))
		return
	}
	r.d = d
}

// ValidateConfig catches what the attribute validators cannot see.
func (r *anchorResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m anchorModel
	if diags := req.Config.Get(ctx, &m); diags.HasError() {
		return // unknown values: pfapid validates at plan time once they are known
	}
	for i, rl := range m.Rules {
		for _, ep := range []struct {
			name string
			e    *endpointModel
		}{{"from", rl.From}, {"to", rl.To}} {
			if ep.e == nil {
				continue
			}
			n := 0
			if ep.e.Prefixes != nil {
				n++
			}
			if !ep.e.Table.IsNull() {
				n++
			}
			if !ep.e.Interface.IsNull() {
				n++
			}
			p := path.Root("rules").AtListIndex(i).AtName(ep.name)
			if n > 1 {
				resp.Diagnostics.AddAttributeError(p, "Conflicting addresses", "Set only one of prefixes, table and interface.")
			}
			if n == 0 && ep.e.Ports == nil {
				resp.Diagnostics.AddAttributeError(p, "Empty endpoint", "Omit "+ep.name+" entirely to mean any.")
			}
		}
	}
}

func rulesOf(m []ruleModel) []client.Rule {
	out := make([]client.Rule, 0, len(m))
	for _, rl := range m {
		out = append(out, toRule(rl))
	}
	return out
}

func sameRules(a, b []ruleModel) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ja, _ := json.Marshal(rulesOf(a))
	jb, _ := json.Marshal(rulesOf(b))
	return string(ja) == string(jb)
}

func stringList(v []string) types.List {
	elems := make([]string, len(v))
	copy(elems, v)
	l, _ := types.ListValueFrom(context.Background(), types.StringType, elems)
	return l
}

// ModifyPlan asks the firewall to check the rules (pfctl -n) so plan fails
// on anything pf would refuse, and shows pf's expansion in pf_rules.
func (r *anchorResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.d == nil {
		return // destroy, or provider not configured yet
	}
	var plan anchorModel
	if diags := req.Plan.Get(ctx, &plan); diags.HasError() || plan.Name.IsUnknown() {
		return // values only known after apply
	}
	var state *anchorModel
	if !req.State.Raw.IsNull() {
		state = &anchorModel{}
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if state != nil && sameRules(plan.Rules, state.Rules) && plan.Name.Equal(state.Name) {
		plan.ETag, plan.PFRules = state.ETag, state.PFRules
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}
	v, err := r.d.client.ValidateAnchor(ctx, plan.Name.ValueString(), rulesOf(plan.Rules))
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("rules"), "Rules rejected by the firewall", err.Error())
		return
	}
	plan.ETag = types.StringUnknown()
	plan.PFRules = stringList(v.Normalised)
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (r *anchorResource) changeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.d.changeWait+2*time.Minute)
}

func staleHint(err error) string {
	if client.IsPrecondition(err) {
		return err.Error() + "\n\nThe object changed on the firewall since Terraform last read it. Run `terraform apply -refresh-only` (or plan again) and re-apply."
	}
	return err.Error()
}

// finish fills etag (and pf_rules if plan time could not) after a change.
func (r *anchorResource) finish(ctx context.Context, m *anchorModel, diags *diag.Diagnostics) {
	st, err := r.d.client.GetAnchor(ctx, m.Name.ValueString())
	if err != nil {
		diags.AddError("Reading anchor after change", err.Error())
		return
	}
	m.ID = m.Name
	m.ETag = types.StringValue(st.ETag)
	if m.PFRules.IsUnknown() || m.PFRules.IsNull() {
		v, err := r.d.client.ValidateAnchor(ctx, m.Name.ValueString(), rulesOf(m.Rules))
		if err != nil {
			diags.AddError("Reading pf rules", err.Error())
			return
		}
		m.PFRules = stringList(v.Normalised)
	}
}

func (r *anchorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m anchorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cctx, cancel := r.changeCtx(ctx)
	defer cancel()
	if _, err := r.d.client.CreateAnchor(cctx, m.Name.ValueString(), rulesOf(m.Rules)); err != nil {
		hint := err.Error()
		if client.IsPrecondition(err) {
			hint += "\n\nThe anchor already exists on the firewall. Import it: terraform import <address> " + m.Name.ValueString()
		}
		resp.Diagnostics.AddError("Creating anchor "+m.Name.ValueString(), hint)
		return
	}
	r.finish(ctx, &m, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *anchorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m anchorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := m.Name.ValueString()
	st, err := r.d.client.GetAnchor(ctx, name)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading anchor "+name, err.Error())
		return
	}
	m.ID = types.StringValue(name)
	m.ETag = types.StringValue(st.ETag)
	m.Rules = make([]ruleModel, 0, len(st.Anchor.Rules))
	for _, rl := range st.Anchor.Rules {
		m.Rules = append(m.Rules, fromRule(rl))
	}
	if m.PFRules.IsNull() || m.PFRules.IsUnknown() { // after import
		if v, err := r.d.client.ValidateAnchor(ctx, name, st.Anchor.Rules); err == nil {
			m.PFRules = stringList(v.Normalised)
		}
	}
	d, err := r.d.client.DriftAnchor(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError("Checking anchor "+name+" for drift", err.Error())
		return
	}
	if !d.InSync {
		resp.Diagnostics.AddWarning("pf anchor api/"+name+" differs from its committed rules",
			"The rules loaded in pf were changed outside pfapid. The next apply loads the configured rules again.\n\nExpected:\n  "+
				strings.Join(d.Expected, "\n  ")+"\nLoaded:\n  "+strings.Join(d.Live, "\n  "))
		m.Rules = nil // forces an update that reloads the anchor
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *anchorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state anchorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cctx, cancel := r.changeCtx(ctx)
	defer cancel()
	if _, err := r.d.client.UpdateAnchor(cctx, plan.Name.ValueString(), state.ETag.ValueString(), rulesOf(plan.Rules)); err != nil {
		resp.Diagnostics.AddError("Updating anchor "+plan.Name.ValueString(), staleHint(err))
		return
	}
	r.finish(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *anchorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state anchorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cctx, cancel := r.changeCtx(ctx)
	defer cancel()
	_, err := r.d.client.DeleteAnchor(cctx, state.Name.ValueString(), state.ETag.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting anchor "+state.Name.ValueString(), staleHint(err))
	}
}

func (r *anchorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !nameRe.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import ID", "Use the anchor name, e.g. k8s-prod.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pf_rules"), types.ListNull(types.StringType))...)
}
