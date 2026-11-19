package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &tableResource{}
	_ resource.ResourceWithConfigure   = &tableResource{}
	_ resource.ResourceWithImportState = &tableResource{}
)

func NewTableResource() resource.Resource { return &tableResource{} }

type tableResource struct{ d *providerData }

type tableModel struct {
	ID      types.String   `tfsdk:"id"`
	Name    types.String   `tfsdk:"name"`
	Entries []types.String `tfsdk:"entries"`
	ETag    types.String   `tfsdk:"etag"`
}

func (r *tableResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_table"
}

func (r *tableResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The contents of a pf table that pfapid manages. The table itself is declared in the firewall's " +
			"base ruleset (`table <name> persist`) and listed in the pfapid policy; this resource owns its entries.\n\n" +
			"Creating the resource replaces whatever the table held; destroying it empties the table. Changes use " +
			"commit-confirm like `pf_anchor`. Entries added by hand (`pfctl -T add`) show as drift and are removed " +
			"by the next apply.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Table name, as in `<name>`.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{stringvalidator.RegexMatches(nameRe, "must match "+nameRe.String())},
			},
			"entries": schema.SetAttribute{
				MarkdownDescription: "Canonical CIDR prefixes, IPv4 and IPv6 mixed (`192.0.2.10/32` for one host). May be empty.",
				ElementType:         types.StringType,
				Required:            true,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(cidr...)},
			},
			"etag": schema.StringAttribute{
				MarkdownDescription: "Version of the committed table contents.",
				Computed:            true,
			},
		},
	}
}

func (r *tableResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func entriesOf(v []types.String) []string {
	out := make([]string, 0, len(v))
	for _, e := range v {
		out = append(out, e.ValueString())
	}
	return out
}

// replace writes entries, starting from the table's current ETag (create
// and delete) or the one in state (update).
func (r *tableResource) replace(ctx context.Context, name, etag string, entries []string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, r.d.changeWait+2*time.Minute)
	defer cancel()
	if etag == "" {
		st, err := r.d.client.GetTable(cctx, name)
		if err != nil {
			return "", err
		}
		etag = st.ETag
	}
	if _, err := r.d.client.ReplaceTable(cctx, name, etag, entries); err != nil {
		return "", err
	}
	st, err := r.d.client.GetTable(cctx, name)
	if err != nil {
		return "", err
	}
	return st.ETag, nil
}

func (r *tableResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m tableModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tag, err := r.replace(ctx, m.Name.ValueString(), "", entriesOf(m.Entries))
	if err != nil {
		resp.Diagnostics.AddError("Setting table "+m.Name.ValueString(), err.Error())
		return
	}
	m.ID, m.ETag = m.Name, types.StringValue(tag)
	if m.Entries == nil {
		m.Entries = []types.String{}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *tableResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m tableModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := m.Name.ValueString()
	st, err := r.d.client.GetTable(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError("Reading table "+name, err.Error())
		return
	}
	m.ID, m.ETag = types.StringValue(name), types.StringValue(st.ETag)
	m.Entries = make([]types.String, 0, len(st.Table.Entries))
	for _, e := range st.Table.Entries {
		m.Entries = append(m.Entries, types.StringValue(e))
	}
	d, err := r.d.client.DriftTable(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError("Checking table "+name+" for drift", err.Error())
		return
	}
	if !d.InSync {
		resp.Diagnostics.AddWarning("pf table <"+name+"> differs from its committed contents",
			"Entries were changed outside pfapid (pfctl -T). The next apply restores the configured entries.\n\nExpected: "+
				strings.Join(d.Expected, " ")+"\nLoaded:   "+strings.Join(d.Live, " "))
		m.Entries = nil // forces an update
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *tableResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state tableModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tag, err := r.replace(ctx, plan.Name.ValueString(), state.ETag.ValueString(), entriesOf(plan.Entries))
	if err != nil {
		resp.Diagnostics.AddError("Updating table "+plan.Name.ValueString(), staleHint(err))
		return
	}
	plan.ID, plan.ETag = plan.Name, types.StringValue(tag)
	if plan.Entries == nil {
		plan.Entries = []types.String{}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *tableResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tableModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.replace(ctx, state.Name.ValueString(), state.ETag.ValueString(), []string{}); err != nil {
		resp.Diagnostics.AddError("Emptying table "+state.Name.ValueString(), staleHint(err))
	}
}

func (r *tableResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !nameRe.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import ID", "Use the table name, e.g. k8s_nodes.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
