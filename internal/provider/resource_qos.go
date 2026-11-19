package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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
	_ resource.Resource                   = &qosResource{}
	_ resource.ResourceWithConfigure      = &qosResource{}
	_ resource.ResourceWithImportState    = &qosResource{}
	_ resource.ResourceWithModifyPlan     = &qosResource{}
	_ resource.ResourceWithValidateConfig = &qosResource{}
)

func NewQoSResource() resource.Resource { return &qosResource{} }

type qosResource struct{ d *providerData }

// qosID is the import ID and id of the one QoS document per firewall.
const qosID = "qos"

var bandwidthRe = regexp.MustCompile(`^[1-9][0-9]{0,11}[KMG]?$`)

type queueModel struct {
	Name      types.String `tfsdk:"name"`
	Interface types.String `tfsdk:"interface"`
	Parent    types.String `tfsdk:"parent"`
	Bandwidth types.String `tfsdk:"bandwidth"`
	Min       types.String `tfsdk:"min"`
	Max       types.String `tfsdk:"max"`
	QLimit    types.Int64  `tfsdk:"qlimit"`
	Default   types.Bool   `tfsdk:"default"`
	Flows     types.Int64  `tfsdk:"flows"`
	Quantum   types.Int64  `tfsdk:"quantum"`
}

type queueSetModel struct {
	Name     types.String `tfsdk:"name"`
	Priority types.String `tfsdk:"priority"`
}

// qosRuleModel is a classification rule: always `match`, so it has no
// action, quick, block_return or nat.
type qosRuleModel struct {
	Direction types.String   `tfsdk:"direction"`
	Log       types.Bool     `tfsdk:"log"`
	Interface types.String   `tfsdk:"interface"`
	Family    types.String   `tfsdk:"family"`
	Protocol  types.String   `tfsdk:"protocol"`
	From      *endpointModel `tfsdk:"from"`
	To        *endpointModel `tfsdk:"to"`
	Queue     *queueSetModel `tfsdk:"queue"`
	Prio      *prioModel     `tfsdk:"prio"`
	Label     types.String   `tfsdk:"label"`
}

type qosModel struct {
	ID      types.String   `tfsdk:"id"`
	Queues  []queueModel   `tfsdk:"queues"`
	Rules   []qosRuleModel `tfsdk:"rules"`
	ETag    types.String   `tfsdk:"etag"`
	PFRules types.List     `tfsdk:"pf_rules"`
}

func (r *qosResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_qos"
}

func bandwidthAttr(desc string, required bool) schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: desc + " A bit rate: a number with an optional `K`, `M` or `G` suffix, e.g. `100M` (pf has no percentages).",
		Required:            required,
		Optional:            !required,
		Validators:          []validator.String{stringvalidator.RegexMatches(bandwidthRe, "must be a number with an optional K, M or G suffix")},
	}
}

func (r *qosResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The firewall's QoS: HFSC queue trees and the `match` rules that classify traffic into them. " +
			"There is **one QoS document per firewall**; declare at most one `pf_qos` per provider configuration.\n\n" +
			"pf only allows queues in the main ruleset, so pfapid applies a change by reloading the base ruleset (atomic; " +
			"API anchors and table contents are kept). Changes use commit-confirm like `pf_anchor`, and `terraform plan` " +
			"checks the queues and rules with `pfctl -n` against the firewall's real base ruleset.\n\n" +
			"Classify on the rule that **creates the state**: for a connection opened from outside, that is `direction = \"in\"`. " +
			"pf then queues the replies that leave the firewall. A `match out` rule is never evaluated for packets of an " +
			"existing state.\n\n" +
			"Creating this resource fails if the firewall already has a QoS document; import it with `terraform import <address> qos`. " +
			"Destroying it removes all queues. The pfapid client needs the `qos` grant.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"queues": schema.ListNestedAttribute{
				MarkdownDescription: "Queues, parents before children. Each physical interface has at most one tree, and each tree " +
					"exactly one `default` leaf. Children may not add up to more than their parent's bandwidth.",
				Required: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						MarkdownDescription: "Queue name, unique on the firewall.",
						Required:            true,
						Validators:          []validator.String{stringvalidator.RegexMatches(nameRe, "must match "+nameRe.String())},
					},
					"interface": schema.StringAttribute{
						MarkdownDescription: "Root queues only: the physical interface (from the firewall's `policy.queue_interfaces`; not a group).",
						Optional:            true,
					},
					"parent": schema.StringAttribute{
						MarkdownDescription: "Every other queue: its parent queue.",
						Optional:            true,
						Validators:          []validator.String{stringvalidator.RegexMatches(nameRe, "must be a queue name")},
					},
					"bandwidth": bandwidthAttr("Target bandwidth.", true),
					"min":       bandwidthAttr("Guaranteed minimum.", false),
					"max":       bandwidthAttr("Hard limit.", false),
					"qlimit": schema.Int64Attribute{
						MarkdownDescription: "Packets the queue may hold.",
						Optional:            true,
						Validators:          []validator.Int64{int64validator.Between(1, 65535)},
					},
					"default": boolAttr("The queue for traffic no rule classifies. Exactly one leaf per tree."),
					"flows": schema.Int64Attribute{
						MarkdownDescription: "Make this leaf an FQ-CoDel queue with this many flows.",
						Optional:            true,
						Validators:          []validator.Int64{int64validator.Between(1, 32767)},
					},
					"quantum": schema.Int64Attribute{
						MarkdownDescription: "FQ-CoDel quantum in bytes (flow queues only).",
						Optional:            true,
						Validators:          []validator.Int64{int64validator.Between(1, 65535)},
					},
				}},
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "Classification rules (`match`), in order. Each sets `queue`, `prio` or both.",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"direction": schema.StringAttribute{
						MarkdownDescription: "`in` or `out`. Omit for both. See the note on states above.",
						Optional:            true,
						Validators:          []validator.String{stringvalidator.OneOf("in", "out")},
					},
					"log": boolAttr("Log matching packets to pflog."),
					"interface": schema.StringAttribute{
						MarkdownDescription: "Interface or group from the firewall's pfapid policy (e.g. `frontend`).",
						Required:            true,
					},
					"family": schema.StringAttribute{
						MarkdownDescription: "`inet` or `inet6`.",
						Required:            true,
						Validators:          []validator.String{stringvalidator.OneOf("inet", "inet6")},
					},
					"protocol": schema.StringAttribute{
						MarkdownDescription: "`tcp`, `udp`, `icmp` (inet) or `icmp6` (inet6). Omit for any.",
						Optional:            true,
						Validators:          []validator.String{stringvalidator.OneOf("tcp", "udp", "icmp", "icmp6")},
					},
					"from": endpointAttr("Source."),
					"to":   endpointAttr("Destination."),
					"queue": schema.SingleNestedAttribute{
						MarkdownDescription: "`set queue`: a leaf queue, and optionally a second one for low-delay packets and TCP ACKs.",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"name":     schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.RegexMatches(nameRe, "must be a queue name")}},
							"priority": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.RegexMatches(nameRe, "must be a queue name")}},
						},
					},
					"prio":  prioAttr(),
					"label": labelAttr(),
				}},
			},
			"etag": schema.StringAttribute{
				MarkdownDescription: "Version of the committed QoS document.",
				Computed:            true,
			},
			"pf_rules": schema.ListAttribute{
				MarkdownDescription: "Queues and rules as pf loads them (`pfctl -nv`). Computed at plan time.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
	}
}

func (r *qosResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *qosResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m qosModel
	if diags := req.Config.Get(ctx, &m); diags.HasError() {
		return
	}
	for i, q := range m.Queues {
		if q.Interface.IsUnknown() || q.Parent.IsUnknown() {
			continue
		}
		if q.Interface.IsNull() == q.Parent.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("queues").AtListIndex(i), "Root or child queue",
				"Set interface (a root queue) or parent (any other queue), not both and not neither.")
		}
	}
	for i, rl := range m.Rules {
		p := path.Root("rules").AtListIndex(i)
		checkEndpoints(p, rl.From, rl.To, &resp.Diagnostics)
		if rl.Queue == nil && rl.Prio == nil {
			resp.Diagnostics.AddAttributeError(p, "Rule does nothing", "Set queue, prio or both.")
		}
	}
}

func optInt(v int) types.Int64 {
	if v == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(int64(v))
}

func toQoS(m qosModel) client.QoS {
	out := client.QoS{Queues: []client.Queue{}, Rules: []client.Rule{}}
	for _, q := range m.Queues {
		out.Queues = append(out.Queues, client.Queue{
			Name: str(q.Name), Interface: str(q.Interface), Parent: str(q.Parent), Bandwidth: str(q.Bandwidth),
			Min: str(q.Min), Max: str(q.Max), QLimit: int(q.QLimit.ValueInt64()), Default: q.Default.ValueBool(),
			Flows: int(q.Flows.ValueInt64()), Quantum: int(q.Quantum.ValueInt64()),
		})
	}
	for _, rl := range m.Rules {
		cr := client.Rule{
			Action: "match", Direction: str(rl.Direction), Log: rl.Log.ValueBool(), Interface: str(rl.Interface),
			Family: str(rl.Family), Protocol: str(rl.Protocol), From: toEndpoint(rl.From), To: toEndpoint(rl.To),
			Prio: toPrio(rl.Prio), Label: str(rl.Label),
		}
		if rl.Queue != nil {
			cr.Queue = &client.QueueSet{Name: str(rl.Queue.Name), Priority: str(rl.Queue.Priority)}
		}
		out.Rules = append(out.Rules, cr)
	}
	return out
}

func fromQoS(q client.QoS) ([]queueModel, []qosRuleModel) {
	queues := make([]queueModel, 0, len(q.Queues))
	for _, qu := range q.Queues {
		queues = append(queues, queueModel{
			Name: types.StringValue(qu.Name), Interface: optStr(qu.Interface), Parent: optStr(qu.Parent),
			Bandwidth: types.StringValue(qu.Bandwidth), Min: optStr(qu.Min), Max: optStr(qu.Max),
			QLimit: optInt(qu.QLimit), Default: types.BoolValue(qu.Default), Flows: optInt(qu.Flows), Quantum: optInt(qu.Quantum),
		})
	}
	rules := make([]qosRuleModel, 0, len(q.Rules))
	for _, rl := range q.Rules {
		m := qosRuleModel{
			Direction: optStr(rl.Direction), Log: types.BoolValue(rl.Log), Interface: types.StringValue(rl.Interface),
			Family: types.StringValue(rl.Family), Protocol: optStr(rl.Protocol), From: fromEndpoint(rl.From),
			To: fromEndpoint(rl.To), Prio: fromPrio(rl.Prio), Label: optStr(rl.Label),
		}
		if rl.Queue != nil {
			m.Queue = &queueSetModel{Name: types.StringValue(rl.Queue.Name), Priority: optStr(rl.Queue.Priority)}
		}
		rules = append(rules, m)
	}
	return queues, rules
}

func sameQoS(a, b qosModel) bool {
	if a.Queues == nil || a.Rules == nil || b.Queues == nil || b.Rules == nil {
		return false
	}
	ja, _ := json.Marshal(toQoS(a))
	jb, _ := json.Marshal(toQoS(b))
	return string(ja) == string(jb)
}

func (r *qosResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.d == nil {
		return
	}
	var plan qosModel
	if diags := req.Plan.Get(ctx, &plan); diags.HasError() {
		return // unknown values: checked at apply
	}
	if !req.State.Raw.IsNull() {
		var state qosModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if sameQoS(plan, state) {
			plan.ETag, plan.PFRules = state.ETag, state.PFRules
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
			return
		}
	}
	v, err := r.d.client.ValidateQoS(ctx, toQoS(plan))
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("queues"), "QoS rejected by the firewall", err.Error())
		return
	}
	plan.ETag = types.StringUnknown()
	plan.PFRules = stringList(v.Normalised)
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (r *qosResource) replace(ctx context.Context, etag string, q client.QoS) error {
	cctx, cancel := context.WithTimeout(ctx, r.d.changeWait+2*time.Minute)
	defer cancel()
	_, err := r.d.client.ReplaceQoS(cctx, etag, q)
	return err
}

func (r *qosResource) finish(ctx context.Context, m *qosModel, diags *diag.Diagnostics) {
	st, err := r.d.client.GetQoS(ctx)
	if err != nil {
		diags.AddError("Reading QoS after change", err.Error())
		return
	}
	m.ID = types.StringValue(qosID)
	m.ETag = types.StringValue(st.ETag)
	if m.PFRules.IsUnknown() || m.PFRules.IsNull() {
		v, err := r.d.client.ValidateQoS(ctx, st.QoS)
		if err != nil {
			diags.AddError("Reading pf queues and rules", err.Error())
			return
		}
		m.PFRules = stringList(v.Normalised)
	}
}

func (r *qosResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m qosModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cur, err := r.d.client.GetQoS(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Reading QoS", err.Error())
		return
	}
	if len(cur.QoS.Queues) > 0 || len(cur.QoS.Rules) > 0 {
		resp.Diagnostics.AddError("The firewall already has a QoS configuration",
			"Refusing to overwrite it. Import it first: terraform import <address> "+qosID)
		return
	}
	if err := r.replace(ctx, cur.ETag, toQoS(m)); err != nil {
		resp.Diagnostics.AddError("Setting QoS", err.Error())
		return
	}
	r.finish(ctx, &m, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *qosResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m qosModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	st, err := r.d.client.GetQoS(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Reading QoS", err.Error())
		return
	}
	m.ID, m.ETag = types.StringValue(qosID), types.StringValue(st.ETag)
	m.Queues, m.Rules = fromQoS(st.QoS)
	if m.PFRules.IsNull() || m.PFRules.IsUnknown() { // after import
		if v, err := r.d.client.ValidateQoS(ctx, st.QoS); err == nil {
			m.PFRules = stringList(v.Normalised)
		}
	}
	d, err := r.d.client.DriftQoS(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Checking QoS for drift", err.Error())
		return
	}
	if !d.InSync {
		resp.Diagnostics.AddWarning("pf queues differ from the committed QoS configuration",
			"Queues or the api-qos anchor were changed outside pfapid. The next apply loads the configured QoS again.\n\nExpected:\n  "+
				strings.Join(d.Expected, "\n  ")+"\nLoaded:\n  "+strings.Join(d.Live, "\n  "))
		m.Queues, m.Rules = nil, nil // forces an update
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *qosResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state qosModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.replace(ctx, state.ETag.ValueString(), toQoS(plan)); err != nil {
		resp.Diagnostics.AddError("Updating QoS", staleHint(err))
		return
	}
	r.finish(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *qosResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state qosModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.replace(ctx, state.ETag.ValueString(), client.QoS{}); err != nil {
		resp.Diagnostics.AddError("Removing QoS", staleHint(err))
	}
}

func (r *qosResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID != qosID {
		resp.Diagnostics.AddError("Invalid import ID", `The QoS configuration is imported with the ID "qos".`)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), qosID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pf_rules"), types.ListNull(types.StringType))...)
}
