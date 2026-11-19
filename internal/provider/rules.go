package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pderuiter/terraform-provider-pf/internal/client"
)

// Terraform models of pfapid's rule JSON. Optional strings are null when
// pfapid omits them, so a value read back always equals the configuration.

type portModel struct {
	From types.Int64 `tfsdk:"from"`
	To   types.Int64 `tfsdk:"to"`
}

type endpointModel struct {
	Prefixes  []types.String `tfsdk:"prefixes"`
	Table     types.String   `tfsdk:"table"`
	Interface types.String   `tfsdk:"interface"`
	Ports     []portModel    `tfsdk:"ports"`
}

type natModel struct {
	Kind      types.String `tfsdk:"kind"`
	Address   types.String `tfsdk:"address"`
	Interface types.String `tfsdk:"interface"`
	Port      *portModel   `tfsdk:"port"`
	ToFamily  types.String `tfsdk:"to_family"`
	AFFrom    types.String `tfsdk:"af_from"`
	AFTo      types.String `tfsdk:"af_to"`
}

type prioModel struct {
	Normal types.Int64 `tfsdk:"normal"`
	Low    types.Int64 `tfsdk:"low"`
}

type ruleModel struct {
	Action      types.String   `tfsdk:"action"`
	Direction   types.String   `tfsdk:"direction"`
	Quick       types.Bool     `tfsdk:"quick"`
	Log         types.Bool     `tfsdk:"log"`
	BlockReturn types.Bool     `tfsdk:"block_return"`
	Interface   types.String   `tfsdk:"interface"`
	Family      types.String   `tfsdk:"family"`
	Protocol    types.String   `tfsdk:"protocol"`
	From        *endpointModel `tfsdk:"from"`
	To          *endpointModel `tfsdk:"to"`
	NAT         *natModel      `tfsdk:"nat"`
	Prio        *prioModel     `tfsdk:"prio"`
	Label       types.String   `tfsdk:"label"`
}

// --- schema -----------------------------------------------------------------

var cidr = []validator.String{cidrValidator{}}

func portAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"from": schema.Int64Attribute{
			MarkdownDescription: "Port, or first port of a range.",
			Required:            true,
			Validators:          []validator.Int64{int64validator.Between(1, 65535)},
		},
		"to": schema.Int64Attribute{
			MarkdownDescription: "Last port of the range (inclusive). Omit for a single port.",
			Optional:            true,
			Validators:          []validator.Int64{int64validator.Between(1, 65535)},
		},
	}
}

func endpointAttr(desc string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: desc + " Omit for `any`. At most one of `prefixes`, `table` and `interface`.",
		Optional:            true,
		Attributes: map[string]schema.Attribute{
			"prefixes": schema.ListAttribute{
				MarkdownDescription: "Canonical CIDR prefixes, all of the rule's `family`.",
				ElementType:         types.StringType,
				Optional:            true,
				Validators:          []validator.List{listvalidator.SizeAtLeast(1), listvalidator.ValueStringsAre(cidr...)},
			},
			"table": schema.StringAttribute{
				MarkdownDescription: "A managed table, `<table>` in pf.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(nameRe, "must be a table name")},
			},
			"interface": schema.StringAttribute{
				MarkdownDescription: "The interface's own addresses, `(name)` in pf.",
				Optional:            true,
			},
			"ports": schema.ListNestedAttribute{
				MarkdownDescription: "Ports (protocol `tcp` or `udp` only).",
				Optional:            true,
				Validators:          []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject:        schema.NestedAttributeObject{Attributes: portAttrs()},
			},
		},
	}
}

func boolAttr(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{MarkdownDescription: desc + " Defaults to `false`.", Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
}

func ruleAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"action": schema.StringAttribute{
			MarkdownDescription: "`pass`, `block` or `match` (`match` for NAT and prio without deciding).",
			Required:            true,
			Validators:          []validator.String{stringvalidator.OneOf("pass", "block", "match")},
		},
		"direction": schema.StringAttribute{
			MarkdownDescription: "`in` or `out`. Omit for both directions.",
			Optional:            true,
			Validators:          []validator.String{stringvalidator.OneOf("in", "out")},
		},
		"quick":        boolAttr("Stop evaluating at this rule if it matches."),
		"log":          boolAttr("Log matching packets to pflog."),
		"block_return": boolAttr("`block` only: answer with TCP RST / ICMP unreachable instead of dropping."),
		"interface": schema.StringAttribute{
			MarkdownDescription: "Interface or interface group from the firewall's pfapid policy (e.g. `frontend`). Never `mgmt`.",
			Required:            true,
		},
		"family": schema.StringAttribute{
			MarkdownDescription: "`inet` or `inet6`. Every rule names one family; use a table to cover both.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.OneOf("inet", "inet6")},
		},
		"protocol": schema.StringAttribute{
			MarkdownDescription: "`tcp`, `udp`, `icmp` (inet) or `icmp6` (inet6). Omit for any protocol.",
			Optional:            true,
			Validators:          []validator.String{stringvalidator.OneOf("tcp", "udp", "icmp", "icmp6")},
		},
		"from": endpointAttr("Source."),
		"to":   endpointAttr("Destination."),
		"nat": schema.SingleNestedAttribute{
			MarkdownDescription: "Address translation. `pass` or `match` rules only.",
			Optional:            true,
			Attributes: map[string]schema.Attribute{
				"kind": schema.StringAttribute{
					MarkdownDescription: "`nat-to`, `rdr-to`, `binat-to` or `af-to` (NAT64/NAT46, `pass in` only).",
					Required:            true,
					Validators:          []validator.String{stringvalidator.OneOf("nat-to", "rdr-to", "binat-to", "af-to")},
				},
				"address": schema.StringAttribute{
					MarkdownDescription: "Translation address or prefix (`nat-to`, `rdr-to`, `binat-to`; same prefix length as the source for `binat-to`).",
					Optional:            true,
					Validators:          cidr,
				},
				"interface": schema.StringAttribute{
					MarkdownDescription: "`nat-to` only: translate to this interface's first address, `(iface:0)`, instead of `address`.",
					Optional:            true,
				},
				"port": schema.SingleNestedAttribute{
					MarkdownDescription: "`rdr-to` only: destination port or range.",
					Optional:            true,
					Attributes:          portAttrs(),
				},
				"to_family": schema.StringAttribute{
					MarkdownDescription: "`af-to` only: the family to translate to.",
					Optional:            true,
					Validators:          []validator.String{stringvalidator.OneOf("inet", "inet6")},
				},
				"af_from": schema.StringAttribute{MarkdownDescription: "`af-to` only: new source prefix.", Optional: true, Validators: cidr},
				"af_to":   schema.StringAttribute{MarkdownDescription: "`af-to` only: new destination prefix.", Optional: true, Validators: cidr},
			},
		},
		"prio":  prioAttr(),
		"label": labelAttr(),
	}
}

func prioAttr() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: "Queue priority (`set prio`): `normal`, and optionally `low` for empty ACKs and low-delay packets. 0–7.",
		Optional:            true,
		Attributes: map[string]schema.Attribute{
			"normal": schema.Int64Attribute{Required: true, Validators: []validator.Int64{int64validator.Between(0, 7)}},
			"low":    schema.Int64Attribute{Optional: true, Validators: []validator.Int64{int64validator.Between(0, 7)}},
		},
	}
}

func labelAttr() schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: "pf label, shown in `pfctl -s labels` (letters, digits, space and `_.:/-`, at most 63).",
		Optional:            true,
		Validators:          []validator.String{stringvalidator.RegexMatches(labelRe, "letters, digits, space and _.:/- only, at most 63 characters")},
	}
}

// --- conversion -------------------------------------------------------------

func str(v types.String) string { return v.ValueString() }

func optStr(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func toPort(p portModel) client.PortRange {
	return client.PortRange{From: uint16(p.From.ValueInt64()), To: uint16(p.To.ValueInt64())} // #nosec G115 -- schema limits to 1..65535
}

func fromPort(p client.PortRange) portModel {
	m := portModel{From: types.Int64Value(int64(p.From)), To: types.Int64Null()}
	if p.To != 0 {
		m.To = types.Int64Value(int64(p.To))
	}
	return m
}

func toEndpoint(e *endpointModel) client.Endpoint {
	if e == nil {
		return client.Endpoint{}
	}
	out := client.Endpoint{Table: str(e.Table), Interface: str(e.Interface)}
	for _, p := range e.Prefixes {
		out.Prefixes = append(out.Prefixes, p.ValueString())
	}
	for _, p := range e.Ports {
		out.Ports = append(out.Ports, toPort(p))
	}
	return out
}

func fromEndpoint(e client.Endpoint) *endpointModel {
	if len(e.Prefixes) == 0 && e.Table == "" && e.Interface == "" && len(e.Ports) == 0 {
		return nil
	}
	m := &endpointModel{Table: optStr(e.Table), Interface: optStr(e.Interface)}
	for _, p := range e.Prefixes {
		m.Prefixes = append(m.Prefixes, types.StringValue(p))
	}
	for _, p := range e.Ports {
		m.Ports = append(m.Ports, fromPort(p))
	}
	return m
}

func toRule(r ruleModel) client.Rule {
	out := client.Rule{
		Action: str(r.Action), Direction: str(r.Direction), Quick: r.Quick.ValueBool(), Log: r.Log.ValueBool(),
		BlockReturn: r.BlockReturn.ValueBool(), Interface: str(r.Interface), Family: str(r.Family),
		Protocol: str(r.Protocol), From: toEndpoint(r.From), To: toEndpoint(r.To), Label: str(r.Label),
	}
	if n := r.NAT; n != nil {
		out.NAT = &client.NAT{Kind: str(n.Kind), Address: str(n.Address), Interface: str(n.Interface),
			ToFamily: str(n.ToFamily), AFFrom: str(n.AFFrom), AFTo: str(n.AFTo)}
		if n.Port != nil {
			p := toPort(*n.Port)
			out.NAT.Port = &p
		}
	}
	out.Prio = toPrio(r.Prio)
	return out
}

func toPrio(p *prioModel) *client.Prio {
	if p == nil {
		return nil
	}
	out := &client.Prio{Normal: uint8(p.Normal.ValueInt64())} // #nosec G115 -- schema limits to 0..7
	if !p.Low.IsNull() {
		low := uint8(p.Low.ValueInt64()) // #nosec G115 -- schema limits to 0..7
		out.Low = &low
	}
	return out
}

func fromPrio(p *client.Prio) *prioModel {
	if p == nil {
		return nil
	}
	m := &prioModel{Normal: types.Int64Value(int64(p.Normal)), Low: types.Int64Null()}
	if p.Low != nil {
		m.Low = types.Int64Value(int64(*p.Low))
	}
	return m
}

func fromRule(r client.Rule) ruleModel {
	m := ruleModel{
		Action: types.StringValue(r.Action), Direction: optStr(r.Direction), Quick: types.BoolValue(r.Quick),
		Log: types.BoolValue(r.Log), BlockReturn: types.BoolValue(r.BlockReturn), Interface: types.StringValue(r.Interface),
		Family: types.StringValue(r.Family), Protocol: optStr(r.Protocol), From: fromEndpoint(r.From),
		To: fromEndpoint(r.To), Label: optStr(r.Label),
	}
	if n := r.NAT; n != nil {
		m.NAT = &natModel{Kind: types.StringValue(n.Kind), Address: optStr(n.Address), Interface: optStr(n.Interface),
			ToFamily: optStr(n.ToFamily), AFFrom: optStr(n.AFFrom), AFTo: optStr(n.AFTo)}
		if n.Port != nil {
			p := fromPort(*n.Port)
			m.NAT.Port = &p
		}
	}
	m.Prio = fromPrio(r.Prio)
	return m
}
