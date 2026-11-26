package provider

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pderuiter/terraform-provider-pf/internal/client"
)

// Unit tests for the model conversions and endpoint checks. The acceptance
// tests cover the same code end to end, but only when TF_ACC is set.

func TestEndpointRoundTrip(t *testing.T) {
	cases := map[string]client.Endpoint{
		"negated table": {Negate: true, Table: "rfc1918"},
		"self":          {Self: true, Ports: []client.PortRange{{From: 22}}},
		"negated self":  {Negate: true, Self: true},
		"negated prefix": {Negate: true, Prefixes: []string{"10.0.0.0/8"},
			Ports: []client.PortRange{{From: 33433, To: 33626}}},
		"interface": {Interface: "backend"},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			m := fromEndpoint(want)
			if m == nil {
				t.Fatal("fromEndpoint returned nil for a non-empty endpoint")
			}
			if got := toEndpoint(m); !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestEndpointAny(t *testing.T) {
	if m := fromEndpoint(client.Endpoint{}); m != nil {
		t.Fatalf("empty endpoint: got %+v, want nil (any)", m)
	}
	if got := toEndpoint(nil); !reflect.DeepEqual(got, client.Endpoint{}) {
		t.Fatalf("nil endpoint: got %+v", got)
	}
}

func TestEndpointNewFieldsReadBackFalse(t *testing.T) {
	// Older pfapid omits negate/self: they must read back as false, not
	// null, so existing anchors plan no change.
	m := fromEndpoint(client.Endpoint{Table: "k8s_nodes"})
	if m.Negate.IsNull() || m.Negate.ValueBool() || m.Self.IsNull() || m.Self.ValueBool() {
		t.Fatalf("negate/self: got %v/%v, want false/false", m.Negate, m.Self)
	}
}

func TestRuleICMPTypesRoundTrip(t *testing.T) {
	want := client.Rule{
		Action: "pass", Direction: "in", Interface: "frontend", Family: "inet6", Protocol: "icmp6",
		From:      client.Endpoint{Negate: true, Prefixes: []string{"fd00::/8"}},
		To:        client.Endpoint{Negate: true, Interface: "backend"},
		ICMPTypes: []string{"echoreq", "128"},
		Label:     "icmp6-in",
	}
	got := toRule(fromRule(want))
	if !reflect.DeepEqual(got.ICMPTypes, want.ICMPTypes) {
		t.Fatalf("icmp_types: got %v, want %v", got.ICMPTypes, want.ICMPTypes)
	}
	if !reflect.DeepEqual(got.From, want.From) || !reflect.DeepEqual(got.To, want.To) {
		t.Fatalf("endpoints: got %+v -> %+v", got.From, got.To)
	}
	if r := toRule(fromRule(client.Rule{Action: "pass", Family: "inet", Interface: "frontend"})); r.ICMPTypes != nil {
		t.Fatalf("no icmp types: got %v, want nil", r.ICMPTypes)
	}
}

func TestCheckEndpoints(t *testing.T) {
	str := types.StringValue
	null := types.StringNull()
	yes, no := types.BoolValue(true), types.BoolNull()
	ep := func(negate types.Bool, prefixes []string, table, iface types.String, self types.Bool, ports bool) *endpointModel {
		e := &endpointModel{Negate: negate, Table: table, Interface: iface, Self: self}
		for _, p := range prefixes {
			e.Prefixes = append(e.Prefixes, str(p))
		}
		if ports {
			e.Ports = []portModel{{From: types.Int64Value(22), To: types.Int64Null()}}
		}
		return e
	}
	cases := []struct {
		name string
		e    *endpointModel
		want string // summary of the single expected error, "" for none
	}{
		{"negated table", ep(yes, nil, str("rfc1918"), null, no, false), ""},
		{"negated single prefix", ep(yes, []string{"10.0.0.0/8"}, null, null, no, false), ""},
		{"negated interface", ep(yes, nil, null, str("backend"), no, false), ""},
		{"negated self", ep(yes, nil, null, null, yes, false), ""},
		{"self with ports", ep(no, nil, null, null, yes, true), ""},
		{"ports only", ep(no, nil, null, null, no, true), ""},
		{"self and table", ep(no, nil, str("t"), null, yes, false), "Conflicting addresses"},
		{"prefixes and interface", ep(no, []string{"10.0.0.0/8"}, null, str("x"), no, false), "Conflicting addresses"},
		{"negate nothing", ep(yes, nil, null, null, no, true), "Nothing to negate"},
		{"negated list", ep(yes, []string{"10.0.0.0/8", "192.168.0.0/16"}, null, null, no, false), "Negated list"},
		{"empty", ep(no, nil, null, null, no, false), "Empty endpoint"},
		{"self false is not an address", ep(no, nil, null, null, types.BoolValue(false), false), "Empty endpoint"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var diags diag.Diagnostics
			checkEndpoints(path.Root("rules").AtListIndex(0), nil, c.e, &diags)
			switch {
			case c.want == "" && diags.HasError():
				t.Fatalf("unexpected errors: %v", diags)
			case c.want != "" && (diags.ErrorsCount() != 1 || diags.Errors()[0].Summary() != c.want):
				t.Fatalf("got %v, want one %q", diags, c.want)
			}
		})
	}
}
