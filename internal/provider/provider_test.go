package provider

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/pderuiter/terraform-provider-pf/internal/fakepfapid"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pf": providerserver.NewProtocol6WithError(New("test")()),
}

// useFake points the provider (through its environment variables) at an
// in-process pfapid. Acceptance tests (TF_ACC=1) need a terraform binary,
// nothing else.
func useFake(t *testing.T, tables ...string) *fakepfapid.Server {
	t.Helper()
	s := fakepfapid.New(tables...)
	t.Cleanup(s.Close)
	t.Setenv(envEndpoint, s.URL)
	t.Setenv(envCACert, string(s.CACertPEM))
	t.Setenv(envClientCert, string(s.ClientCertPEM))
	t.Setenv(envClientKey, string(s.ClientKeyPEM))
	return s
}

func TestProviderSchemas(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	var ps fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &ps)
	if d := ps.Schema.ValidateImplementation(ctx); d.HasError() {
		t.Fatal(d)
	}
	for _, f := range p.Resources(ctx) {
		r := f()
		var resp fwresource.SchemaResponse
		r.Schema(ctx, fwresource.SchemaRequest{}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%T: %v", r, resp.Diagnostics)
		}
		if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
			t.Fatalf("%T: %v", r, d)
		}
	}
}

func TestCanonicalCIDR(t *testing.T) {
	for _, ok := range []string{"10.0.0.0/8", "192.0.2.10/32", "2001:db8::/32", "fd00:b::225/128", "0.0.0.0/0"} {
		if err := canonicalCIDR(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"10.1.2.3/8", "192.0.2.10", "2001:DB8::/32", "2001:0db8::/32", "::ffff:10.0.0.0/104", "fe80::1%vio0/128", "x"} {
		if err := canonicalCIDR(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

const anchorV1 = `
resource "pf_anchor" "k8s" {
  name = "k8s-test"
  rules = [
    {
      action    = "pass"
      direction = "in"
      quick     = true
      interface = "frontend"
      family    = "inet"
      protocol  = "tcp"
      from      = { prefixes = ["10.70.1.0/24"] }
      to        = { table = "k8s_nodes", ports = [{ from = 443 }, { from = 6443 }] }
      label     = "k8s-api"
    },
    {
      action    = "match"
      direction = "out"
      interface = "frontend"
      family    = "inet6"
      from      = { prefixes = ["fd00:b::/64"] }
      nat       = { kind = "nat-to", interface = "frontend" }
    },
  ]
}
`

const anchorV2 = `
resource "pf_anchor" "k8s" {
  name = "k8s-test"
  rules = [
    {
      action       = "block"
      block_return = true
      direction    = "in"
      interface    = "frontend"
      family       = "inet"
      protocol     = "tcp"
      to           = { ports = [{ from = 1024, to = 2048 }] }
      prio         = { normal = 2, low = 6 }
    },
  ]
}
`

func TestAccAnchor(t *testing.T) {
	s := useFake(t, "k8s_nodes")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: anchorV1,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pf_anchor.k8s", "id", "k8s-test"),
					resource.TestCheckResourceAttr("pf_anchor.k8s", "rules.#", "2"),
					resource.TestCheckResourceAttr("pf_anchor.k8s", "pf_rules.#", "2"),
					resource.TestCheckResourceAttrSet("pf_anchor.k8s", "etag"),
				),
			},
			{ResourceName: "pf_anchor.k8s", ImportState: true, ImportStateId: "k8s-test", ImportStateVerify: true},
			{
				Config: anchorV2,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("pf_anchor.k8s", plancheck.ResourceActionUpdate),
				}},
				Check: resource.TestCheckResourceAttr("pf_anchor.k8s", "rules.0.prio.low", "6"),
			},
			{
				// Someone edits pf by hand: refresh notices, apply reloads.
				PreConfig: func() { s.TamperAnchor("k8s-test") },
				Config:    anchorV2,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("pf_anchor.k8s", plancheck.ResourceActionUpdate),
				}},
			},
			{Config: anchorV2, PlanOnly: true}, // converged
		},
	})
	if s.Anchor("k8s-test") != nil {
		t.Fatal("anchor left behind after destroy")
	}
	if s.Pending() {
		t.Fatal("change left pending")
	}
}

// The base-ruleset forms wbyc-fw01 migrates into anchors: a negated
// (referenced) table, self and icmp-type. They must round-trip without a
// diff, through import too.
const anchorNegation = `
resource "pf_anchor" "egress" {
  name = "egress"
  rules = [
    {
      action    = "pass"
      direction = "in"
      interface = "vlan699"
      family    = "inet"
      from      = { table = "clusters" }
      to        = { negate = true, table = "rfc1918" }
    },
    {
      action     = "pass"
      direction  = "in"
      interface  = "vlan699"
      family     = "inet"
      protocol   = "icmp"
      from       = { table = "clusters" }
      to         = { self = true }
      icmp_types = ["echoreq"]
    },
    {
      action     = "pass"
      direction  = "in"
      interface  = "vlan699"
      family     = "inet6"
      protocol   = "icmp6"
      from       = { negate = true, prefixes = ["fd00::/8"] }
      icmp_types = ["echoreq", "128"]
    },
  ]
}
`

func TestAccAnchorNegationICMP(t *testing.T) {
	s := useFake(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: anchorNegation,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pf_anchor.egress", "rules.0.to.negate", "true"),
					resource.TestCheckResourceAttr("pf_anchor.egress", "rules.0.to.self", "false"),
					resource.TestCheckResourceAttr("pf_anchor.egress", "rules.0.from.negate", "false"),
					resource.TestCheckResourceAttr("pf_anchor.egress", "rules.1.to.self", "true"),
					resource.TestCheckResourceAttr("pf_anchor.egress", "rules.1.icmp_types.0", "echoreq"),
					resource.TestCheckResourceAttr("pf_anchor.egress", "rules.2.icmp_types.#", "2"),
				),
			},
			{Config: anchorNegation, PlanOnly: true},
			{ResourceName: "pf_anchor.egress", ImportState: true, ImportStateId: "egress", ImportStateVerify: true},
		},
	})
	if s.Anchor("egress") != nil {
		t.Fatal("anchor left behind after destroy")
	}
}

func TestAccAnchorRejectedAtPlan(t *testing.T) {
	s := useFake(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pf_anchor" "bad" {
  name  = "bad"
  rules = [{ action = "pass", interface = "frontend", family = "inet", label = "` + fakepfapid.RejectLabel + `" }]
}`,
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`Rules rejected by the firewall`),
		}},
	})
	if s.Confirms != 0 {
		t.Fatal("a rejected plan changed the firewall")
	}
}

func TestAccAnchorConfigValidation(t *testing.T) {
	useFake(t)
	for name, cfg := range map[string]string{
		"non-canonical prefix": `from = { prefixes = ["2001:DB8::/32"] }`,
		"host bits":            `from = { prefixes = ["10.1.2.3/8"] }`,
		"two address kinds":    `from = { prefixes = ["10.0.0.0/8"], table = "x" }`,
		"empty endpoint":       `from = {}`,
		"self and table":       `to = { self = true, table = "x" }`,
		"negate nothing":       `to = { negate = true, ports = [{ from = 22 }] }`,
		"negated list":         `to = { negate = true, prefixes = ["10.0.0.0/8", "192.168.0.0/16"] }`,
		"icmp type injection":  `protocol = "icmp", icmp_types = ["echoreq }"]`,
		"icmp type duplicate":  `protocol = "icmp", icmp_types = ["echoreq", "echoreq"]`,
		"label injection":      `label = "x\" pass all"`,
	} {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      `resource "pf_anchor" "x" { ` + "\n" + `name = "x"` + "\n" + `rules = [{ action = "pass", interface = "frontend", family = "inet", ` + cfg + ` }]` + "\n}",
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(`(?i)invalid|conflicting|empty endpoint|must|negate|duplicate`),
				}},
			})
		})
	}
}

func TestAccTable(t *testing.T) {
	s := useFake(t, "k8s_nodes")
	cfg := func(entries ...string) string {
		return `resource "pf_table" "nodes" {
  name    = "k8s_nodes"
  entries = ["` + strings.Join(entries, `", "`) + `"]
}`
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg("10.70.1.10/32", "2001:db8:70::/64"), Check: resource.TestCheckResourceAttr("pf_table.nodes", "entries.#", "2")},
			{ResourceName: "pf_table.nodes", ImportState: true, ImportStateId: "k8s_nodes", ImportStateVerify: true},
			{Config: cfg("10.70.1.10/32", "10.70.1.11/32", "2001:db8:70::/64"), Check: resource.TestCheckResourceAttr("pf_table.nodes", "entries.#", "3")},
			{
				PreConfig: func() { s.TamperTable("k8s_nodes", "192.0.2.99/32") },
				Config:    cfg("10.70.1.10/32", "10.70.1.11/32", "2001:db8:70::/64"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("pf_table.nodes", plancheck.ResourceActionUpdate),
				}},
			},
			{Config: cfg("10.70.1.10/32", "10.70.1.11/32", "2001:db8:70::/64"), PlanOnly: true},
		},
	})
	if got := s.Table("k8s_nodes"); len(got) != 0 {
		t.Fatalf("destroy did not empty the table: %v", got)
	}
}

// TestAccLab runs against a real pfapid when PFAPID_ENDPOINT etc. point at
// one (the lab firewall, see README). It creates and destroys anchor
// "k8s-tfacc" and needs table k8s_nodes in the firewall's policy.
func TestAccLab(t *testing.T) {
	if os.Getenv(envEndpoint) == "" {
		t.Skip(envEndpoint + " not set: no lab firewall")
	}
	cfg := strings.Replace(anchorV1, `"k8s-test"`, `"k8s-tfacc"`, 1)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					// pfctl expands the port list: 2 API rules -> 3 pf rules.
					resource.TestCheckResourceAttr("pf_anchor.k8s", "pf_rules.#", "3"),
					resource.TestMatchResourceAttr("pf_anchor.k8s", "pf_rules.1", regexp.MustCompile(`port = 6443 flags S/SA label "k8s-api"$`)),
				),
			},
			{Config: cfg, PlanOnly: true},
			{ResourceName: "pf_anchor.k8s", ImportState: true, ImportStateId: "k8s-tfacc", ImportStateVerify: true},
		},
	})
}
