package provider

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

func qosConfig(slow string) string {
	return `
resource "pf_qos" "fw" {
  queues = [
    { name = "rootq", interface = "vio1", bandwidth = "1G", max = "1G" },
    { name = "std", parent = "rootq", bandwidth = "900M", default = true },
    { name = "slow", parent = "rootq", bandwidth = "` + slow + `", max = "` + slow + `" },
    { name = "voip", parent = "rootq", bandwidth = "10M", flows = 1024, quantum = 1500 },
  ]
  rules = [
    {
      direction = "in"
      interface = "frontend"
      family    = "inet"
      protocol  = "tcp"
      to        = { ports = [{ from = 5001 }] }
      queue     = { name = "slow" }
      label     = "tfacc-slow"
    },
    {
      direction = "in"
      interface = "frontend"
      family    = "inet6"
      protocol  = "udp"
      to        = { ports = [{ from = 5060, to = 5061 }] }
      queue     = { name = "voip", priority = "std" }
      prio      = { normal = 6 }
    },
  ]
}
`
}

func TestAccQoS(t *testing.T) {
	s := useFake(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: qosConfig("2M"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pf_qos.fw", "id", "qos"),
					resource.TestCheckResourceAttr("pf_qos.fw", "queues.#", "4"),
					resource.TestCheckResourceAttr("pf_qos.fw", "queues.1.default", "true"),
					resource.TestCheckResourceAttr("pf_qos.fw", "rules.1.queue.priority", "std"),
					resource.TestCheckResourceAttr("pf_qos.fw", "pf_rules.#", "6"),
					resource.TestCheckResourceAttrSet("pf_qos.fw", "etag"),
				),
			},
			{ResourceName: "pf_qos.fw", ImportState: true, ImportStateId: "qos", ImportStateVerify: true},
			{
				Config: qosConfig("5M"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("pf_qos.fw", plancheck.ResourceActionUpdate),
				}},
				Check: resource.TestCheckResourceAttr("pf_qos.fw", "queues.2.max", "5M"),
			},
			{
				PreConfig: s.TamperQoS,
				Config:    qosConfig("5M"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("pf_qos.fw", plancheck.ResourceActionUpdate),
				}},
			},
			{Config: qosConfig("5M"), PlanOnly: true},
		},
	})
	if got := string(s.QoS()); got != `{"queues":[],"rules":[]}` {
		t.Fatalf("destroy left QoS behind: %s", got)
	}
	if s.Pending() {
		t.Fatal("change left pending")
	}
}

func TestAccQoSRefusesToOverwrite(t *testing.T) {
	useFake(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: qosConfig("2M")},
			{
				// A second configuration (state removed) must not take over.
				Config:      qosConfig("2M") + strings.Replace(qosConfig("3M"), `"fw"`, `"other"`, 1),
				ExpectError: regexp.MustCompile(`already has a QoS configuration`),
			},
		},
	})
}

func TestAccQoSConfigValidation(t *testing.T) {
	useFake(t)
	for name, cfg := range map[string]string{
		"percent bandwidth": `queues = [{ name = "r", interface = "vio1", bandwidth = "50%" }]
  rules = []`,
		"root and child": `queues = [{ name = "r", interface = "vio1", parent = "x", bandwidth = "1M" }]
  rules = []`,
		"rule without effect": `queues = []
  rules = [{ interface = "frontend", family = "inet" }]`,
	} {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      "resource \"pf_qos\" \"x\" {\n  " + cfg + "\n}",
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(`(?i)must be a number|root or child|does nothing`),
				}},
			})
		})
	}
}

// TestAccLabQoS runs against the lab firewall (see TestAccLab). It needs an
// empty QoS document on the firewall and a client with the qos grant.
func TestAccLabQoS(t *testing.T) {
	if os.Getenv(envEndpoint) == "" {
		t.Skip(envEndpoint + " not set: no lab firewall")
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: qosConfig("2M"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pf_qos.fw", "pf_rules.#", "6"),
					resource.TestCheckResourceAttr("pf_qos.fw", "pf_rules.2", "queue slow parent rootq bandwidth 2M, max 2M"),
					resource.TestMatchResourceAttr("pf_qos.fw", "pf_rules.5", regexp.MustCompile(`port 5060:5061 set \(prio 6, queue\(voip, std\)\)$`)),
				),
			},
			{Config: qosConfig("2M"), PlanOnly: true},
			{ResourceName: "pf_qos.fw", ImportState: true, ImportStateId: "qos", ImportStateVerify: true},
		},
	})
}
