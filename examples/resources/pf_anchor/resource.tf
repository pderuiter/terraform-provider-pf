# Kubernetes API and ingress for the prod cluster, plus egress NAT for its
# IPv4 node network. Loaded as anchor api/k8s-prod.
resource "pf_anchor" "k8s_prod" {
  name = "k8s-prod"
  rules = [
    {
      action    = "pass"
      direction = "in"
      quick     = true
      interface = "frontend"
      family    = "inet"
      protocol  = "tcp"
      to        = { table = "k8s_nodes", ports = [{ from = 443 }, { from = 6443 }] }
      label     = "k8s-prod-api"
    },
    {
      action    = "pass"
      direction = "in"
      quick     = true
      interface = "frontend"
      family    = "inet6"
      protocol  = "tcp"
      to        = { table = "k8s_nodes", ports = [{ from = 443 }] }
    },
    {
      action    = "match"
      direction = "out"
      interface = "frontend"
      family    = "inet"
      from      = { prefixes = ["10.70.1.0/24"] }
      nat       = { kind = "nat-to", interface = "frontend" }
    },
  ]
}

# Egress to the internet only (everything but RFC 1918, a const table the
# base ruleset owns and lists in policy.ref_tables), and ping to the
# firewall itself.
resource "pf_anchor" "egress" {
  name = "egress"
  rules = [
    {
      action    = "pass"
      direction = "in"
      interface = "frontend"
      family    = "inet"
      from      = { prefixes = ["10.70.1.0/24"] }
      to        = { negate = true, table = "rfc1918" }
    },
    {
      action     = "pass"
      direction  = "in"
      interface  = "frontend"
      family     = "inet"
      protocol   = "icmp"
      from       = { prefixes = ["10.70.1.0/24"] }
      to         = { self = true }
      icmp_types = ["echoreq"]
    },
  ]
}
