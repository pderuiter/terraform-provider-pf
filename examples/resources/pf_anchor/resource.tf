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
