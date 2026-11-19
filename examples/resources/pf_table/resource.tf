# Contents of <k8s_nodes>, declared in the base ruleset as
#   table <k8s_nodes> persist
resource "pf_table" "k8s_nodes" {
  name = "k8s_nodes"
  entries = [
    "10.70.1.10/32",
    "10.70.1.11/32",
    "10.70.1.12/32",
    "2001:db8:70::/64",
  ]
}
