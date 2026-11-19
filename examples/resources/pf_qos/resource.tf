# One QoS configuration per firewall. The base ruleset must carry pfapid's
# QoS hooks, and vio1 must be in the firewall's policy.queue_interfaces.
resource "pf_qos" "fw" {
  queues = [
    { name = "rootq", interface = "vio1", bandwidth = "1G", max = "1G" },
    { name = "std", parent = "rootq", bandwidth = "800M", default = true },
    { name = "backup", parent = "rootq", bandwidth = "100M", max = "200M" },
    { name = "voip", parent = "rootq", bandwidth = "50M", flows = 1024, quantum = 1500 },
  ]

  rules = [
    # Classify where the state is created: connections come IN on frontend,
    # and pf queues the replies leaving the firewall.
    {
      direction = "in"
      interface = "frontend"
      family    = "inet"
      protocol  = "tcp"
      to        = { table = "backup_targets", ports = [{ from = 873 }] }
      queue     = { name = "backup" }
      label     = "qos-backup"
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
