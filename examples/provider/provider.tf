# Credentials normally come from the environment:
#   PFAPID_ENDPOINT, PFAPID_CA_CERT, PFAPID_CLIENT_CERT, PFAPID_CLIENT_KEY
provider "pf" {
  endpoint    = "https://192.0.2.1:8443"
  ca_cert     = "/etc/pfapid-client/ca.crt"
  client_cert = "/etc/pfapid-client/tf-k8s-prod.crt"
  client_key  = "/etc/pfapid-client/tf-k8s-prod.key"
}
