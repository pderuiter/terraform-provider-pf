# terraform-provider-pf

Terraform provider for OpenBSD pf, through
[pfapid](https://gitlab.bsdserver.nl/wbyc/infra/pfapid) on the firewall.

* `pf_anchor`: the rules of anchor `api/<name>` (typed rules, NAT, prio, IPv4 and IPv6).
* `pf_table`: the contents of a managed table.

Every change is commit-confirm: if the provider cannot confirm a change (for
example because it cut itself off), the firewall rolls it back. `terraform
plan` checks new rules with the firewall's `pfctl -n`. Hand edits in pf show
as drift and are restored by the next apply.

Documentation: [docs/](docs/index.md). API contract: pfapid `api/openapi.yaml`.

## Development

```sh
make test       # unit tests
make testacc    # Terraform against an in-process fake pfapid (needs terraform)
make generate   # docs/
```

Against the lab firewall (wbyc-srv-test02, a pfapid client scoped to `k8s-*`):

```sh
export PFAPID_ENDPOINT=https://192.168.2.196:8443
export PFAPID_CA_CERT=… PFAPID_CLIENT_CERT=… PFAPID_CLIENT_KEY=…
TF_ACC=1 go test ./internal/provider/ -run TestAccLab -v
```

Trying it from a configuration without a release:

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides { "pderuiter/pf" = "/path/to/go/bin" }
  direct {}
}
```

## Releases

Not wired yet. The plan is the estate's provider release flow (GoReleaser on
base-go, GPG + cosign signing, Nexus raw repo `terraform-providers`, GitHub
mirror and Terraform Registry, see terraform-provider-listmonk RELEASING.md).
It needs this project added to the `gitlab-ci-terraform-registry` JWT role and
`signing_project_ids`.
