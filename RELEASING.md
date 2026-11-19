# Releasing

Releases are fully automated: merge to `main`, and the pipeline tags, builds,
signs, stores and publishes. The flow is the same as terraform-provider-listmonk
(GitLab project 276), which is the reference. Everything is built and signed on our own GitLab
runners. Nexus holds the copy of record; GitHub only receives a copy of those
exact files, because the Terraform Registry ingests GitHub releases.

```
MR merged to main
  └─ main pipeline: tests ─┬─ mirror:github   main → github.com/pderuiter/terraform-provider-pf
                           └─ release:tag     vX.Y.Z from Conventional Commits (ci-cd-toolkit)
tag pipeline (vX.Y.Z)
  └─ tests ── build:release   GoReleaser (build only): zips, SHA256SUMS, manifest
               ├─ sign:gpg     SHA256SUMS.sig (Registry key, from Vault)
               └─ sign:cosign  *.sigstore.json (estate cosign key, Vault transit)
             publish:nexus     → nexus.bsdserver.nl/repository/terraform-providers/pderuiter/pf/<version>/
             publish:github    fetch from Nexus, verify checksums + signature, mirror tag,
                               draft release + assets → publish (Registry ingests it), GitLab release
             verify:registry   terraform init from registry.terraform.io (signature checked)
```

The GitHub release is created as a draft and only published once every asset
is uploaded, so the Registry never ingests a partial release.

## Platforms

Linux, macOS, Windows, FreeBSD and OpenBSD (`.goreleaser.yml`). OpenBSD is
included because the operator of a pf firewall may well run Terraform there.

## Versions

Semantic Versioning, computed by the toolkit's `release:tag` from the commits
since the last tag:

| Commits contain                                   | Bump  |
|---------------------------------------------------|-------|
| `type!:` / `type(scope)!:` or `BREAKING CHANGE:`  | major |
| `feat:` / `feat(scope):`                          | minor |
| anything else                                     | patch |

Breaking changes for a provider: removing or renaming a resource, data source
or attribute; making an optional attribute required; changing a default;
anything that makes an existing configuration plan a replacement. While on
0.x these still get a `!` so the changelog says so. Add upgrade notes to
`CHANGELOG.md` in the same MR.

Deprecate before removing: mark the attribute `DeprecationMessage` in one minor
release, remove it in the next major.

### Manual or pre-release tags

The release jobs accept any `vX.Y.Z` or `vX.Y.Z-pre` tag pushed by a maintainer
(protected tags). Pre-releases become GitHub pre-releases; users only get them
by pinning the exact version.

## Published versions are immutable

The Registry stores each version's checksums and users lock them in
`.terraform.lock.hcl`. Never delete and re-push a tag or edit a GitHub release's
assets. The Nexus repository is `ALLOW_ONCE`, `publish:nexus` fails when a
stored file differs from a rebuild, `publish:github` refuses to overwrite a tag
that GitHub has at another commit and never edits a published release. A
broken release gets fixed by the next patch version.

If a release must be pulled: delete the version in the Registry (provider
settings → versions); leave the tag.

## Secrets and access

| What                       | Where                                                 |
|----------------------------|-------------------------------------------------------|
| GPG signing key            | Vault `secret/wbyc/prd/infra/terraform-registry/gpg`: `private_key` (ASCII-armoured), `passphrase`, `public_key` (reference copy; CI checks against the committed `.asc`, not this) |
| GitHub token               | Vault `secret/wbyc/prd/infra/github/pderuiter`: `token` (shared by every provider repository; adopted by terragrunt-live prd/security/vault-management) |
| Nexus upload               | Vault `secret/prod/nexus/ci-publish` (service account `ci-publish`, managed by prd/infra/nexus-security) |
| cosign                     | Vault transit key `cosign-estate` (never leaves Vault) |
| Vault login                | JWT role `gitlab-ci-terraform-registry` (`RELEASE_VAULT_ROLE`), bound to this project's protected refs |
| Tag push                   | group access token `PROJECT_ACCESS_TOKEN` on wbyc/infra/iac/terraform |

The shared `gitlab-ci` Vault policy explicitly denies
`secret/wbyc/prd/infra/terraform-registry/*` and `secret/wbyc/prd/infra/github/*`:
only the release role can read the signing key and the GitHub token, and only
from protected refs of the provider projects.

The GitHub token is a fine-grained PAT of `pderuiter` limited to the provider
repositories (`terraform-provider-listmonk`, `terraform-provider-haproxy-dataplane`,
`terraform-provider-pf`) with *Contents: read and write* (push, releases) and
*Metadata: read*. A new provider is added to that token's repository list, not
given its own token.

The signing key must be RSA or DSA (Registry requirement) and its public half
registered at registry.terraform.io → pderuiter → Settings → Signing Keys. The
current key is `10A2F1058821D55C61E45C7EE97C02FEE2F51B23` (RSA 4096,
sign-only, expires 2029-11-12). It was generated straight into Vault with a
random passphrase and exists nowhere else. Its public half is committed as
`scripts/terraform-registry-signing-key.asc`, and `sign:gpg` refuses any other
key. The earlier namespace key `39C79E83…` stays registered for the versions it
signed (terraform-provider-haproxy-dataplane), but cannot sign anything new.

### Rotating the GPG key

1. Generate an RSA 4096 key, add the public key to the Registry namespace
   **before** the first release signed with it (keep the old key listed: old
   versions stay signed with it).
2. Replace `scripts/terraform-registry-signing-key.asc` with the new public
   key (MR) and the fields in Vault.
3. The next release is signed with the new key; `verify:registry` confirms the
   Registry accepts it. The key expires 2029-11-12: rotate (or extend the
   expiry and re-register) well before.

## One-time setup

Each step must be done **before** the first `feat:`/`fix:` merge to `main`
with these jobs in place. Otherwise the tag pipeline stops at the Vault login,
and that version number has to be released by retrying the jobs once
everything is in place.

1. GitHub: public repo `pderuiter/terraform-provider-pf`, empty (the mirror
   pushes `main`), no branch protection that blocks the mirror; issues on, PRs
   answered with a pointer to GitLab.
2. GitHub token: add `terraform-provider-pf` to the repository list of the
   shared PAT (Vault `secret/wbyc/prd/infra/github/pderuiter`).
3. Vault: GitLab project 317 in the `bound_claims` of JWT role
   `gitlab-ci-terraform-registry` (terragrunt-live prd/security/vault-jwt-auth).
4. GitLab: 317 in `signing_project_ids` of terraform-gitlab-config (Maintainer-only
   merge, `v*` tags protected); the project lives under
   wbyc/infra/iac/terraform, so it inherits `PROJECT_ACCESS_TOKEN`.
5. Registry: after the first GitHub release, registry.terraform.io → Publish →
   Provider → `pderuiter/terraform-provider-pf`. The Registry then picks up
   every published release. The namespace's signing key is already registered.

Shared with the other providers and already in place: Nexus raw repository
`terraform-providers` (ALLOW_ONCE) with the `ci-publish` grant, the Registry
signing key, and the cosign transit key.

## When the Registry does not show a release

`verify:registry` fails after 15 minutes. Check, in order: the GitHub release
has all assets (`_SHA256SUMS`, `.sig`, `_manifest.json`, zips); then
**Resync** on the provider's Registry settings page. A signature error in the Registry means the
key in Vault is not one registered for the namespace.
