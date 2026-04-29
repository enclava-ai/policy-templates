# Enclava Policy Templates

This repository owns CAP's authoritative Trustee policy templates and the
off-cluster signing-service implementation described by
`cap/SECURITY_MITIGATION_PLAN.md` rev14.

CAP API must not compose policy text. The signing service reconstructs Rego
from versioned templates in this repository, signs the reconstructed artifact,
and returns the signed envelope to CAP for Trustee storage.

## v1 Decisions

- Key custody: GitHub Actions OIDC + cosign keyless for container provenance;
  service policy-signing key loaded from platform secret storage at runtime.
- Policy template id: `trustee-resource-policy-v1`.
- Canonical encoding: CE-v1 raw TLV bytes for Ed25519 signing inputs.
- Template source of truth: `templates/trustee-resource-policy-v1.rego`.
- Owner state: signing service SQLite DB, not CAP DB.
- Signed request blobs: base64-encoded JSON envelopes for
  `DeploymentDescriptorEnvelope` and `OrgKeyringEnvelope`.

## Layout

- `templates/` - reviewed Rego templates.
- `fixtures/` - CE-v1 sign/verify reference vectors.
- `signing-service/` - Rust HTTP service.
- `docs/` - bootstrap, rotation, and release-runbook notes.

## Signing Service Runtime

Required production env:

- `POLICY_SIGNING_KEY_B64` - base64 Ed25519 seed, 32 bytes.
- `POLICY_SIGNING_KEY_ID` - release/key version bound into signed metadata.
- `OWNER_DB_PATH` - durable SQLite owner DB path.

Optional local/dev env:

- `BIND_ADDR` - defaults to `0.0.0.0:8080`.
- `ALLOW_EPHEMERAL_SIGNING_KEY=1` - test-only escape hatch when no signing key
  is configured.
- `GENPOLICY_BIN`, `GENPOLICY_VERSION_PIN`, `GENPOLICY_SETTINGS_DIR` - see
  `docs/genpolicy-adapter.md`. The service refuses to start if
  `GENPOLICY_VERSION_PIN` is missing, `unconfigured`, or `unpinned`.

## Signing Service Image

Build the image from the repository root so the crate can embed the reviewed
Rego template at compile time:

```bash
docker build -f signing-service/Dockerfile -t enclava-policy-signing-service:local .
```

The image runs as non-root UID/GID `65532`, listens on `BIND_ADDR`, and stores
the owner SQLite database at `OWNER_DB_PATH`. The default image env sets:

- `BIND_ADDR=0.0.0.0:8080`
- `OWNER_DB_PATH=/data/owner-state.sqlite3`
- `GENPOLICY_BIN=/usr/local/bin/genpolicy`
- `GENPOLICY_RULES_PATH=/etc/genpolicy/rules.rego`
- `GENPOLICY_SETTINGS_DIR=/etc/genpolicy`

Production deployments must mount durable storage at `/data` and provide
`POLICY_SIGNING_KEY_B64`, `POLICY_SIGNING_KEY_ID`, `OWNER_DB_PATH`, and a
pinned `GENPOLICY_VERSION_PIN`. The image bakes Kata `genpolicy` from the
pinned `kata-tools-static` release plus `rules.rego` and the default settings
under `/etc/genpolicy`; override `GENPOLICY_BIN`, `GENPOLICY_RULES_PATH`, or
`GENPOLICY_SETTINGS_DIR` only when shipping a new platform release. Do not set
`ALLOW_EPHEMERAL_SIGNING_KEY` outside local tests.

cap-test01 currently records the live Kata runtime source as
`kata-containers/genpolicy@3.28.0+660e3bb6535b141c84430acb25b159857278d596`.
The Dockerfile verifies the matching
`kata-tools-static-3.28.0-amd64.tar.zst` digest
`825dbf929dc5fe3f77d1a473511fd8950f08b5f81b33803c79085dbc233ab94b` and copies
`genpolicy` from that archive.

Minimal Kubernetes scaffolding lives in
`signing-service/deploy/kubernetes.yaml`. Before applying it, replace the image
placeholder with an immutable digest, source the signing key from the platform
secret manager, set the genpolicy version pin, and wire any genpolicy binary or
settings mounts required by the release.

`POST /sign` no longer accepts caller-provided policy slots. It decodes the
descriptor and keyring blobs, verifies:

1. org keyring owner signature against the bootstrapped owner pubkey in the
   signing-service DB,
2. descriptor signer membership in the verified keyring,
3. descriptor Ed25519 signature over D11 CE-v1 bytes,
4. Kata `genpolicy` can render an agent policy from the verified descriptor,
5. template id/hash and rendered KBS policy hash.

Only then does it return `SignedPolicyArtifact`.
The v1 envelope field names match Trustee and `enclava-init`: `{ metadata,
rego_text, signature }`, with `signature` encoded as lowercase hex. Extra
diagnostic fields such as `rego_sha256` and `verify_pubkey_b64` are
non-authoritative.

## Release Requirements

Every platform release must publish:

- `policy_template_id`
- `policy_template_sha256`
- `policy_template_text`
- signing-service verify pubkey
- genpolicy version pin
- signing-service image digest/provenance

## Local Verification

```bash
cd signing-service
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Container build verification:

```bash
docker build -f signing-service/Dockerfile -t enclava-policy-signing-service:local .
```
