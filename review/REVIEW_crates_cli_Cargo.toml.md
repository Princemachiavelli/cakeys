# Review: crates/cli/Cargo.toml (64 lines)

Reviewed 2026-11-18 [read]. Summary: the `cakeys` library and binary; provider features
forwarded to cli-common; a long dev-dependency list for the integration-test harness.

## Findings

### F1. The description is stale — nit

`crates/cli/Cargo.toml:3`.
"Content-addressed identity for PKCS#11 (and later TPM) objects": TPM keys are supported now
(tpm2-pkcs11 provider and `tpm-certify`, the `tpm2` feature on line 24). [read]

### F2. `serde_json` repeated under dev-dependencies — nit

`crates/cli/Cargo.toml:34`, `:46`.
Already a normal dependency. [read]

## Design

None.

## Checked, no issue

- B7 (Done): `serde` is no longer a dependency of `cakeys`; `cakeys` depends on neither caprobe
  nor camigrate, as ARCHITECTURE.md says.
- `tpm2`/`ykcs11` test targets require their features.
