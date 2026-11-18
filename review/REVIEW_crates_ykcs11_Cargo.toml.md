# Review: crates/ykcs11/Cargo.toml (24 lines)

Reviewed 2026-11-18 [read]. Summary: workspace-inherited metadata and lints; dependencies are
core, pkcs11, cryptoki, x509-cert, sha2; build-dependencies base16ct and sha2 for the root pins.

## Findings

### F1. No feature gates the fuzzing entry point — nit

`crates/ykcs11/Cargo.toml` (whole file). There is no `fuzzing` feature, so `pub mod fuzzing` and
the test-fixture root it embeds (see REVIEW_crates_ykcs11_src_attest.rs.md F1) are always
compiled into the provider. Add `[features] fuzzing = []` and enable it from `fuzz/Cargo.toml`.
[read]

## Design

None.

## Checked, no issue

- Every dependency is used: `sha2` by `attest.rs` (`rsa_pkcs1v15::<sha2::Sha256>` etc.),
  `x509-cert` for parsing, `cryptoki` for attributes. No dev-dependencies needed (fixtures are
  read with `std::fs`).
- `publish.workspace = true` (false), consistent with ISSUES.md's deferred publish pass.
