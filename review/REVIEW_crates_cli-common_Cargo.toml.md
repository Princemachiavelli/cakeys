# Review: crates/cli-common/Cargo.toml (31 lines)

Reviewed 2026-11-18 [read]. Summary: the shared CLI crate; kmsp11 and aws-cloudhsm always
linked, ykcs11 and tpm2-pkcs11 optional behind `ykcs11`/`tpm2`.

## Findings

### F1. The description lists exit codes, which live in core — nit

`crates/cli-common/Cargo.toml:3`.
"…the provider registry, opening tokens, exit codes": the codes are `KmError::exit_code` in
cakeys-core; this crate only maps errors to them. Also missing are profile activation and the
lock read/save it now owns (Q14, Q24). [read]

**Fixed (2026-11-18):** the description lists the provider registry, profile activation,
opening tokens, reading and saving the lock, and mapping errors to their exit codes.

## Design

None.

## Checked, no issue

- `default = ["tpm2", "ykcs11"]` here is overridden by the workspace's `default-features = false`
  on `cakeys-cli-common`, so each binary's own features decide; `dep:` syntax keeps the optional
  crates from becoming implicit features.
- `serde` is used (`print`'s `Serialize` bound) and `cakeys-profile` by `activate_profiles`.
