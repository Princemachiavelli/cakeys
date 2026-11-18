# Review: crates/tpm2-pkcs11/Cargo.toml (31 lines)

Reviewed 2026-11-18 [read]. Summary: workspace metadata; dependencies for the provider, the
TSS (`tss-esapi`), the store (`rusqlite`, `serde_norway`), the object-auth unwrap (`aes-gcm`),
hashing, RNG, zeroize, memfd (`rustix`) and base64; dev-dependencies `toml` and `proptest`.

## Findings

### F1. No feature gates the fuzzing entry points — nit

`crates/tpm2-pkcs11/Cargo.toml` (whole file). As in ykcs11, `fuzzing` modules
(`lib.rs:105`, `attest/mod.rs:11`) are always compiled into the provider; a `fuzzing = []`
feature enabled from `fuzz/Cargo.toml` would keep them out of the binaries. [read]

## Design

`rustix` is used for one call (`memfd_create`), Linux-only; the crate is built only with the
`tpm2` feature, which Darwin omits (ARCHITECTURE.md), so this is consistent.

## Checked, no issue

- Every dependency is used: `serde` (`Tpm2Options`, `Attrs`), `serde_norway` (store YAML),
  `cryptoki` (attributes), `getrandom` (nonce), `zeroize` (`Zeroizing`), `base64` (PEM in
  ptool), `sha2` (Name, seal auth), `aes-gcm` (object auth). `toml` and `proptest` are used only
  in tests.
