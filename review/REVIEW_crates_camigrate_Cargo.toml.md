# Review: crates/camigrate/Cargo.toml (63 lines)

Reviewed 2026-11-18 [read]. Summary: the manifest. It has workspace-inherited metadata and lints,
the `tpm2`/`ykcs11` provider features (default on), the `kwp` feature for the patched cryptoki,
and runtime and test dependencies. Every runtime dependency is used in `src/`.

## Findings

### F1. `sha2` is listed twice — nit

`crates/camigrate/Cargo.toml:50` and `:61`. It is a normal dependency (file.rs's PKCS#12 MAC),
so the dev-dependency entry adds nothing. [read]

**Fixed (2026-11-18):** the dev-dependency entry is gone.

### F2. The `kwp` feature is not tied to the patch it needs — nit

`crates/camigrate/Cargo.toml:29`. Turning on `kwp` without the patched cryptoki fails to compile.
The reverse case (the patched binding linked without `kwp`) is caught only by a unit test
(lib.rs:1519, `the_kwp_feature_comes_with_the_patched_binding`). That is documented and
deliberate. Noted only because the same pairing exists for caprobe's `kwp` and
`cakeys-pkcs11/rv-value`, `sign-after-init`: one workspace-level feature might be simpler to keep
consistent. [read]

**Fixed (2026-11-18):** each tool has one `patched-cryptoki` feature implying `kwp`,
`cakeys-pkcs11/rv-value` and `sign-after-init`, which the Nix build names (review D3).

## Design

None.

## Checked, no issue

- Runtime dependencies are all used: `rsa` (sealed, keyfile), `x509-cert` (public, keyfile),
  `pkcs8`, `pkcs12` and `der` (file, keyfile), `hmac` and `getrandom` (file), `serde_json`
  (plans as JSON), `cakeys-profile` (tokens), `zeroize`.
- The dev-dependencies `aes`, `aes-kw`, `cmac` and `des` are used by the shared test harness
  `crates/cli/tests/common/mod.rs`, which the integration tests include. `p11-fault` is a
  dev-dependency so its cdylib is built for `tests/fault.rs`.
