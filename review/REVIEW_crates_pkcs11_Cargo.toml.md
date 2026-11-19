# Review: crates/pkcs11/Cargo.toml (36 lines)

Reviewed 2026-11-18 [read]. Summary: the crate manifest: workspace metadata and lints, ten
dependencies, two features for the patched cryptoki. Tidy; one dependency belongs in
dev-dependencies, and the feature split has a consequence worth stating.

## Findings

### F1. `rv-value` is off by default, and its absence changes behaviour, not only names — risk

**Verification:** confirmed; same root cause as REVIEW_crates_pkcs11_src_token_mod.rs.md F1 (one fix). The feature comment (Cargo.toml:32-35) and ARCHITECTURE.md:218-220 say only that a failure "carries no value", but caprobe branches on that value (probe.rs:391,1241 via `rv_is`, token/mod.rs:302), and caprobe's Cargo.toml does not enable `cakeys-pkcs11/rv-value` (only nix/package-common.nix:81 does). [read]
`crates/pkcs11/Cargo.toml:31-35`. The comment says "Without it a named failure carries no
value, only its name". Since Q3, caprobe branches on that value (`rv_is(..,
OperationActive)`), so a plain cargo build of caprobe records busy-session failures as `no`
rows. Details and fix in `REVIEW_crates_pkcs11_src_token_mod.rs.md` F1 (same root cause, one
fix); at the manifest level, either derive the value without the patch or have caprobe require
the feature. [read]

**Fixed (2026-11-18):** each tool has one `patched-cryptoki` feature implying `kwp`, `rv-value`
and `sign-after-init`, which the Nix builds (package-common.nix `features`, the crane `minimal`
build) name instead of the parts. `caprobe probe` refuses to write or diff a profile unless the
binding is patched and both `rv-value` and `kwp` are on (`build_lacks`), and the tests of
`cakeys-pkcs11` and caprobe fail when the patched binding is linked without them. Tests:
`a_kept_profile_needs_every_patch_and_feature`, `the_patched_binding_comes_with_its_features`.

### F2. `toml` is used only by tests — nit

`crates/pkcs11/Cargo.toml:18`. In `crates/pkcs11/src`, `toml::` appears only inside
`#[cfg(test)]` modules (`gate.rs:274`, `resolution.rs:457`, `token/uri.rs:209`). It is a normal
dependency, so every consumer builds it for this crate (core pulls it too, so the cost is nil
today). Fix: move it to `[dev-dependencies]`. [read]

## Design

None beyond F1.

## Checked, no issue

- `[lints] workspace = true`: the `unsafe_code` lint applies; the one `unsafe` (`loaded_path`)
  carries an `#[expect]` with a reason.
- B7 (`aes`, `sha2` dropped): neither is listed; `aes-kw`, `getrandom`, `libc`, `rsa`,
  `x509-cert`, `der`, `zeroize`, `cryptoki-sys` are each used in `src/`.
- `sign-after-init` is documented with what a build without it refuses.
