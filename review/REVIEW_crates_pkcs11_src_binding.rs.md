# Review: crates/pkcs11/src/binding.rs (78 lines)

Reviewed 2026-11-18 [read]. Summary: the cryptoki binding layer, empty when this build's
cryptoki carries the HMAC key-type fix, else the committed subtractions; plus a test that the
patched binding comes with `sign-after-init`. Small and correct.

## Findings

### F1. The patched binding is not held to `rv-value` the way it is to `sign-after-init` — nit

`crates/pkcs11/src/binding.rs:68-76`. `the_sign_after_init_feature_comes_with_the_patched_binding`
fails a build that links the patched cryptoki without `sign-after-init`. The `rv-value` feature
comes from the same patch set (`nix/package-common.nix:81`) and its absence changes control
flow, not only names (`REVIEW_crates_pkcs11_src_token_mod.rs.md` F1), yet nothing pins it. Fix:
add `assert!(!patched() || cfg!(feature = "rv-value"))` beside the existing assertion. [read]

## Design

- `patched()` infers "the Nix patch set is applied" from one of its patches (the HMAC
  constants); the doc says the KWP patch rides along. The `rv-value` and `sign-after-init`
  features are separate switches over the same patch set, so a build can be half-patched in
  spirit. One `cfg` (a single `nix-patched` feature implying the others) would remove the
  combinations nobody tests.

## Checked, no issue

- `patched()` compares the three constants with PKCS#11's values (0x2e, 0x2c, 0x2d), as
  `token::hmac_key_type` does.
- `layer()` returns the committed `cryptoki/0.12` profile from the active set when unpatched,
  and an empty layer named the same when patched (test).
