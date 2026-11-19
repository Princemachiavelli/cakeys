# Review: crates/tpm2-pkcs11/src/lib.rs (195 lines)

Reviewed 2026-11-18 [read]. Summary: the tpm2-pkcs11 provider: P-521 `CKA_EC_POINT` repair,
the secret-key hint, `tpm-certify` capability and hook, options check, and the `tpm2_ptool`
import. `fix_ec_point` is exact and proven (Kani for inputs up to 258 bytes, proptest beyond).
No findings of substance.

## Findings

None.

## Design

- The crate's public surface is wider than the `Provider` hook set: `pub mod attest` (with
  `esys`, `store` and their functions), `pub fn fix_ec_point`, and `pub mod fuzzing`. Outside the
  crate only `cli-common`'s registration and three fuzz targets use it. See
  REVIEW_crates_tpm2-pkcs11_src_attest_mod.rs.md, Design.
- `classes: [PrivateKey, SecretKey]` and the hint ("secret keys cannot be generated … adopt them")
  agree with the profile's subtractions; consistent with ARCHITECTURE.md's provider table.

## Checked, no issue

- `fix_ec_point` / `is_der_octets`: `rest.len() == len` before rewriting; `04 81 80 <128>` (valid
  DER) left alone (found by the proptest, now in the unit test); the property "repaired is DER of
  the same point and idempotent" is the Kani harness (`checks.kani`, commit 69ee620).
- `repair` keeps `Cow::Borrowed` where nothing changes; other `Report` variants pass through.
  It runs on every `CKA_EC_POINT`, Edwards keys included, but the shape it rewrites
  (`04 <len ≥ 0x80> <len bytes>`, not already DER) is one no raw or DER Edwards point has.
- `matches`: exact manufacturer `tpm2-software.github.io`, as both tpm2 profiles' `[match]`.
- `check_options` delegates to `Tpm2Options::of` (unknown names and bad `akHandle` → 17 at open).
