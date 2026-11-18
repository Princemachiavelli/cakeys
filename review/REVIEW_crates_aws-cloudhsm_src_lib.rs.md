# Review: crates/aws-cloudhsm/src/lib.rs (140 lines)

Reviewed 2026-11-18 [read]. Summary: the AWS CloudHSM provider: repairs the Ed25519 key's
`CKA_EC_POINT` (whole SPKI → point) and `CKA_KEY_TYPE` (`CKK_EC` with the Ed25519 OID →
`CKK_EC_EDWARDS`), and stands in `CKM_EC_KEY_PAIR_GEN` and the vendor `CKM_CLOUDHSM_EDDSA` for
the Edwards generation and pure EdDSA. Small, exact, tested. No findings of substance.

## Findings

### F1. A direct `cryptoki-sys` dependency for one null-pointer check — nit

`crates/aws-cloudhsm/src/lib.rs:74`, `crates/aws-cloudhsm/Cargo.toml`. Whether the requested
EdDSA mechanism is pure is read by converting it to a raw `CK_MECHANISM` and testing
`pParameter.is_null()`. It works (tested for `Pure` and `Ed25519ctx`), but ties the provider to
cryptoki's FFI layout; a match on the `Mechanism::Eddsa` parameters (the scheme `Pure`, if
cryptoki exposes it) would say the same in the safe API. [read]

## Design

- §4(b) holds (verified 2026-11-18): imports only `ModuleInfo`, `Provider`, `Report` and cryptoki
  types; implements `name`, `matches`, `repair`, `stand_in`.
- `crates/pkcs11/src/provider.rs:641-643` documents `aws-cloudhsm` as one of the *data*
  providers (`Data`), but this crate registers a code provider of that name, which
  `Registry::named_in` prefers (`cli-common` registers it). The doc comment is stale; noted here
  because the overlap of names is this crate's (the profile family `aws-cloudhsm` and the code
  provider share one name).

## Checked, no issue

- `ed25519_point`: strips the exact 12-byte RFC 8410 prefix only when 32 bytes follow; anything
  else (SEC1, DER-wrapped, short) passes through. A SEC1 or DER-wrapped point never starts with
  `0x30`, so no other key's point is touched.
- Key-type repair only for `CKK_EC` with `CKA_EC_PARAMS` exactly the Ed25519 OID.
- `stand_in`: Edwards generation → `CKM_EC_KEY_PAIR_GEN`; EdDSA only without parameters →
  vendor mechanism; Ed25519ctx/ph and Ed448 have none. `stand_ins()` derives
  `[ECC_EDWARDS_KEY_PAIR_GEN, EDDSA]`, which the probe measures before anything relies on it.
- `matches`: manufacturer `CloudHSM` with padding trimmed, as the profiles' `[match]`.
