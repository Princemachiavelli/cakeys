# Draft PR for parallaxsecond/rust-cryptoki: `RvError` back to its `CK_RV`, and its name

Status: **filed as a draft, parallaxsecond/rust-cryptoki#380** (branch
`Princemachiavelli:jhoffer/Add-RvError-to-CK_RV`). Its first commit was the two-match version;
the second (2026-11-17) is this patch: the table and the ten 3.x variants, rustfmt- and
clippy-clean, against main as of 2e4ff5d (`rv.rs` and `rv_error.rs` as in 0.12.1). The body
below is the PR's.

- cakeys builds with this file as it is, no local copy: `nix/package-common.nix` lists it among
  the cryptoki patches (and `scripts/local-tests.sh` applies it from there), and
  `cakeys_pkcs11::token`'s `rv_value` and `rv_name` use `CK_RV::from` and `RvError::name` behind
  the `rv-value` feature. Without it (plain cargo) a failure is named from its variant, which
  `names_agree` holds equal, and carries no value. When a release has the conversion, drop the
  feature and the patch line. p11-fault keeps `p11-names`' table: its plans name values.
- The patch: `0003-Add-RvError-to-CK_RV-and-its-name.patch`, against 0.12.1's
  `cryptoki/src/error/rv.rs` and `rv_error.rs`, paths relative to the crate as 0002's are. It
  turns upstream's one list (the `From<CK_RV> for Rv` match) into a `macro_rules!` table,
  `Variant => CKR_CONSTANT`, that generates that match, its inverse and `name` (`stringify!` of
  the constant): one list, so the three cannot disagree, and `rv.rs` grows by about 50 lines
  rather than two more 100-arm matches. The generated inverse match is exhaustive, so a new
  variant fails to compile until it has a row. `round_trip` passes against 0.12.1 (the crate's
  own unit tests, run without its dev-dependencies).
- It also adds the ten return values cryptoki-sys 0.5 defines but `RvError` had no variant for,
  all PKCS#11 3.x: `CKR_AEAD_DECRYPT_FAILED` (0x42) and `CKR_TOKEN_RESOURCE_EXCEEDED` through
  `CKR_PARAMETER_SET_NOT_SUPPORTED` (0x201–0x209). Until now they arrived as `UnknownErrorCode`.
  Their doc and `Display` text is the constant's name, as for `NewPinMode` and `NextOtp`,
  except `OperationCancelFailed`, which quotes PKCS#11 3.1 §5.1.6; 3.1 describes none of the
  others in §5.1 (v3.2's text not checked).
- A new variant of a public enum without `#[non_exhaustive]` is a breaking change in principle:
  a `match` naming every variant and no `_` stops compiling. In practice `RvError` has some
  ninety variants and its users match a few and fall through, so we expect no one to notice;
  the PR says so, and a 0.x minor release may break anyway. The one quiet change: a caller
  testing `UnknownErrorCode(0x208)` now gets `TokenNotInitialized`.
- Why not derive the name from the variant (`GeneralError` -> `CKR_GENERAL_ERROR`, what
  `derived_name` in cakeys does without the patch): it holds for every variant today
  (`names_agree`), but it gives an allocated `String`, holds only while every
  variant is named after its constant, and cannot give the value back; the table gives all three
  from the constant itself.

---

**Title:** Convert `RvError` and `Rv` back to `CK_RV`, and name the `CKR_*` constant

**Body:**

`Rv` converts from a `CK_RV`, but not back. A caller that wants the numeric return value of a
failed call (to log it, compare it with a vendor's documentation, or hand it to another layer
that speaks `CK_RV`) has only `Debug` or `Display`: `Display` is the specification's prose, and
deriving a `CKR_*` name from `Debug` depends on the variant names matching the constants.

This PR turns the `From<CK_RV> for Rv` match into a table (`RvError` variant => `CKR_*`
constant) that a `macro_rules!` expands into that match and the two additions below, so one list
serves all three and they cannot disagree. The generated inverse match is exhaustive: a new
variant fails to compile until it has a row. It adds:

- `impl From<RvError> for CK_RV` and `impl From<Rv> for CK_RV`, the inverse of
  `From<CK_RV> for Rv`: `VendorDefined` and `UnknownErrorCode` give back the value they carry.
- `RvError::name(&self) -> Option<&'static str>`: the `CKR_*` constant's name as the
  specification spells it, `None` for a vendor-defined or unknown value.
- Variants for the ten return values `cryptoki-sys` already defines but `RvError` lacked, all
  from PKCS#11 3.x: `AeadDecryptFailed` (`CKR_AEAD_DECRYPT_FAILED`), `TokenResourceExceeded`,
  `OperationCancelFailed`, `KeyExhausted`, `Pending`, `SessionAsyncNotSupported`,
  `SeedRandomRequired`, `OperationNotValidated`, `TokenNotInitialized` and
  `ParameterSetNotSupported` (`CKR_TOKEN_RESOURCE_EXCEEDED` through
  `CKR_PARAMETER_SET_NOT_SUPPORTED`). They used to come back as `UnknownErrorCode`. Their
  `Display` is the constant's name, as for `NewPinMode` and `NextOtp`, except
  `OperationCancelFailed`, which quotes the specification; it describes none of the others.

Adding variants to `RvError`, which is not `#[non_exhaustive]`, breaks a `match` that lists
every variant without a wildcard; with some ninety variants we expect none does. A caller that
tested for `UnknownErrorCode` with one of these ten values now gets the named variant.

The test `round_trip` converts every value below `0x1000` and two vendor-defined ones to `Rv`
and back, and checks that exactly the named variants have a name.

We use the value to keep a module's return code in our errors and the name in messages and in
recorded evidence, where it must not change with the binding's wording.
