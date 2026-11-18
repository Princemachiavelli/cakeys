# Draft PR for parallaxsecond/rust-cryptoki: `RvError` back to its `CK_RV`, and its name

Status: **draft, not filed.** Upstream main has only `From<CK_RV> for Rv` (checked 2026-11-17).

- cakeys builds with this file as it is, no local copy: `nix/package-common.nix` lists it among
  the cryptoki patches (and `scripts/local-tests.sh` applies it from there), and
  `cakeys_pkcs11::token`'s `rv_value` and `rv_name` use `CK_RV::from` and `RvError::name` behind
  the `rv-value` feature. Without it (plain cargo) a failure is named from its variant, which
  `names_agree` holds equal, and carries no value. When a release has the conversion, drop the
  feature and the patch line. p11-fault keeps `p11-names`' table: its plans name values.
- Not covered: the eleven PKCS#11 3.x return values cryptoki-sys defines but `RvError` has no
  variant for (`CKR_TOKEN_NOT_INITIALIZED`, `CKR_PENDING`, ...) stay `UnknownErrorCode`, so
  `name()` is `None` and cakeys prints them as `CKR 0x…`. Adding variants breaks exhaustive
  matches downstream (`RvError` is not `#[non_exhaustive]`): a follow-up for a breaking release.
- The patch: `0003-Add-RvError-to-CK_RV-and-its-name.patch`, against 0.12.1's
  `cryptoki/src/error/rv.rs`, paths relative to the crate as 0002's are. It turns upstream's one list (the `From<CK_RV> for Rv` match) into
  a `macro_rules!` table, `Variant => CKR_CONSTANT`, that generates that match, its inverse and
  `name` (`stringify!` of the constant): one list, so the three cannot disagree, and the file
  grows by 51 lines rather than two more 100-arm matches. The generated inverse match is
  exhaustive, so a new variant fails to compile until it has a row. `round_trip` passes against
  0.12.1 (the crate's own unit tests, run without its dev-dependencies).
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
serves all three. It adds:

- `impl From<RvError> for CK_RV` and `impl From<Rv> for CK_RV`, the inverse of
  `From<CK_RV> for Rv`: `VendorDefined` and `UnknownErrorCode` give back the value they carry.
- `RvError::name(&self) -> Option<&'static str>`: the `CKR_*` constant's name as the
  specification spells it, `None` for a vendor-defined or unknown value.

The test `round_trip` converts every value below `0x1000` and two vendor-defined ones to `Rv`
and back, and checks that exactly the named variants have a name.

We use the value to keep a module's return code in our errors and the name in messages and in
recorded evidence, where it must not change with the binding's wording.
