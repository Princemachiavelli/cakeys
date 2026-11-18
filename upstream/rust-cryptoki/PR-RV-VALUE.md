# Draft PR for parallaxsecond/rust-cryptoki: `RvError` back to its `CK_RV`, and its name

Status: **draft, not filed.** Upstream main has only `From<CK_RV> for Rv` (checked 2026-11-17).

- cakeys does not carry this as a local patch: `cakeys_pkcs11::token::rv_value` finds the value
  by running `p11-names`' `cryptoki-sys` table through `Rv::from` (ISSUES.md Q4). When a release
  has the conversion, `rv_value` and `rv_name` use it, and only p11-fault keeps the table (its
  plans name values).
- The patch: `0003-Add-RvError-to-CK_RV-and-its-name.patch`, against 0.12.1's
  `cryptoki/src/error/rv.rs`. It turns upstream's one list (the `From<CK_RV> for Rv` match) into
  a `macro_rules!` table, `Variant => CKR_CONSTANT`, that generates that match, its inverse and
  `name` (`stringify!` of the constant): one list, so the three cannot disagree, and the file
  grows by 51 lines rather than two more 100-arm matches. The generated inverse match is
  exhaustive, so a new variant fails to compile until it has a row. `round_trip` passes against
  0.12.1 (the crate's own unit tests, run without its dev-dependencies).
- Why not derive the name from the variant (`GeneralError` -> `CKR_GENERAL_ERROR`, what
  `derived_name` in cakeys does where the table lacks a value): it holds for every variant today
  (`every_named_value_converts_back`), but it gives an allocated `String`, holds only while every
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
