# Draft PR for parallaxsecond/rust-cryptoki: test that vendor-defined mechanism types convert

Status: **draft, not filed; the fix itself is not needed.** Upstream main already accepts a
vendor-range value in `TryFrom<CK_MECHANISM_TYPE> for MechanismType` (6cc2278, "Accept
`TryFrom<CK_MECHANISM_TYPE>` for vendor mechanisms", 2026-06-03, James Wainwright), unreleased:
no tag contains it, 0.12.1 (the version cakeys builds) lacks it. What upstream lacks is a test.
Before opening it:

- Check main still has the arm (`rg 'CKM_VENDOR_DEFINED =>|val >= CKM_VENDOR_DEFINED'
  cryptoki/src/mechanism/mod.rs`) and that no test was added since: this was checked against
  `origin/main` at 2e4ff5d (2026-10-23).
- The patch: `0004-Test-that-vendor-defined-mechanism-types-convert.patch`, a mail with its
  sign-off and paths relative to the repository (`cryptoki/src/mechanism/mod.rs`), unlike
  0001–0003, which are relative to the crate for `nix/package-common.nix`. It applies with
  `git am` to `origin/main` at 2e4ff5d. The test passes there, and fails when the arm is removed
  (what 0.12.1 does): both run with `cargo test -p cryptoki --lib vendor_defined`.
- The commit has a Co-Authored-By line; the PR body below has no AI attribution and no session
  link.
- The repository has no PR template (`.github/` holds workflows only).

Why cakeys wants it: tpm2-pkcs11's `CKM_TPM2_*` and a Kryoptic mechanism (`0x8007678c`) were
dropped from `C_GetMechanismList` by 0.12.1 (the provider asks `C_GetMechanismInfo` instead, which
works either way). cakeys applies the same arm with the same test to 0.12.1 as a local patch,
`nix/patches/cryptoki-vendor-mechanisms.patch`, and regenerated its Kryoptic profile for the row
it now sees (`unknown 8007678c`). When a release has 6cc2278, drop the patch and its line in
`nix/package-common.nix`; the profile row stays.

A remaining wart, not in this PR: a vendor mechanism's `Display` is `unknown 8007678c`, from
`stringify`'s fallback (cakeys' profiles record that text in `advertise`). A name such as
`CKM_VENDOR_DEFINED | 0x8007678c` would be clearer; it changes text callers may match on, so it
is a separate question for upstream.

---

**Title:** Test that vendor-defined mechanism types convert

**Body:**

`TryFrom<CK_MECHANISM_TYPE> for MechanismType` accepts a value in the vendor range since 6cc2278.
That matters beyond the conversion: `Pkcs11::get_mechanism_list` drops every mechanism that does
not convert (`filter_map(|type_| type_.try_into().ok())`), so without the arm a token's vendor
mechanisms vanish from the list and the caller sees a shorter one, with only an `error!` log
line.

Nothing tests it, so removing the arm would pass the suite. This adds one unit test next to the
conversion: a vendor-range value converts to a `MechanismType` that keeps its value and equals
what `MechanismType::new_vendor_defined` makes, and the value just below the range, which has no
name, is still refused.

The test passes on main and fails with the arm removed.
