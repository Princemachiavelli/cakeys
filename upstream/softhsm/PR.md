# Draft PR for softhsm/SoftHSMv2

Status: **draft, not filed.** Before opening it:

- Add your sign-off if the project asks for one, and set the commit date and author:
  `git am` the patch, then `git commit --amend --reset-author`.
- **Issue and prior PR.** This fixes [#628](https://github.com/softhsm/SoftHSMv2/issues/628)
  ("Unwrapped AES keys have VALUE_LEN set to 0", open since the report). A maintainer confirmed
  the cause in that thread (`CKA_VALUE_LEN` is not set on `C_UnwrapKey`). **PR #650**
  ("CKA_VALUE_LEN is synthesized on every secret key", branch `fix-issue-628`) is open and
  unmerged, with the same core change and one `dcoombs` confirmation that it fixes the problem.
  Decide before filing: comment on #650 with the points below (the `attributeExists` guard, the
  test that destroys the unwrapped key, the AES check), or file this one. Do not file both
  without linking them.
- When a release with the fix is out, drop `nix/softhsm-unwrap-value-len.nix`,
  `checks.softhsm-unwrap-value-len` and this directory's patch, and read the `[manual]` entry
  in `profiles/modules/softhsm/2.7.toml` again.

Checked on 2026-11-13 against main `7380895` (2026-11-11) and release 2.7.0 (nixpkgs' build):
both still have the bug (`src/lib/SoftHSM.cpp`, `C_UnwrapKey`). The patch was made against 2.7.0
and applies to `7380895` with offsets only (SoftHSM.cpp +1221 lines, the test file +5).

Local equivalent: `nix/softhsm-unwrap-value-len.nix` applies this patch to nixpkgs' `softhsm`.

---

**Title:** C_UnwrapKey: set CKA_VALUE_LEN on the unwrapped secret key

**Body:**

Fixes #628.

`C_UnwrapKey` creates the secret key from the template, then stores the recovered `CKA_VALUE`.
`CKA_VALUE_LEN` is never written, so it keeps the default that `P11AttrValueLen::setDefault()`
gives it, 0:

    $ # AES-256 key wrapped with CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD or CKM_RSA_PKCS_OAEP,
    $ # then unwrapped with a template of CKA_SENSITIVE=false, CKA_EXTRACTABLE=true
    CKA_VALUE_LEN=0 len(CKA_VALUE)=32

The key works, because the internal code uses the length of `CKA_VALUE`, but a client that reads
`CKA_VALUE_LEN` (to pick a mechanism, to compare the key with the one it wrapped, to re-wrap
it) is told the key has no length.

The template cannot fix it. `P11AttrValueLen::updateAttr()` refuses `CKA_VALUE_LEN` outside
generate and derive with `CKR_ATTRIBUTE_READ_ONLY`, and for AES the attribute carries `ck6`
("must not be specified when unwrapped"). That matches PKCS#11 (v2.40 4.1.2, footnote 6):
`CKA_VALUE_LEN` is not to be in the template, and the mechanism supplies it, "the mechanism
contributes only the CKA_CLASS and CKA_VALUE (and CKA_VALUE_LEN, if the key has it) attributes to
the recovered key". So this change leaves the refusal alone and sets the attribute from the
recovered value.

Changes:

- **`C_UnwrapKey`:** after storing `CKA_VALUE`, set `CKA_VALUE_LEN` to the length of the
  recovered key data. Only when the object has the attribute: AES and generic secret keys do,
  DES and DES3 keys do not, and are left as they were.
- **test:** `aesWrapUnwrapGeneric` (run for `CKM_AES_KEY_WRAP`, `CKM_AES_CBC_PAD` and
  `CKM_AES_KEY_WRAP_PAD`) reads `CKA_VALUE_LEN` of the unwrapped key and compares it with the
  key length it wrapped (128 bytes, or 125 for the padded mechanism, so a padded key reports its
  unpadded length). It also destroys the unwrapped key, which the test leaked. Without the fix
  it fails with `assertion failed - Expression: unwrappedValueLen == keyLen`.

Checked on SoftHSM 2.7.0 with OpenSSL 3.5: `make check` passes with the patch, and `p11test`
fails on the new assertion without it. An AES-256 key wrapped and unwrapped with
`CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD` and `CKM_RSA_PKCS_OAEP` (python-pkcs11, as in the
report) reads `CKA_VALUE_LEN` 0 before and 32 after, with `CKA_VALUE` unchanged.

Not covered: unwrapped private keys (`CKO_PRIVATE_KEY`) have no `CKA_VALUE_LEN`, and unwrapping
a key type that has no `CKA_VALUE_LEN` object attribute is unchanged.
