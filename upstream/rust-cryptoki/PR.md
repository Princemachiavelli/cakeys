# Draft PR for parallaxsecond/rust-cryptoki

Status: **draft, not filed.** Before opening it:
- Add your DCO sign-off; rust-cryptoki commits carry `Signed-off-by`. Run `git am` on the patch, then
  `git commit --amend -s`.
- When a release with the fix is out, drop `nix/patches/cryptoki-hmac-key-types.patch` and the
  `postPatch` that applies it in `nix/package.nix`.

Checked on 2026-11-11 against main `2e4ff5d` and release 0.12.1 (the bug is in both; key-mgmnt uses
0.10.1, which has it too). There is no existing issue or PR for `SHA384_HMAC`.

Local equivalent: `nix/patches/cryptoki-hmac-key-types.patch` (the same three constants, against
0.10.1).

---

**Title:** Fix the values of the SHA-224/384/512 HMAC key types

**Body:**

`KeyType::SHA224_HMAC`, `KeyType::SHA384_HMAC` and `KeyType::SHA512_HMAC` are all defined with
`val: CKK_SHA256_HMAC` (0x2b):

```rust
/// SHA384 HMAC key
pub const SHA384_HMAC: KeyType = KeyType {
    val: CKK_SHA256_HMAC,
};
```

That breaks both directions:
- **Writing.** `Attribute::KeyType(KeyType::SHA384_HMAC)` creates a `CKK_SHA256_HMAC` key. SoftHSM
  then rejects `CKM_SHA384_HMAC` on it with `CKR_KEY_TYPE_INCONSISTENT`.
- **Reading.** `TryFrom<CK_KEY_TYPE>` maps `CKK_SHA224_HMAC` (0x2e), `CKK_SHA384_HMAC` (0x2c) and
  `CKK_SHA512_HMAC` (0x2d) to these constants. A key type read from a token therefore comes back as
  `CKK_SHA256_HMAC`, and the four HMAC key types cannot be told apart.

This PR uses the matching `CKK_*` values and adds a unit test that every HMAC key type round-trips
through `TryFrom<CK_KEY_TYPE>`. Without the fix, the test fails with
`assertion left == right failed: CKK_SHA256_HMAC, left: 43, right: 46`.

We found this while adopting `CKK_SHA384_HMAC` keys created by `tpm2_ptool import
--algorithm=hmac:sha384` (tpm2-pkcs11), and SoftHSM keys of each HMAC type. With the fix, HMAC
signatures with each key's own mechanism match a host-side HMAC.
