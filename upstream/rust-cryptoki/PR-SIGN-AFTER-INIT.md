# Draft PR for parallaxsecond/rust-cryptoki: single-part sign after `sign_init`

Status: **draft, not filed.** Before opening it:

- Apply `nix/patches/cryptoki-sign-after-init.patch` (made against release 0.12.1, which cakeys
  uses) to a checkout of main, commit with your DCO sign-off (`git commit -s`), and check that
  main has no equivalent by now.
- Add a test against SoftHSM like the existing signing ones: a key with
  `CKA_ALWAYS_AUTHENTICATE = true`, `sign_init`, `login(UserType::ContextSpecific, …)`, then
  `sign_initialized`, and verify the signature; and the same key failing `Session::sign` without
  the login.
- Consider the same for `C_Decrypt` after `C_DecryptInit` (`decrypt_initialized`): decryption
  keys can be `CKA_ALWAYS_AUTHENTICATE` too.
- When a release with it is out, drop the patch, its line in `nix/package-common.nix` and the
  `sign-after-init` feature of `cakeys-pkcs11`.

Local equivalent: `nix/patches/cryptoki-sign-after-init.patch`.

---

**Title:** Add `Session::sign_initialized`: single-part `C_Sign` after `sign_init`

**Body:**

A key with `CKA_ALWAYS_AUTHENTICATE = true` needs a context-specific login after `C_SignInit` and
before the signature (PKCS#11 3.2 §5.1: `C_SignInit`, `C_Login` with `CKU_CONTEXT_SPECIFIC`,
then `C_Sign`). `Session::sign` issues `C_SignInit` and `C_Sign` in one call, leaving no point
for the login, so the only way today is the multi-part `sign_init`/`sign_update`/`sign_final`.
That fails where a mechanism signs in a single part only: `CKM_EDDSA` and raw `CKM_ECDSA` by
the specification, and modules that offer some mechanisms single-part only (SoftHSM 2.7 signs
`CKM_ECDSA_SHA256` that way).

This PR adds `Session::sign_initialized(&self, data: &[u8]) -> Result<Vec<u8>>`: the single-part
`C_Sign` (length query, then the signature) for an operation `sign_init` started, as
`Session::sign` does after its own `C_SignInit`.

We use it to prove possession of `CKA_ALWAYS_AUTHENTICATE` keys (a fresh challenge signed under the
per-use PIN) on SoftHSM, kryoptic and YubiKey PIV slots whose PIN policy is "always".
