# Draft PR for parallaxsecond/rust-cryptoki: single-part sign after `sign_init`

Status: **not needed, not filed.** Upstream main already has the same call as
`Session::sign_single` (d1b283ec, "Expose single-part crypto operations", 2026-02-12), not yet in a
release (0.12.1 lacks it).

- Done: cakeys depends on main (the git rev in `Cargo.toml`) and calls `sign_single`; the patch,
  its line in `nix/package-common.nix` and the `sign-after-init` feature of `cakeys-pkcs11` are
  gone.

The draft below is kept for the record.

Local equivalent (removed): a `nix/patches/cryptoki-sign-after-init.patch` with the same
`sign_initialized`, in this repository's history.

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
