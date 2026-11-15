# PR for parallaxsecond/rust-cryptoki: `CKM_RSA_AES_KEY_WRAP`

Status: **filed** as draft [#377](https://github.com/parallaxsecond/rust-cryptoki/pull/377)
(2026-11-15), branch `jhoffer/Add-CKM_RSA_AES_KEY_WRAP` of Princemachiavelli/rust-cryptoki.

- `nix/patches/cryptoki-rsa-aes-key-wrap.patch` on main, plus a test, `wrap_and_unwrap_key_rsa_aes`:
  an AES key wrapped under an RSA public key and unwrapped under its private key encrypts alike.
  It passes on SoftHSM 2.7.0 and is skipped where the token does not list the mechanism
  (kryoptic 1.5.3).
- When a release with it is out, drop the patch and its line in `nix/package-common.nix`.

Local equivalent: `nix/patches/cryptoki-rsa-aes-key-wrap.patch`.
