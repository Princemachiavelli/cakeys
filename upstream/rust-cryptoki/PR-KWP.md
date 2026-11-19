# Draft PR for parallaxsecond/rust-cryptoki: `CKM_AES_KEY_WRAP_KWP`

Status: **filed** as [#376](https://github.com/parallaxsecond/rust-cryptoki/pull/376)
(2026-11-14, open).

- The review asked for a test that uses the mechanism; it is in the PR's one commit (squashed,
  `2cde156`): a wrap and unwrap like `wrap_and_unwrap_key_rsa_aes` in #377
  (PR-RSA-AES-KEY-WRAP.md), skipped where the token does not list it (SoftHSM names RFC 5649
  `CKM_AES_KEY_WRAP_PAD`; kryoptic offers `_KWP`).
- When a release with it is out, drop `nix/patches/cryptoki-aes-key-wrap-kwp.patch` and its line
  in `nix/package-common.nix`; `kwp` then stays only if a build without the wraps still needs it
  (it sits in caprobe's and camigrate's `patched-cryptoki`, `patched_cryptoki.rs` and `build_lacks`).

Local equivalent: `nix/patches/cryptoki-aes-key-wrap-kwp.patch`.

---

**Title:** Add `CKM_AES_KEY_WRAP_KWP` (RFC 5649 key wrap with padding)

**Body:**

PKCS#11 3.0 added `CKM_AES_KEY_WRAP_KWP` (0x210B) for AES key wrap with padding as specified in
RFC 5649, because the 2.40 `CKM_AES_KEY_WRAP_PAD` (0x210A) was ambiguous about which padding it
means. Modules implementing 3.x offer the new ID; kryoptic, for example, lists 0x210B (and 0x210C,
`CKM_AES_KEY_WRAP_PKCS7`) but not 0x210A. `cryptoki-sys` already has the constant; `cryptoki` has
no `MechanismType` or `Mechanism` for it, and a raw `MechanismType` can only be built in the vendor
range, so the mechanism cannot be used.

This PR adds `MechanismType::AES_KEY_WRAP_KWP` (with its `Display` name and `TryFrom` arm) and a
parameterless `Mechanism::AesKeyWrapKwp`, mirroring `AES_KEY_WRAP_PAD`.

We need it to move private keys between tokens: wrapped with RFC 5649 on one module and unwrapped on
another. Between SoftHSM 2.7 (`CKM_AES_KEY_WRAP_PAD`) and kryoptic 1.5.4 (`CKM_AES_KEY_WRAP_KWP`) the
wrapped bytes are interchangeable in both directions, for secret keys and for PKCS#8 private keys,
so the two IDs name one format there, but the mechanism must be requested by the ID the module
offers.
