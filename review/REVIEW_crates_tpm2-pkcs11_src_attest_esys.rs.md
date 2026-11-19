# Review: crates/tpm2-pkcs11/src/attest/esys.rs (657 lines)

Reviewed 2026-11-18 [read]. Summary: the native `TPM2_Certify` path: AK provisioning and
template check, unsealing the token wrapping key, unwrapping the object auth, loading the
store's blobs, certifying with a fresh 32-byte nonce, and host verification (ECDSA-SHA256 over
the re-marshalled `TPMS_ATTEST`, Names against the store blob and the loaded object, qualified
signer, material cross-check). Freshness, signer and Name checks are right. The one weakness is
which public area the material and attribute cross-checks read.

## Findings

### F1. Material and `objectAttributes` come from `TPM2_ReadPublic`, not from the bytes whose Name was signed — risk

**Verification:** confirmed. The attested Name is compared with `recompute_name(&tobj.pub_blob)` and with ReadPublic's `name` (esys.rs:530-535), but `material` (SPKI, `local`, `extractable`) is `material_of(&live_public)`, ReadPublic's `outPublic` (:518,546,572-578), which nothing hashes; ESYS returns the three fields as unmarshalled (`Tss2_Sys_ReadPublic_Complete`, Esys_ReadPublic.c:341-345 in the store's tpm2-tss source), and only password sessions are used (esys.rs:102,113,217,279,329), so no response HMAC binds them. The attack needs a pinned AK (a first-run interposer could also substitute the AK's ReadPublic at :92/:123); the fix, `material_of(unmarshal(tobj.pub_blob))`, is cheap. [read, src]
`crates/tpm2-pkcs11/src/attest/esys.rs:518, 546, 572-579`. The signed statement covers the Name;
the host recomputes that Name from the store's blob (`:530`) and compares it with
`ReadPublic`'s *name* (`:533`), but then derives the SPKI and `local`/`extractable` from
`live_public`, `ReadPublic`'s *public area*, which the host never hashes. Nothing on the host
ties `live_public` to the signed Name. With an honest TPM and transport they are the same; but
the transport is unauthenticated (no salted/HMAC session), and the module doc (`:10-12`: "its
Name is recomputed from the store's public blob, and the key material it names is cross-checked")
and DESIGN §3.7 ("match the signed `objectAttributes`") claim the cross-checks read signed data.
Scenario: a TCTI-level interposer (resource manager, `swtpm:` socket) passes Certify through
for an object K but rewrites the `ReadPublic` response's `outPublic` to the victim key's public
area while keeping K's `name` → every check passes and the attestation is recorded for material
it does not name. The library does not close it: tpm2-tss's `Esys_ReadPublic_Finish`
(`src/tss2-esys/api/Esys_ReadPublic.c`, source in the Nix store) unmarshals `outPublic`, `name`
and `qualifiedName` as the TPM sent them, without recomputing the name [src]. Fix:
derive `material` from `unmarshal_public(&tobj.pub_blob)` (the blob `recompute_name` hashed and
the signed Name equals), and keep `live_public` only for the Name comparison. [read]

**Fixed (2026-11-18):** `verify_certified` derives the material from `unmarshal_public(pub_blob)`
and refuses a ReadPublic area that is not that blob's (13). Test:
`the_material_is_the_attested_blobs_not_read_publics`.

### F2. The PIN-derived seal auth is not zeroized — practice

`crates/tpm2-pkcs11/src/attest/esys.rs:190-197, 208`. `seal_auth` returns a plain `Vec<u8>`
(the hex of `SHA-256[..16](PIN‖salt)`), which unseals the token wrapping key exactly as the PIN
does; the digest array is not wiped either. It is consumed by `Auth::try_from`, but the
intermediate `String` from `hex::encode` and the `GenericArray` stay in freed memory. Elsewhere
the file is careful (`Zeroizing` wrapping key and object auth). Return `Zeroizing<Vec<u8>>`
and wipe the digest. [read]

**Fixed (2026-11-18):** `seal_auth` returns `Zeroizing<Vec<u8>>` holding the hex text's own
buffer (`into_bytes`, no copy), wipes the digest, and `wrapping_key` copies it into `Auth` from a
slice. Test: `the_seal_auth_is_the_modules_and_wiped` (known answer: PIN "123456", salt "abcd"
→ `7eb6640227367c8ff142d877496ca3ec`, computed with `sha256sum`).

### F3. Any `TR_FromTPMPublic` failure is taken for "no AK at the handle" — nit

`crates/tpm2-pkcs11/src/attest/esys.rs:88-100`. `if let Ok(tr) = …` swallows the error: a TPM
communication error is reported as "no Attestation Key … `lock` provisions it" (16, or 14 once
locked) on a read, and under `lock` leads to `create_primary` + `EvictControl` and a misleading
"is the handle free?" failure. Distinguish `TPM_RC_HANDLE` (absent) from other errors. [read]

**Fixed (2026-11-18):** `ak_at` takes only `TPM_RC_HANDLE` for "no AK at the handle"; any other
`Esys_TR_FromTPMPublic` failure is unavailable (16), naming the handle and the error, and
`lock` provisions nothing. The swtpm suite's `tpm2_keys_attest_their_tpm_residence` and
`tpm2_attestation_says_what_it_lacks` pass with it (swtpm answers an empty handle with
`TPM_RC_HANDLE`) [run]. Test: `only_tpm_rc_handle_means_no_attestation_key`.

### F4. The signature's hash algorithm is not checked — nit

`crates/tpm2-pkcs11/src/attest/esys.rs:365-378`. `Signature::EcDsa(ecc)` is verified with
SHA-256 whatever `ecc.hashing_algorithm()` says. The AK's restricted scheme forces SHA-256, and a
different hash would simply fail to verify, so this only gives a worse message than "the AK
signed with … not ECDSA-SHA256" which the function promises. Check it. [read]

**Fixed (2026-11-18):** `verify_signature` refuses an ECDSA signature over any hash but SHA-256
as unsupported (15), naming the hash, before any verification. Test:
`attestation_signatures_are_verified_on_the_host` (its SHA-384 case).

## Design

- The AK is trusted on first use (DESIGN §3.7, "not implemented yet": EK → AK). Together with F1
  this means the whole TPM path's integrity rests on the TCTI transport at `lock` time; an
  encrypted/HMAC session salted to the AK (or EK) would authenticate `ReadPublic` responses too,
  and is the natural companion of the EK work.
- `flushing` (`:63-67`) ignores the flush error on purpose; persistent handles from
  `tr_from_tpm_public` (parent twice, AK once) are never `tr_close`d, which is harmless as the
  context is dropped after one attestation.

## Checked, no issue

- Freshness: 32 random bytes from `getrandom`, compared with `extra_data` (`:339`); type must be
  `Certify` (`:334`, again at `:522`).
- Signature: host ECDSA-SHA256 over `attest.marshall()`; r/s left-padded with a length check
  (no panic on > 32 bytes); the magic is re-emitted as `TPM_GENERATED_VALUE`, so only a
  TPM-generated structure can verify under a restricted key.
- Signer: `qualified_signer` equals the AK's qualified Name; the AK's public area must equal the
  template except `unique` (`check_ak`): restricted, sign-only, fixedTPM/fixedParent,
  sensitiveDataOrigin, empty policy, P-256/ECDSA-SHA256 — an unrestricted key at the handle is
  refused (13).
- Name: `recompute_name` hashes the store blob's TPMT_PUBLIC with its `nameAlg` (SHA-256/384/512,
  others refused), all slicing via `get`/`first_chunk` (no panics; fuzzed). Attested Name and
  qualified Name must equal the loaded object's.
- Material: RSA exponent 0 → 65537; ECC point from `unique` (TPM pads coordinates to the curve
  size); symmetric objects have no SPKI and an asymmetric/symmetric mismatch is a conflict.
- Unwrap of the object auth: `<iv>:<tag>:<ct>`, 12-byte IV and 16-byte tag enforced, AES-256-GCM,
  output `Zeroizing`; wrapping key length checked (32).
- `blob_content`: `2 + size` cannot overflow (`size ≤ 0xFFFF`); trailing bytes are ignored, and a
  lossy tss-esapi round trip would make the loaded Name differ (caught at `:533`).
