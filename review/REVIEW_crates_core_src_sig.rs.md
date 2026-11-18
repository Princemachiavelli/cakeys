# Review: crates/core/src/sig.rs (165 lines)

Reviewed 2026-11-18 [read]. Summary: the signature verifiers every host-side check shares
(proof of possession, the PIV chain, `TPM2_Certify`): ECDSA in raw or DER encoding over a
chosen or curve-default hash, strict Ed25519, RSA PKCS#1 v1.5 and PSS. Small and correct; the
contract of its return type no longer matches how it is used after Q20.

## Findings

### F1. `Verdict`'s `None` means two things, and the module doc describes the pre-Q20 use — practice

`crates/core/src/sig.rs:1-5,13-14` vs `:99,113,128` and `:68-71`. The doc says each function
answers `None` "when the SPKI is not a key it verifies, so callers can try the next
algorithm". Since Q20 no caller tries the next one (`pop::verify_with`, ykcs11
`attest.rs:310-317`, tpm2 `esys.rs:378`, caprobe all pick by algorithm first). And the
helpers disagree: `ed25519`, `rsa_pkcs1v15` and `rsa_pss` return `None` when their own parser
refuses a key of the right algorithm (dropping the reason, e.g. rsa's `ModulusTooSmall`),
while `ecdsa` returns `Some(Err("the public key: …"))` for the same situation. Callers then
word "not my kind" and "malformed key" the same way (see REVIEW pop.rs F3). Fix: return
`Result<(), VerifyError>` with a `Key(String)` / `Signature(String)` split, and update the
module doc. [read]

### F2. `ecdsa` re-parses the SPKI twice — nit

`crates/core/src/sig.rs:68,85`. `KeyAlg::of_spki` parses the SPKI to pick the curve, then
`PublicKey::from_public_key_der` parses it again. Harmless at these sizes; mentioned only
because the same double parse is in `pop::ecdh_challenge` and `id::spki_canonical`, and a
`KeyAlg` that carried the parsed `SubjectPublicKeyInfoRef` would remove all three. [read]

## Design

None.

## Checked, no issue

- `normalize_s` before verify: accepts either `s` (needed for secp256k1's low-s verifier).
- Ed25519 uses `verify_strict` (rejects small-order and non-canonical encodings).
- `HashAlg::for_curve` matches FIPS 186-5 strength pairing; Edwards → `None`.
- PSS salt length is the digest length (`rsa::pss::VerifyingKey::new`), as the doc says.
- Q15 (Done in part): `EcdsaHash` is `HashAlg` and serves both ECDSA and RSA.
