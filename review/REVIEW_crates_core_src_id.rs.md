# Review: crates/core/src/id.rs (1068 lines)

Reviewed 2026-11-18 [read]. Summary: SRI rendering, the spec digest (JCS), scheme names,
commitment labels and inputs, attestation encodings, curves and their OIDs, and canonical SPKI
from points, SPKIs, RSA components and certificates. The identity definitions are pinned by
known-answer tests and the Q20 dispatch (`KeyAlg`) is in place. Issues are at the edges: RSA
key sizes the `rsa` crate refuses, and one OID dispatcher that Q20 left behind.

## Findings

### F1. RSA keys outside 1024–8192 bits (or with e > 2^33−1) have no identity, reported as 13 — risk

**Verification:** confirmed. `rsa_spki` calls `rsa::PublicKey::new` (id.rs:649-653), which in rsa-0.10.0 is `new_with_size_limits(.., 1024..=8192)` plus the exponent cap (public_key.rs:89-91,246), and maps the error to `Conflict` (exit 13, error.rs:140); `Token::spki` reaches it through `material_spki` (identity.rs:87,270) with no earlier size refusal (the only modulus floor is for declared transport keys, config.rs:1631). The SPKI path (`from_public_key_der` → `PublicKey::new`, encoding.rs:88,187) gives `Unsupported` 15. [read]
`crates/core/src/id.rs:648-655` (`rsa_spki`), `:639` (`spki_canonical`, RSA arm). Both build an
`rsa::PublicKey` with `PublicKey::new` / `from_public_key_der`, which in rsa 0.10.0 enforce
`MIN_SIZE = 1024`, `MAX_SIZE = 8192` and `MAX_PUB_EXPONENT = 2^33−1`
(`rsa-0.10.0/src/public_key.rs:36-60,89-125`). Identity is a hash of public bytes and does not
need a key the crate would use. Failure scenario: adopting a legacy RSA-768 key, or a
certificate whose subject key is RSA-768 or RSA-16384, on any token → `rsa_spki` returns
`Conflict("invalid RSA public key: ModulusTooSmall")`, exit 13 ("the object is not what the spec
says"), which reads as tampering; via `cert_spki`/`spki_canonical` it is `Unsupported` (15).
Legacy and oversized keys are realistic on HSMs (project memory: real-world objects are not
the clean test set). Fix: canonicalize RSA SPKIs with the `pkcs1`/`spki` encoders directly (or
`PublicKey::new_unchecked` after the odd/nonzero check), and report a key cakeys refuses on
policy as `Unsupported` with its size, never `Conflict`. Uncertain whether any shipped verb
refuses such keys earlier on purpose (the RSA size check in `pkcs11/src/token/policy.rs` is
for declared `modulusBits`); if the refusal is intended, it still needs the 15 code and a
message. [read]

### F2. `spki_curve` is a second OID dispatcher beside `KeyAlg::of`, with looser rules — complexity

`crates/core/src/id.rs:663-680` vs `:552-575`. Q20 moved five sites onto `KeyAlg`; this one
still matches OID strings itself and differs: it accepts `id-ecPublicKey` whose parameters are
an Edwards OID or the by-name `PrintableString "edwards25519"` (`Curve::from_params` also
matches `params_by_name`, `:492-494`; returns `Ed25519`), and an algorithm OID that is a Weierstrass curve's OID
(e.g. 1.3.132.0.34 as the algorithm returns `P384`), both of which `KeyAlg::of` refuses; and it
returns `Conflict` for a non-SPKI where `KeyAlg::of_spki` returns `Unsupported`. It also
reaches `spki` through `x509_cert::spki` while the rest of the file uses `p256::pkcs8`. Used by
the stand-in check ("as the stand-in check compares it with the private key's own"). Fix:
`KeyAlg::of_spki(spki).map(|a| match a { KeyAlg::Ec(c) => Some(c), KeyAlg::Rsa => None })`. [read]

## Design

- The identity of a public key is defined as "canonical DER SPKI" but computed through crypto
  crates that also apply usage policy (size limits, point validation). Point validation is
  wanted (it is the canonicalization), size policy is not; F1 is where the two meet.
- Ed448 points are checked for length only (`:604-605`, documented). Any 57-byte string is an
  "Ed448 public key" identity; a token returning garbage for an Ed448 `CKA_EC_POINT` is pinned
  as that garbage. Acceptable while Ed448 binding must be `token-asserted`, but worth a line in
  DESIGN.md's assurance table.

## Checked, no issue

- Q20 (Done): `spki_canonical`, `KeyAlg::of_spki`/`of_pkcs8` dispatch on the algorithm OID; a
  malformed key is refused by its own parser and named.
- `spki_from_point` wrapped-then-raw fallback cannot misread a raw point as a wrapped one: for
  every curve the inner length of a "wrapped" reading of a valid raw point is never a valid
  point length (P-256 65→63, P-521 133→130, Ed25519 32→30, Ed448 57→55).
- `rsa_spki` with a zero-padded modulus: the DER encoder strips leading zeros (`UintRef::new`),
  so padding does not change the identity (B17's concern on the hashing side).
- `is_sri` uses the canonical-padding STANDARD engine; `Commit::label` cannot overflow
  (`valueLen` bounded to `u32::MAX` at load, ×8 fits `u64`).
- `attest_encoding` is length-prefixed and injective (fuzzing.rs property, Kani-free by design).
- Scheme names, deprecation register, spec digests and commitment inputs are pinned by tests.
