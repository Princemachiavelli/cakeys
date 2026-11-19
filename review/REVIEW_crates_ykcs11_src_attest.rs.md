# Review: crates/ykcs11/src/attest.rs (478 lines)

Reviewed 2026-11-18 [read]. Summary: host-side verification of a YubiKey PIV attestation (slot
certificate ← f9 device certificate ← pooled Yubico intermediates ← pinned root), the
material cross-check against the object's canonical SPKI, and the `piv-attestation` digest over
the slot certificate's asserted fields. The soundness core holds: every link is signature-checked
over the original `tbsCertificate` bytes, every issuer must be a CA within `pathLen`, the pool is
narrowed to the PIV branch, and the attested SPKI must equal the object's. Findings are hygiene,
not holes.

## Findings

### F1. The production crate verifies chains to the test fixture's root — practice

`crates/ykcs11/src/attest.rs:213-225` (reached from the public `cakeys_ykcs11::fuzzing`,
`lib.rs:42-53`). `fuzz_piv_attestation` embeds `tests/fixtures/root.pem` into the library and
falls back to verifying against it (`.or_else(|_| verify_piv_attestation(.., &FIXTURE_ROOT, ..))`).
It returns `Result<()>`, so no commitment can come out of it and nothing in the verbs calls it;
but it is a public, non-test entry point that accepts a chain to a non-Yubico anchor, and the
fixture PEM ships in every build. Gate `pub mod fuzzing` and this function behind a `fuzzing`
cargo feature (or `cfg(fuzzing)`), as test-only anchors should never be linkable from the
provider. [read]

**Fixed (2026-11-18):** `fuzz_piv_attestation`, its fixture root and `pub mod fuzzing` are compiled only under `cfg(test)`, `kani` or the `fuzzing` feature, which only fuzz/Cargo.toml enables. No test.

### F2. The outer `signatureAlgorithm` is not compared with `tbsCertificate.signature` — nit

`crates/ykcs11/src/attest.rs:311`. Verification dispatches on the unsigned outer
`signature_algorithm().oid` only; RFC 5280 §4.1.1.2 requires it to equal the signed inner
`signature` field, and the RSA `NULL` / ECDSA absent parameters are not checked either. Not
exploitable (an attacker who can swap the hash under the same key still cannot forge), but a
strict verifier refuses the mismatch. Compare `tbs_certificate().signature()` with the outer
algorithm (OID and parameters) before dispatching. [read]

**Fixed (2026-11-18):** `verify_signed_by` refuses (13) a certificate whose outer
`signatureAlgorithm` is not its `tbsCertificate.signature`, OID and parameters, before any
signature check. Test: `the_outer_signature_algorithm_is_the_signed_one`.

### F3. Pool and anchor certificates are re-encoded, against `tbs()`'s own rationale — nit

`crates/ykcs11/src/attest.rs:140` vs `:52-65`. `pem_certs` stores `parsed.to_der()` as `der`,
and pooled intermediates' signatures are verified over `tbs()` sliced from that re-encoding —
exactly the lossy round trip `tbs()`'s comment warns about (an explicit DEFAULT dropped by der
0.8). Today's 15 Yubico intermediates verify (`the_yubico_roots_are_pinned`), so this is latent:
a future intermediate with an explicit `version` DEFAULT or other non-canonical DER would be
refused, never accepted. Keep the PEM-decoded bytes (`der::pem::decode_vec` per block) instead of
re-encoding. [read]

**Fixed (2026-11-18):** `pem_certs` decodes each PEM block itself (`der::pem::decode_vec`) and
keeps those bytes as the certificate's DER; a block that is not a `CERTIFICATE` is refused.
Test: `pem_certificates_keep_their_bytes` (an explicit `version [0] v1`, which der re-encodes
differently, survives).

### F4. Name comparison treats two encoding failures as equal — nit

`crates/ykcs11/src/attest.rs:84-90, 129-131`. `subject_der`/`issuer_der` fall back to an empty
`Vec` on encoding failure, so `issued()` is true for any pair whose names both fail to encode.
Re-encoding a just-decoded `Name` should not fail, and the signature check still follows, so
this is only a misleading shortcut; return `Result` or compare the decoded `Name`s directly. [read]

**Fixed (2026-11-18):** `issued` compares the decoded subject and issuer `Name`s;
`subject_der`/`issuer_der` and their `unwrap_or_default` are gone. No behaviour a valid
certificate can reach changes. Test: `issuers_are_linked_by_name`.

### F5. The walk takes the first name-matching issuer and never backtracks — nit

`crates/ykcs11/src/attest.rs:282, 289`. `pool.iter().find(|c| c.issued(current))` picks the first
certificate with the right subject; if Yubico ever publishes two intermediates with one subject
(a re-key), a chain through the second fails with that first one's signature error. Fine for the
pinned 2025-02-03 pool; worth a comment, or try every name match before failing. [read]

**Fixed (2026-11-18):** the walk (`issuer_chain`) tries every name-matching issuer, pooled
intermediates first and then anchors, depth-bounded at 3 links; when none links, the first
candidate's error is returned, so one-candidate chains report exactly as before. Test:
`every_name_matching_issuer_is_tried` (a decoy with the fixture root's subject and another key,
in the pool and as an earlier anchor).

## Design

- The commitment hashes `extension()` values with "absent" and "empty" both encoded as an empty
  field (`:118-126`, length-prefixed in `id::attest_encoding`, so not ambiguous across fields).
  The values are signed by the device key, so this is acceptable; just note that a firmware that
  drops an extension changes the ID the same way an empty one would.
- `piv_pool` selects the PIV branch by subject-string prefix (`:231-238`). The `pathLen:0` of the
  non-PIV product CAs is the real barrier (`may_issue(1)` refuses them), so the prefix filter is
  belt and braces; a policy-OID or EKU check would be a sturdier selector than CN text if Yubico
  renames CAs.

## Checked, no issue

- ISSUES.md B8 "Done 2026-11-17": verified. `chain_to_anchor` checks the device certificate
  (`:278`), each pooled issuer (`:285`) and the anchor (`:292`), and `verify_piv_attestation`
  the slot certificate (`:175-177`), all against `at`; `at` is `Some` only under `check`
  (`crates/cli/src/lib.rs:144-149`), `lock`/`create`/camigrate pass `ChainTime::Unchecked`.
  Inclusive bounds per RFC 5280 §4.1.2.5.
- `pathLen` counting: `below` counts the CA certificates under the issuer, f9 included; root ←
  f9 needs `pathLen ≥ 1` (classic root has 1), root ← IntA ← PIV A ← f9 gives 1/2/3 (Attestation
  Root 1 has 3). Correct. Verified the pinned roots with openssl: PIV root CA:TRUE pathlen:1
  2016–2052; Attestation Root 1 CA:TRUE pathlen:3 2024–9999.
- Binding: the slot certificate must be signed by the device certificate's key (`:178`), the
  device certificate must chain to a pinned anchor, and the slot certificate's SPKI (canonical)
  must equal the object's canonical SPKI (`:185-195`). A substituted f9 (management-key holder)
  cannot chain; a genuine f9 copied from another device does not verify the slot certificate.
- `tbs()` slices the original DER (header then `tlv_bytes`), no panics on short input; all parse
  failures are `Conflict`, never a panic. The fuzz target exercises it (ISSUES.md "Fuzz the
  remaining parsers" Done).
- Signature dispatch: ECDSA (DER) with the named hash via `sig::ecdsa`, RSA PKCS#1 v1.5 via
  `sig::rsa_pkcs1v15`; any other OID is refused, `None` (key type mismatch) is a conflict.
