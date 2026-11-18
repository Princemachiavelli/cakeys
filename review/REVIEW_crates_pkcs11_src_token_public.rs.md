# Review: crates/pkcs11/src/token/public.rs (75 lines)

Reviewed 2026-11-18 [read]. Summary: `C_CreateObject` attributes for a public object from its
value: a certificate (with subject, issuer, serial), a data object, or a public key from its
SPKI. Small and clear; one gap between the documented and the actual checks.

## Findings

### F1. An EC or Edwards public key's SPKI is not checked against the object's type or curve — practice

`crates/pkcs11/src/token/public.rs:66-74`. For any non-RSA object the SPKI is parsed only as a
generic `SubjectPublicKeyInfo` and its bit string is taken as the point; the algorithm OID and
curve are never compared with `object`. The doc (`:52-55`) promises `Conflict` "when the SPKI is
not a key of `object`'s type". Given a P-384 or RSA SPKI for a P-256 object, it builds
`CKA_EC_PARAMS` of P-256 with a foreign `CKA_EC_POINT`, which a module may store as is. Today's
callers (`crates/camigrate/src/public.rs:189`, `:197`, the probe's `moves.rs`) pass the source
key's own SPKI, already identified for that object, so this is not reachable in practice. Fix:
compare `id::spki_curve(spki)` (or Q20's `KeyAlg::of_spki`) with `curve_of(object)` before
building the attributes. [read]

## Design

None.

## Checked, no issue

- Certificates: parsed as X.509 before anything is built; `CKA_SUBJECT`, `CKA_ISSUER` and
  `CKA_SERIAL_NUMBER` are the DER of the parsed fields; the value is the input bytes.
- RSA: modulus and exponent trimmed of leading zeros (`to_be_bytes_trimmed_vartime`).
- EC point wrapped as a DER OCTET STRING (PKCS#11's encoding), Edwards included.
- A secret or private class is refused (`Validation`).
