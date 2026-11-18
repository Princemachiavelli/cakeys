# Review: crates/core/src/plaintext.rs (201 lines)

Reviewed 2026-11-18 [read]. Summary: parses a PKCS#8 private key (the host path's plaintext)
into the parts `C_CreateObject` takes, every secret part in `Zeroizing`, and derives a key
file's canonical SPKI. Careful work (decoder copies wrapped too, no secret in an error); one
copy of an RSA secret escapes the wiping the module promises.

## Findings

### F1. The CRT coefficient's temporary is dropped unzeroized — practice

**Verification:** confirmed (practice kept). `be(&key.crt_coefficient()…?)` (plaintext.rs:154) borrows an owned `BoxedUint` that rsa-0.10.0 computes afresh with `q.invert_odd_mod(p)` (private_key.rs:523-527); crypto-bigint 0.7.11 derives only `Clone` on `BoxedUint` and implements `Zeroize` (boxed.rs:55-56,603) but no `Drop`, so the temporary's limbs are freed unwiped, contrary to the module doc (:3) and the comment at :143. [read]
`crates/core/src/plaintext.rs:154` (and the claim at `:3` and `:143`). rsa 0.10's
`crt_coefficient()` returns an owned `BoxedUint` computed afresh (`q.invert_odd_mod(p)`,
`rsa-0.10.0/src/private_key.rs:524-528`), not a reference like `dp()`/`dq()`. `be(&…)` copies
it into a `Zeroizing<Vec<u8>>`, and the temporary `BoxedUint` then drops; crypto-bigint 0.7.11
gives `BoxedUint` no `Drop`/`ZeroizeOnDrop`, so `q⁻¹ mod p` (a private CRT value) stays in freed
heap memory. The comment at `:143` ("no second, unzeroized copy of a private part") and the
module doc ("Every secret part is zeroized when dropped") are wrong for this one. Fix:
`let mut qinv = key.crt_coefficient().ok_or_else(bad)?; let c = be(&qinv); qinv.zeroize();`
(`BoxedUint: Zeroize` with crypto-bigint's `zeroize` feature, which rsa enables), or use
`key.qinv()` if a canonical form is available. [read]

### F2. Multi-prime RSA keys are refused as "not a PKCS#8 RSA key" — nit

`crates/core/src/plaintext.rs:145`. `let [p, q] = key.primes() else { return Err(bad()) }`
turns a valid three-prime key into `Conflict` (13) with a message saying it is not RSA.
PKCS#11 has no attributes for more than two primes, so refusing is right; the code and text
should say so (`Unsupported`, "multi-prime RSA keys have no PKCS#11 form"). [read]

### F3. Error kinds and texts — nit

`crates/core/src/plaintext.rs:83` formats the key type with `{kt:?}` ("a Ec private key")
where every other message uses the PKCS#11 name (`{kt}` → `CKK_EC`); `:133-135` maps an SPKI
*encoding* failure to `Unavailable` (16, "the token cannot be used now"), though no token is
involved — `Conflict` or `Io`-like exit 1 fits better. [read]

## Design

- `private_from_pkcs8` takes `curve: Option<&str>` and re-parses it with `Curve::from_cfg`,
  while the object's type was already parsed at load into `ObjectKind`. Passing the
  `AsymmetricKey` (or `Curve`) would remove the `(kt, None)` fallthrough for an EC key without
  a curve, which load already refuses.

## Checked, no issue

- B16, scalar half (Done): EC and Edwards scalars go through `scalar()`, which wraps the
  decoder's by-value copy in `Zeroizing` too; `SecretKey`/`SigningKey` zeroize on drop.
- RSA parts other than the coefficient: `to_be_bytes_trimmed_vartime().into_vec()` keeps the
  allocation, so no second copy; `rsa::PrivateKey` zeroizes on drop.
- No secret bytes in any error (test `pkcs8_keys_parse_into_their_parts` checks the input is
  not echoed); parse errors are mapped with `|_|`, dropping the crate's text on purpose.
- Q20 (Done): `spki_of_pkcs8` dispatches on `KeyAlg::of_pkcs8`.
