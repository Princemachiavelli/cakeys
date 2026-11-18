# Review: crates/pkcs11/src/token/uri.rs (262 lines)

Reviewed 2026-11-18 [read]. Summary: RFC 7512 URIs of a checked object, the query attributes a
consumer asks for (module path, PIN by reference or value), pkcs11-provider's PEM key file, and
the locator attributes. Correct escaping per §2.3 (B3), byte-exact PEM against `uri2pem.py`, good
tests. No findings beyond a note on the PIN-by-value output.

## Findings

### F1. `--uri-pin value` leaves the PIN in plain `String`s — nit

`crates/pkcs11/src/token/uri.rs:87`, `:90`, `:101-115`. `PinRef::Value` keeps the PIN in
`Zeroizing`, but `with_query` copies it into the returned URI `String` (and intermediate
`qpct` strings), and `provider_pem` into the PEM `String`, none wiped. The output exists to be
printed, so this is inherent to the feature; it only makes the `Zeroizing` on `PinRef::Value`
cosmetic. Fix, if wanted: return `Zeroizing<String>` from both when a value PIN is present.
[read]

## Design

None.

## Checked, no issue

- B3 (fixed in `2120ec1`): `/` escaped in path attributes, kept with `:` in query attributes;
  `;`, `?`, `&`, `%` and space always escaped (tests).
- `id=` is every byte percent-encoded from the hex locator; a non-hex `CKA_ID` is `Validation`
  without panicking (test).
- `type=` values (`private`, `public`, `cert`, `data`, `secret-key`) are RFC 7512's.
- `pin_ref`: env var before file, a relative file made absolute against the working directory
  as cakeys reads it, no PIN is `Validation`.
- `provider_pem`: short and both long length forms match pkcs11-provider 1.3's tool (test).
