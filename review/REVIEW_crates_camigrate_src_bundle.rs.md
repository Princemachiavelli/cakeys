# Review: crates/camigrate/src/bundle.rs (454 lines)

Reviewed 2026-11-18 [read]. Summary: the export bundle's serde types and `Bundle::parse`, which
checks the form of untrusted input. `parse` covers:

- format and version;
- each object listed once;
- known methods, and a KEK exactly when a composed method needs one, with one OAEP hash;
- exposures that fit the method;
- base64 blobs and SRI IDs;
- a `publicKey` that hashes to `rfc7093m4`.

It has a proptest that no text panics, and a pinned field layout. Solid. Only minor findings.

## Findings

### F1. The module comment overstates what the wrap authenticates — practice

`crates/camigrate/src/bundle.rs:7-9` ("the wrapped blobs are authenticated by RFC 5649 (or OAEP)
… so a bundle may cross untrusted channels"). OAEP authenticates nothing, and RFC 5649 only
relative to a KEK anyone can make for the public transport key. Only the target's identity
recompute and the proof of possession reject a substituted key. See sealed.rs F1 for the case
neither covers (`token-asserted`). [read]

**Fixed (2026-11-18):** the module comment says the wrap authenticates nothing (the transport
key is public; RFC 5649's check holds only under a KEK anyone can make; OAEP has none), and that
the target's identity recompute and binding proof, with `check_carried`, are what a bundle may
cross untrusted channels on.

### F2. Fields are not checked against the entry's class — nit

`crates/camigrate/src/bundle.rs:57-64`, `:171-176`. `publicKey` is accepted on any entry, and
`commitmentLabel` too. Today this is harmless: the import compares `ids` and the label to the
lock, so a `publicKey` on a secret-key entry fails `parse` (no `rfc7093m4` among a secret key's
IDs) or `check_against_lock`. Refusing them by class in `parse` would make the form check say
what it means. [read]

**Fixed (2026-11-18):** `parse` refuses (17) a `commitmentLabel` on anything but a secret key and
a `publicKey` on anything but a private key. Test: `malformed_bundles_are_refused`.

### F3. `source.provider` is carried and never used — nit

`crates/camigrate/src/bundle.rs:91`. Import records only `source.token`
(`sealed.rs:380`). If the provider is meant as provenance, record it; otherwise it is dead weight
in a frozen format. [read]

**Fixed (2026-11-18):** it is provenance for the reader: `import` names it in its "imported … from
<token> (<provider>)" note and in the refusal of a source keys.toml does not name
(`check_source`). The lock records no provider in `Origin` (core's frozen format): the source
token's own realisation records its provider. Test: `the_source_must_be_a_token_keys_toml_names`.

## Design

None beyond sealed.rs's.

## Checked, no issue

- `parse` refuses every malformed shape the tests list, and `any_text_parses_or_is_invalid`
  pins "17, never a panic" for arbitrary text.
- Composed entries share one KEK and one hash (`kek_hashes`). An entry with its own KEK must be a
  composed method, and `enforced` needs its own KEK.
- A `publicKey` must hash to the entry's `rfc7093m4`.
- `object_type` is canonicalized on read, so the comparison with the lock's type is not fooled by
  spelling.
