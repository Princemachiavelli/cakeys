# Review: crates/kmsp11/src/lib.rs (539 lines)

Reviewed 2026-11-18 [read]. Summary: the libkmsp11 provider: chooses one Cloud KMS algorithm
per key spec from the embedded `keys.json` (`generation`), refuses before creating what cakeys
could not identify, show as declared, or prove, and lists the probe's bound keys. Logic is
careful and well-tested; the embedded table has one inconsistent row.

## Findings

### F1. `keys.json`'s `HMAC_SHA256` row lists no mechanisms — bug

**Verification:** confirmed. keys.json:20 has `"mechanisms":[]` while rows 21-24 each list their HMAC mechanism, and `algorithm_for` with a declared `CKA_ALLOWED_MECHANISMS` keeps only a row whose sorted list equals it (lib.rs:267-287), so `["CKM_SHA256_HMAC"]` matches no candidate (15); `mechanisms` has no other reader that would make the empty list deliberate (lib.rs:270,275,371; the probe stops before using it for a key with no public half, caprobe probe.rs:832). libkmsp11's `kmsp11/algorithm_details.cc` (kms-integrations master, fetched) gives `HMAC_SHA256` `{CKM_SHA256_HMAC}` as its allowed mechanisms, as for HMAC_SHA384, so the empty row is a transcription slip. [read, src]
`crates/kmsp11/src/keys.json:20`, read by `algorithm_for`
(`crates/kmsp11/src/lib.rs:267-290`). Every other HMAC row lists its one mechanism
(`HMAC_SHA1` → `CKM_SHA_1_HMAC`, `HMAC_SHA384` → `CKM_SHA384_HMAC`, …); `HMAC_SHA256` has
`"mechanisms": []`, although `CKM_SHA256_HMAC` is in `MECHANISMS` and is what libkmsp11's
`algorithm_details.cc` gives that algorithm (from memory; not re-checked against the source).
Scenario: a `CKK_SHA256_HMAC` spec declaring `CKA_ALLOWED_MECHANISMS = ["CKM_SHA256_HMAC"]` is
refused (15) "no Cloud KMS algorithm serves exactly …", while the identical spec for SHA-384 is
accepted. The probe is unaffected (it never operates bound secret keys, `caprobe/src/probe.rs:831`).
Fill in the row and add a test that each HMAC type is chosen by its own mechanism. [read]

**Fixed (2026-11-18):** the `HMAC_SHA256` row lists `CKM_SHA256_HMAC`. Test:
`every_mac_row_serves_its_hmac`.

### F2. `CKA_ALLOWED_MECHANISMS` in `publicAttributes` is ignored — nit

`crates/kmsp11/src/lib.rs:176-180, 292`. `check_reported` skips every non-boolean value, and
`algorithm_for` reads `CKA_ALLOWED_MECHANISMS` from `spec.attributes` only. A spec declaring it on
the public half is neither matched nor refused, unlike every other declared public attribute,
which is refused when libkmsp11 would not report it. Refuse it (or compare it with the row) so
the "refused before creating" promise holds for the public half too. [read]

**Fixed (2026-11-18):** `check_reported` compares a public `CKA_ALLOWED_MECHANISMS` with the
row's set and refuses another (15); any other non-boolean value is refused. That libkmsp11
reports the set on the public key is not checked on Cloud KMS. Test:
`what_could_not_be_proven_or_shown_is_refused_before_creating`.

## Design

- §4(b) holds (verified 2026-11-18): the crate imports `cakeys_core` config/types,
  `cakeys_pkcs11::{BoundKey, Generation, Provider}` and `cakeys_profile::{KeyKind, On}`, and
  implements `name`, `matches`, `hint`, `generation`, `bound_keys` only. It is referenced outside
  its directory only by `cli-common`'s registry.
- The table cannot express the OAEP hash (`RSA_DECRYPT_OAEP_4096_SHA256` and `_SHA512` share
  `[CKM_RSA_PKCS_OAEP]`), so `create` can never make the SHA-512 one; documented in a comment
  and a test. A spec field for it (e.g. matching on `binding`'s hash) would be the place if it
  is ever needed.
- `keys.json` is parsed at first use with `expect`/`panic!` (`:94-126`, `mechanism` at `:58`).
  ISSUES.md Q22 "Fixed" (one `LazyLock`) holds; a malformed row still panics at run time rather
  than at build time, covered by `the_table_parses_and_its_probe_rows_are_the_nineteen`. A
  `const` Rust table or a build.rs check would make it a compile error; acceptable as is.

## Checked, no issue

- ISSUES.md B11: `pop-unwrap` and `pop-ecdh` refused (`:300-308`), `pop-decrypt` and `pop-sign`
  allowed on PSS and SHA-512 rows. Core's `plan_mode` (`crates/core/src/plan.rs:180-212`)
  already requires `CKA_SIGN`/`CKA_DECRYPT`/`CKA_UNWRAP`/`CKA_DERIVE` = true for the matching
  binding, so the provider's refusals are the documented backstop. Still unrun on Cloud KMS
  ("To test").
- Purpose selection: sign and decrypt both true refused; EC decrypt refused; RSA with neither
  refused; HMAC → `MAC`; AES, Triple DES, Edwards, generic secret refused with reasons.
- `CKA_ALLOWED_MECHANISMS` comparison: `AttrValue::mechanisms` stores a sorted set and the row is
  sorted before comparing, so order does not matter.
- Curve names: `object.curve` is canonical after load (`config.rs:311-316`), so `secp256r1`
  matches a `P-256` spelling in keys.toml.
- Locator: label alone, a valid CryptoKey ID (1–63 of `[A-Za-z0-9_-]`); an ID is refused (17).
- `CKA_KMS_ALGORITHM` as a native-endian 8-byte `CK_ULONG`: right on every LP64 target the flake
  serves.
- Bound-key labels are unique and valid CryptoKey IDs (tested).
