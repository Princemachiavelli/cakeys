# Review: crates/pkcs11/src/token/generate.rs (391 lines)

Reviewed 2026-11-18 [read]. Summary: key generation from cakeys' templates or the provider's own
(`create_declared`, `generate`, `generate_own`), the B18 by-name retry (`retries_by_name`), the
public-default fallback (`with_public_default_dropped`), destruction (`destroy`,
`destroy_identified`, `destroy_plain`) and the typed `CreateNote` (Q3). Compact and tested at
the unit level where it can be. B18's fix is in place and correct for the live token; the notes
below concern what feeds it and a too-broad "declared" test shared with `templates.rs`.

## Findings

### F1. "Declared `CKA_PRIVATE`" mixes the two halves' policies — nit

`crates/pkcs11/src/token/generate.rs:130-131`. `private_declared` is true when either
`spec.attributes` (the private key's policy) or `spec.publicAttributes` declares
`CKA_PRIVATE`. It mirrors `templates::public_defaults`, whose real consequence is reported in
`REVIEW_crates_pkcs11_src_templates.rs.md` F1 (a private key's `CKA_PRIVATE = true` leaves the
public half at the module's default). Here it is moot (no default in the template, nothing to
drop), but the predicate should change with that fix: test only `spec.public_attributes`.
[read]

### F2. `answers` records a generation without the `via = "by-name"` the run needed — nit

`crates/pkcs11/src/ops.rs:465-466` with `generate.rs:157`. When the curve generated only by
name (`CreateNote::by_name`), the lock records `generate.<kt>.<curve> = yes` with no `via`.
`Resolved::with_answers` (`resolution.rs:42-68`) puts recorded rows over the module profile,
replacing the profile's `via = "by-name"` row with a plain yes. Today that only reaches the
static gate and camigrate's plan, which read the answer, not `via`. But ISSUES.md B18 says
`retries_by_name` reads the profile "the lock's recorded answers included"; that is not so
(`Token::open` never calls `with_answers`), and if it were, a recorded plain yes would make
`retries_by_name` return false and the second Ed25519 key on a YubiKey would fail. Fix: record
`via = "by-name"` from the `CreateNote` in `answers`, and correct the B18 text. [read]

### F3. The by-name retry reports the first refusal even when the second is the more telling — nit

`crates/pkcs11/src/token/generate.rs:157`. `.map_err(|_| e)` discards the by-name attempt's
error. Where the profile says `via = "by-name"`, the OID refusal is expected and the by-name
refusal is the real answer (e.g. a PIN or template problem), yet the user is shown the expected
OID refusal. Fix: when `retries_by_name` was decided by a profile row (not by the absence of
one), report the second error. [read]

## Design

- `create_declared` runs both `self.generation_key(on)` and `self.generation_public(on, None)`
  inside the `managing` closure (via `generate`), so on ykcs11 the provider's template hook and
  the policy mapping run while logged in as SO. They are pure; harmless, but a refusal there
  costs an SO login and logout. `ops::check_templates` already asked them before, so this is
  only duplicated work.

## Checked, no issue

- B18 (done 2026-11-17): `retries_by_name` builds the row key with `kt.to_string()`
  (`CKK_EC`/`CKK_EC_EDWARDS`) and `curve.name()` (`edwards25519`), the same spelling the probe
  writes (`profiles/modules/ykcs11/2.7.toml:53`); a row with `answer = no` or a `yes` without
  `via` refuses the retry; no module profile retries, as documented.
- Q3 `CreateNote`: `Display` reproduces the former text (unit test), `of` returns `None` when
  nothing is said.
- `with_public_default_dropped`: retries only on `CKR_ATTRIBUTE_VALUE_INVALID`, once, and
  reports the first refusal; unit-tested.
- `destroy_plain`: `CKR_OBJECT_HANDLE_INVALID` tolerated only after the first handle; runs as SO
  where the provider manages as SO.
- `destroy_identified` removes only public key objects holding the private key's SPKI.
