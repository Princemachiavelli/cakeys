# Review: crates/profile/src/names.rs (150 lines)

Reviewed 2026-11-18 [read]. Summary: a macro producing `KeyKind`, `Proof` and `Operation`:
known names as variants, anything else as `Other(String)`, with `Eq`/`Hash`/`Ord` by name
(ISSUES.md Q28). The Q28 fix is correct: the three trait impls agree, so `BTreeMap`/`HashMap`
use is sound and rows sort exactly as the strings did.

## Findings

### F1. `Other` is public and can hold a known name, which `matches!` then misses — nit

`crates/profile/src/names.rs:13`; consumers at `capability.rs:40` (`matches!(key_type,
KeyKind::Rsa)`) and `effective.rs:162` (`matches!(r.operation, Operation::Generate)`).
`KeyKind::Other("CKK_RSA".into())` equals `KeyKind::Rsa` by `Eq`/`Hash`/`Ord`, but a pattern match
does not see it, so such a value would read `generate.CKK_RSA.2048`'s size as bytes. Only
`From` normalises; nothing outside tests builds `Other` directly today. Either make the
invariant structural (a private newtype inside `Other`) or match on `name()` in those two
places.
[read]

**Fixed (2026-11-18):** `Other` holds a private `Unknown` that only `From` builds, after the known names did not match, so it never holds a known name. Test: `names_are_values_and_order_as_text`.

### F2. `Proof::Other` and `Proof::PopSignPin` are unreachable from profile data — nit

See REVIEW capability.rs F2: `prove.*` parsing is gated on `capability::PROOFS`, which lacks
`pop-sign-pin` and refuses unknown proofs, so the module comment's forward-compatibility promise
("any other … kept as read, so a profile still loads") holds for `KeyKind` and `Operation`
only. Also, `gate.rs:241-244`'s test checks `Binding::name()`, while capability rows are keyed
by `Binding::proof_name()`.
[read]

**Fixed (2026-11-18):** `prove.*` rows take any proof name (`Proof::from`; an unknown one is kept as `Other`), and gate.rs's test checks `Binding::proof_name()`, the name capability rows are keyed by. Tests: `every_capability_reads_back_from_its_key`, `the_profiles_know_every_key_type_and_proof_cakeys_has` (pkcs11 gate.rs).

## Design

None.

## Checked, no issue

- ISSUES.md Q28 (Done 2026-11-17): `PartialEq`, `Hash`, `Ord` all go through `name()`;
  `Deserialize` goes through `From<&str>`, so a known name read as text is the variant.
- No `Display`/`name` divergence: `Display` writes `name()`.
