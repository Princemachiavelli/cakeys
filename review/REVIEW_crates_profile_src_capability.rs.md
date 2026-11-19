# Review: crates/profile/src/capability.rs (432 lines)

Reviewed 2026-11-18 [read]. Summary: the one capability row type: `Capability` (parsed from
and displayed as the TOML key), `On`, `Way`, `Move`, `Answer`, `Row`. Parse and `Display` are
inverse for every variant (tested); unknown keys are refused. Clean; two small normalisation
issues.

## Findings

### F1. Non-canonical sizes collapse silently into one row — nit

`crates/profile/src/capability.rs:38-44` and `:349-352`. `on.parse::<u32>()` accepts `"02048"`
and `"+2048"`, so `generate.CKK_RSA.02048` and `generate.CKK_RSA.2048` both parse to
`Generate { Bits(2048) }`; `deserialize` collects into a `BTreeMap`, so with both present the
later one wins without a word (TOML only refuses identical keys). The emitter then writes
`2048`, so a hand-edited key changes on regeneration. Refuse a numeric `on` whose `Display`
differs from the text read.
[read]

**Fixed (2026-11-18):** a numeric `on` that does not print back as read (`02048`, `+2048`) is refused, so two spellings of one row cannot collapse. Test: `one_row_has_one_key`.

### F2. `PROOFS` duplicates `names::Proof` and disagrees with it — nit

`crates/profile/src/capability.rs:20` and `:253`; `names.rs:115-121`. Parsing a `prove.*` key is
gated on the 4-entry `PROOFS` list, while `Proof` has five variants (`pop-sign-pin`) plus
`Other`. So `Proof::PopSignPin` and `Proof::Other` can never come from a profile, and a profile
from a newer cakeys with a new proof name fails to load as a whole, unlike an unknown key type
(see REVIEW names.rs F1). Either derive the gate from `Proof`'s known variants or drop the
unreachable ones; document that only key types are forward compatible.
[read]

**Fixed (2026-11-18):** a `prove.*` row's proof (any `pop-*`), an OAEP hash and an
unwrap-template attribute (any `CKA_*`) load as read, as an unknown key type does; only a row's
shape is refused. `PROOFS` is gone: the round trip runs over `Proof::NAMES`, so a known proof
can never be refused again. Readers ask only for the names they know, so the new rows answer
nothing. Tests: `every_capability_reads_back_from_its_key`,
`a_newer_cakeys_names_load_and_answer_nothing`.

## Design

None.

## Checked, no issue

- `create.CKO_PUBLIC_KEY` without a key is refused before the general `create` arm.
- `unwrap.CKK_*` vs `unwrap.template.*` disambiguated by the `CKK_` prefix guard.
- `delete.<CKO_*>` refuses dotted suffixes.
- `On` unit is chosen from the key type (bits for RSA, bytes otherwise), as documented.
- `Row` and `[capabilities]` keys deny unknown fields / keys.
