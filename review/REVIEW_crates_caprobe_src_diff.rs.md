# Review: crates/caprobe/src/diff.rs (269 lines)

Reviewed 2026-11-18 [read]. Summary: the conformance/drift diff: match keys, advertisement and
reported sizes (the read-only part), then `subtract.mechanisms`, `add`, restrictions and every
probed capability row (answer and `via`), one sorted line per difference. Clear, well tested.

## Findings

### F1. `subtract.key-types` is not compared — nit

`crates/caprobe/src/diff.rs:19`.
`diff` compares `subtract.mechanisms` but not `subtract.key_types`, which the emitter writes
(`emit.rs:130-132`) and the profile parses. The probe never writes key-type subtractions today
(the binding layer does, and layers are not diffed), so nothing drifts unseen now; the doc
comment's "never compared" list should name it, or the line should be added for symmetry. [read]

**Fixed (2026-11-18):** `diff` compares `subtract.key-types` as it does the mechanisms; the doc
comment says both are. Test: `key_type_subtractions_and_repeated_restrictions_are_named`.

### F2. Duplicate `[[restrict]]` rows collapse silently — nit

`crates/caprobe/src/diff.rs:94-96`.
`restrictions` keys rows by `(operation, key_type)` in a `BTreeMap`, so two rows for the same
pair on one side compare as the last one only. Profiles do not contain duplicates today; the
profile parser would be the place to refuse them. [read]

**Fixed (2026-11-18):** a pair listed twice on one side is a drift line of its own
(`restrict.<op>.<kt>: observed|claimed more than once`). Refusing it in the profile parser
belongs to the profile crate. Test: `key_type_subtractions_and_repeated_restrictions_are_named`.

## Design

None.

## Checked, no issue

- Names, `partial`, notes, evidence, `[manual]`, `[migration]` and `move.*` rows are excluded,
  as the doc comment and CAPROBE.md say; a `partial` claimed profile skips the advertisement.
- A row's `via` is part of what is compared (`shown`), so a curve that starts generating only
  by name is drift.
- Every comparison is symmetric (only observed / only claimed / differs), and output is sorted.
