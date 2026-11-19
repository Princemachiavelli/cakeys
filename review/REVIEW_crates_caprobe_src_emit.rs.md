# Review: crates/caprobe/src/emit.rs (357 lines)

Reviewed 2026-11-18 [read]. Summary: the hand-written profile emitter (ISSUES.md Q27, accepted:
it mirrors taplo's layout so generated profiles survive `nix fmt`). Escaping is right and the
byte-for-byte test over every committed module profile is strong. Two fields that parse are not
emitted, so the "parse, emit, parse is a fixed point" property the fuzz target checks does not
hold for every parseable profile.

## Findings

### F1. Two parseable fields are dropped by the emitter — risk

**Verification:** confirmed. `filters_toml` writes `note` only inside `if !mechanisms.is_empty() || !key_types.is_empty()` (emit.rs:124-136), and `public-accepts` rows go through `accept_toml(.., false)` (:188-190), which skips `min-bits`/`max-bits` (:59-64), while `Subtract.note` and `AcceptRow`'s bounds parse on every table (profile.rs:46-56, :159-174) and camigrate reads `public_accepts` through `accept_of` (tokens.rs:133-135); `profile_round_trip` (caprobe lib.rs:40-47) asserts equality and would fail on such input. [read]
`crates/caprobe/src/emit.rs:123-137`, `:188-190`; `crates/profile/src/profile.rs:46-56`, `:159-174`.
(a) `filters_toml` writes `[subtract]` only when `mechanisms` or `key-types` is non-empty, so a
`[subtract]` holding only `note = "…"` (which `Subtract` parses) is emitted without it.
(b) `[[migration.public-accepts]]` rows are emitted with `bits = false`, dropping `min-bits` /
`max-bits`, which `AcceptRow` parses on that table too. Either way `Profile::from_toml(emit(p))
!= p`, which `fuzzing::profile_round_trip` (lib.rs:40-47) asserts; no committed profile has
these shapes (the byte-for-byte test would fail), so the fuzz corpus seeded from them may not
reach it. Reachable in practice through `probe --write --out` over a `--profiles`/hand-kept file
with such a `public-accepts` row: `keep_claims` keeps `[migration]`, and the emitter silently
loses the bounds. Fix: emit the note whenever present, and either emit bits for public-accepts
or reject them at parse time (`deny` in the profile crate) so the two agree. [read]

**Fixed (2026-11-18):** a note alone writes `[subtract]`; every accepts row writes its bits. Test:
`every_optional_field_alone_round_trips` (each optional field alone, through `profile_round_trip`),
the Design note's test.

## Design

- The fixed-point property is only as good as the emitter's coverage of the parser's types;
  a test that builds a `Profile` with every optional field set (or a `proptest` strategy over
  `Profile`) would catch the next field added to the parser but not the emitter, which the
  committed-profile test cannot (it only sees shapes that exist).

## Checked, no issue

- `toml_str` escapes `"`, `\` and every control character (NUL padding, DEL) as `\uXXXX`;
  the round-trip test covers module-supplied text.
- Every section is written only when non-empty, in a fixed order, and `[capabilities]` rows come
  from a `BTreeMap`, so regeneration is deterministic.
- Q27 (Accepted): the layout logic itself (120 columns, trailing commas) is not re-reported.
