# Review: crates/profile/src/profile.rs (427 lines)

Reviewed 2026-11-18 [read]. Summary: the `Profile` data model (match info, subtractions, rows,
reported ranges, migration claims, restrictions, notes, manual findings) and its queries
(`wrap_oaep`, `unwraps`, `generation`, …). Every section denies unknown fields (B12 holds).
Solid; the one real issue is `generation` reporting "says something" for rows it then drops.

## Findings

### F1. `generation` returns `Some` for rows it discards — risk

**Verification:** confirmed (downgraded to nit). profile.rs:387 sets `any = true` before `(On::Bytes(_), _) => {}` (:399) drops the row, so byte-only rows give `Some(GenerateRow::default())`; but no committed profile has `generate.*` byte rows and `set_generation` never writes one, so today it is only a second route into effective.rs F1, whose fix (answer from the rows' answers) covers it. [read]
`crates/profile/src/profile.rs:387` and `:399`. `any = true` is set before the match, and
`(On::Bytes(_), _) => {}` drops secret-key-size rows, so a key type with only
`generate.CKK_AES.32`-style rows yields `Some(GenerateRow::default())`. `Effective::generate`
treats `Some` as "the module said something" and, with no item or size asked, answers *yes*
(REVIEW effective.rs F1). No committed profile has such rows today. Set `any` only for rows
that land in the `GenerateRow`, or carry byte sizes in it.
[read]

### F2. `set_generation` can write a row that does not read back — nit

`crates/profile/src/profile.rs:417-422` with `capability.rs:38-44`. `can_bits`/`cannot_bits`
become `On::Bits` for any key type, but on re-parse only `CKK_RSA` reads a number as bits;
for another key type the row comes back as `On::Bytes`, which `generation` ignores. The one
caller (`caprobe/src/probe.rs:343`) fills bits only for RSA, so latent. Debug-assert the key
type, or build `On` via `On::parse`.
[read]

### F3. `family`'s `unwrap_or` is dead — nit

`crates/profile/src/profile.rs:285`. `split('/').next()` is always `Some`; `split_once('/')
.map_or(&self.profile, |(f, _)| f)` says the same thing directly.
[read]

## Design

- `Restrict` and `Reported` take `min-bits`/`max-bits` without checking `min <= max`; an
  inverted hand-written range would make every size *no* (effective.rs:165/188). Generated
  profiles never do this; a load-time check would be cheap.

## Checked, no issue

- ISSUES.md B12 (Fixed in 2120ec1): `MatchInfo`, `Subtract`, `Restrict`, `AcceptRow`,
  `Migration`, `Manual`, `Reported`, `Profile` all `deny_unknown_fields`.
- ISSUES.md Q28: `Restrict`'s `operation`/`key_type` are `Operation`/`KeyKind`; an unknown
  operation deserialises as `Other` and restricts nothing.
- `yes_of`/`unwrap_refuse` keep "never probed" (`None`) apart from "probed, all no".
- `any_of` returns `None` when no row matches (peekable), else any-yes.
