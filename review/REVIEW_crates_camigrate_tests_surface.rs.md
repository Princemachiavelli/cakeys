# Review: crates/camigrate/tests/surface.rs (13 lines)

Reviewed 2026-11-18 [read]. Summary: calls the shared `common::surface::assert_covered` with
`camigrate::command()` and an empty `UNTESTED` list: every verb and long flag clap defines must
appear as a string literal in camigrate's `tests/` or in `crates/cli/tests/common/`. The file is
a correct three-line use of the shared check; the check's limits are worth stating.

## Findings

### F1. The shared harness's literals count as camigrate's coverage — nit

`crates/camigrate/tests/surface.rs:12`; `crates/cli/tests/common/surface.rs:46-52`. The search
text includes all of `crates/cli/tests/common/`, which is written for three tools. A literal
there satisfies the flag for every tool, whichever tool it is passed to: `"--dry-run"` in the
dry-run twin (`common/xref.rs:154`, `:173`), `"--token"`/`"--out"` in
`assert_profile_conforms` (a caprobe call, `common/mod.rs:303`), `"--config"` in every runner.
A camigrate flag of the same name as one of those would count as tested if every camigrate
test dropped it. Also, any literal starting with the flag counts, including assertion messages
such as `"--spec {spec}: {}"` (dry_run.rs:1940). docs/DEVELOPMENT.md already calls this
"a floor, not a measure"; noting it so nobody reads the empty `UNTESTED` as "every flag is
exercised by a camigrate run". A stronger floor would scan only argument arrays passed to
`km`/`km_alone`, or record the arguments each run used at runtime. [read]

**Decided (2026-11-18):** the remaining part (the `"{name} "` form counting message literals) is in common/surface.rs, the shared harness, outside this file's owner..

## Design

- camigrate and caprobe each wrap the one shared implementation with the same 13 lines; that
  is the right amount of duplication.

## Checked, no issue

- The stale-entry check (`common/surface.rs:56-57`) fails for an `UNTESTED` entry that is tested
  or no longer defined, so the empty list cannot hide anything.
- `sources` skips files named `surface.rs`, so this file's own literals do not count.
