# Review: crates/caprobe/src/coverage.rs (438 lines)

Reviewed 2026-11-18 [read]. Summary: test-only generator and check of
`spec-coverage/cakeys.toml`: reads the p11-fault trace (tool calls only), names traced values
per baseline table (flags per family), applies `manual.toml`'s glob rules, falls back to
"profile" for names a capability profile mentions, and compares with the committed file.
Sound; `unwrap`/`panic` on trace fields is acceptable in a test. Two ways it can overstate
coverage.

## Findings

### F1. "profile" status counts any `CK?_` token anywhere in a profile file — practice

`crates/caprobe/src/coverage.rs:254-276`, `:311-312`.
`profile_names` tokenises the whole text of every file under `profiles/{modules,layers,hardware}`
— comments, note strings, evidence — so a name mentioned only in prose ("`CKR_ARGUMENTS_BAD`",
"refuses CKM_X") gives that baseline row the status `profile`, i.e. "a capability profile
records it". Evidence strings carry many `CKR_*` names. The status then claims more than any
profile states as a row. Fix: parse each profile and collect names from its structured fields
(`advertise`, `add`, `subtract`, capability keys, `reported` keys), or rename the status to say
"mentioned". [read]

**Fixed (2026-11-18):** `profile_names` parses each profile and takes `CK?_` names from keys,
lists and values only, never from comments or the prose fields (`evidence`, `finding`, `note`,
`requires-provider`, the values of `[notes]` and `[manual]`). The committed coverage file is
unchanged by it. docs/CAPROBE.md's status table says so. Test:
`profiles_record_names_outside_their_prose`.

### F2. A wildcard manual rule that only matches used rows is never flagged — nit

`crates/caprobe/src/coverage.rs:296-302`, `:307-310`.
The "names a used row" check runs only for patterns without `*`; a wildcard rule whose every
match is now `used` decides nothing yet passes ("matches no row" is false). CAPROBE.md says a
manual rule that "names a used row … fails". Flag a rule none of whose matches it decides.
[read]

**Fixed (2026-11-18):** a wildcard rule whose every row is used fails ("names used rows only"),
as a plain name of a used row does; docs/CAPROBE.md says so. The wider check (a rule each of
whose rows an earlier rule decides) finds three such rules in spec-coverage/manual.toml today
(`mechanisms CKM_X9_42_*`, `mechanisms CKM_SHAKE_*`, `sources CKZ_*`), a file outside this
change: left to whoever owns it. Test: `a_wildcard_rule_over_used_rows_only_fails`.

### F3. Traced names outside the baseline are dropped from the report — nit

`crates/caprobe/src/coverage.rs:206-209`.
`add("functions", …)` and `add("return-values", rv)` insert whatever string the trace carries;
a vendor return value (`CKR 0x8…`) or a function the baseline lacks becomes a `seen.rows` entry
that `generate` never looks at (it iterates baseline rows only), and unlike unnamed mechanism
numbers it is not listed under "no baseline name" in `coverage-report.txt`. Route these into
`seen.unnamed` too. [read]

**Fixed (2026-11-18):** a traced function or return value the baseline does not name goes to
`seen.unnamed` (now names, mechanism numbers in hex), never a row, and the report lists it.
Test: `traced_names_outside_the_baseline_are_unnamed`.

## Design

None.

## Checked, no issue

- `glob`: prefix, leftmost match of each middle part, then a suffix check on what is left, so
  parts never overlap; the unit test covers the edge cases (empty match, whole-name anchoring).
- Flags are named within the family of the trace field that carried the word, since `CKF_`
  values repeat across families; `flag_families_name_baseline_flags_once` pins it.
- Only the three tools' calls count (`exe` filter), as CAPROBE.md says.
- Without a trace the committed `used` rows stand in, so every other status is still checked on
  every run; the file is rewritten only with both `CAKEYS_COVERAGE_TRACE` and
  `CAKEYS_UPDATE_COVERAGE`.
