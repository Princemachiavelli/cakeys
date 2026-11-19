# Review: crates/caprobe/tests/surface.rs (13 lines)

Reviewed 2026-11-18 [read]. Summary: the caprobe twin of crates/camigrate/tests/surface.rs:
`common::surface::assert_covered(&caprobe::command(), tests/, [])`. Correct; the same limit
applies.

## Findings

### F1. The shared harness's literals count as caprobe's coverage — nit

`crates/caprobe/tests/surface.rs:12`; `crates/cli/tests/common/surface.rs:46-52`. As in
camigrate's surface review F1: `common::assert_profile_conforms` (`crates/cli/tests/common/mod.rs:303-312`)
holds `"probe"`, `"--token"`, `"--write"`, `"--rsa-max-bits"`, `"--diff"`, `"--out"`, which
satisfy caprobe's surface on their own. They are caprobe's flags and caprobe tests call that
helper, so the result is right today, but the check would stay green if caprobe's own tests
stopped calling it. [read]

**Fixed (2026-11-18):** the shared harness counts toward no tool's surface (verified FIXED)..

## Design

- None (see camigrate's surface review).

## Checked, no issue

- Empty `UNTESTED` with the stale-entry check in force.
