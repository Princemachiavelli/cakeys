# Review: crates/cli/tests/reference/create.rs (322 lines)

Reviewed 2026-11-18 [read]. Summary: `create`'s contract: never over an occupied locator (13),
never against a pinned identity (14), every unpinned pair created once with pinned pairs verified
(0/10/14) and unpinned keys already there refused (19), the capability gate with `--dry-run` and
`--skip-unsupported`, recorded token answers deciding before profiles, and recording what was made
before a later failure. Each verdict is backed by a count of the objects on the token, not only an
exit code. Thorough. Only small issues.

## Findings

### F1. The doc promises an exit 11 the test does not check — nit

`reference/create.rs:281` says a name that selects nothing is refused "(17, 11)", but `:318-321`
assert only 17. Either assert the 11 case or drop it from the doc. [read]

**Fixed (2026-11-18):** every such name is 17; the doc says so, and each case pins its reason.

### F2. The `--dry-run` in `create_makes_keys_and_nothing_else_does` is not shown to write nothing — nit

`reference/create.rs:130-133` checks the dry run's exit code and plan but not that the lock and the
token are unchanged. The gate test does check this (`:202, 215`), so the property is covered once,
on a refused plan only. Comparing the lock bytes before and after here would cover a passing plan
too. [read]

### F3. Profile prose pinned with an em dash — nit

`reference/create.rs:210` pins `"... cannot generate it: no — kryoptic/1.5"`, and `:219, 224` pin
the run's message wording. The exit codes are frozen; this text is not. [read]

## Design

None.

## Checked, no issue

- The "Done 2026-11-17" `create` rework (ISSUES.md, "`create` flags" item) is exercised as
  documented: pinned and matching → 0 with a note and `[]`, pinned with other material → 10 named
  or not, pinned but lost → 14, unpinned but present → 19 naming `lock`, and `--dry-run` says
  `verify` and `skip`. Each also asserts the token still holds exactly one pair.
- B2 (`create` never finds a key: 19) is tested both named and unnamed.
- `create_records_what_it_made_before_a_failure` covers both an unopenable module (16) and a
  second session on the same module (16, without "already been initialized").
