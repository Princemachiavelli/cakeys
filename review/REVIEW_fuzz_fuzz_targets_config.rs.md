# Review: fuzz/fuzz_targets/config.rs (12 lines)

Reviewed 2026-11-18 [read]. Summary: keys.toml text through `parse_config_with`, with every
`$NAME` path reference set to `/x`; on error the exit code must be 15 or 17. Property: "no
panic, right exit code", which fits a human-written file with no writer in cakeys to
round-trip against. Seeded from the fixture keys.toml (`nix/fuzz.nix:54`). No findings.

## Findings

None.

## Design

- Because the `env` lookup always answers, the "unset `$NAME`" refusal
  (`crates/core/src/config.rs:1449-1466`) is never fuzzed; an `env` that answers `None` for
  some names would reach it. Minor.

## Checked, no issue

- 15 (an object type cakeys does not manage) and 17 (invalid) are the two codes
  `parse_config_with` documents.
