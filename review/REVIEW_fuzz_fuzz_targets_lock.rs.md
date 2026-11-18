# Review: fuzz/fuzz_targets/lock.rs (11 lines)

Reviewed 2026-11-18 [read]. Summary: keys.lock text through `parse_lock`; on error the exit code
must be 17. Property: "no panic, right exit code". Seeded from the fixture lock
(`nix/fuzz.nix:51`).

## Findings

### F1. The lock is written by cakeys and re-read every run, but the target checks no round trip — practice

`fuzz/fuzz_targets/lock.rs:8-10`. Every writing verb saves the lock with
`toml::to_string_pretty(lock)` (`crates/core/src/config.rs:1798-1803`) and the next run reads it
with `parse_lock`, which canonicalises object types and runs `Lock::validate`
(`config.rs:1781-1789`). A lock that parses but whose serialisation does not parse back (a
serde rename or `skip_serializing_if` mismatch, a canonicalisation that `validate` then
refuses) would leave a repository with a lock cakeys itself cannot read; this target cannot
see that. The `profile` target already shows the pattern. Add: for `Ok(lock)`, `let text =
to_string_pretty(&lock)`; `parse_lock(&text)` succeeds and re-serialises to `text`
(`Lock` has no `PartialEq`, so compare texts). One fixture test does this today
(`config.rs:2576`).
[read]

## Design

None.

## Checked, no issue

- Exit 17 is the documented code for an invalid lock.
