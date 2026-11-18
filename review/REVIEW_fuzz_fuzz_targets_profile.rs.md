# Review: fuzz/fuzz_targets/profile.rs (11 lines)

Reviewed 2026-11-18 [read]. Summary: `caprobe::fuzzing::profile_round_trip` on UTF-8 input:
parse, emit, re-parse equals, re-emit equals. A real property over the hand-written emitter
(ISSUES.md Q27) and the profile parser. Seeded from the committed profiles (`nix/fuzz.nix:58`).

## Findings

### F1. The round trip starts after parse, so it cannot see inputs that collapse on parse — nit

`fuzz/fuzz_targets/profile.rs:8-10`. Keys that parse to the same `Capability`
(`generate.CKK_RSA.02048` and `…2048`, REVIEW crates/profile/src/capability.rs F1) lose a row
silently in `Profile::from_toml`; parse, emit, parse is still a fixed point, so the target
passes. Adding "every `[capabilities]` key of the input re-displays to itself" (or a row count
against a raw `toml::Value` parse) would catch this class.
[read]

## Design

- Mutations of TOML text rarely survive `deny_unknown_fields` and capability-key validation,
  so most inputs stop at parse; the seeds carry it. Fine for a smoke run.

## Checked, no issue

- Non-UTF-8 inputs are skipped rather than lossily converted.
