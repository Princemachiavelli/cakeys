# Review: crates/caprobe/tests/yubikey.rs (104 lines)

Reviewed 2026-11-18 [read]. Summary: opt-in caprobe tests on a real YubiKey: the write probe in
scratch slot 94 (`CKA_ID` 17) reproduces `profiles/modules/ykcs11/2.7.toml` byte for byte, and
a read-only probe refuses `--write` on a `scratch = true` token (17, naming the SO and
`scratchId`) and conforms. Every CLI run is time-bounded (`run_within`), credentials are file
paths only, and the slot is the one DEVELOPMENT.md assigns. The write test re-implements the
shared conformance helper and probes the device twice.

## Findings

### F1. Opt-in with an unpatched build is a silent pass — risk

**Verification:** confirmed (downgraded to practice). `patched()` returns false and the tests `return` under a plain cargo build (`yubikey.rs:25-31`, `:51-53`); but unlike ftpm.rs this file documents no `cargo test` command, and the documented runner, `scripts/coverage-full.sh:72-104` inside `scripts/local-tests.sh` (`:9-16`: "refuses to run unless the build resolves cryptoki to the patched copy"), always has the patch, so only an undocumented ad hoc run passes vacuously. [read]
`crates/caprobe/tests/yubikey.rs:25-31`, `:51-53`, `:99-101`. After the user sets all three
variables, `patched()` returns false under any cargo build (the HMAC fix exists only in the Nix
build; the workspace has no `[patch]`), so the write-probe test returns `ok` having run nothing,
and the read-only test skips its diff. The comment says so, but the user who opted in still sees
a pass. Fix: once the opt-in variables are set, fail with the "unpatched cryptoki: run through
`scripts/local-tests.sh`/coverage-full" message instead of returning (same fix as ftpm.rs F1).
[read]

### F2. The conformance check is re-implemented, with a redundant first write probe — complexity

`crates/caprobe/tests/yubikey.rs:56-79` vs `common::assert_profile_conforms`
(`crates/cli/tests/common/mod.rs:293-314`). The test runs `probe --write --diff` once without
`--out` and then again with `--out`, i.e. two full write probes (each "every curve and RSA size",
74 s measured) on the device, where the shared helper does one (it diffs and regenerates in the
same run, and says why one is better). The helper takes a `km` closure, so
`assert_profile_conforms(|a| run_within(&config, a, PROBE_LIMIT), "yubikey", "ykcs11/2.7",
"modules/ykcs11/2.7.toml", &copy)` would do the same checks (plus the read-only `--out` refusal)
with one write probe. [read]

### F3. `patched()` duplicates `common::cryptoki_hmac_types_fixed` — complexity

`crates/caprobe/tests/yubikey.rs:25-31` is `cryptoki_hmac_types_fixed(false)`
(`crates/cli/tests/common/mod.rs:174-181`) with another skip message. Use the shared one (with
`require = true` once opted in, F1). [read]

### F4. Exit code asserted without the output in the message — nit

`crates/caprobe/tests/yubikey.rs:72`, `:101-103`. On hardware, a failure message without
stderr means a second run to find out why; `run_within` logs the output, but the assertion
message should carry it as the others do. [read]

## Design

- See camigrate's yubikey.rs review: one helper for hardware opt-in (all-or-none variables,
  fail on an unpatched build once opted in) would fix F1 here, ftpm.rs F1/F2 and camigrate's
  yubikey.rs F2 together.

## Checked, no issue

- Hardware rules (docs/DEVELOPMENT.md): the write probe's `scratchId = "17"` is the slot the
  rules assign (retired slot 94); credentials go in as file paths (`yubikey_token`) and are never
  read here; the read-only test gives no credentials at all; each run is bounded (`RUN_LIMIT`
  60 s, `PROBE_LIMIT` 300 s against a measured 74 s), so a touch or PIN prompt fails rather than
  hangs.
- `yubikey_label` opens the module through the shared `Module` context and drops it before the
  subprocesses run.
