# Review: crates/camigrate/tests/yubikey.rs (85 lines)

Reviewed 2026-11-18 [read]. Summary: the opt-in YubiKey test of camigrate's `piv-import`: a P-256
key made on SoftHSM moves through the host into retired PIV slot 95 (`CKA_ID` 18), is recorded
with its origin, verified by `cakeys`, and a second move into the occupied slot is refused (13).
It follows the hardware rules on credentials (file paths only, never read) and slot (95 only),
but its CLI runs have no time bound, and a partial opt-in skips silently.

## Findings

### F1. CLI runs against the YubiKey are not time-bounded — risk

**Verification:** confirmed (downgraded to practice). `yubikey.rs:18-29` is a plain `Command::output()` while `common::run_within` (`crates/cli/tests/common/mod.rs:126-170`) exists for exactly this; but the only documented runner, `scripts/coverage-full.sh:94` (inside `scripts/local-tests.sh`), is nextest, whose `.config/nextest.toml` kills a test after ten 60 s periods, so a touch/PIN wait fails late rather than hanging forever. [read]
`crates/camigrate/tests/yubikey.rs:18-29`, used at `:60-83`. The local `run` is
`Command::output()` with no limit. `common::run_within` (`crates/cli/tests/common/mod.rs:126-170`)
exists so that "on hardware, a touch or PIN prompt fails the test instead of hanging it", and
docs/DEVELOPMENT.md says the YubiKey suite bounds each CLI run. If the import or the proof in
`cakeys verify` waits for a touch (a touch-policy key, or ykcs11 asking for the PIN again), this
test hangs until nextest's ten-minute kill (`.config/nextest.toml`) or forever under `cargo
test`. Fix: replace `run` with `run_within(&dir.join("keys.toml"), args, limit)`, which needs a
`bin` parameter to call `cakeys` as well as camigrate (it uses `BIN` only today). [read]

### F2. A partial opt-in is a silent pass — risk

**Verification:** confirmed (downgraded to practice). The skip at `yubikey.rs:33-40` is real, but the documented runner sets all four: `scripts/local-tests.sh:107` exports `CAKEYS_TEST_MODULE`, and `scripts/coverage-full.sh:72-77` checks the PIN/MGM files and module are readable (exit 1 otherwise) before exporting the three YubiKey variables; only an ad hoc shell run can skip silently. [read]
`crates/camigrate/tests/yubikey.rs:33-40`. The test skips when any of four variables is unset,
including `CAKEYS_TEST_MODULE`, which `nix develop` does not set. Someone who sets the three
YubiKey variables to run this test from a shell without SoftHSM gets "ok" and one stderr line
nextest hides. There is no REQUIRE variable as the reference suites have (`common::suite_var`).
Fix: skip only when none of the YubiKey variables is set, and fail when some but not all are;
or mark the test `#[ignore = "needs a YubiKey: CAKEYS_TEST_YUBIKEY_*"]` so runners report it as
skipped, and have `scripts/coverage-full.sh` pass `--run-ignored`. [read]

### F3. The second move's refusal checks the exit only — nit

`crates/camigrate/tests/yubikey.rs:77-84`. The comment says "refused before anything is
written", but the test asserts exit 13 only, not that the new `keys.lock` is unchanged by the
refused move (the slot cannot be checked, it is occupied by design). Fix: compare the lock bytes
before and after the refused `migrate`. [read]

### F4. The test leaves slot 95 occupied, so a second run fails at the first move — nit

`crates/camigrate/tests/yubikey.rs:8-9`, `:70-71`. Documented ("Slot 95 must be empty first";
`scripts/coverage-full.sh` wipes it when `CAKEYS_YUBIKEY_WIPE_95=1`), but a direct re-run fails
with 13 at `:71` with no hint. A pre-check that slot 95 is empty, failing with "wipe slot 95
first (ykman piv keys delete 95)", would make the cause obvious. [read]

### F5. Its own runner duplicates the harness's — complexity

`crates/camigrate/tests/yubikey.rs:18-29` and `:41-44` duplicate `common::Workdir::km_env` and
`Workdir::new` (`crates/cli/tests/common/mod.rs:351-389`), except that it can call either binary.
A `Workdir::run(bin, args)` (bounded, F1) would serve this file and caprobe's yubikey.rs. [read]

## Design

- Opt-in hardware tests across the workspace each implement their own skip (`suite_var` with
  REQUIRE for references; ad hoc `let Ok(..) else return` here, in caprobe's yubikey.rs and
  ftpm.rs). One `hardware_var(&[..])` helper with the "all or none" rule (F2) would make them
  consistent.

## Checked, no issue

- Hardware rules (docs/DEVELOPMENT.md): the PIN and management key are passed as file paths
  (`yubikey_token`, `pinFile`/`soCredentialFile`) and never read or printed by the test; the only
  slot written is 95 (`CKA_ID = "18"`); the stderr echoed by `run` is the CLI's, which does not
  print credentials.
- The SoftHSM side clears its `piv-import` label first, so re-runs start clean there.
- The dry run is asserted to plan `piv-import` and ready before the real move.
