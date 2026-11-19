# Review: crates/cli/tests/yubikey.rs (239 lines)

Reviewed 2026-11-18 [read]. Summary: read-write tests on a real YubiKey through ykcs11, slots
90-95 (`CKA_ID` 13-18) only. Five key types each generated or adopted, attested, proven without
touch, recorded, verified, and refused on `delete` (15). Every run is bounded so a touch policy
fails rather than hangs, and the secrets travel only as file paths. The PIN-try budget is not
protected when the two tests run in parallel.

## Findings

### F1. The two tests can spend two of the PIN's three tries in parallel — risk

**Verification:** confirmed, but parallelism is not the cause. With a wrong PIN file, each test's first login fails and spends a try (yubikey.rs:220-239; .config/nextest.toml sets no serial group). Run one after the other, the second login is not stopped either: `Pin::guard` refuses only on `PIN_LOCKED`/`FINAL_TRY` (crates/pkcs11/src/token/mod.rs:84-105), and `COUNT_LOW` is only a warning (:466-474). So `--test-threads=1` alone still spends two; only scripts/coverage-full.sh's `--fail-fast` (:66) holds to the "stop after one failed login" rule (docs/DEVELOPMENT.md:93). [read]
`yubikey.rs:220-239`. `rw_lifecycle_…` and `rw_key_types_…` are separate `#[test]`s. Under plain
`cargo test` (libtest's default thread count), which is how the header implies the suite is run, they
start concurrently. If the PIN file is wrong, both log in and fail: 2 of 3 tries spent before
anyone sees the first failure. docs/DEVELOPMENT.md's hardware rule is "if a login fails once,
stop". When the tests run one after the other, cakeys' own PIN-counter guard (tested in
`reference/tokens.rs`) can stop the second login if ykcs11 reports the low count. Two logins started
at the same time both pass that check before either fails. `ftpm.rs` documents `--test-threads=1`;
this header does not. Only `scripts/coverage-full.sh`
(`--test-threads 1 --fail-fast`) is safe. Fix: state `--test-threads=1` in the header and, in
`env`, hold a process-wide `Mutex`. Better, have the first login failure set a flag (or file)
that makes later tests refuse. [read]

**Fixed (2026-11-18):** `common::YubikeyTurn` holds an exclusive lock on a file in the shared
target tmpdir for each `YubiKey` test (cakeys, caprobe, camigrate), so no two log in at once
in any process. Any `CKR_PIN_*` in a run's output latches every later test off until a person
removes the latch. Login failures now name their `CKR_*` (they printed cryptoki's prose, which
the latch could not read), held by `a_failing_module_call_is_unavailable` on real output. Test:
`a_failed_yubikey_login_stops_every_later_one` (no device).

### F2. The "generates" tests silently adopt on every run after the first — practice

`yubikey.rs:165-168`. If `create` gives 19 (a key already in the slot), the test falls back to
`lock` and continues. Slots 90-93 are never emptied by any script (`coverage-full.sh` wipes only
95, for camigrate), so after the first run the SO generation path, Ed25519 generation by curve name
and RSA-3072 generation are not exercised, while the test names say "generates". The header
documents this (`:23-25`), so it is not hidden, but nothing in the output says which path ran. Fix:
print "adopted, not generated" when the fallback is taken. Optionally, wipe slots 90-93 with
`ykman piv keys delete` in coverage-full as it does slot 95, after confirming with the owner that
those slots are free to wipe. [read]

**Fixed (2026-11-18), the silence:** a run that finds an earlier run's key says it adopts it with `lock`. **Decided:** the slots are not wiped first: PIV cannot erase a key, and only slot 95 may be wiped (docs/DEVELOPMENT.md, hardware rules).

### F3. Local copies of common helpers — complexity

`yubikey.rs:59-64` (`workdir`, without the package prefix `common::test_dir` adds, so caprobe's and
cakeys' YubiKey suites share `CARGO_TARGET_TMPDIR` names), `:211` (`code`), `:145` (`lock`) and
`:170-176` (`got:` parsing, `common::got_hash`), while the file declares `mod common`. [read]

**Fixed (2026-11-18):** the local copies are gone: the suite uses common's `Workdir::new` (with the package prefix), `code` and `got_hash`, and `lock` reads through `Workdir::lock`. No test checks these helpers specifically.

### F4. No require variable — nit

`yubikey.rs:46-56`: see ftpm.rs F2. [read]

**Fixed (2026-11-18):** the opt-in is common's `yubikey_opted_in` through `OptIn`, with the require variable `CAKEYS_YUBIKEY_REQUIRE`: a half-set opt-in, or the require variable alone, fails. Tests: `a_half_set_opt_in_fails`, `every_hardware_suite_opts_in_through_the_harness`.

## Design

- PIN safety rests on how the suite is invoked (one thread, fail fast) rather than on the tests
  themselves. With a 3-try PIN, the test code should enforce it (F1).

## Checked, no issue

- Only slots 90-95 are named. 82-84 are never touched.
- `run_within` bounds every run at 60 s, so a touch or PIN prompt fails the test.
- The attestation is asserted per realisation (`yubico-piv`), with possession proven, not asserted.
- Re-realising is checked to generate nothing and keep the identity.
