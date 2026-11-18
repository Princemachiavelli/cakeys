# Review: crates/cli/tests/common/mod.rs (744 lines)

Reviewed 2026-11-18 [read]. Summary: the harness every cakeys, caprobe and camigrate integration
test includes: the binary, per-suite token headers, `Workdir`, the skip/require gate, the shared
refcounted PKCS#11 context and an independent DER/AES/DES3 oracle. The oracle is well separated
from the code under test. The runners and gates have been copied into several suites instead of
shared, and no runner clears the variables that point `cakeys` at another lock.

## Findings

### F1. No test runner clears `CAKEYS_LOCK`, so a developer's real lock can be written — risk

**Verification:** confirmed. `--lock` takes `env = "CAKEYS_LOCK"` (crates/cli/src/lib.rs:33-34); `km_env` (common/mod.rs:371-380) and `run_within` (:132-141) pass only `--config` and remove only `NIX_BUILD_TOP`/`IN_NIX_SHELL`; no runner in crates/*/tests, scripts/local-tests.sh, nix/test-tokens.sh or .config/nextest.toml unsets `CAKEYS_LOCK` (rg finds only caprobe's `env_remove("CAKEYS_CONFIG")`, supports.rs:74). Needs a developer to export it, hence risk. [read]
`common/mod.rs:371-380` (`Workdir::km_env`), `:132-141` (`run_within`), `common/xref.rs:182-191`,
`reference/lockfile.rs:216-224`, `validate.rs:13-15`, `tpm2.rs:807-815`, `tpm2.rs:905-912`. Every
runner passes `--config` but never `--lock`, and none calls `env_remove("CAKEYS_LOCK")`. `cakeys`
takes the lock path from `CAKEYS_LOCK` when `--lock` is absent (`crates/cli/src/lib.rs:33`).
Neither `scripts/local-tests.sh` nor `nix/test-tokens.sh` scrubs the environment. Failure
scenario: a developer who exports `CAKEYS_LOCK=/etc/cakeys/keys.lock` for real work runs
`scripts/local-tests.sh`. Every `lock --update-lock`, `create` and `gc --apply` in the suites then
writes test realisations into that real lock (and `gc --apply` removes its entries) before the test
fails on `Workdir::lock()` reading `dir/keys.lock`. Fix: scrub `CAKEYS_LOCK` and `CAKEYS_CONFIG`
in one shared runner (see F5), or pass `--lock <dir>/keys.lock` explicitly. [read]

**Fixed (2026-11-18):** nix/test-tokens.sh unsets `CAKEYS_CONFIG` and `CAKEYS_LOCK`, and
every run the suites start goes through `common::tool`, which removes them (with
`NIX_BUILD_TOP` and `IN_NIX_SHELL`): `run_within`, `km_env`, xref, validate, tpm2,
lockfile, and the camigrate and caprobe suites. Test: `no_test_run_sees_a_real_keys_toml_or_lock`.

### F2. 243 of the 247 tests in the 11 `cakeys` test binaries pass without running anything — risk

**Verification:** confirmed (downgraded to practice). The arithmetic holds (68 `#[test]` under reference/ × softhsm/kryoptic/fault + fault 8, tpm2 16, p11kit 3, references 5, ftpm 3, yubikey 2, cloud 2 = 243; plus surface 1, validate 3). But docs/DEVELOPMENT.md:26-27 documents the skip under plain `cargo test`, and both supported runners set every `*_REQUIRE` the CI-able binaries read (nix/package-common.nix:179-213, nix/test-tokens.sh:78, scripts/local-tests.sh:107-119), so a missing module fails there; the hardware binaries cannot run in CI by design. Of the in-test quiet skips listed, only tpm2.rs's `on_swtpm` ones are a live CI blind spot (REVIEW_crates_cli_tests_tpm2.rs.md F3); identity.rs:349, tpm2.rs:473 and references.rs:405-408 are shadowed by loud failures elsewhere, matrix.rs:12 is a fixed per-binary choice. [read]
`common/mod.rs:49-56` (`suite_var`), `reference/mod.rs:46-55`, `tpm2.rs:31-38`, `p11kit.rs:29-37`,
`common/xref.rs:39-65`, `ftpm.rs:39-45`, `yubikey.rs:46-56`, `cloud.rs:63-73`. With no suite
variables set (plain `cargo test -p cakeys`), every token test returns early and is reported as
passed. Only `surface` (1) and `validate` (3) run. That leaves 68 reference tests × 3 binaries,
plus fault 8, tpm2 16, p11kit 3, references 5, ftpm 3, yubikey 2 and cloud 2. CI does catch this
for 6 binaries: `nix/package-common.nix:179, 189, 202, 213` set `CAKEYS_TEST_REQUIRE`,
`_KRYOPTIC_REQUIRE`, `_P11KIT_REQUIRE` and `_TPM_REQUIRE`, `nix/test-tokens.sh:78` sets
`CAKEYS_FAULT_REQUIRE`, and `references` follows them. `ftpm`, `yubikey` and `cloud` have no
require variable. Several skips inside tests also ignore the require variables:
`reference/identity.rs:349` (wrong variable), `tpm2.rs:473`, `tpm2.rs:841`, `tpm2.rs:930`,
`references.rs:405-408`, `reference/matrix.rs:12` and `reference/lockfile.rs:287, 297`. A
regression that makes one of those conditions false (for example the `on_swtpm` bus-name match)
removes the test from CI silently. Fix: print a machine-readable `SKIPPED` line and fail the check
phase if any appears while a `*_REQUIRE` variable is set. Give the hardware suites
`CAKEYS_FTPM_REQUIRE`/`CAKEYS_YUBIKEY_REQUIRE`, which `scripts/coverage-full.sh` exports. [read]

### F3. `run_within` reads the child's pipes only after it exits: a large output hangs, then blames the user — risk

**Verification:** confirmed (downgraded to practice). The mechanism is real: common/mod.rs:138-139 pipes both streams and :146-153 reads them only after `try_wait` reports exit. Its largest caller is caprobe's write probe (crates/caprobe/tests/yubikey.rs:56-59): stdout is the profile (profiles/modules/ykcs11/2.7.toml, 9.3 KB), and stderr carries only notes and, on drift, one line per differing profile row (crates/caprobe/src/lib.rs:274-282; no per-step progress in probe.rs), so both stay far under 64 KiB and nothing hangs today. [read]
`common/mod.rs:132-170`. stdout and stderr are piped (`:138-139`) but drained only after `try_wait`
reports an exit. A child writing more than the pipe buffer (64 KiB on Linux) blocks on `write` and
never exits. After `limit`, the test panics with "user presence (touch or PIN) needed?", which sends
the person debugging toward the hardware. It is used by the YubiKey suites, including caprobe's
write probe, whose stderr can be long. Fix: drain both pipes on threads right after `spawn`. [read]

### F4. `MODULES` is keyed by the path string as given, not the file — risk

**Verification:** confirmed (downgraded to nit). `held.entry(path.to_owned())` (common/mod.rs:661) is keyed by the string. But glibc's dlopen returns the already-loaded handle for the same file under another name, so a second holder's `C_Initialize` returns `CKR_CRYPTOKI_ALREADY_INITIALIZED` and the `.unwrap()` at :663 panics loudly rather than racing to a SIGSEGV; and, as the finding says, no in-process caller names one module two ways (the p11-fault tags are separate file copies, nix/test-tokens.sh:66-71). [read]
`common/mod.rs:655-668`. `held.entry(path.to_owned())`: two holders that name one module by
different paths (a symlink and its target, or a relative and an absolute path) get two initialized
contexts in one process. That is the double-initialize/finalize-under-another SIGSEGV the doc at
`:644-649` says this struct prevents. ISSUES.md B5 fixed the same thing in the library cache by
canonicalising. No current in-process caller does this (`reference/lockfile.rs:67-70` gives its
symlink only to a child process). Fix: key by `std::fs::canonicalize(path)`. [read]

### F5. The skip gate, the `Env` wrapper and the "run BIN" helper are each copied 4-8 times — complexity

- Skip/require gate: `suite_var` (`:49`) re-implemented at `reference/mod.rs:46-51`, `tpm2.rs:31-36`,
  `p11kit.rs:29-34`, `common/xref.rs:39-43`, `ftpm.rs:39-43` and `yubikey.rs:46-54`.
- `struct Env { w: Workdir, .. }` + `Deref` + `config()`: `reference/mod.rs:34-61`, `tpm2.rs:19-44`,
  `p11kit.rs:16-43` and `ftpm.rs:26-51`.
- "Run BIN with `--config`": `Workdir::km_env` (`:371`), `run_within` (`:132`), `xref::run_once`
  and `km_in_nix_build` (`xref.rs:99, 182`), `validate.rs:13`, `reference/lockfile.rs:216`,
  `tpm2.rs:807` and `tpm2.rs:905`. Most copies exist because `km_env` can add variables but never
  remove one (`HOME`, `TPM2_PKCS11_STORE`). As a result they scrub different sets: `km_env` removes
  `NIX_BUILD_TOP` and `IN_NIX_SHELL`, `run_within` only `NIX_BUILD_TOP`, and `validate.rs`
  neither.

Fix: one builder (`w.cakeys().env(..).env_remove(..).bounded(limit).run(args)`) with one scrub
list (F1), and a generic suite gate that takes the `Reference`'s variable names. [read]

### F6. The shared-token clean-up is vestigial and half-applied — nit

`common/mod.rs:712-717` ("the token is shared between runs"). Under nextest every test has its own
token set (`nix/test-tokens.sh`), and running the token suites under plain parallel `cargo test` is
not the supported route (docs/DEVELOPMENT.md). About 13 of the 68 reference tests still call
`clear` (`reference/create.rs:90`, `reference/check.rs:195`, `reference/proofs.rs:12`, …) and the
rest do not. Stale comments: `reference/drift.rs:200, 264`, `reference/proofs.rs:89`,
`reference/validate.rs:113`, `reference/tokens.rs:139-141`. Drop them, or make every test clear.
[read]

### F7. `cryptoki_hmac_types_fixed(require: bool)` invites a hard-coded or missing variable — nit

`common/mod.rs:174`. Callers compute `require` themselves, and two get it wrong:
`reference/identity.rs:349` always reads `CAKEYS_TEST_REQUIRE`, and `tpm2.rs:473` passes `false`.
`caprobe/tests/reference.rs:18` does it right (`r.require_var`). Take the variable name instead.
[read]

### F8. No `P256` OID constant; the literal is repeated 14 times — nit

`common/mod.rs:543-545` defines `P384`, `ED25519` and `ED448`, but not P-256. The OID is written
out at `reference/drift.rs:47, 104, 270, 314, 363`, `reference/proofs.rs:151, 196, 244, 290, 399,
445`, `references.rs:396`, `object_matrix/mod.rs:673` and `fault.rs:181`. [read]

## Design

- Three packages share this harness through `#[path]` includes, yet each suite re-implements the
  gate and the runner (F5). A small `Suite` abstraction would also give F1 and F2 one place to
  live.
- Skips are reported as passes everywhere. The `*_REQUIRE` variables are the only defence, and they
  cover the outer gate, not the skips inside tests (F2).

## Checked, no issue

- `Module`/`TestSession` drop order: the session is dropped before the context, and the last
  holder finalizes under the same mutex that initializes (ISSUES.md "Token suites crash", Done
  2026-11-17). Correct apart from F4.
- `test_dir` names include package and crate, so `softhsm`, `kryoptic` and `fault` (one shared
  reference suite) never share a directory.
- `assert_profile_conforms` checks that regeneration matches byte for byte and that a read-only
  probe refuses `--out` (17) and leaves the file intact.
- The DER oracle and the AES/DES3 commitment oracles use RustCrypto directly, not cakeys code.
- `fault_shim()` fails loudly when the shim is not built.
- `Set::activate_embedded` (Q24): not used in this batch; not applicable.
