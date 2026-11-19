# Full code review, 2026-11-18

Branch `worktree-architecture-review` at `69ee620`. A fresh file-by-file pass for bugs,
complexity, poor practices and design issues. It builds on [ISSUES.md](../ISSUES.md) (the
2026-11-16 review): items still open there are cited by ID, not re-listed, and the fixes
marked "Done 2026-11-17" were spot-checked where they touch a reviewed file.

## Conventions

- One file per reviewed source file: `review/REVIEW_<path with / replaced by _>.md`, e.g.
  `review/REVIEW_crates_core_src_config.rs.md`.
- Evidence tags as in the repo: **[read]** from the code, **[run]** reproduced or measured.
- Severity: **bug** (wrong behaviour, reachable), **risk** (correctness risk: likely bug, or
  one under conditions not shown reachable), **practice** (poor practice), **complexity**
  (hard to read or change), **nit**. Design observations go in a `## Design` section per file
  and are collected in [REVIEW_DESIGN.md](REVIEW_DESIGN.md).
- Verification: every bug and risk is re-read by a second pass and marked **confirmed** or
  **withdrawn**.

## Scope

In: every `.rs` file (src, tests, examples, fuzz targets, build script), every `.nix`, `.sh`,
`.py` and `.c` file, the three workflows, the Cargo manifests, `deny.toml`, `flake.nix`,
`treefmt.nix`, `rustfmt.toml`, `.config/nextest.toml`.

Out: fixtures (keys, certificates, YAML, `keys.toml`/`keys.lock` test data), the patches under
`nix/patches/` and `upstream/`, the committed profiles, docs and reports, the Terraform under
`scripts/cloud/`, the Quint spec (`crates/core/spec/lock.qnt`, read only as context for
`lock_mbt.rs`).

## Batches

At most four review agents at a time.

| Wave | Batch | Files | Status |
|---|---|---|---|
| 1 | core | `crates/core/src/*` | done: 3 bug, 1 risk, 7 practice, 3 complexity, 18 nit |
| 1 | pkcs11 | `crates/pkcs11/src/**` | done: 2 bug, 6 risk, 5 practice, 2 complexity, 21 nit |
| 1 | camigrate | `crates/camigrate/src/*` | done: 2 bug, 6 risk, 5 practice, 3 complexity, 21 nit |
| 1 | caprobe, cli, cli-common | `crates/caprobe/src/**`, `crates/cli/src/*`, `crates/cli/examples/*`, `crates/cli-common/src/*` | done: 2 bug, 8 risk, 9 practice, 2 complexity, 20 nit |
| 2 | profile, p11-fault, p11-names, fuzz | their `src/`, `fuzz/fuzz_targets/*` | done: 1 bug, 8 risk, 6 practice, 0 complexity, 14 nit |
| 2 | providers | `crates/{ykcs11,tpm2-pkcs11,kmsp11,aws-cloudhsm}/src/**`, `crates/ykcs11/build.rs` | done: 2 bug, 2 risk, 2 practice, 0 complexity, 16 nit |
| 2 | build and scripts | `nix/`, `scripts/`, `examples/`, `upstream/**/*.{sh,py}`, workflows, manifests, `flake.nix`, `apps.nix`, `checks.nix`, `pkgs.nix`, `treefmt.nix` | done: 1 bug, 10 risk, 13 practice, 6 complexity, 52 nit |
| 2 | tests (cli) | `crates/cli/tests/**/*.rs` (27 files) | done: 1 bug, 14 risk, 16 practice, 9 complexity, 38 nit |
| 2 | tests (other crates) | `crates/{core,pkcs11,profile,camigrate,caprobe}/tests/**/*.rs` (18 files) | done: 0 bug, 16 risk, 9 practice, 8 complexity, 30 nit |
| 3 | verification A | bug/risk in core, pkcs11, providers | done: 19 confirmed, 0 withdrawn (plus pop.rs F1, plaintext.rs F1 confirmed) |
| 3 | verification B | bug/risk in camigrate, caprobe, cli, p11-fault, profile | done: 27 confirmed, 0 withdrawn, 9 re-graded down (7 to nit, 2 to practice) |
| 3 | verification C | bug/risk in nix/scripts/CI and cli tests | done: 26 checked, 2 withdrawn, 7 re-graded down, 1 bug to risk |
| 3 | verification D | bug/risk in the other crates' tests | done: 17 checked, 2 confirmed risk, 15 downgraded to practice, 0 withdrawn |

## Baseline

In `nix develop`: `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test
--workspace --no-fail-fast` 532 passed, 0 failed [run]. Plain `cargo` outside the dev shell
fails to build `tss-esapi-sys` (no pkg-config). Token suites skip under plain `cargo test`; no
Nix check or token run was part of this review.

## Result

211 files in scope, 211 review files (checked by script: every in-scope tracked file has its
`REVIEW_*.md`). Cross-cutting design findings: [REVIEW_DESIGN.md](REVIEW_DESIGN.md). No
source file was changed: after the review `git status` lists exactly the 213 new files under
`review/` and nothing else [run].

Findings as first reported (counted from the headings): 420 in all, 14 bug, 71 risk, 72
practice, 33 complexity, 230 nit. Every one of
the 85 bug and risk findings was re-read by a separate verification agent, with a
`**Verification:**` line under its heading: 2 withdrawn, 1 bug moved to risk, 29 risks moved
down (17 to practice, 12 to nit), and the other 53 confirmed as reported (13 bug, 40 risk). None duplicates an item still open in
ISSUES.md. Headings keep the severity first reported; the verification line overrides it.

Two "Done" claims in ISSUES.md do not hold: **B16** (the `pop-unwrap` secret and the RSA CRT
coefficient are still not wiped) and **B18**'s note that the by-name retry reads the lock's
recorded answers (`with_answers` is never applied at `Token::open`).

### Confirmed bugs (13)

| Where | What |
|---|---|
| [tpm2-pkcs11 ptool.rs](REVIEW_crates_tpm2-pkcs11_src_ptool.rs.md) F1 | `tpm2_ptool import --id` gets cakeys' hex text, which tpm2_ptool stores as the `CKA_ID` bytes (`0a` becomes `30 61`): the import is not found under its locator, and the cleanup finds nothing, leaving the key on the TPM |
| [camigrate lib.rs](REVIEW_crates_camigrate_src_lib.rs.md) F1, F2 | The only refusal of `attestation = true` on an import into a YubiKey slot is in the planner's `landing_checks`; it ignores `--spec`, and key-file imports never plan. The key is written and cannot be deleted (ykcs11) |
| [core reconcile.rs](REVIEW_crates_core_src_reconcile.rs.md) F1 | `compare` judges downgrades of a retargeted spec against its previous object, so `lock` refuses the retarget |
| [core config.rs](REVIEW_crates_core_src_config.rs.md) F1 | `gc --apply` can drop an object a kept realisation names; the saved lock then fails to load for every verb |
| [core config.rs](REVIEW_crates_core_src_config.rs.md) F2 | `check_observations` validates only the first observation's module hash |
| [pkcs11 token/policy.rs](REVIEW_crates_pkcs11_src_token_policy.rs.md) F1 | A certificate's declared policy attributes (`CKA_TRUSTED`, …) are never compared with the token |
| [pkcs11 ops.rs](REVIEW_crates_pkcs11_src_ops.rs.md) F1 | `create` on a pinned pair without a configured PIN reports the key lost (14) instead of asking for a login |
| [profile effective.rs](REVIEW_crates_profile_src_effective.rs.md) F1 | A key type whose every probed row says no answers yes when no curve or size is asked (`supports CKK_EC_EDWARDS` on swtpm) [run] |
| [caprobe lib.rs](REVIEW_crates_caprobe_src_lib.rs.md) F1 | `supports` and `probe --diff` ignore keys.toml's `profileDirs`. **Fixed** in dc3f102 |
| [caprobe supports.rs](REVIEW_crates_caprobe_src_supports.rs.md) F1 | `supports --token` leaves out the token's configured profile layers. **Fixed** in dc3f102 |
| [kmsp11 lib.rs](REVIEW_crates_kmsp11_src_lib.rs.md) F1 | `keys.json`'s `HMAC_SHA256` row lists no mechanisms, so a spec allowing `CKM_SHA256_HMAC` is refused (15) |
| [nix examples.nix](REVIEW_nix_examples.nix.md) F1 | The EFI stub path is x86_64-only, so `checks.aarch64-linux.examples` fails (CI builds only x86_64) |

### Confirmed risks (most serious first)

| Where | What |
|---|---|
| [tpm2-pkcs11 attest/esys.rs](REVIEW_crates_tpm2-pkcs11_src_attest_esys.rs.md) F1 | The SPKI and `CKA_LOCAL`/`CKA_EXTRACTABLE` checks read `TPM2_ReadPublic`'s area, not the store blob whose Name the attestation signs. **Fixed** (ISSUES.md "Fixed since") |
| [camigrate sealed.rs](REVIEW_crates_camigrate_src_sealed.rs.md) F1 | A forged bundle with a swapped EC private key passes under `token-asserted` on targets that expose no public point. **Fixed**: `import --in` refuses it (ISSUES.md "Fixed since") |
| [camigrate lib.rs](REVIEW_crates_camigrate_src_lib.rs.md) F3, F4 | A transport file is read twice, only the first read checked; the lock is saved once per run, after all token writes. **Fixed** (ISSUES.md "Fixed since") |
| [camigrate host.rs](REVIEW_crates_camigrate_src_host.rs.md) F1 | A failed reopen after `tpm2_ptool import` leaves the key in the TPM, unrecorded. **Fixed** (ISSUES.md "Fixed since") |
| [camigrate keyfile.rs](REVIEW_crates_camigrate_src_keyfile.rs.md) F1 | The plaintext gate and the PEM parser disagree on what a PEM block is. **Fixed** (ISSUES.md "Fixed since") |
| [pkcs11 token/mod.rs](REVIEW_crates_pkcs11_src_token_mod.rs.md) F1, [pkcs11 Cargo.toml](REVIEW_crates_pkcs11_Cargo.toml.md) F1, [caprobe Cargo.toml](REVIEW_crates_caprobe_Cargo.toml.md) F1, [caprobe probe.rs](REVIEW_crates_caprobe_src_probe.rs.md) F2 | Without `rv-value`, no error carries its `CK_RV`; the probe's busy-session handling goes dead (one root cause). **Fixed** (ISSUES.md "Fixed since") |
| [pkcs11 token/mod.rs](REVIEW_crates_pkcs11_src_token_mod.rs.md) F2 | `as_so` turns a step that changed the token into an error when the SO logout or re-login fails. **Fixed** (ISSUES.md "Fixed since") |
| [pkcs11 ops.rs](REVIEW_crates_pkcs11_src_ops.rs.md) F2 | Errors after the module created something skip `create_absent`'s cleanup. **Fixed** (ISSUES.md "Fixed since") |
| [pkcs11 token/mod.rs](REVIEW_crates_pkcs11_src_token_mod.rs.md) F3 | The library cache keys a bare module name apart from a path to the same file. **Fixed** (ISSUES.md "Fixed since") |
| [pkcs11 templates.rs](REVIEW_crates_pkcs11_src_templates.rs.md) F1 | A declared `CKA_PRIVATE` on a private key drops the public half's `CKA_PRIVATE = false` (shows on SoftHSM imports). **Fixed** (ISSUES.md "Fixed since") |
| [core id.rs](REVIEW_crates_core_src_id.rs.md) F1 | RSA keys outside 1024–8192 bits have no identity and are reported as a conflict (13). **Fixed** (ISSUES.md "Fixed since") |
| [ykcs11 lib.rs](REVIEW_crates_ykcs11_src_lib.rs.md) F1 | `matches` claims YubiHSM 2's module too (same manufacturer string). **Fixed** (ISSUES.md "Fixed since") |
| [profile effective.rs](REVIEW_crates_profile_src_effective.rs.md) F2 | RSA size interpolation ignores a refused size in between [run]. **Fixed** in dc3f102 (profile verdicts) |
| [caprobe probe.rs](REVIEW_crates_caprobe_src_probe.rs.md) F3 | `Made::create` loses track of a key pair it made. **Fixed** (ISSUES.md "Fixed since") |
| [caprobe emit.rs](REVIEW_crates_caprobe_src_emit.rs.md) F1 | Two parseable fields are dropped by the emitter. **Fixed** (ISSUES.md "Fixed since") |
| [cli lib.rs](REVIEW_crates_cli_src_lib.rs.md) F1 | A failed lock save after `create` hides what was created and the pair's own error. **Fixed** with the per-object save (ISSUES.md "Fixed since") |
| [p11-fault hooks.rs](REVIEW_crates_p11-fault_src_hooks.rs.md) F1, [p11-fault plan.rs](REVIEW_crates_p11-fault_src_plan.rs.md) F1 | `use_label` fires on no match; slot and token flag names collide by value. **Fixed** (ISSUES.md "Fixed since") |
| [nix module.nix](REVIEW_nix_module.nix.md) F1, F2; [nix module-test.nix](REVIEW_nix_module-test.nix.md) F1 | The check unit is once per boot (a restart is not re-checked), is not ordered after time sync, and is tested only from a stopped state. **Fixed** (ISSUES.md "Fixed since") |
| [nix deny.nix](REVIEW_nix_deny.nix.md) F1 | No path checks against current advisories |
| [flake.nix](REVIEW_flake.nix.md) F1, [flake-check.yml](REVIEW_.github_workflows_flake-check.yml.md) F1, [nix package-crane.nix](REVIEW_nix_package-crane.nix.md) F2, [nix package-common.nix](REVIEW_nix_package-common.nix.md) F1 | One system of three built; heavy checks share one runner; Kani unbounded; global test stack a silent fallback (latent) |
| [scripts cloud/gcp.sh](REVIEW_scripts_cloud_gcp.sh.md) F1, [scripts pkcs11-check.sh](REVIEW_scripts_pkcs11-check.sh.md) F1 | `status` says nothing is billing when gcloud fails; a run can report the previous run's results |
| [cli tests common/mod.rs](REVIEW_crates_cli_tests_common_mod.rs.md) F1 | No runner clears `CAKEYS_LOCK`, so the suites can write a developer's real lock. **Fixed** (ISSUES.md "Fixed since") |
| [cli tests tpm2.rs](REVIEW_crates_cli_tests_tpm2.rs.md) F1, F3 | Persistent TPM handles made outside the swtpm guard; `on_swtpm()` is a substring test whose failure skips silently. **Fixed** (ISSUES.md "Fixed since") |
| [cli tests common/xref.rs](REVIEW_crates_cli_tests_common_xref.rs.md) F1 | The dry-run twin compares no kryoptic token for runs naming `kryoptic-der`. **Fixed** (ISSUES.md "Fixed since") |
| [cli tests yubikey.rs](REVIEW_crates_cli_tests_yubikey.rs.md) F1, [cli tests reference/lockfile.rs](REVIEW_crates_cli_tests_reference_lockfile.rs.md) F1, [cli tests reference/check.rs](REVIEW_crates_cli_tests_reference_check.rs.md) F1 | Wrong-PIN tests can spend two of three tries; the lock-wait test is weak behind the fault shim; B8's CLI test never reaches an attestation. **Fixed** (ISSUES.md "Fixed since") |
| [caprobe tests ftpm.rs](REVIEW_crates_caprobe_tests_ftpm.rs.md) F1, [camigrate tests dry_run.rs](REVIEW_crates_camigrate_tests_dry_run.rs.md) F1 | The documented command skips the only assertion and passes; the host-move matrix drops non-ready rows. **Fixed** (ISSUES.md "Fixed since") |

### Withdrawn (2)

- [cli tests common/xref.rs](REVIEW_crates_cli_tests_common_xref.rs.md) F2: the pinned kryoptic
  never uses WAL, so comparing the main database file is enough.
- [cli tests object_matrix/mod.rs](REVIEW_crates_cli_tests_object_matrix_mod.rs.md) F1: each
  contention mechanism named is guarded.

Practice, complexity and nit findings were not separately verified; they are in each file.
