# Area C: CLI, cli-common, reference suite and harness, Nix, CI, scripts, examples — review 2026-11-24

## Root causes in this area (fill at the end: 3-8 causes, each with the finding IDs that evidence it)

1. **The gate the work is written against is not the gate that decides, and the deciding gate
   is not required before merge.**
   - The dev gate is darwin. There `tpm2` is not compiled, and the VM, examples and fuzz checks
     do not exist.
   - The fast token run and the profile regeneration are Linux-only (C-12).
   - CI is Linux-only. Nothing in the tree makes a merge wait for it (branch protection cannot
     be seen from here). PR #5 (bc94263) merged with C-3's two checks, which fail by reading.
     Their CI result was not checked: `gh` is not available here.
   - Large batches were written unbuilt (6d4beab), then "drift" commits (8aaba2e) edited tests
     until the visible failures stopped.
   - Result: two Nix checks fail at HEAD (C-3); Linux-only golden tables and hardware profiles
     were edited by hand (C-8); a failure row was shipped untested (C-1).
   - Evidence: C-1, C-3, C-8, C-12; unguarded `cli-common/src/lib.rs:362-369`.
2. **Expectations come from the code under test.**
   - Golden tables are regenerated in the same commit as the behaviour (36 of 47 commits).
   - A fixture was added so the old expectation holds (`gate.lock`).
   - `validate --json` is checked against the text form of the same code.
   - Change is detected; error is not. Evidence: C-8, C-3, C-1.
3. **Oracles follow helper convenience.**
   - Exit code and stderr prose are one call each.
   - "Nothing changed" has no shared helper (the twin's `state()` is private and camigrate-only).
   - Machine output is asserted on success only.
   - Evidence: C-9 (39 of 131 tests exit/prose-only), C-1, C-4, C-5.
4. **Text lints and hand-copied lists stand in for behaviour.**
   - The surface test counts mentions, refusals included.
   - The opt-in lint and doc-references each carry their own pattern list.
   - CLI words and the exit-code table are copied into docs, an example and `demo.sh` by hand.
   - Fixes then sweep with `rg` for the reported spelling in one language and miss copies in
     Nix, shell or prose.
   - Evidence: C-2, C-5, C-7, C-13, C-3 (the sweep missed 2 Nix checks).
5. **Skipping is silent.**
   - Every gated test skips and passes. The guard is one `*_REQUIRE` variable per suite, and the
     fault suites' guard is set by the same `case` arm as the thing it guards.
   - No runner counts the tests that ran, or the binaries that `required-features` removed.
   - Gated behaviour therefore looks tested. Evidence: C-11, C-7, C-4 (VM-only).
6. **Tests pin internal artifacts and override defaults**, so the shipped surface is never the
   tested one. Every module evaluation sets `package`; the checks use `cakeys-crane` and
   `demo-crane`, and users get `unchecked` and `demo`. Evidence: C-10.
7. **Hostile-module coverage follows past findings, not the verb × class space.** The lie table
   covers 3 verbs × 1 class. A real device stands in for the destructive case, and on the
   reference tokens every success path is a friendly one. Evidence: C-6, C-9.

## Test gap map (fill at the end: per crate, what behaviour has no failing test, and why: gated, absent, oracle)

- **cli**:
  - The `--json` failure rows (absent: C-1).
  - `delete --dry-run` on a matching key: VM only (gated: C-4).
  - `delete`, secret keys, certificates and data objects under a lying module (friendly: C-6).
  - `validate` with an unknown provider; `--if-match` with several pairs; `create`'s recall
    applied to other verbs (absent).
  - "Lock and token unchanged" after a refusal: asserted only in `fault.rs`'s lie table and
    `lockfile.rs` (oracle: C-9).
- **cli-common**:
  - The writing half of the missing-lock unit test inside Nix (gated: early return).
  - The `profileDirs` note in cakeys (absent).
- **the harness (cli/tests/common)**:
  - `required_var` / `suite_var` themselves (absent).
  - The twin compares `pkcs11-tool --list-objects` text, not attributes such as `CKA_TRUSTED`
    (oracle).
  - The fault routing (gated: C-11).
  - The surface floor counts refusals (oracle: C-5).
- **golden data (profiles, object tables, coverage)**:
  - Every row (tautological: C-8).
  - The hardware and cloud profiles: no automated comparison at all (gated: C-8).
- **Nix**:
  - The module's default package and the apps (absent: C-10).
  - `featurePrefix` and `nix.systemFeature` (absent).
  - The `sandbox.tpm2` id-count assertion (absent).
  - `mkKeys`' `--module` words: Linux VM only (gated).
  - `checks.profiles` and `checks.examples` fail at HEAD (C-3).
- **scripts**:
  - `local-tests.sh`, `coverage-*` and `regen-profiles.sh` on darwin (gated: C-12).
  - `yubikey-empty-slots.py`'s kept-slot comparison covers 82-84 only.
- **examples**:
  - Exit-code-only oracles except inject, TLS and secure-boot.
  - `custom-provider.rs` is never run (absent: C-2).

## Test execution matrix

Runners:

- **cargo**: plain `cargo test`, in or out of `nix develop`.
- **crane**: the check phase of `cakeys-crane`, i.e. `checks.cakeys`, `checks-crane-only` and
  `nix flake check`. It runs cargo-nextest, one process per test, through `nix/test-tokens.sh`,
  with `test_env`'s tokens and `*_REQUIRE` variables.
- **CI-light**: `checks.yml` → `.#checks-no-vm` plus `nix flake check --no-build`, x86_64-linux.
- **CI-vm**: `.#checks-vm`, with KVM.
- **CI-kani**.
- **reports**: `reports.yml`. `coverage` on each push to main; `mutants` weekly.
- **local**: `scripts/local-tests.sh` (Linux only, C-12).
- **cov-full**: `apps.coverage-full`, on the host, opt-in hardware.
- **manual**: by hand only.

"Darwin" is the dev gate (`checks-crane-only` on aarch64-darwin), which no CI job runs.

| Suite (tests) | Runners | Needs | When absent | Zero tests run noticed? |
|---|---|---|---|---|
| cli `softhsm`, `kryoptic`: the reference suite (75 each) | crane (all), CI-light, local, reports, cov-full | SoftHSM / kryoptic template per test | cargo: skip, pass. crane: fails (`CAKEYS_TEST_REQUIRE`, `_KRYOPTIC_REQUIRE` from `test_env`) | yes, through the require variables |
| cli `fault` (14 + the 75 through p11-fault), caprobe `fault` (7), camigrate `fault` (6) | crane, CI-light, local; untraced in spec-coverage | `P11_FAULT_MODULE` + the shim | skip, pass everywhere. The require variable is set only by the runner's `suite = fault` arm | **no** (C-11) |
| cli `p11kit` (3), `references` (5); caprobe `reference` (7); camigrate `dry_run` (25) | crane, CI-light, local | a p11-kit server per test (runner's list) | fails (`CAKEYS_P11KIT_REQUIRE` global) | yes |
| cli `tpm2` (21), caprobe `tpm2` (2), the TPM references in `references` / `dry_run` | crane on Linux, CI-light, local | swtpm + abrmd per test; `tpm2` feature | darwin: not compiled (`required-features`); Linux: fails (`CAKEYS_TPM_REQUIRE`) | Linux yes; darwin: the binaries vanish unnoticed |
| pkcs11 `library` (1), `logins` (2), `templates` (2) | crane, CI-light, local | `CAKEYS_TEST_MODULE` | cargo: skip; crane: fails | yes |
| cli `ftpm` (4), caprobe `ftpm` (1) | cov-full, manual | real `/dev/tpmrm0`, `CAKEYS_FTPM_*`; tpm2 feature | skip, pass. The 2 attest tests skip even under `CAKEYS_FTPM_REQUIRE` (C-7) | partly |
| cli `yubikey` (2), caprobe `yubikey` (2), camigrate `yubikey` (1) | cov-full, manual | YubiKey + PIN/MGM files; ykcs11 feature | skip, pass. caprobe's read-only probe ignores `CAKEYS_YUBIKEY_REQUIRE` (C-7) | partly |
| cli `cloud` (2) | manual only (returns early inside a Nix build; no script sets its variables) | AWS CloudHSM / GCP KMS | skip, pass; no require variable | **no** |
| cli `offline` (3), `validate` (4), `harness` (8), `surface` (1); caprobe `supports` (5), `template_hook` (1), `surface` (1); camigrate `from_files` (4), `surface` (1); core `config_doc`, `exit_codes`, `fuzzing_surface`, `properties`, `refusals` (32); profile `answers` (2); pkcs11 `patched_cryptoki` (1) | cargo, crane, CI-light, local, reports | none (the HMAC cases need the patched cryptoki: harness-guarded) | run | n/a |
| core `lock_mbt` (1) | crane, CI-light, local | `quint` (a check input) | not verified outside Nix | n/a |
| inline `#[cfg(test)]` units, all crates | cargo, crane, CI-light, local; `mutants` for core, profile and camigrate's plan/bundle/file/transport | none. cli-common's lock test returns early inside a Nix build | – | – |
| `checks.quint` | all systems, CI-light | quint | – | yes (each witness's count) |
| `checks.lib`, `checks.module-assertions` (evaluation) | all systems / all, CI-light | – | – | – |
| `checks.profiles` (caprobe `supports` + `validate`) | all systems, CI-light | – | **fails at HEAD** (C-3) | – |
| `checks.demo` (`demo-crane`) | all systems, CI-light | SoftHSM, kryoptic | exit per step | – |
| `checks.examples` (5 run.sh + 2 evaluated Nix files) | Linux, CI-light | swtpm, pkcs11-provider | **fails at HEAD** (C-3) | – |
| `checks.vm`, `checks.module`, `checks.tpm` | Linux+KVM, CI-vm | KVM | absent on darwin and in `checks-crane-only` without KVM | – |
| `checks.fuzz` (fixed-seed smoke) / `apps.fuzz` | Linux, CI-vm / manual | libFuzzer | absent on darwin | – |
| `checks.kani` (3 proofs) | x86_64-linux `nix flake check`, CI-kani | Kani | absent elsewhere | – |
| `checks.{formatting,clippy,doc,msrv,deny,minimal,doc-references,token-setup,ci-jobs,softhsm-*}` | all systems, CI-light | – | – | – |
| `packages.test-nspawn` | **none** (needs `uid-range`; in no check) | uid-range | – | – |
| `packages.default` / `cakeys` / `caprobe` / `camigrate`, `apps.*`, the module's default package | **none** builds them (C-10) | – | – | – |
| `crates/cli/examples/custom-provider.rs` | compiled by clippy/doc; never run | – | – | – (C-2) |
| `packages.coverage`, `packages.mutants`, `packages.spec-coverage` | reports (coverage, mutants); spec-coverage manual | tokens | a report; a failure leaves the badge stale and gates nothing | – |
| `apps.pkcs11-check-compare`, `scripts/xversion.sh`, `apps.deny-online`, `apps.pcsc-*` | manual | – | – | – |

**Never exercised by any automated runner:**

- The ykcs11 provider on a device. This includes its post-destroy re-check, the only "did it
  really destroy" check in the workspace.
- Real-TPM attestation and the EK chain.
- Both cloud providers. Their hand-edited profiles likewise (C-8).
- `delete`, or any secret-key, certificate or data-object verb, under a lying module (C-6).
- The `--json` failure rows (C-1).
- `validate` with an unknown provider, and `--if-match` with several pairs.
- The shipped `packages.default`, the module's default package and every app (C-10).
- `test-nspawn`.
- The darwin build, outside the developer's own machine (C-12).
- `custom-provider.rs` as a program.
- The `delete --dry-run` would-delete path is exercised only by the VM (C-4), and the
  read-only-lock cases only when not run as root.

**Is the shipped artifact what the tests run against?** No. `packages.default` is
`cakeys-crane.unchecked`, a sibling derivation that no check or CI job builds. Every NixOS-module
evaluation overrides the package, so the `mkDefault` users get is never evaluated. `apps.demo`
is `local.demo`, but the check is `demo-crane`. The binaries come from identical inputs. The
wiring (attribute paths, the unchecked derivation's own attrs, the apps' programs) is untested
(C-10).

**What the reports measure and exclude, and whether they reveal the gaps:**

- **`packages.coverage`**: llvm-cov line, region and function coverage of the crane nextest
  run, x86_64-linux, tokens included.
  - It measures execution, not assertion.
  - It excludes: the hardware and cloud suites; everything the VM, module, tpm, examples, demo
    and Nix-evaluation checks run (their binaries are not instrumented); fuzz and Kani; darwin's
    `cfg`s.
  - It never gates.
  - It would show C-1's failure row and C-4's dry-run branch as uncovered. C-4 is covered by the
    VM, so the report understates that one.
  - It cannot show C-6, C-8, C-9 or C-5: a line run by a well-behaved token counts as covered
    whatever the test asserts.
  - It cannot show C-3, C-10 or C-11: a suite that skipped only lowers the number a little, and
    nothing compares it.
- **`packages.mutants`**: core, profile, and camigrate's plan, bundle, file and transport
  modules only. It leaves out cli, cli-common, pkcs11, the providers and caprobe, which is where
  C-1, C-4 and C-6 live. `mutantsOf` reaches them, by hand. Weekly, never gating.
- **`spec-coverage`**: which spec rows some traced PKCS#11 call reached, not which verdicts were
  asserted. The fault suites are untraced. Manual.
- **`.mezura/config.txt`**: line counts of the tree (excluding `profiles/baselines/headers`).
  It is no test measure.
- None of the reports would reveal the two classes that matter most here: weak oracles and
  silent skips.

## Findings (appended per file)

### crates/cli/src (lib.rs, main.rs), crates/cli/examples, crates/cli/Cargo.toml

### C-1. The per-object failure row of the C-7 fix has no test, and the rows have no single shape — medium — verified

`crates/cli/src/lib.rs:496-523`, `:333-345`, `:351-371`, `:665-676`; `crates/cli/tests/common/mod.rs:579-585`
What: `each()` pushes `{object, spec, token, outcome: "failed", exit, error}` when a `lock` or
`delete` pair fails. That row is the whole point of the C-7 fix: "the caller prints every pair's
outcome whatever ended the run". But the rows of one array do not share a shape. A `lock`
success row is the full `Resolved`, with no `outcome` and no `exit`. A `delete` success row has
`outcome` and no `exit`. `create` prints only `done.created`, with no row for the failure at all.
The 2026-11-23 Status says "`import`, `migrate`, `delete` and `lock` print one JSON result per
object (object, spec, token, outcome, method, exit), as `create` does". That is not true of
cakeys' `lock` or `create`, and `delete`'s rows have no `method` or `exit`.
Why missed: T-ABSENT, T-ORACLE, P-UNRUN. `rg '"failed"|\["exit"\]|\["error"\]' crates/*/tests`
finds 0 hits; only camigrate's `dry_run.rs:2246-2250` reads an `outcome`. The C-7 status names
`lock_result` as its test, but `lock_result` asserts exactly one row and is only ever called on
a successful run. So a regression that dropped the failure row, or printed nothing on failure,
fails no test. The row arrived in 6d4beab (344 lines of cli/src/lib.rs, written without a build:
REVIEW-2026-11-23.md Status says "Not yet run"), and that commit's test changes are exit-code
rewrites (0→22).
Class: machine-readable output that is asserted on the success path only. Siblings: `create
--dry-run` rows (`create.rs` reads `action` only), `validate --json` (`offline.rs` checks it
against the text form, which is the same code's other branch: T-TAUTO), and `gc --json`. 4
outputs. Instance fix: a `lock a b` test whose `b` fails; assert both rows' keys and `exit`.
Class fix: one serde `Outcome` row type for every per-object verb of all three tools, with one
test that runs each verb once failing and once passing and checks the row against that type.

### C-2. `verify` outlived the C-3 rename in an example, two docs and the lock model — low — verified

`crates/cli/examples/custom-provider.rs:2`; `docs/CAMIGRATE.md:300`; `docs/PLAN.md:463`; `crates/core/spec/lock.qnt:288`
What: the example's usage line runs `verify <object> --token acme`. That is now a clap usage
error (2). The docs still say "`cakeys verify` accepts it" and "`cakeys verify` is 0".
Why missed: D-PARALLEL, D-DOCS, T-INSTANCE. C-3 removed the verb and fixed the docs it was
pointed at. `nix/doc-references.py` checks function names and paths but never a CLI verb or flag.
Prior C proposal 4 asked for exactly that check and was not done. The example compiles under
clippy but never runs.
Class: CLI words in prose and comments, renamed by hand. Instances: these 4. The flag renames
of the same commit (`--write`→`--write-probes`, `--transport-key`→`--transport-spec`,
`--update-lock`) left none outside the archive.
Instance fix: edit the 4. Class fix: make doc-references parse every `cakeys|caprobe|camigrate
<verb> --flag` in docs, comments and scripts and check it against `command()` (the surface
test's `surface()` already lists the words).

### C-3. C-16's missing-lock rule reached `validate`; the two Nix checks that run `validate` on a lone keys.toml were not updated and now exit 17 — medium — verified (by reading; not run, per the rules)

`checks.nix:208-209` (`profiles`); `nix/examples.nix:81`; `crates/cli/src/lib.rs:290-302`; `crates/cli-common/src/lib.rs:269-274`; `crates/cli/tests/fixtures/gate.lock` (added in 6d4beab)
What: `dispatch` calls `read_lock(.., new_lock=false, ..)` for every verb. A missing default
lock (`<config>.lock`) is therefore 17 for `validate` too. That is the decided C-16 behaviour,
and `nix/test.nix:125-128` asserts it (`validate` → 17, `--new-lock validate` → 0). But two
checks run `validate` on a store copy of a single file, `${./…/gate.toml}` and
`${../examples/yubikey-secureboot.toml}`. Nix copies each file alone to `/nix/store/<hash>-<name>`,
so the default lock beside it never exists:

- `checks.profiles` (every system, `checks-crane-only`, CI `checks-no-vm`) runs
  `expect 15 ${gate.toml}`. That run now gets 17.
- `checks.examples` (Linux) runs `cakeys --config ${yubikey-secureboot.toml} validate | tee`
  under pipefail. That run now gets 17 and fails the build. Its `yubikey-secureboot.lock` sits
  in `examples/` but is not copied.
Both lines date from before 6d4beab (84a4539, 4569a9c) and were not touched by it or by
8aaba2e ("fix review test drift").
Why missed: D-PARALLEL, P-UNRUN, T-TAUTO. The same scenario (gate.toml → 15) is asserted twice:
in `crates/cli/tests/validate.rs` and in `checks.profiles`. Only the cargo test failed on the
darwin gate's `cakeys-crane` run. It was fixed by committing `fixtures/gate.lock` beside the
fixture, so the expectation moved to the code. `gate.toml`'s own header names
`checks.profiles` as a user, and that copy was left behind. 8aaba2e's message lists the drift it
fixed and names no check run. `checks-crane-only`, DEVELOPMENT.md's "after a significant
change" gate, contains `profiles`, so it was not run after 6d4beab.
Class: one behaviour change, with expectations of it in several runners (cargo tests, Nix
`runCommand` checks, the VM test, `nix/demo.sh`, `examples/*/run.sh`) and no single place that
fails first. Here: the `validate.rs` fixture, `test.nix` and `examples/{every-object,secure-boot}/run.sh`
(`--new-lock validate`) were updated, and 2 were missed. `rg -- '--config \$\{' checks.nix nix/` finds no other.
Instance fix: `--new-lock` (or a lock path) in both checks. Class fix: the gate a commit is
written against must be the one CI runs. DEVELOPMENT.md's darwin `checks-crane-only` is that
gate, minus the Linux checks. Make a commit that touches `crates/*/src` and tests without a
recorded `checks-crane-only` run unmergeable: the PR template asks for its store path, and CI
compares it.

### crates/cli/tests (the harness `common/`, and the reference suite and the suites around it)

### C-4. `delete --dry-run` on a matching key is tested only in the Linux VM test; the cargo suites run it once, as a refusal — low — verified

`crates/pkcs11/src/ops/mod.rs:607-610` (the branch); `crates/cli/src/lib.rs:351-371`; `crates/cli/tests/reference/delete.rs:74`; `nix/test.nix:190-191`
What: `delete --dry-run` must identify the object and destroy nothing. The `WouldDelete` return
before `destroy_identified` is all that keeps a dry run from destroying the key. The cargo
suites run `delete --dry-run` once, at `delete.rs:74`, on an object with no expected identity,
where it exits 14 before that branch. The would-delete path runs only in `checks.vm`
(`test.nix:190`, dry delete → 0, then `check` → 0). That check is a KVM VM test: Linux only,
CI's `checks-vm` job, not on the darwin gate, and it does not compare the lock or the `--json`
row.
Why missed: T-GATED, T-ORACLE. `--dry-run` on `delete` arrived in 6d4beab with the VM step and
the refusal assertion. The surface test counts the flag as tested from the refusal (C-5). The
dry-run twin (`xref.rs:174-201`), which proves "a dry run changes nothing" for the lock and the
tokens, runs only for `camigrate`.
Class: a dry run's "changes nothing" checked per test, not as a harness property. In cakeys,
`lock`, `delete`, `gc` and `create` take `--dry-run`. `gc` and `create` are checked in the
cargo suites. `lock --dry-run` is checked only on absent or first-use objects. `delete` is
checked in the VM only.
Instance fix: dry-delete a locked key in `reference/delete.rs`; assert exit 0, the
`would-delete` row, the token's objects and the lock bytes. Class fix: run every cakeys
`--dry-run` through the twin, as camigrate's are: the lock and the named tokens byte-identical.

### C-5. The surface test accepts a refusal or a gated suite as a flag's "use" — low — verified

`crates/cli/tests/common/surface.rs:92-120`; `crates/cli/tests/surface.rs`
What: a flag counts as covered once its spelling appears in any test source, whatever the test
asserts and whether it ever runs. Example: in the cargo suites, `delete --dry-run` is covered
only by a 14 refusal (C-4). DEVELOPMENT.md calls it "a floor, not a measure". But it is the only
automated check of CLI coverage, and the C-4 fix of 2026-11-23 cited it ("Tests: the surface
test") as the test for the new flags.
Why missed: T-ORACLE. The check reads source text, not behaviour.
Class: lints over test sources that stand in for behaviour tests. `harness.rs` holds 5 more
(`no_opted_in_suite_skips_an_unpatched_build`, `the_harness_helpers_are_written_once`,
`every_test_with_its_own_fault_shim_runs_untraced`,
`every_hardware_suite_opts_in_through_the_harness`, and the surface test itself). They are
useful, but each needs its own list of patterns, and C-7 shows the opt-in lint already missing
cases.
Instance fix: none needed. Class fix: measure flag coverage by behaviour. Run the coverage
build (`packages.coverage`) with clap's matched flags logged (`CAKEYS_TRACE_ARGS`), and fail
when a flag is only ever matched on runs that exit 2 or 17.

### C-6. The lying-module table covers `check`, `lock` and `create` of five private keys; no lie reaches `delete`, a secret key, a certificate or a data object — medium — verified

`crates/cli/tests/fault.rs:206-305`; `crates/pkcs11/src/token/generate.rs:203-245`; `crates/pkcs11/src/ops/mod.rs:587-616`
What: `a_lying_module_is_refused` is the workspace's best oracle: 26 lies, each asserting the
exit code, the reason, that the rule fired, and that the lock is unchanged. But every case is
`check`, `lock` or `create` on keys `k`, `d`, `r`, `u` or `a` (EC and RSA private keys). Not
covered:

- `delete`, the one destructive verb. The generic provider's `destroy` trusts
  `C_DestroyObject`'s CKR_OK and does not look again. A module that says OK and keeps the key
  gets "destroyed 1 object(s)", and its realisation is removed from the lock: the lock forgets a
  key that still exists. Only the ykcs11 provider checks again. That path is tested only on a
  real YubiKey (`yubikey.rs`, opt-in).
- The commitments of secret keys (cmac, kcv-ecb, kw, HMAC), where a lying `C_Sign` or
  `C_Encrypt` decides the identity.
- Certificates, data objects and both attestation verifiers.
The `C_DestroyObject` rule in the suite (`fault.rs:422`) is about undoing a failed creation,
not about `delete`.
Why missed: T-FRIENDLY, T-GATED. The table grew from the private-key proofs (review fault.rs F1
and B-tests). Only the reported paths got rows; the hardware suite stands in for the "delete
leaves the key" case.
Class: hostile-module coverage follows past findings rather than the verb × class matrix. Of 7
verbs × 4 classes, 3 verbs × 1 class have lies (about 11%).
Instance fix: rows for `delete` (`C_DestroyObject` OK without destroying; `C_FindObjects`
adding a second match between identify and destroy), a lying `C_SignInit` on an HMAC key, and a
substituted `CKA_VALUE` on a certificate. Class fix: generate the lie table as verbs × classes ×
{fail, lie about attribute, substitute key}, each cell an expected exit or an explicit "n/a, why".
Then a missing cell is visible the same way a missing flag is in the surface test.

### C-7. Four opt-ins bypass the harness's all-or-none rule, so a run that asked for them can pass having run nothing — low — verified

`crates/cli/tests/ftpm.rs:96-100`, `:141-148`; `crates/caprobe/tests/yubikey.rs:61-64`; `crates/cli/tests/cloud.rs:64-74`; `crates/cli/tests/harness.rs` (`every_hardware_suite_opts_in_through_the_harness`)
What:

- `CAKEYS_FTPM_ATTEST` and `CAKEYS_FTPM_EK_CERTIFICATE` are read directly: `=true`, or the
  certificate without `ATTEST=1`, skips 2 attestation tests silently, even under
  `CAKEYS_FTPM_REQUIRE`.
- caprobe's `the_read_only_probe_conforms` reads `CAKEYS_TEST_YUBIKEY_MODULE` itself and ignores
  `CAKEYS_YUBIKEY_REQUIRE`.
- cloud.rs has no require variable, and it returns early inside a Nix build even when
  `CAKEYS_TEST_AWS` is set.
The lint that is meant to stop this checks only the four variables in `FTPM_OPT_IN.vars` and
`YUBIKEY_OPT_IN.vars`.
Why missed: T-INSTANCE, T-GATED. Review ftpm.rs F2 (an opt-in that passed having run nothing)
was fixed by `OptIn`/`opted_in` for the suites' primary variables, plus a lint over that same
list.
Class: 5 tests in 4 files. Instance fix: give each its own `OptIn` with its require variable.
Class fix: make the lint flag every `std::env::var("CAKEYS_` read in a test outside `common/`
(the harness already bans module reads this way).

### C-8. The golden tables are the oracle for the matrix, conformance and coverage tests; the code under test generates them, and the hardware and TPM ones were edited by hand where nothing could regenerate them — medium — verified

`spec-coverage/objects/*.toml`; `profiles/modules/**`; `spec-coverage/cakeys.toml`; `crates/cli/tests/object_matrix/mod.rs:817-833`; `crates/cli/tests/common/mod.rs:550-572`
What: `object_matrix_is_the_committed_one` (×3 tokens), `assert_profile_conforms` (every
reference) and the coverage file compare a run with a committed file. That file is produced by
the same code (`CAKEYS_UPDATE_OBJECTS`, `caprobe probe --diff --out`). Each file's header says
"never by hand". Two problems follow.

1. These tests detect change, not error. 36 of the 47 commits that touched these files also
   changed `crates/*/src` in the same commit, so the expectation moved with the code. The tables
   cannot catch a bug introduced in the commit that regenerated them. The gate's own tests
   (`validate.rs`: "probed 1, 16, 32 … bytes only", "softhsm/2.7: not advertised") then assert
   decisions derived from those generated profiles.
2. The review fixes changed the tables where the gate could not generate them. fcaa6aa
   rewrote `tpm2-pkcs11+swtpm.toml` rows (15→17), and 61b7000 edited the hardware and cloud
   profiles: `aws-cloudhsm` FIPS/non-FIPS, `ykcs11/2.7`, `tpm2-pkcs11/1.10+amd-ftpm`, `kmsp11`
   (evidence strings, `kcv-ecb-decrypt`→`kcv-ecb-dec`, `Max(16)`→`16`). That was on a darwin
   gate that builds neither tpm2 nor any hardware suite (REVIEW-2026-11-23 Status: "[linux] … not
   run on the branch's darwin gate", "[hw] needs the hardware"). The hardware profiles'
   conformance tests are opt-in, so no automated runner will ever compare those hand edits with
   a probe.
Why missed: T-TAUTO, T-GATED, P-UNRUN.
Class: snapshot oracles. 9 module profiles, 3 object tables, 5 baselines and the coverage file:
18 files. 6 of them (the hardware and cloud profiles) have no automated regeneration check.
Even the SoftHSM and kryoptic profiles cannot be regenerated on the darwin gate, because
`scripts/regen-profiles.sh:28` requires a tpm2-pkcs11 module (C-12). There, every profile
change is a hand edit.
Instance fix: re-probe amd-ftpm, ykcs11, aws-cloudhsm and kmsp11, or mark the hand-edited rows
`unverified`. Class fix: keep golden files as change detectors, but put in front of each one a
small set of hand-written property assertions, independent of the generator. Example: "an EC
key with `CKA_ALLOWED_MECHANISMS = [CKM_ECDH1_DERIVE]` and `CKA_SIGN` is 17 because of A-10".
Refuse a commit that changes a table whose generator its gate cannot run, unless it carries a
`[hand-edited]` marker that the gate checks.

### C-9. Most of the suite's assertions are about exit codes and stderr prose, not about state — medium — verified

`crates/cli/tests/**` (counts by a script over the 131 test functions of `reference/`, `fault.rs`, `p11kit.rs`, `references.rs`, `tpm2.rs`, `ftpm.rs`, `yubikey.rs`, `offline.rs`, `validate.rs`)
What: in those test bodies, 494 exit-code checks and 541 stderr/stdout `contains` checks stand
against 160 reads of the lock, 114 token-state reads and 61 independent oracles (`sri`,
`oracle_spki`, `aes_commitment`, openssl, the pinned certificate hashes). 39 of the 131 tests
assert only exit codes and prose. Among them: `binding_downgrade_is_refused`,
`s3_an_unrecorded_token_is_a_precondition_failure`, `s4_a_public_only_flip_is_a_spec_change`,
`tpm2_a_secret_keys_attestation_is_bound_to_its_material`,
`tpm2_attestation_refuses_a_store_that_disagrees`, and 7 of fault.rs's 14. For a refusal, the
exit code and the reason are the right oracle. But C-1 (a result row never parsed), C-4 (a dry
run never checked against the token) and the lock-unchanged checks missing from most refusal
tests (only fault.rs's lie table and lockfile.rs compare the lock bytes) show the gap.
Why missed: T-ORACLE. The harness's helpers (`Workdir::code`, `stderr`, `got_hash`) make the
exit-and-prose assertion the cheapest one to write. No helper asserts "nothing changed": the
camigrate twin's `state()` is the only one, and it is private to `xref.rs`.
Class: oracle choice driven by helper convenience. 39 of 131 tests.
Instance fix: none per test. Class fix: a `Workdir::refused(args, code, why)` helper that also
snapshots the lock and the token's objects (the twin's `state()`, moved to `common/`) and
asserts both are unchanged. Every refusal test then gets the state oracle for free.

### Nix (flake.nix, checks.nix, apps.nix, pkgs.nix, nix/*), CI workflows, scripts/, examples/

### C-10. What users get is not what any check builds or tests: `packages.default`, the module's default package and the apps are a separate derivation no runner builds, and every module test overrides the default — medium — verified

`pkgs.nix:22-24`; `nix/package-crane.nix:206-226`; `flake.nix:95-100`, `:123`; `checks.nix:17-18`, `:389`; `nix/test.nix:84`; `nix/module-test.nix:79`; `nix/tpm-test.nix:48`; `nix/examples.nix:22`; `apps.nix:22-38`; `docs/DEVELOPMENT.md:35-36`
What: the 2026-11-23 C-8 fix made `packages.cakeys` (also `default`, `caprobe`, `camigrate`,
`p11-fault`) `cakeys-crane.unchecked`. That is a second `craneLib.buildPackage` with
`doCheck = false` and its own store path, written by hand next to the checked one
(`common.args // base // {…}`, plus its own `passthru.patchedCryptoki`).

- No check and no CI job builds it. CI builds `checks-no-vm`, `checks-vm` and `kani`
  (`checks.ci-jobs` pins exactly those). `checks.cakeys` is the checked derivation, and
  `nix flake check --no-build` evaluates x86_64-linux only.
- The NixOS module's `services.cakeys.package = mkDefault self.packages.<system>.cakeys` is never
  even evaluated. All 5 module evaluations (`test.nix`, `module-test.nix`, `tpm-test.nix`,
  `examples.nix`'s tls system, `checks.module-assertions`) set `services.cakeys.package = cakeys`
  (crane), so the `mkDefault` loses and is never forced.
- `apps.demo` runs `local.demo` (on the unchecked build); `checks.demo` runs `demo-crane`.
  `apps.caprobe`/`camigrate` are the unchecked outputs.
- The comments claim the opposite. `pkgs.nix:22`: "the build every check and CI job builds".
  `package-crane.nix:209`: "what users run is what every check and CI job builds". And
  DEVELOPMENT.md:35 still says "Both builds (the checks' crane build and `packages.cakeys`) run
  the tests".
The binaries should be equal, since the inputs are the same. What no runner sees is the wiring:
the attribute the module defaults to, the unchecked derivation's own attrs and passthru (which
`scripts/local-tests.sh` evaluates), and the apps' programs.
Why missed: D-SEAM, D-DOCS, T-GATED, P-REVIEW. The tests pin the package explicitly, so the
default under test is never the default users get. The C-8 fix renamed which derivation is
shipped, but no check was added that builds or evaluates the shipped one.
Class: tests that override the default they exist to check. 5 of 5 module evaluations; 1 of 1
demo; 4 apps.
Instance fix: add `packages.default` to `checks-no-vm`. It shares crane's artifacts, so it costs
one link step. Add a `module-default` assertion that evaluates `nixosModules.default` without
setting `package` and compares it with `self.packages.<system>.default`. Class fix: let checks
consume only public outputs: `self.packages.*`, `self.nixosModules.default` unmodified,
`self.apps.*`. Make the checked build a test derivation over the shipped one: crane's
`cargoNextest` on `packages.cakeys`'s artifacts. Then "shipped = tested" is structural, not a
comment.

### C-11. A fault suite that is not routed runs nothing and passes: the require variable is set in the same `case` arm as the module it guards — medium — verified

`nix/test-tokens.sh:79-83`; `crates/cli/tests/fault.rs` (via `suite_var`); `crates/caprobe/tests/fault.rs:17`; `crates/camigrate/tests/fault.rs:23`
What: the three crates' `fault` binaries (14 + 7 + 6 tests, plus the 75-test reference suite
through p11-fault) run only when `P11_FAULT_MODULE` is set. They fail on its absence only when
`CAKEYS_FAULT_REQUIRE` is set. `test-tokens.sh` sets both in one place:
`if [ "$suite" = fault ]`, where `suite` is the binary name less cargo's hash. Rename a binary, or
change how nextest names it, and both variables vanish together. All of the workspace's
hostile-module tests then skip, and the check is green. The other suites do not have this
problem: `test_env` exports their `*_REQUIRE` globally, so a suite left out of the p11-kit or TPM
lists fails (DEVELOPMENT.md: "a suite the runner's lists leave out fails").
More generally, no runner counts what ran. A skip returns early and passes. nextest's summary is
not compared to anything. A test binary compiled out by `required-features` (`tpm2`, `ftpm`,
`yubikey` in cli and caprobe; all of `tpm2` on darwin) leaves no trace.
Conditional skips with no require variable at all:

- `lockfile.rs:350/365/415`, when run as root;
- `matrix.rs:13`, under the shim;
- `adoption.rs:246`, kryoptic RSA-768, by design;
- `ftpm.rs:96/141` and `caprobe/tests/yubikey.rs:61` (C-7);
- `cloud.rs` (C-7);
- `dry_run.rs:42/1527`, when the kryoptic references are absent (guarded indirectly by
  `CAKEYS_KRYOPTIC_REQUIRE`).
Why missed: T-GATED, D-SEAM. The `*_REQUIRE` design checks "module missing", not "suite not
started". The runner was designed for the token suites, and the fault routing is a name match
inside it.
Class: 1 suite family whose guard and subject are set together. 10 conditional skips without a
require variable.
Instance fix: export `CAKEYS_FAULT_REQUIRE=1` from `test_env` with the others, and let
`suite_var` read `P11_FAULT_MODULE` from a variable the fault binary derives itself (the shim
sits beside the binary). Class fix: every skip goes through one harness function. That function
appends `suite/test: why` to `$CAKEYS_SKIP_LOG`, and the check phase fails on any line not in a
committed allow-list (the same shape as the surface test's `untested`). Commit `nextest list`'s
per-binary counts as well, so that a binary that loses its tests fails.

### C-12. The fast token run and the profile regeneration are Linux-only; the gate the work is done on is darwin — low — verified

`scripts/local-tests.sh:27-28`, `:113-115`; `scripts/regen-profiles.sh:28`; `flake.nix:165`; `docs/DEVELOPMENT.md:44-48`
What: `local-tests.sh`, which DEVELOPMENT.md calls "the quickest way to test a change to token
behaviour", cannot run on darwin:

- It builds `.#tpm2-pkcs11-vendor.out`, a Linux-only flake output, and `nixpkgs#tpm2-pkcs11.out`.
- It names `libkryoptic_pkcs11.so` (darwin: `.dylib`).
- It always passes the TPM modules to `test_env`.
On darwin the `nix build` inside `mapfile < <(…)` fails unseen (a process substitution's status
is not checked), and the script then stops at `path_of`'s "no softhsm-unwrap-value-len among"
an empty list. `coverage-file.sh` and `coverage-full.sh` run through it. `regen-profiles.sh`
requires `TPM2_PKCS11_MODULE` (`:?`, line 28). So on the darwin gate there is no per-test token run
other than the full `nix build .#cakeys-crane`, and no profile, SoftHSM's included, can be
regenerated: only hand-edited (C-8). REVIEW-2026-11-23's Status says the [linux] items "were not
run on the branch's darwin gate". CI is x86_64-linux only, so darwin (a `meta.platforms` entry
and the dev platform) is built nowhere but the developer's machine.
Why missed: D-DOCS, T-GATED. DEVELOPMENT.md documents neither restriction.
Class: 4 scripts are Linux-only. 5 checks are Linux-only (vm, module, tpm, examples, fuzz), and
kani is x86_64-linux only. darwin is in no CI job.
Instance fix: pass the TPM arguments only on Linux, use the platform's library extension, and
check the `nix build` status. Class fix: add a `macos-latest` CI job running
`.#checks-crane-only` (the dev gate), and make CI green (both platforms) a merge requirement.
Then a [linux] item cannot be merged unrun.

### C-13. Facts copied by hand into scripts and docs drifted with the decisions batch — low — verified

`nix/demo.sh:32-37`; `scripts/regen-profiles.sh:14`; `docs/DEVELOPMENT.md:35`; `crates/cli/tests/reference/delete.rs:112` (and its 5 `--apply` comments)
What:

- `demo.sh`'s `meaning` table lists exits 0 and 10-18 and 22. It has no 1, 2, 19, 20 or 21,
  although 21 is now every refusal inside a Nix build, and the demo check runs inside one.
- `regen-profiles.sh` tells the reader to build `packages.x86_64-linux.cakeys.overrideAttrs
  { doCheck = false; }`, which is what `packages.cakeys` now is.
- DEVELOPMENT.md:35 says `packages.cakeys` runs the tests (C-10).
- `delete.rs:112` loops over `[&["gc"], &["gc"]]`, the same run twice, where it was `gc` and
  `gc --apply` before the rename. Its comments still say `--apply`.
Why missed: D-PARALLEL. None of these is a test oracle except the `gc` loop, which now tests
half of what it says.
Class: copies of the exit-code table and the CLI words outside the code: 4 here, C-2's 4
elsewhere. Instance fix: edit them. Class fix: as C-2. `demo.sh` reads its table from
`cakeys --help`'s rendered `EXIT_CODES`, and doc-references checks CLI words and `--flags`.

## Unguarded decisions (appended per file, from mutation testing)

**crates/cli/src/lib.rs**

- `:352` — `--if-match` with more than one pair is 17. No failing test: `delete.rs` always names one spec.
- `:534-542` — `validate`: an unknown named provider is 17. No failing test: `rg 'unknown provider' crates/*/tests` finds 0 hits. The same holds at token open, `pkcs11/src/registry.rs:76-87`.
- `:360` — `delete --dry-run` opens `Access::Read`. No failing test: no reference token is write-protected, so `Access::Write` passes every test.
- `:305` — only `create` recalls the lock's observation. No failing test if `check` or `lock` also recalled it: `a_tokens_own_answers_decide_before_its_profile` exercises create only (plausible).
- `:512-518` — the failure row (C-1).
- `:251` — `plain()` refuses `<object>.id.<scheme>` outside `check`. An equivalent mutant: without it the name is an unknown object, also 17. `validate.rs:218` asserts the code only.

**crates/cli-common/src/lib.rs**

- `:52-57` — the "profiles added from profileDirs" note. No cakeys test sets `profileDirs`; caprobe's `supports.rs` does.
- `:362-369` — `a_missing_lock_is_refused_unless_a_new_one_is_asked_for` returns early inside a Nix build (added in 8aaba2e after the unrun 6d4beab failed there). So in `nix flake check` its writing half (guard, `save_changed`, `main`→22) never runs. The 22 mapping is still covered by integration tests.

**crates/cli/tests/common (the harness)**

- `mod.rs:173` — `required_var`'s assertion that a missing module fails when its `*_REQUIRE` is set. This is the one guard between "token missing" and "suite silently green" in every Nix check. No failing test if it were deleted: `harness.rs` tests `opt_in` and `needs_in`, never `required_var` or `suite_var`.
- `nix/token-env.sh:46-60` with `mod.rs:173` — each `*_REQUIRE=1` is exported by the same `test_env` call that sets up the tokens. A `preCheck` that stopped calling it would set neither the modules nor the require variables, and every token suite would skip and pass. Nothing checks that the require variables are set where they are expected (see the matrix).
- `xref.rs:241-254` — the twin compares what `pkcs11-tool --list-objects` prints: label, ID, usage, access flags. A dry run that changed `CKA_TRUSTED`, `CKA_WRAP_WITH_TRUSTED`, `CKA_MODIFIABLE`/`CKA_DESTROYABLE` or a data object's value passes. `enforced` moves use `CKA_TRUSTED` keys (plausible).
- `xref.rs:147-149` — the twin lets a dry-run 0 be followed by a real 16 when stderr contains the prose "damaged or altered bundle".
- `xref.rs:176` — the twin runs for `camigrate` only (C-4).
- `mod.rs:387-390` — `failed_login` finds a failed YubiKey login by the text `CKR_PIN_`; `fault.rs:117-120` holds cakeys to printing it. caprobe and camigrate login failures have no such test (plausible).

**crates/cli/tests (suites)**

- `reference/matrix.rs:12-15` — the object matrix skips under the fault shim with no require variable (by design: SoftHSM's table is checked directly).
- `reference/lockfile.rs:350`, `:365`, `:415` — the read-only-lock, read-only-directory and unreadable-lock cases skip when the user can write anyway (root). No require variable. They run in the Nix sandbox (nixbld) and are skipped wherever the suite runs as root.

**Nix**

- `nix/lib.nix:87` — `featuresOf`: a token's `nix.systemFeature` overrides `<featurePrefix><t>`. No failing test: `checks.lib` asserts only the default (`token-softhsm`). The fixture's `yubikey` override (`keys.toml:8`) is never asserted, and `featurePrefix` (lib and module) is set by no test (module option scan: 0 of 5 evaluations).
- `nix/lib.nix:180-187` — the `--module <t>=<p>` words from `modules`. `checks.lib` asserts nothing about them. Only the Linux VM consumer (`test.nix:45-59`) runs a `check` that needs them.
- `nix/module.nix:310-315` — `sandbox.tpm2`'s "id-count is a multiple of 65536" assertion. Not in `checks.module-assertions`.
- `nix/module.nix:43-48` — `valuePin` recognises `--uri-pin value` and `--uri-pin=value`. Both are asserted, but an abbreviation or a `checkArgs`-style split through `args` is not. Clap takes no abbreviations, so this is equivalent today (plausible).
- `nix/module-test.nix:239` — `machine.fail(resolve …)` after `delete` accepts any nonzero exit (11 expected).
- `nix/sandbox-hook.sh:35-39` — a map entry whose source does not exist is dropped, with a note. No test: module-test's grants all exist (plausible).
- `flake.nix:99` — the module's `mkDefault` package: never evaluated (C-10).
- `nix/test-tokens.sh:79-83` — the fault routing by binary name (C-11).
- `checks.nix:208-209`, `nix/examples.nix:81` — `validate` on a lone store copy (C-3).

**scripts/**

- `scripts/local-tests.sh:27` — `mapfile < <(nix build …)`: the build's status is never checked (C-12).
- `scripts/yubikey-empty-slots.py:22` — only slots 82-84 are compared before and after. 9a/9c/9d/9e, the PIV slots a user is most likely to depend on, are not. The script never addresses them, so this guards against a yubikit slot-mapping bug only (plausible).

**examples/**

- `examples/lib.sh:26-44` — every step's oracle is its exit code. Outputs are asserted only in `inject/run.sh` (the URI, `openssl req -verify`) and in the TLS and secure-boot signature checks.

## Prior fixes re-checked (prior ID — holds / instance only / wrong / regressed)

- C-3 (`verify` gone): **instance only**. The verb is gone from the CLI and the docs it was pointed at; 4 references remain (C-2).
- C-4 (no-op flags): **holds** for cakeys. `--update-lock` is gone, and `lockfile.rs` asserts it is a usage error (2).
- C-7 (notes stream; a result per object): **partly**. Notes stream (`Notes::streaming`). The per-object result rows are untested, and differ per verb (C-1).
- C-10 (one exit-code table): **holds**. `with_exit_codes` + `the_help_carries_every_exit_code`.
- C-16 (a missing `--lock` is 17): **holds** on cakeys and camigrate, both through `read_lock`. `validate` included, by decision; the VM test asserts it. Two Nix checks were not updated and fail (C-3): **regressed** for those checks.
- C-5 (one flag scheme): **holds** across the three tools. `-c`, `-l` and `--module` are top-level options, accepted before the verb only; `--new-lock` and `--json` are clap-global. CAMIGRATE.md:30 calls all five "global". Nothing in the docs or scripts uses the other order, so this is asymmetric but consistent.
- C-8 (shipped package = what CI builds): **partly**. The shipped package is now the crane build without its tests, so first use runs no suite. But it is a sibling derivation that no check or CI job builds, the module's default is never evaluated, and the comments claim otherwise (C-10).
- C-9 (host-wide grants): **holds**. Option descriptions say so; the pcscd warning is asserted in `checks.module-assertions`.
- C-11 (`--write` → `--write-probes`): **holds** (the surface test lists it).
- C-12 (21 inside a Nix build): **holds** for cakeys (`read_lock`: `writes && lock_unwritable`; `lockfile.rs` asserts 21).
- C-19 (test variables written twice): **holds**. `test_env` is called by `preCheck` and `local-tests.sh`. But the fault suites' variables are still set in a third place, `test-tokens.sh` (C-11).

## Cross-area notes (one line each)

- B: the generic provider's `destroy` trusts `C_DestroyObject`'s CKR_OK; only ykcs11 checks again, and only on a device (C-6).
- D: camigrate's `--json` rows carry `outcome`, `method` and `exit`; cakeys' `lock` and `create` rows do not. One row type for all three tools (C-1).
- D: the dry-run twin (`cli/tests/common/xref.rs`) runs for camigrate only; cakeys' four `--dry-run` verbs do not use it (C-4).
- A: `crates/core/spec/lock.qnt:288` still says `cakeys verify` (C-2).
- A/B: `profiles/modules/{ykcs11,aws-cloudhsm,kmsp11,tpm2-pkcs11/1.10+amd-ftpm}` were edited by hand in 61b7000; no runner can re-probe them (C-8).
- All: the CLI surface is consistent across the three tools. The same `EXIT_CODES` table is shown in `--help` and mapped by `cli-common::main`. `--new-lock` and `--json` are global, but `--config`, `--lock` and `--module` must come before the verb in all three. caprobe parses through its own `try_get_matches_from` + `with_config` path, not `cli-common::parse`, with the same exit codes.
- All: no CI job runs on darwin, the platform the work is gated on (C-12).

## Files reviewed (every file in scope: clean | finding IDs | unguarded count)

**crates/cli, crates/cli-common**

- `crates/cli/src/lib.rs`: C-1, C-3 | 6 unguarded
- `crates/cli/src/main.rs`: clean
- `crates/cli/examples/custom-provider.rs`: C-2
- `crates/cli/Cargo.toml`: clean (`[[test]] required-features` keeps `tpm2`/`ftpm`/`yubikey` out of a build without the feature; see the matrix)
- `crates/cli-common/src/lib.rs`: C-3 | 2 unguarded (the sidecar guard is tested: `update_lock_waits_for_the_sidecar_lock`)
- `crates/cli-common/Cargo.toml`: clean

**crates/cli/tests**

- `common/mod.rs`: C-7, C-9 | 2 unguarded
- `common/surface.rs`: C-5
- `common/xref.rs`: C-4 | 3 unguarded
- `harness.rs`: C-5, C-7 (the lints and their lists)
- `surface.rs`: C-5
- `softhsm.rs`, `kryoptic.rs`: clean (include the reference suite)
- `reference/mod.rs`: clean
- `reference/adoption.rs`: clean (pinned openssl hashes: independent oracle)
- `reference/check.rs`: clean (PEM key file verified with openssl alone)
- `reference/create.rs`: C-9
- `reference/delete.rs`: C-4; stale `--apply` in 5 comments, and the loop at `:112` now runs `gc` twice (it was `gc`, `gc --apply`) — C-13
- `reference/drift.rs`: C-9 (`s3_…`, `s4_…` exit-only)
- `reference/identity.rs`: clean (host oracles throughout)
- `reference/lockfile.rs`: clean | 1 unguarded (root skips)
- `reference/matrix.rs`: C-8 | 1 unguarded
- `reference/proofs.rs`: C-9 (`binding_downgrade_is_refused` exit-only)
- `reference/tokens.rs`: C-9
- `reference/validate.rs`: C-9
- `object_matrix/mod.rs`: C-8
- `fault.rs`: C-6, C-9
- `references.rs`: clean (host oracle for every scheme)
- `p11kit.rs`: clean
- `tpm2.rs`: C-8 (its object table), C-9 (8 of 21 exit/prose-only)
- `ftpm.rs`: C-7
- `yubikey.rs`: clean (hardware-only; see the matrix)
- `cloud.rs`: C-7
- `offline.rs`: C-1 (`validate --json` checked against the text form)
- `validate.rs`: C-3 (the `gate.lock` fixture), C-8 (decisions read off generated profiles)
- `fixtures/*` (19 files): clean. `keys.lock` is a synthetic, hand-written fixture and says so; the certificate hashes are openssl's. `gate.lock` see C-3.

**Nix, CI**

- `flake.nix`: C-10, C-12 (CI x86_64-linux only) | 1 unguarded
- `checks.nix`: C-3 (`profiles`), C-10 | 1 unguarded
- `apps.nix`: C-10 (apps from the unchecked build)
- `pkgs.nix`: C-10
- `treefmt.nix`: clean (shellcheck on; examples' run.sh are sourced scripts without a shebang, and shellcheck covers them through `.sh`)
- `nix/lib.nix`: clean | 2 unguarded (the shell quoting, version, missing-lock and `--new-lock` decisions are all asserted in `checks.lib`)
- `nix/module.nix`: clean | 2 unguarded (`writeOutput` is atomic under errexit; module-test covers grant, gate, mode, removal)
- `nix/module-test.nix`: clean | 1 unguarded
- `nix/test.nix`: clean. It is the only test of `delete --dry-run`'s would-delete path (C-4) and of `validate` without a lock.
- `nix/tpm-test.nix`, `nix/vm-common.nix`: clean
- `nix/examples.nix`: C-3 | 1 unguarded
- `nix/demo.nix`: C-10 (apps.demo vs checks.demo); `nix/demo.sh`: C-13
- `nix/package-crane.nix`: C-10
- `nix/package-common.nix`: clean (preCheck → `test_env`; `withTpm2 = isLinux`)
- `nix/test-tokens.sh`: C-11 | 1 unguarded
- `nix/token-env.sh`: C-11 (the require variables live here, not with the fault routing)
- `nix/p11kit-test-env.sh`, `nix/tpm2-test-env.sh`, `nix/ftpm-test-env.sh`: clean (`/proc` zombie check is Linux-only, but so are the TPM scripts; p11kit's `alive` falls back to `kill -0` on darwin)
- `nix/sandbox-hook.sh`: clean | 1 unguarded (always exits 0; reads paths only from the map)
- `nix/doc-references.py`: C-2 (checks fn names of 4+ words and paths; no CLI words)
- `nix/fuzz.nix`, `nix/kani.nix`, `nix/deny.nix`: clean (area A owns the targets)
- `nix/mezura.nix`: clean (line counts; `.mezura/config.txt` excludes vendored headers)
- `nix/pkcs11-check.nix`, `nix/softhsm-unwrap-value-len.nix`, `nix/tpm2-pkcs11-vendor.nix`, `nix/kmsp11.nix`, `nix/cloudhsm.nix`, `nix/cloud-tools.nix`, `nix/pcsc-probe.nix`, `nix/pcsc-sandbox-probe.nix`: clean (packaging; skimmed)
- `.github/workflows/checks.yml`: C-12 (no darwin job)
- `.github/workflows/reports.yml`: clean (reports never gate; see the matrix)
- `.config/nextest.toml`: clean

**scripts/**

- `local-tests.sh`: C-12 | 1 unguarded
- `coverage-full.sh`: clean (hardware passes get their `*_REQUIRE`; TPM handles and lockout compared). Runs on local-tests, so C-12 applies.
- `coverage-file.sh`: C-12 (through local-tests)
- `regen-profiles.sh`: C-8, C-12, C-13
- `badges.sh`: clean
- `xversion.sh`, `pkcs11-check.sh`, `pkcs11-check-compare.py`: clean (manual tools; test PINs only)
- `yubikey-empty-slots.py`: clean | 1 unguarded
- `cloud/aws.sh`, `cloud/gcp.sh`, `cloud/aws/*`, `cloud/gcp/*`: clean (skimmed; they never set `CAKEYS_TEST_AWS`/`GCP`, so cloud.rs is run by hand only: C-7)

**examples/**

- `lib.sh`: clean | 1 unguarded
- `every-object/run.sh`, `programs/run.sh`, `secure-boot/run.sh`, `tls/run.sh`, `inject/run.sh`: clean (updated to `--new-lock` for C-16)
- `inject/unotify-inject`: clean (its README-level caveats are stated: "the filter is no sandbox")
- `secure-boot/sign.nix`: clean. It takes `cakeys = self` and so uses the unchecked package; evaluated only (C-10).
- `tls/configuration.nix`: clean
- `yubikey-secureboot.toml`: C-3 (its `validate` in checks.examples has no lock); `yubikey-secureboot.lock`: clean
- `README.md`, `*/keys.toml`, `programs/sign.py`: clean
- `crates/cli/tests/fixtures/`, each file: `adopt-cert{,-ed25519,-p384}.der`, `matrix-ed25519{.pem,-cert.der}`, `tpm-import-{p256,rsa2048}{.pem,-cert.der}`: clean (inputs; the hashes they are checked against are openssl's). `keys.toml`/`keys.lock`, `odd-names.toml`, `p256-alias.toml`, `from-file.toml`, `version-99.lock`, `empty.lock`: clean (hand-written, used by `checks.lib` and the suites). `gate.toml`/`gate.lock`: C-3.
- `nix/patches/cryptoki-*.patch` (4), `nix/kani/library-Cargo.lock`, `nix/kmsp11-release-key.pem`, `nix/pcsc-probe.c`: listed, not reviewed in depth (cryptoki semantics are area B's; the others are pinned inputs)
- `scripts/cloud/{aws,gcp}/{main.tf,cakeys.toml,.gitignore}`: clean (skimmed)
