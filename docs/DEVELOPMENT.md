# Development

How to build, test and change cakeys, and the rules that protect the hardware attached to the
development machine.

## Environment and the checks

Development happens on NixOS or on macOS with Determinate Nix. Neither provides a usable system
`cargo` or `python3`: macOS's `python3` lacks `tomllib`, so run the repository's scripts through
`nix develop -c`.

- Build and test with `nix develop -c cargo …`; any other tool with `nix shell nixpkgs#<name> -c …`.
  Use `rg`, not `grep`; shell scripts start with `#!/usr/bin/env bash`.
- Format with `nix fmt -- --no-cache` (the cache has missed files before).
- **Per change:** `nix develop -c cargo clippy --workspace --all-targets -- -D warnings` and the
  unit tests. Clippy is pedantic: a function that can panic needs a `# Panics` section, and
  exemptions are per-site `#[expect(lint, reason = "…")]`.
- **After a significant change:** `nix build .#checks-crane-only`, every check except the fuzz
  smoke run, on the crane build (its dependencies cached per `Cargo.lock`).
- **At the end of a piece of work:** the tiers below. T0 must pass, and T1 and T2 are run or
  recorded as not run.
- **CI** (GitHub Actions, on pushes to `main` and pull requests, x86_64 Linux):
  `.github/workflows/checks.yml` builds every check once, over three runners: `.#checks-no-vm`
  (every check but the VM tests, the fuzz run and Kani) after `nix flake check --no-build`,
  `.#checks-vm` (the VM tests and the fuzz run) on a runner with KVM, and Kani on its own. The
  split is one list in flake.nix (`vmChecks`), and `checks.ci-jobs` holds the workflow to it.
  The jobs run Determinate Nix (determinate-nix-action, pinned) with the Magic Nix Cache.
  `.github/workflows/reports.yml` builds `packages.coverage` on each push to `main`, and
  `.github/workflows/mutants.yml` runs the mutation gate (each pull request's diff, the week's
  changes, and a monthly sweep of every mutant); each pushes its number (`scripts/badges.sh`:
  lines covered; mutants caught of the viable ones, from the sweep) to the `badges` branch,
  which the README's badges read. The builds run with a read-only token; only a separate
  publish job per report, which runs no repository code, may push.
- The token suites (SoftHSM, kryoptic, p11-kit, swtpm) run only in the Nix build's check phase
  and `scripts/local-tests.sh`; under plain `cargo test` they skip. Run with tokens configured
  but in one process (plain `cargo test`), they share one token set and do not pass: the token
  suites need a token set per test, which only the per-test runner gives (OPEN.md,
  "Engineering"). A change to token behaviour is not tested until a Nix check has run.
- The checks' crane build (`packages.cakeys-crane`; `packages.cakeys` is it without the check
  phase) runs the tests under `cargo-nextest`, one process per test, each through `nix/test-tokens.sh`: a SoftHSM token and
  a kryoptic database of its own (copies of templates), and for the suites that use them its own
  `p11-kit server` and swtpm; there is no shared server or swtpm, so a suite the runner's lists
  leave out fails rather than sharing one. The tokens are set up by one script,
  `nix/token-env.sh`, which the check phase, the runner, `scripts/local-tests.sh` and the
  profile, demo and example scripts all source. So the tests run in parallel (268 tests in about 40 s; the
  camigrate suite alone took 130 s on one thread) and none depends on what another left on a
  token. `nix build .#cakeys-crane` is that run alone.
- `scripts/local-tests.sh [nextest arguments]` is the same run outside Nix, seconds per test:
  the quickest way to test a change to token behaviour. It builds against the patched cryptoki
  (the patches `nix/package-common.nix` lists, applied under `target/local-tests/`, in a copy of
  the tree so `Cargo.lock` stays as it is), refuses to run when cryptoki does not resolve to
  that copy, and requires every reference token, so nothing skips but the hardware and cloud
  suites (`CAKEYS_REQUIRE_ALL`, below). A Nix check still decides.
- `nix flake check` sees only files git knows: `git add` new files first.
- `packages.cakeys-crane` is the crane build the checks use, its test suites included;
  `packages.cakeys` is the same build without its check phase, what users and the NixOS module
  get. `nix/package-common.nix` holds the source, outputs, patches, features and test environment.
- Generated profiles must stay byte-identical to the committed ones, and only the Nix-built
  binary carries the patched cryptoki the probe needs: `profiles/LEDGER.toml` names each
  profile's command (`scripts/regen-profiles.sh` for the software tokens). The baseline is
  regenerated with `CAKEYS_UPDATE_BASELINE=1 CAKEYS_ACCEPT=1`, then `nix fmt`. Every
  regeneration is written beside the file it would replace until accepted ("Golden files").
- What only hardware or a cloud can measure is in `profiles/LEDGER.toml`, with its last run. A
  change to the code on its path, or a hand edit, fails `checks.ledger` until the ledger records
  it: an `[artifact.acknowledged]` saying who, why and what needs a run, or a hand-edit row.
  After a run on the device, record it there (CAPROBE.md, "The ledger").
- Port 23211 on the development machine belongs to another process's swtpm: pass another port
  (`TPM_PORT`, or the third argument of `nix/tpm2-test-env.sh`).

**Frozen names.** Scheme names, method names, exposure levels, the bundle format and exit codes
are pinned by tests (`scheme_definitions_are_pinned`, `method_names_are_pinned_and_round_trip`,
`spec_digests_are_pinned`). If one of those fails, the change is wrong, not the test.

**Git.** Work on a branch; the user decides what is pushed and merged. Match the surrounding
code's style and comment density.

**Built-in material.** Every trust anchor or key a build embeds or verifies with is pinned by
its SHA-256 in the code that uses it, not trusted to git: Yubico's roots in
`crates/ykcs11/build.rs` (a changed file fails the build), Google's kmsp11 release key in
`nix/kmsp11.nix` (fails evaluation). A new one gets the same pin, its hash taken from the
publisher's copy, not the repository's. Test fixtures need none.

## The gate, in tiers

Hardware is scarce, so not every merge can run every check. What each tier runs, and when it
must pass:

| Tier | What | Needs | Must pass |
|---|---|---|---|
| T0 | `.#checks-no-vm`: the crane build and its software-token suites (SoftHSM, kryoptic, p11-kit, swtpm, the fault shim), clippy, rustdoc, formatting, `doc-references`, `claims` (a universal claim of the documents that say what the tools guarantee names its tests in `docs/claims.toml`, or is counted against a number that only goes down), `test-count`, `oracle-count` (no test file asserts on a tool's prose more often than `nix/oracle-count.toml` allows, a number that only goes down), `ledger` (with the golden files: each change of what a build regenerates and compares with is recorded with the rows it moved and why; on a pull request the light job's `nix/golden-rows.py` holds the record to exactly the rows the diff moved), `fuzz-lock` and `kani-library-lock` (the second lockfiles still match: a drifted `fuzz/Cargo.lock` kept `vm` red from 38967ae to 61b7000) | Linux, no hardware | before a merge to `main` |
| T1 | `.#checks-vm`: the NixOS VM tests and the fuzz smoke run | Linux with KVM | before a merge, or within a day of it; red is fixed forward first |
| T2 | the YubiKey, AMD fTPM, Cloud KMS and CloudHSM suites and probes (`nix run .#coverage-full`, `scripts/cloud/*.sh`) | the device or a billed cloud account | on a schedule or before a release; recorded in the [ledger](CAPROBE.md#the-ledger) |

- **A change does not merge on red T0.** On macOS, single Linux checks build locally through
  Determinate Nix's Linux builder: `nix build --option builders '' -L .#checks.aarch64-linux.<name>`.
  CI builds the same set for x86_64 on every pull request. `checks.aarch64-linux.examples` and
  the VM tests need x86_64 or KVM, so they are left to CI.
- **What T2 did not see stays visible.** A change to code on a hardware path fails `checks.ledger`
  until it is re-probed, or until an `acknowledged` record says why it is not yet re-probed.
- **Nothing skips silently.** Under `CAKEYS_REQUIRE_ALL`, set in every T0 test run, only the T2
  suites may skip (Testing, below). `checks.test-count` fails when a test disappears without a
  manifest edit.
- **Every commit says what ran.** Use `Ran:` and `Not run:` trailers, and follow the fix protocol
  in [REVIEWING.md](REVIEWING.md).
- **On GitHub, `checks / light` is a required status check for `main`,** and `checks / vm` is
  recommended. That is a repository setting, not a file.

## Hardware rules

Two real devices are attached to the development machine, and both hold things the user depends
on. These rules have no exceptions; if a task cannot be done within them, stop and report.

**The TPM (AMD fTPM, firmware 3.87).** It unlocks the disk and backs secure boot.

- Never run `tpm2_clear`, change a hierarchy auth, use the lockout auth, extend a PCR, or
  define, write or undefine NV indices.
- Never evict or change the persistent handles `0x81000001`, `0x81000002` and `0x81010001`.
  Record `tpm2_getcap handles-persistent` before and after any TPM work and compare.
- Never send a wrong PIN or auth value. The dictionary-attack counter is shared with disk
  unlock; check `TPM2_PT_LOCKOUT_COUNTER` is still 0 afterwards.
- Reach the TPM through `nix/ftpm-test-env.sh` (tpm2-abrmd over `/dev/tpmrm0`), never
  `/dev/tpm0`.
- The one persistent object cakeys made is its Attestation Key at `0x81000016` (2026-11-14);
  `tpm2_evictcontrol -C o -c 0x81000016` removes it.

**The YubiKey (5C NFC FIPS, firmware 5.7.4).**

- Slots 82, 83 and 84 hold the user's keys. Never write to them, never generate, import or
  delete there, and do not run a proof of possession on them. `examples/yubikey-secureboot.*`
  describes those keys: do not `lock` it against the device.
- Test keys go in retired slots 90–95 only (`CKA_ID` 13–18). The scratch slot for write probes
  is `probe.scratchId = "17"`; camigrate's import test uses slot 95 (ask before running it).
  The probe accepts that slot only empty or holding its own certificate (`CN=cakeys-probe`), which
  each run leaves there: a slot from before that rule, or from a run that stopped part way, is
  refused until emptied (`scripts/yubikey-empty-slots.py <mgm file> 94`).
- The credentials are files in `/data/srcs/waste/yubikey_data`: `PIN.txt` is the PIN and
  `piv_mnmgt_key.current.txt` the management key. Pass them as file paths (`pinFile`,
  `soCredentialFile`). Never print them, copy them into the repository, or put them in a commit, a
  log or a report.
- The PIN has 3 tries. Never guess; if a login fails once, stop.

## Testing

| Suite | Where | What |
|---|---|---|
| unit | `cargo test --workspace` | digests (pinned), curves and OIDs, SPKI round-trips, registry, P-521 fix-up, hex parsing, proof-of-possession host math (both ECDH MAC sides), the signature verifiers, the deprecation register and scheme names, AES strength order, the observed policy vectors, the attestation scheme definitions and lock invariants, the lock rules (first use, what a write may override, attestation changes, provenance warnings), the PIV chain verifier (fixture chain + Yubico's own roots and intermediates) |
| `crates/core/tests/properties.rs` | `cargo test --workspace` | proptest: recording then comparing passes and a second write changes nothing; after a recorded realisation, another material is 10 and a weaker binding or replaced object 14 in both modes, drift fails only a compare, and a successful write never overwrites a locked ID; material links only through a shared scheme (disjoint 14, other material 10, else gaps filled); the attestation and commitment-label encodings are injective; `sri`/`is_sri` agree; key and certificate parsers and the loaders never panic. Mutation-checked: disabling the binding-downgrade or the shared-scheme rule fails it |
| `crates/core/tests/lock_mbt.rs` | package build; `cargo test` with `quint` on `PATH` (`nix develop` has it) | model-based (quint-connect): `quint run` simulates `crates/core/spec/lock.qnt`, 500 traces of 12 runs from a fixed seed, and each trace is replayed against `reconcile`. After every run the lock, projected onto the model's, the verdict (the exit code, or whether the lock changed) and the rule that decided it must be the model's, and the lock must load; the replay must reach every rule the model's `decidedBy` witnesses name. A second test holds every lock check that `reconcile.rs` refuses by to a rule of the model or to the list of those the model leaves out. Mutation-checked: the model without its binding-downgrade rule fails it; alone it leaves 9 of `reconcile.rs`'s 113 viable mutants, all outside the model (archive/COVERAGE_PLAN.md, "The lock model"). "The lock model and the Rust" below |
| shared properties | `cargo test --workspace` | properties written once as functions (`cakeys_core::fuzzing`, `cakeys_tpm2_pkcs11::fuzzing`, `camigrate::fuzzing`; OPEN.md, "Kani and fuzzing") and run three ways: proptests under `cargo test`, cargo-fuzz targets (`checks.fuzz`) and, where one fits, Kani proofs (`checks.kani`). `hex::decode` takes exactly hex of whole bytes and `encode` round-trips (`fuzzing::tests::only_hex_decodes`, `hex_round_trips`; fuzz target `hex`; both proved in `checks.kani`, every input up to four and two bytes); the attestation encoding reads back to its fields (`attest_encoding_reads_back`; `attest_encoding`); a lock that loads, and a bundle that reads, is read back from its own writing as it was (`lock_round_trips`, `bundle_round_trips`, seeded with the repository's locks and the sample bundle; `lock`, `bundle`); a key file is read or refused, and a private key only from a file the shape scan says holds one (`key_file`, seeded with the key-file fixtures; `key_file`); tpm2-pkcs11's `fix_ec_point` repairs exactly the malformed short form (`ec_point_fix_holds_on_any_bytes`; `p521_point`; proved in `checks.kani` for every input up to 258 bytes; it found that DER of 128 bytes was "repaired") |
| `checks.kani` | `nix flake check` (x86_64-linux) | `cargo kani -p cakeys-core` and `-p cakeys-tpm2-pkcs11` with Kani from `nix/kani.nix`: the proofs in the two `fuzzing` modules, for every input up to each proof's bound (three today, each also a proptest: OPEN.md, "Kani and fuzzing"); not in `checks-crane-only` |
| `checks.quint` | sandbox | `lock.qnt` typechecks; a fixed-seed simulation (2000 traces of 12 runs) holds every invariant and reaches every rule that can decide a run; Apalache proves the invariants for every run of up to two steps (about two minutes) |
| `checks.fuzz`, `apps.fuzz` | package build / host | cargo-fuzz targets (`fuzz/`: the key and certificate parsers, the lock and config loaders, the bundle, and tpm2-pkcs11's store rows, `TPMS_ATTEST` and P-521 point fix-up, the PIV attestation chain with its dates, a profile's emit and parse round trip, and the shared hex and attestation-encoding properties) on the stable rustc (`RUSTC_BOOTSTRAP=1`, no sanitizer, debug assertions): the check runs 100 000 inputs per target from a fixed seed and the fixtures; `nix run .#fuzz -- <target> [libFuzzer flags]` runs one as long as wanted |
| `tests/softhsm.rs`, `tests/kryoptic.rs` | package build | one shared suite (`tests/reference/`) against each software reference: lifecycle, every type and scheme against independent oracles (hand-written DER encoder, openssl-hashed fixtures, RustCrypto `hmac`/`cmac`/`aes`/`aes-kw`/`des`); the same verdicts on both, with each token's facts in its `Reference` descriptor (`tests/common/`) |
| `tests/tpm2.rs` | package build, `nix/tpm2-test-env.sh` | swtpm + tpm2-abrmd + tpm2-pkcs11; the native `tpm-certify` attestation (AK provisioning and validation, reads that never provision, a lost attestation as a downgrade, cross-checks), one material attested on two tokens with an attestation each, and the travel of attested material to SoftHSM through the shared portable scheme; also with `CAKEYS_TPM_VENDOR_MODULE` (nixpkgs' module plus `upstream/tpm2-pkcs11/`'s vendor-mechanism patches, `nix/tpm2-pkcs11-vendor.nix`, built from upstream master): the same attestation ID and root through the module's `CKM_TPM2_CERTIFY` as through the store, and an Attestation Key that is a token object (`akLabel`) attesting with no TCTI and no store, and that module's statement told lies behind p11-fault (`tests/liars/tpm2.toml`: another signature, another run's nonce, another public area, another object certified, each refused by its own check) |
| `tests/p11kit.rs` | package build, `nix/p11kit-test-env.sh` | SoftHSM behind `p11-kit server`, compared with direct access |
| `tests/fault.rs` | package build | `crates/p11-fault` (docs/FAULT_SHIM.md): the reference suite again, through the shim in front of SoftHSM with no plan (it must pass as directly), but the object matrix, which would be SoftHSM's table again; `pkcs11-tool` through the shim; cakeys meeting a module whose calls fail (16, the call named), each rule shown fired in the trace |
| `tests/liars.rs`, `tests/liar_lint.rs` | package build; the lint `cargo test --workspace` | the liar matrix (docs/FAULT_SHIM.md): SoftHSM behind the shim, one lie per cell (`tests/liars/cakeys.toml`), each verb of cakeys meeting it about each kind of object, one test per class of lie; every cell asserts its exit, its row's rule and device bit, the lock and the token as it found them, and its rule fired. Every run exits 22 exactly when it changed the lock, a `check` changes nothing, and the lock holds no value a token returned. The lint, pure: every plan rule fired by a cell, a unit test or an exemption, and every (lie class, verb, object class) a cell or decided |
| `crates/camigrate/tests/fault.rs`, `crates/caprobe/tests/fault.rs` | package build | the shim in front of a move's source or target (each failing step refused, the target left clean, the lock unchanged) and of the write probes (what a refusing or lying module does becomes the profile's row and note, or is said undetermined) |
| `tests/references.rs` | package build | cross-reference: the same material (the P-256 and RSA fixtures, P-384/P-521/Ed25519/Ed448 exported from one reference, AES, generic secret and HMAC values, a certificate, a data object) planted on SoftHSM, kryoptic (raw and DER Edwards points), SoftHSM behind p11-kit and — what `tpm2_ptool` imports — tpm2-pkcs11, realised into one lock: one identity per scheme everywhere; and the same verdict for the same scenario (absent 11, two objects 12, another type 13, a swapped private key 13) |
| `crates/camigrate/tests/dry_run.rs` | package build | the dry-run property: for every source and target reference and the types each takes, the plan's verdict is the outcome, a ready move is recorded with its `origin` and verified by `cakeys`; the bundle, key files, `enforced` and host paths, and each refusal's exit code |
| the dry-run twin | package build, inside `tests/common/xref.rs` | every `camigrate` `export`, `import` or `migrate` a test runs is preceded by the same command with `--dry-run`, which must leave the lock, the output file and each token it names as they were, and whose verdict the real run must keep (a dry run that passed may still end in 10 or 13, which only the real material can show). It costs the camigrate suite about 80 s |
| `tests/surface.rs` (each tool) | `cargo test --workspace` | every verb and flag clap defines appears in an integration test of that tool, read from the test sources; `UNTESTED` lists exceptions with why, and fails when stale. A floor, not a measure: it does not say which verb a flag was tested with |
| `caprobe/tests/supports.rs` | `cargo test --workspace` | `caprobe supports` against the embedded profiles, a layer, a hardware pair, a class and `--profiles` |
| `packages.coverage` | by hand: `nix build .#coverage`; CI on `main` (the README badge) | `cargo-llvm-cov` over the whole test run, token suites included (the tests spawn instrumented binaries). `result/summary.txt` gives each file's line, region and function coverage; `result/missing.txt` its uncovered line numbers; `result/html/index.html` every source file with the uncovered lines and regions marked; `result/uncovered-functions.txt` the functions no test entered; `result/lcov.info` the same data for an editor. A report, never a check |
| `apps.coverage-full` | by hand, on the host: `nix run .#coverage-full` (scripts/coverage-full.sh) | the same measurement outside the sandbox (the suites as `scripts/local-tests.sh` runs them), then the opt-in hardware suites into the same report when their variables are set: the YubiKey suites (`CAKEYS_TEST_YUBIKEY_PIN`, `_MGM`; `CAKEYS_YUBIKEY_WIPE=1` empties the test slots 90-95 with scripts/yubikey-empty-slots.py, the management key alone, so camigrate's import runs and cakeys' suite generates every key) and the real-TPM suites (`CAKEYS_FTPM_PROFILE`, `CAKEYS_FTPM_ATTEST=1`), one test at a time, stopping at a failure; the TPM's persistent handles and lockout counter are compared before and after. `target/coverage-full/`, with `suites.txt` naming what ran |
| `packages.mutants` | by hand: `nix build .#mutants`; CI: the unit tier of `.github/workflows/mutants.yml` (the README badge, monthly) | `cargo-mutants` over the code whose own unit and property tests are its tests (`core`, `profile`, camigrate's planner, bundle, key file and transport file), each package's mutants against that package's tests: `result/<package>/missed.txt` lists the changes no test noticed. `cakeys-crane.mutantsOf { package; files; re ? null; }` does one package's files (`re` keeping only the mutants whose name matches, e.g. one function) against every crate's tests, the token suites included (cargo-nextest, a token set per test; minutes for each mutant no test catches). archive/COVERAGE_PLAN.md lists what is left and why. A report, never a check |
| `tests/yubikey.rs` | opt-in, never in the Nix build (`CAKEYS_TEST_YUBIKEY_MODULE`, `_PIN`, `_MGM` — file paths; the secrets are only ever read from them) | a real YubiKey, read-write: generate into the scratch PIV slot `0x95` in an SO step, then (back as the user) attest it and prove possession by signing, record, verify; `delete` refused (15) with the realisation kept; re-lock idempotent — each CLI run bounded, so a touch or PIN prompt fails instead of waiting (`rw_lifecycle_generates_attests_proves_and_refuses_delete_without_touch`) |
| `checks.vm` / `test-nspawn` | QEMU / systemd-nspawn | the CLI flow; in the VM also the pseudo-FOD consumer built in the guest sandbox |
| `checks.module`, `checks.tpm`, `checks.lib` | QEMU / eval | module, hook, pcscd, TPM ACL, Nix library |
| `checks.examples` | sandbox, Linux | every `examples/*/run.sh` on throwaway tokens (SoftHSM, kryoptic, tpm2-pkcs11 on swtpm), each step's exit code required: creating every object kind and moving it to every token kind, a TLS handshake and an EFI signature through pkcs11-provider on a TPM key, a Python program signing through the checked URI; `examples/tls/configuration.nix`'s units and `examples/secure-boot/sign.nix` evaluated. Runs with `CAKEYS_ALLOW_NIX_STORE_KEYS=1` |
| `checks.minimal` | package build | the CLI without its `tpm2`/`ykcs11` features builds without tpm2-tss and sqlite |
| `checks.doc` | package build | rustdoc over every crate, private items included, with `-D warnings`: no doc link that does not resolve. An evidence tag in a doc comment is written `\[run\]`, or rustdoc reads it as a link |
| `checks.msrv` | package build | `cargo check --all-targets` with the toolchain at `Cargo.toml`'s `rust-version` (rust-overlay), the dependencies built with it too |
| `checks.doc-references` | sandbox | what the docs and the Rust comments cite exists (`nix/doc-references.py`, its fixture tests in `nix/doc-references-test.py` first): a test or function the docs name in backticks is a `fn` in `crates/` or `fuzz/`; a snake name (`a_b`) in a `//`, `///` or `//!` comment, and each segment of a path (`KeyAlg::of_spki`) in either, is a name the Rust code defines (an item, field, variant, parameter or module) or uses as only an item can be (after `.` or `::`, in a `use`), so std's, cryptoki's and a dependency's names pass unlisted, as does a path from another crate; every `docs/*.md` and Rust source (`crates/…/*.rs`) cited from docs, sources, scripts or Nix is a file, and every relative Markdown link resolves. Names of software the code never names, and paths of other software, are listed in the script with what they are; an entry nothing needs fails |
| `checks.claims` | sandbox | `nix/claims.py` and its fixture tests (`nix/claims-test.py`): a line of CAKEYS, CAMIGRATE, CAPROBE or DESIGN.md that speaks for every case (every, never, always, the one way, …) about a security subject (a PIN, the lock, a slot, plaintext, …) is registered in `docs/claims.toml`, with the tests that hold it (each a `fn`) or as descriptive with why, or is counted against its `max-unregistered`. The check fails above the count and below it, so the number moves only in a diff, and the tests keep it at or below its seed. Each bullet of DESIGN.md §8.1, "Enforced (with tests)", names in backticks a test that holds it (a `#[test]` fn, or a NixOS test as `checks.<name>`) |
| `checks.ledger` | sandbox | `nix/ledger.py` and its fixture tests (`nix/ledger-test.py`): every file `profiles/LEDGER.toml` records from a run on hardware or a cloud is the one recorded, a hand edit since the run is listed, and the code on its path is the run's or an acknowledged change; every module profile has an entry; every regeneration is `caprobe regenerate`, which probes RSA up to `[regen] rsa-max-bits`; every golden file (what a build regenerates and compares with) is the one a record names, and that record lists only rows that moved, each with a written why (CAPROBE.md, "The ledger") |
| `checks.formatting` | treefmt | `nix fmt` would change nothing: the formatters and linters in `treefmt.nix` (rustfmt with `rustfmt.toml`, nixfmt, taplo, shfmt, rumdl, keep-sorted, statix, deadnix, shellcheck, typos) |
| `checks.test-count` | sandbox | no test binary has fewer tests in its source than `nix/test-count.toml` says (`nix/test-count.py`, its own tests in `nix/test-count-tests.py` first); "No test goes unnoticed" below |
| `checks.oracle-count` | sandbox | no integration test file has more prose assertion sites (an assert whose subject is `.contains(…)` on a tool's stderr, stdout or rows) than `nix/oracle-count.toml` gives it, and a file it does not name has none; exit-code sites are counted, not limited (`nix/oracle-count.py`, its fixture tests in `nix/oracle-count-tests.py` first). A refusal asserts its exit, the rule its row names and the state it left through `Workdir::refused` (`crates/cli/tests/common/state.rs`) instead. It also fails on a number above its file's count, so a site removed lowers the manifest in the same diff (as `claims` does); `--write` lowers the numbers, never raises them |
| `scripts/xversion.sh` | by hand, per refactor | a lock recorded by one build verifies, compares and re-records byte-identically with another (every class) |

`tests/yubikey.rs` and the camigrate YubiKey import (`crates/camigrate/tests/yubikey.rs`) are
opt-in, as is the real-TPM attestation test (`CAKEYS_FTPM_ATTEST=1`, through
`nix/ftpm-test-env.sh`). `packages.test-nspawn` needs the `uid-range` feature, so it is outside
`checks`.

A test that cannot run here skips through one helper, `crates/test-skip.rs`'s `skip`, which
fails instead when its `*_REQUIRE` variable is set, or `CAKEYS_REQUIRE_ALL` and the variable is
not a hardware or cloud suite's (its `HARDWARE` list; the swtpm's too in a build without tpm2).
cakeys' harness test fails on a skip written any other way. The software tokens' variables are
`CAKEYS_TEST_REQUIRE` (SoftHSM), `CAKEYS_KRYOPTIC_REQUIRE`, `CAKEYS_P11KIT_REQUIRE`,
`CAKEYS_TPM_REQUIRE` (swtpm) and `CAKEYS_FAULT_REQUIRE`; `test_env` (`nix/token-env.sh`) sets
them all and `CAKEYS_REQUIRE_ALL`, for the Nix builds and `scripts/local-tests.sh`, once for the
run and apart from `nix/test-tokens.sh`'s routing, so a suite the routing misses fails. The
hardware suites' are `CAKEYS_YUBIKEY_REQUIRE`
(with `CAKEYS_TEST_YUBIKEY_PIN` and `_MGM`), `CAKEYS_FTPM_REQUIRE` (with
`CAKEYS_FTPM_MODULE` and `CAKEYS_FTPM_PROFILE`) and `CAKEYS_FTPM_ATTEST_REQUIRE` (with
`CAKEYS_FTPM_ATTEST=1`), and the cloud suite's is `CAKEYS_CLOUD_REQUIRE`: a suite's opt-in
variables are set all together or not at all, and its require variable without them fails rather
than passing having run nothing. `scripts/coverage-full.sh` sets each beside the suite's
variables, and only for that suite's pass.

**No test goes unnoticed.** `checks.test-count` counts each test binary's tests in the source
(`nix/test-count.py`: every `#[test]` its root reaches through `mod` and `#[path]`, whatever its
`cfg`, under nextest's name for the binary) and fails where one has fewer than
`nix/test-count.toml` says. A test that goes is brought back, or the same diff lowers the manifest
(`--write`) and says why; a new test needs no edit. It runs on every system in seconds:
`nix develop -c python3 -I nix/test-count.py .` names the tests gone since the manifest's commit
(or `--base <rev>`). At run time, nextest writes every test it ran to
`<target>/nextest/default/junit.xml` (`.config/nextest.toml`) and `skip` logs each skip to
`$CAKEYS_SKIP_LOG` (`test_env`). After the check phase and `scripts/local-tests.sh`,
`nix/test-count.py --junit` prints each binary's run and skipped counts and the skips by name. It
fails when a binary that the run's cargo arguments build ran other tests than its source has: a
binary lost, or a test left out. With nextest arguments, local-tests only reports. Every nextest
run passes `--no-tests=fail`.

### Golden files

A golden file is what a build regenerates and compares with: the object matrix's tables
(`spec-coverage/objects/`), the profiles of the software tokens, `spec-coverage/cakeys.toml` and
the baseline. The code under test writes them, so a test against one detects a change, not an
error (review 2026-11-24 C-8). What stands in front of them:

- **The ledger records each change.** `profiles/LEDGER.toml` has a `[golden."<path>"]` entry per
  file (CAPROBE.md, "The ledger"): every change adds a record naming the file it made and each
  row that moved, with what it was and why the new value is right. `checks.ledger` fails a file
  no record names, a why left `"TODO"` and a listed row that did not move. On a pull request,
  `nix/golden-rows.py --base <rev>` fails when the record lists other rows than the diff moved,
  and writes them, old and new, to the job summary. `nix develop -c python3 -I
  nix/golden-rows.py --stub` prints the record to fill in.
- **A regeneration waits beside the file.** Every writer of one (`caprobe probe --out`, each
  `CAKEYS_UPDATE_*` test, the regeneration scripts) goes through `cakeys_profile::regenerate`: a
  file the new text differs from is replaced only when accepted, by `caprobe probe --accept` or
  `CAKEYS_ACCEPT=1` (for a test or a script); otherwise the text goes beside it as `<file>.new`,
  which git ignores and `golden-rows.py --stub` reads. The baseline is formatted after it is
  written: stub it once accepted and formatted.
- **Properties stand in front of the tables and profiles.** What a golden file must say whatever
  the code makes of it, derived from PKCS #11, DESIGN.md or the module's own documentation, never
  from the file: `crates/cli/tests/object_matrix/properties.rs` for the object matrix (each
  token's fresh table before it is compared or regenerated, and every committed table without a
  token), `crates/profile/tests/properties.rs` for the software tokens' profiles, and
  `every_regenerated_yes_says_by_whom` for their provenance. Each is seen failing on its row
  flipped in a copy. A property that a regeneration breaks is a finding, never a property to
  change to fit it.

## Verification beyond tests

Bugs so far came from three places: the design (an identity taken from an unbound public
object, a forged `CKA_PUBLIC_KEY_INFO` accepted, a per-device attestation stored per object),
module and binding behaviour (ykcs11's delete, tpm2-pkcs11's P-521 point, cryptoki's HMAC
constants, p11-kit's dropped mechanisms), and very few from the pure logic. Only tests against
real modules catch the second kind; a proof of the Rust code would target the kind with the
fewest bugs. So the order is: the reference tokens and cross-reference tests (done), proptest
and cargo-fuzz (done), then models of the design — Quint for the lock rules (begun, below),
Alloy for the lock's structure and its merge rule, Tamarin for proof of possession and
attestation — and Kani harnesses for small pure functions ([OPEN.md](OPEN.md)). Verus or Aeneas
only for a carved-out kernel, after a model says what it must satisfy.

### The lock model and the Rust

`crates/core/spec/lock.qnt` states what `reconcile`, `compare` and `record` do to an abstract
lock (objects with their type, IDs and label; realisations with their mode, binding,
attestation, schemes, policy, immutables and spec digest), one `realise` step per cakeys run,
and the properties the rules exist for: a failed run or a compare writes nothing; no run
overwrites a locked ID or type; an object's IDs are all one material; one object per material
in a class; a realisation's schemes are among its object's IDs; a successful run never lowers a
recorded mode, binding, attestation, scheme set or immutable; what a write recorded compares
clean and re-records unchanged. Its header lists what it leaves out (imports and provenance,
observations, pairs, locators, labels other than the default).

Two different claims, kept apart:

- **The model satisfies its properties.** `checks.quint` simulates it and has Apalache prove
  them for every run of up to two steps from the empty lock. A proof of the model, bounded.
- **The Rust behaves like the model.** Tested, not proven: `lock_mbt.rs` replays simulated
  traces through the real `reconcile` and compares state, verdict and the deciding rule after
  every step. What says the test is worth something: each rule is reached (`checks.quint` fails
  when a `decidedBy` witness is never seen, and the test itself when its own 500 traces never
  reach one); a rule taken out of the model fails it; and cargo-mutants
  over `reconcile.rs` with this test as the only test (archive/COVERAGE_PLAN.md, "The lock model"),
  where each surviving mutant is either behaviour the model leaves out or a change to no
  observable behaviour.

The projection (`State::from_driver`) is the trusted part: it maps the lock as serialised onto
the model's shape, field for field, and refuses anything the model does not name rather than
dropping it: every field of the lock as serialised is either read or named as one the model
leaves out (the locator, observations), so a new one fails the test. A refusal maps to its rule
by the check that it names (`cakeys_core::Check`, docs/CAKEYS.md "Rules and checks"): the
model's rule is the check's name without `lock.` (`identity.material` is `mismatch`), and a
refusal that names no check, or a check that the model leaves out, fails the step. A change to
a lock rule the model's traces reach fails `lock_mbt.rs` unless the model changes with it; a
rule keyed on what the model leaves out or fixes (its header lists them: imports, locators and
`publicOnly`, pairs, and in its fixed keys.toml no RSA key and no object two specs share) is
never reached, so a change to it passes (review 2026-11-24 A-6). The test
`every_lock_rule_is_modelled_or_left_out` lists those left out (`LEFT_OUT`: `lock.import-ids`
and `lock.same-object`): every lock check that `reconcile.rs` refuses by is a rule of the model
or one of them, never both, and a second spec of one object on one token, the case of A-6 that
the model leaves out, is refused by `lock.same-object`.
