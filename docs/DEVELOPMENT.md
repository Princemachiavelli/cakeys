# Development

This document describes how to build, test and change cakeys. It also gives the rules that
protect the hardware attached to the development machine.

## Environment and the checks

Development happens on NixOS, or on macOS with Determinate Nix. Neither system provides a usable
`cargo` or `python3` of its own. For example, the `python3` of macOS lacks the `tomllib` module,
so run the repository's scripts through `nix develop -c`.

- Build and test with `nix develop -c cargo …`. Run any other tool with
  `nix shell nixpkgs#<name> -c …`. Search with `rg`, not `grep`. Every shell script starts with
  `#!/usr/bin/env bash`.
- Format with `nix fmt -- --no-cache`. The option makes treefmt read every file, because its cache
  has skipped changed files before.
- **For each change:** run `nix develop -c cargo clippy --workspace --all-targets -- -D warnings`
  and the unit tests. Clippy runs with all of its pedantic lints, so a function that can panic
  needs a `# Panics` section in its doc comment. An exemption from a lint is written at the site
  that needs it, as `#[expect(lint, reason = "…")]`. `Cargo.toml` allows `#[allow(…, reason)]`
  only where `#[expect]` cannot be fulfilled: on a `use` item, or where the lint does not fire in
  every test binary.
- **After a significant change:** run `nix build .#checks-crane-only`. It builds every check
  except the fuzz smoke run and the Kani proofs, whose builds cannot reuse the dependencies of the
  crane build. The crane build caches its dependencies for each `Cargo.lock`.
- **At the end of a piece of work:** run the tiers below. T0 must pass. T1 and T2 must be run, or
  recorded as not run.
- **CI** runs on GitHub Actions, on x86_64 Linux, for pushes to `main`, for pull requests, and by
  hand. `.github/workflows/checks.yml` builds every check once, on three runners:
  `.#checks-no-vm` (every check except the VM tests, the fuzz run and Kani) after
  `nix flake check --no-build` has evaluated every output; `.#checks-vm` (the VM tests and the fuzz
  run) on a runner with KVM; and Kani on a runner of its own. One list in flake.nix (`vmChecks`)
  makes the split, and `checks.ci-jobs` fails when the workflow does not build each part exactly
  once. The jobs run Determinate Nix (determinate-nix-action, pinned to a commit) with the Magic
  Nix Cache.
- `.github/workflows/reports.yml` builds `packages.coverage` on each push to `main`.
  `.github/workflows/mutants.yml` runs the mutation gate on the diff of each pull request, on each
  week's changes, and in a monthly sweep of every mutant. `scripts/badges.sh` reduces each report
  to one number: the share of lines that the tests cover, and the share of viable mutants that the
  tests caught (from the sweep). Each workflow pushes its number to the `badges` branch, which the
  README's badges read. The builds run with a read-only token. Only a separate publish job for each
  report may push, and that job runs no code from the repository.
- The token suites (SoftHSM, kryoptic, p11-kit, swtpm) run only in the check phase of the Nix
  build and in `scripts/local-tests.sh`. Under plain `cargo test`, they skip. When the tokens are
  configured but the tests run in one process (plain `cargo test`), all tests share one token set,
  and the suites do not pass. The token suites need a token set for each test, which only the
  per-test runner provides (OPEN.md, "Engineering"). So a change to how cakeys uses a token is not
  tested until a Nix check has run.
- The crane build of the checks (`packages.cakeys-crane`; `packages.cakeys` is the same build
  without the check phase) runs the tests under `cargo-nextest`, one process per test, and starts
  each process through `nix/test-tokens.sh`. That script gives the test a SoftHSM token and a
  kryoptic database of its own (copies of templates), and, for the suites that use them, its own
  `p11-kit server` and its own swtpm. There is no shared server and no shared swtpm, so a suite
  that the runner's lists leave out fails instead of sharing one. One script, `nix/token-env.sh`,
  sets the tokens up. The check phase, the runner, `scripts/local-tests.sh`, the profile script
  (`scripts/regen-profiles.sh`), `scripts/pkcs11-check.sh`, the demo (`nix/demo.sh`) and the
  examples (`examples/lib.sh`) all source it. Because each test has tokens of its own, the tests
  run in parallel, and no test depends on what another test left on a token. On 2026-11-14, the
  268 tests of that time ran in about 40 s, where the camigrate suite alone had taken 130 s on one
  thread. The source now has 900 tests (`nix develop -c python3 -I nix/test-count.py .`).
  `nix build .#cakeys-crane` runs this test run alone.
- `scripts/local-tests.sh [nextest arguments]` runs the same test run outside Nix, in seconds per
  test. It is the quickest way to test a change to how cakeys uses a token. The script builds
  against the patched cryptoki: it applies the patches that `nix/package-common.nix` lists, under
  `target/local-tests/`, and it builds in a copy of the tree, so the repository's `Cargo.lock`
  does not change. It refuses to run when cryptoki does not resolve to the patched copy. It
  requires every reference token, so only the hardware and cloud suites can skip
  (`CAKEYS_REQUIRE_ALL`, below). A Nix check still decides whether a change passes.
- `nix flake check` sees only the files that git tracks, so run `git add` on new files first.
- `packages.cakeys-crane` is the crane build that the checks use, including its test suites.
  `packages.cakeys` is the same build without its check phase, and it is what users and the NixOS
  module get. `nix/package-common.nix` holds the source, the outputs, the patches, the features
  and the test environment of both.
- A generated profile must stay byte-identical to the committed one. The probe refuses to write
  through a cryptoki without the patches, and the Nix-built binary carries them.
  `profiles/LEDGER.toml` names the command that regenerates each profile (`scripts/regen-profiles.sh`
  for the software tokens). To regenerate the baseline, run its test with
  `CAKEYS_UPDATE_BASELINE=1 CAKEYS_ACCEPT=1` set, and then run `nix fmt`. Until a regeneration is
  accepted, it is written beside the file that it would replace ("Golden files", below).
- `profiles/LEDGER.toml` records what only hardware or a cloud account can measure, with the last
  run of each. A change to the code on the path of such a file, or a hand edit of the file, fails
  `checks.ledger` until the ledger records it. The record is either an `[artifact.acknowledged]`
  entry, which says who accepted the change, why, and what still needs a run, or a hand-edit row.
  After a run on the device, record the run there (CAPROBE.md, "The ledger").
- On the development machine, another process's swtpm uses port 23211, which is also the default
  port of `nix/tpm2-test-env.sh`. Pass another port: as the third argument of
  `nix/tpm2-test-env.sh`, or in `TPM_PORT` for the scripts that read it (`examples/lib.sh`,
  `scripts/regen-profiles.sh` and `scripts/pkcs11-check.sh`). The per-test runner takes its ports
  from `CAKEYS_TPM_PORT_BASE`, which is 24000 by default.

**Frozen names.** Tests pin the scheme names, the method names, the exposure levels, the bundle
format, the spec digests and the exit codes: `scheme_definitions_are_pinned`, `scheme_names_are_pinned`,
`method_names_are_pinned_and_round_trip` (the method names and the exposure levels),
`the_format_is_pinned_and_round_trips` (the bundle), `spec_digests_are_pinned`, and
`crates/core/tests/exit_codes.rs` (the exit codes, against the table in docs/CAKEYS.md). If one of
those tests fails, the change is wrong, not the test.

**Git.** Work on a branch. The user decides what is pushed and what is merged. Match the style and
the comment density of the surrounding code.

**Built-in material.** Every trust anchor or key that a build embeds, or verifies with, is pinned
by its SHA-256 in the code that uses it, so that the build does not depend on git to keep the file
unchanged. Yubico's roots are pinned in `crates/ykcs11/build.rs`, and AMD's fTPM roots in
`crates/tpm2-pkcs11/build.rs`. Both call the check in `crates/pin-roots.rs`, so a changed file
fails the build. Google's kmsp11 release key is pinned in `nix/kmsp11.nix`, so a changed file
fails evaluation. A new anchor or key gets the same pin, with its hash taken from the publisher's
copy, not from the repository's copy. Test fixtures need no pin.

## The gate, in tiers

Hardware is scarce, so not every merge can run every check. The table gives what each tier runs,
what it needs, and when it must pass.

| Tier | What | Needs | Must pass |
|---|---|---|---|
| T0 | `.#checks-no-vm`. It holds the crane build with its software-token suites (SoftHSM, kryoptic, p11-kit, swtpm, the fault shim), clippy, rustdoc, formatting, `doc-references` and `claims` (each universal claim of the documents that say what the tools guarantee names its tests in `docs/claims.toml`, or is counted against a number that only goes down). It holds `test-count`, `oracle-count` (no test file asserts on a tool's prose more often than `nix/oracle-count.toml` allows, and that number only goes down) and `mutants-scopes`. It holds `ledger`, which also covers the golden files: each change to a file that a build regenerates and compares with is recorded with the rows that it moved and why, and on a pull request, `nix/golden-rows.py` in the `light` job requires that the record lists exactly the rows that the diff moved. It holds `fuzz-lock` and `kani-library-lock`, which check that the second lockfiles still match: `fuzz/Cargo.lock` must hold what the fuzz crate needs at the versions of `Cargo.lock`, and `nix/kani/library-Cargo.lock` must be the Kani nightly's own (a drifted `fuzz/Cargo.lock` kept the `vm` job failing from 38967ae to 61b7000). On a pull request, the `unit` job of `.github/workflows/mutants.yml` is also T0 | Linux, no hardware | before a merge to `main` |
| T1 | `.#checks-vm`: the NixOS VM tests and the fuzz smoke run. On a pull request, the token tier of the mutation gate is also T1 | Linux with KVM | before a merge, or within a day after it. When T1 fails, the fix is a new commit, and it comes before other work |
| T2 | the YubiKey, AMD fTPM, Cloud KMS and CloudHSM suites and probes (`nix run .#coverage-full`, `scripts/cloud/*.sh`) | the device, or a cloud account that bills | on a schedule or before a release, and recorded in the [ledger](CAPROBE.md#the-ledger) |

- **A change does not merge while T0 fails.** On macOS, single Linux checks build locally through
  the Linux builder of Determinate Nix:
  `nix build --option builders '' -L .#checks.aarch64-linux.<name>`. CI builds the same set for
  x86_64 on every pull request. The VM tests need KVM, so they are left to CI.
  `checks.aarch64-linux.examples` builds locally, but it skips `examples/inject`, whose tool runs
  only on x86-64. CI's x86_64 build runs that example.
- **Results that T2 has not confirmed stay visible.** A change to code on a hardware path fails
  `checks.ledger` until the hardware is probed again, or until an `acknowledged` record says why it
  is not probed yet.
- **Nothing skips silently.** Every T0 test run sets `CAKEYS_REQUIRE_ALL`, and under that variable
  only the T2 suites may skip ("Testing", below). `checks.test-count` fails when a test disappears
  without an edit of the manifest.
- **Every commit says what ran.** Write the `Ran:` and `Not run:` trailers, and follow the fix
  protocol in [REVIEWING.md](REVIEWING.md).
- **On GitHub, `checks / light` is a required status check for `main`,** and `checks / vm` is
  recommended. This is a setting of the repository, not a file in it.

## Hardware rules

Two real devices are attached to the development machine, and both hold things that the user
depends on. These rules have no exceptions. If a task cannot be done within them, stop and report.

**The TPM (AMD fTPM, firmware 3.87).** The TPM unlocks the disk and is part of secure boot.

- Never run `tpm2_clear`, never change a hierarchy's auth value, never use the lockout auth, never
  extend a PCR, and never define, write or undefine NV indices.
- Never evict or change the persistent handles `0x81000001`, `0x81000002` and `0x81010001`. Record
  the output of `tpm2_getcap handles-persistent` before and after any TPM work, and compare the
  two.
- Never send a wrong PIN or auth value. The dictionary-attack counter is shared with the disk
  unlock. Afterwards, check that `TPM2_PT_LOCKOUT_COUNTER` is still 0.
- Reach the TPM through `nix/ftpm-test-env.sh` (tpm2-abrmd over `/dev/tpmrm0`), never through
  `/dev/tpm0`.
- The only persistent object that cakeys has made is its Attestation Key at `0x81000016`
  (2026-11-14). `tpm2_evictcontrol -C o -c 0x81000016` removes it.

**The YubiKey (5C NFC FIPS, firmware 5.7.4).**

- Slots 82, 83 and 84 hold the user's keys. Never write to them, never generate, import or delete a
  key there, and do not run a proof of possession on them. `examples/yubikey-secureboot.*`
  describes those keys, so do not run `lock` with that configuration against the device.
- Test keys go only in the retired slots 90–95 (`CKA_ID` 13–18). The scratch slot for write probes
  is `probe.scratchId = "17"`, which is slot 94. camigrate's import test uses slot 95; ask before
  running it. The probe accepts the scratch slot only when the slot is empty, or when it holds the
  probe's own certificate (`CN=cakeys-probe`) issued over the key in the slot, which each run
  leaves there. A slot that holds an older mark (a fixed certificate, from before review
  2026-11-24 E-6), or a slot from a run that stopped part way, is refused until it is emptied
  (`scripts/yubikey-empty-slots.py <mgm file> 94`).
- The credentials are files in `/data/srcs/waste/yubikey_data`: `PIN.txt` holds the PIN, and
  `piv_mnmgt_key.current.txt` holds the management key. Pass them as file paths (`pinFile`,
  `soCredentialFile`). Never print them, copy them into the repository, or put them in a commit, a
  log or a report.
- The PIN allows 3 tries. Never guess it. If a login fails once, stop.

## Testing

| Suite | Where | What |
|---|---|---|
| unit | `cargo test --workspace` | The unit tests cover the digests (pinned), the curves and OIDs, SPKI round trips, the registry, the P-521 fix-up, hex parsing, the host's computation for proof of possession (both sides of the ECDH MAC), the signature verifiers, the deprecation register and the scheme names, the order of AES strengths, the observed policy vectors, the attestation scheme definitions and the lock invariants, the lock rules (first use, what a write may override, changes of attestation, provenance warnings), and the PIV chain verifier (with a fixture chain, and with Yubico's own roots and intermediates) |
| `crates/core/tests/properties.rs` | `cargo test --workspace` | Properties checked with proptest. Recording and then comparing passes, and a second write changes nothing. After a realisation is recorded, other material exits 10, and a weaker binding or a replaced object exits 14, both for a compare and for a write; a drift fails only a compare; and a write that succeeds never overwrites a locked ID. Material links only through a shared scheme: disjoint schemes exit 14, other material exits 10, and otherwise the write fills the gaps. The attestation and commitment-label encodings are injective. `sri` and `is_sri` agree. The key and certificate parsers and the loaders never panic. A mutation check by hand (2026-11-14) showed that the test fails when the binding-downgrade rule or the shared-scheme rule is disabled |
| `crates/core/tests/lock_mbt.rs` | the package build; `cargo test` with `quint` on `PATH` (`nix develop` provides it) | A model-based test (quint-connect). `quint run` simulates `crates/core/spec/lock.qnt`: 500 traces of 12 runs each, from a fixed seed. The test replays each trace against `reconcile`. After every run, the lock (projected onto the model's lock), the verdict (the exit code, or whether the lock changed) and the rule that decided the run must equal the model's, and the lock must load. The replay must reach every rule that the model's `decidedBy` witnesses name. A second test requires that every lock check by which `reconcile.rs` refuses is either a rule of the model or in the list of checks that the model leaves out. A mutation check by hand (2026-11-18) showed that the model without its binding-downgrade rule makes the test fail, and that with this test alone, 9 of the 113 viable mutants of `reconcile.rs` survive, all in behavior that the model leaves out (archive/COVERAGE_PLAN.md, "The lock model"). See "The lock model and the Rust" below |
| shared properties | `cargo test --workspace` | Each property is written once, as a function (`cakeys_core::fuzzing`, `cakeys_tpm2_pkcs11::fuzzing`, `camigrate::fuzzing`; OPEN.md, "Kani and fuzzing"), and runs in three ways: as a proptest under `cargo test`, as a cargo-fuzz target (`checks.fuzz`), and, where a proof fits, as a Kani proof (`checks.kani`). `hex::decode` accepts exactly hex of whole bytes, and `encode` round-trips (`fuzzing::tests::only_hex_decodes`, `hex_round_trips`; fuzz target `hex`; both proved in `checks.kani`, for every input of up to four bytes and two bytes respectively). The attestation encoding reads back to its fields (`attest_encoding_reads_back`; target `attest_encoding`). A lock that loads, and a bundle that reads, reads back unchanged from its own output (`lock_round_trips`, `bundle_round_trips`, seeded with the repository's locks and the sample bundle; targets `lock` and `bundle`). A key file is read or refused, and a private key is read only from a file that the shape scan says holds one (`key_file`, seeded with the key-file fixtures; target `key_file`). tpm2-pkcs11's `fix_ec_point` repairs exactly the malformed short form (`ec_point_fix_holds_on_any_bytes`; target `p521_point`; proved in `checks.kani` for every input of up to 258 bytes). This property found that `fix_ec_point` changed a valid DER point of 128 bytes |
| `checks.kani` | `nix flake check` (x86_64-linux) | `cargo kani -p cakeys-core` and `-p cakeys-tpm2-pkcs11`, with Kani from `nix/kani.nix`. It proves the properties in the two `fuzzing` modules for every input up to each proof's bound. There are three proofs today, and each is also a proptest (OPEN.md, "Kani and fuzzing"). It is not in `checks-crane-only`, and CI builds it in the `kani` job |
| `checks.quint` | sandbox | `lock.qnt` typechecks. A simulation from a fixed seed (2000 traces of 12 runs) holds every invariant and reaches every rule that can decide a run. Apalache proves the invariants for every run of up to two steps, which takes about two minutes |
| `checks.fuzz`, `apps.fuzz` | package build / host | The cargo-fuzz targets in `fuzz/` cover the key, key-file and certificate parsers, the lock and config loaders, the bundle, tpm2-pkcs11's store rows, `TPMS_ATTEST` and the P-521 point fix-up, the PIV attestation chain with its dates, a profile's round trip through emit and parse, and the shared hex and attestation-encoding properties. They build with the stable rustc (`RUSTC_BOOTSTRAP=1`, no sanitizer, debug assertions on). The check runs 100 000 inputs per target, from a fixed seed and the fixtures. `nix run .#fuzz -- <target> [libFuzzer flags]` runs one target for as long as wanted |
| `tests/softhsm.rs`, `tests/kryoptic.rs` | package build | One shared suite (`tests/reference/`) runs against each software reference token. It covers the lifecycle, and it checks every type and scheme against independent oracles: a hand-written DER encoder, fixtures hashed by openssl, and the RustCrypto crates `hmac`, `cmac`, `aes`, `aes-kw` and `des`. Both tokens must give the same verdicts. Each token's own facts are in its `Reference` descriptor (`tests/common/`) |
| `tests/tpm2.rs` | package build, `nix/tpm2-test-env.sh` | swtpm, tpm2-abrmd and tpm2-pkcs11. It tests the native `tpm-certify` attestation (the provisioning and validation of the Attestation Key, reads that never provision, a lost attestation as a downgrade, and cross-checks), one material attested on two tokens with an attestation each, and the move of attested material to SoftHSM through the shared portable scheme. It also runs with `CAKEYS_TPM_VENDOR_MODULE`: nixpkgs' module with the vendor-mechanism patches of `upstream/tpm2-pkcs11/` (`nix/tpm2-pkcs11-vendor.nix`, built from upstream master). With that module, `CKM_TPM2_CERTIFY` must give the same attestation ID and root as the store; an Attestation Key that is a token object (`akLabel`) must attest with no TCTI and no store; and the module's attestation statements, falsified behind p11-fault (`tests/liars/tpm2.toml`: another signature, another run's nonce, another public area, another object certified), must each be refused by the check that the falsification targets |
| `tests/p11kit.rs` | package build, `nix/p11kit-test-env.sh` | SoftHSM behind `p11-kit server`, compared with direct access to SoftHSM |
| `tests/fault.rs` | package build | `crates/p11-fault` (docs/FAULT_SHIM.md). The test runs the reference suite again through the shim, which forwards to SoftHSM with no fault plan, and the suite must pass as it does with SoftHSM directly. It leaves out the object matrix, which would only repeat SoftHSM's table. It runs `pkcs11-tool` through the shim. It runs cakeys against a module whose calls fail: each run must exit 16 and name the failed call, and the trace must show that each rule fired |
| `tests/liars.rs`, `tests/liar_lint.rs` | package build; the lint also under `cargo test --workspace` | The liar matrix (docs/FAULT_SHIM.md). A lie is a fault plan under which the module returns false data, for example the value of another object. The shim forwards to SoftHSM and injects one lie per cell (`tests/liars/cakeys.toml`), and each verb of cakeys meets each lie about each kind of object. There is one test per class of lie. Every cell asserts its exit code, the rule and the device bit that its row names, the state of the lock and the token after the run, and that its rule fired. Every run exits 22 exactly when it changed the lock, and a `check` changes nothing. After `check` and `lock`, the lock holds no public value of 16 bytes or more that the token returned (`a_lock_holds_no_token_output`). The lint needs no token. It requires that a cell, a unit test or an exemption fires every rule of the plan, and that a cell covers, or a row decides, every combination of lie class, verb and object class. camigrate's and caprobe's own `tests/liars.rs` run their tables through the same runner |
| `crates/camigrate/tests/fault.rs`, `crates/caprobe/tests/fault.rs` | package build | The shim is loaded in place of the source module or the target module of a move: each failing step must be refused, the target must be left clean, and the lock must be unchanged. The shim is also loaded in place of the module that the write probes use: what a module that refuses or returns false data does becomes the profile's row and note, or is recorded as undetermined |
| `tests/references.rs` | package build | A cross-reference test. The same material is planted on SoftHSM, on kryoptic (with raw and DER Edwards points), on SoftHSM behind p11-kit, and on tpm2-pkcs11 (only what `tpm2_ptool` imports): the P-256 and RSA fixtures, P-384, P-521, Ed25519 and Ed448 keys exported from one reference, AES, generic secret and HMAC values, a certificate and a data object. When the material is realised into one lock, it has one identity per scheme on every token. The same scenario gives the same verdict on every token: an absent object exits 11, two objects 12, another type 13, and a swapped private key 13 |
| `crates/camigrate/tests/dry_run.rs` | package build | The dry-run property. For every source and target reference and the types that each accepts, the verdict of the plan is the outcome, and a ready move is recorded with its `origin` and verified by `cakeys`. The test also covers the bundle, key files, `enforced`, the host paths, and the exit code of each refusal |
| the dry-run twin | package build, inside `tests/common/xref.rs` | Before every `camigrate` `export`, `import` or `migrate` that a test runs, the harness runs the same command with `--dry-run`. The dry run must leave the lock, the output file and each token that it names unchanged, and the real run must keep the dry run's verdict. A dry run that passed may still end in 10 or 13, which only the real material can show. On 2026-11-14, the twin added about 80 s to the camigrate suite |
| `tests/surface.rs` (each tool) | `cargo test --workspace` | Every verb and flag that clap defines must appear in an integration test of that tool, as read from the test sources. `UNTESTED` lists the exceptions with the reason for each, and the test fails when an entry is stale. The test shows only that each flag appears in some test; it does not show which verb a flag was tested with |
| `caprobe/tests/supports.rs` | `cargo test --workspace` | `caprobe supports` against the embedded profiles, a layer, a hardware pair, a class and `--profiles` |
| `packages.coverage` | by hand: `nix build .#coverage`; CI on `main` (the README badge) | `cargo-llvm-cov` over the whole test run, including the token suites (the tests start instrumented binaries). `result/summary.txt` gives each file's line, region and function coverage. `result/missing.txt` gives each file's uncovered line numbers. `result/html/index.html` shows every source file with the uncovered lines and regions marked. `result/uncovered-functions.txt` lists the functions that no test entered. `result/lcov.info` holds the same data for an editor. It is a report, never a check |
| `apps.coverage-full` | by hand, on the host: `nix run .#coverage-full` (scripts/coverage-full.sh) | The same measurement outside the sandbox, with the suites run as `scripts/local-tests.sh` runs them. When their variables are set, the opt-in hardware suites are then added to the same report: the YubiKey suites (`CAKEYS_TEST_YUBIKEY_PIN`, `_MGM`) and the real-TPM suites (`CAKEYS_FTPM_PROFILE`, `CAKEYS_FTPM_ATTEST=1`). `CAKEYS_YUBIKEY_WIPE=1` empties the test slots 90-95 with scripts/yubikey-empty-slots.py, which uses the management key alone, so that camigrate's import runs and cakeys' suite generates every key. The hardware suites run one test at a time and stop at the first failure. The TPM's persistent handles and its lockout counter are compared before and after. The report is in `target/coverage-full/`, and `suites.txt` names what ran |
| `packages.mutants` | by hand: `nix build .#mutants`; CI: `.github/workflows/mutants.yml` on each pull request, weekly and monthly | The unit tier of the mutation gate. cargo-mutants mutates the unit tier's files of `nix/mutants-scopes.toml`, and each package's mutants run against that package's own tests. `result/<scope>/missed.txt` lists the mutants that no test caught. "Mutation testing" below describes the gate, its token tier and its baseline |
| `tests/yubikey.rs` | opt-in, never in the Nix build (`CAKEYS_TEST_YUBIKEY_MODULE`, `_PIN`, `_MGM`, which are file paths; the secrets are read only from those files) | A real YubiKey, read and written. The first test generates a key into the test's PIV slot `0x95` in an SO step. Then, logged in as the user again, it attests the key, proves possession by signing, records the key and verifies it. `delete` is refused (15), and the realisation is kept. Running `lock` again changes nothing. Each CLI run has a time limit, so a touch or PIN prompt fails the test instead of waiting (`rw_lifecycle_generates_attests_proves_and_refuses_delete_without_touch`). A second test does the same for the other key types, in slots 90–93 (`rw_key_types_generate_attest_and_prove_each_way_without_touch`) |
| `checks.vm` / `test-nspawn` | QEMU / systemd-nspawn | The CLI flow. In the VM, the test also builds, in the guest's Nix sandbox, a consumer derivation that runs the key check (the "pseudo-FOD" test): that check never creates a key, it fails on first use and prints the value that it got, and the consumer builds once the lock is recorded |
| `checks.module`, `checks.tpm`, `checks.lib` | QEMU / eval | The NixOS module, the hook, pcscd, the TPM ACL, and the Nix library. `checks.module-assertions` evaluates the module's assertions without a VM |
| `checks.examples` | sandbox, Linux | Runs every `examples/*/run.sh` on throwaway tokens (SoftHSM, kryoptic, and tpm2-pkcs11 on swtpm) and requires each step's exit code. The examples create every object kind and move it to every token kind, perform a TLS handshake and an EFI signature through pkcs11-provider on a TPM key, and run a Python program that signs through the checked URI. The check also evaluates the units of `examples/tls/configuration.nix` and `examples/secure-boot/sign.nix`, and it validates the YubiKey configuration against its lock. `examples/inject` runs only on x86-64; on other systems, the check requires the tool's refusal and logs the skip. The check runs with `CAKEYS_ALLOW_NIX_STORE_KEYS=1` |
| `checks.minimal` | package build | cakeys, caprobe and camigrate build without their `tpm2` and `ykcs11` features, and so without tpm2-tss and sqlite |
| `checks.doc` | package build | rustdoc over every crate, private items included, with `-D warnings`, so every doc link must resolve. Write an evidence tag in a doc comment as `\[run\]`; otherwise rustdoc reads it as a link |
| `checks.msrv` | package build | `cargo check --all-targets` with the toolchain at `Cargo.toml`'s `rust-version` (from rust-overlay), with the dependencies built by that toolchain too |
| `checks.doc-references` | sandbox | Checks that what the docs and the Rust comments cite exists (`nix/doc-references.py`; its fixture tests in `nix/doc-references-test.py` run first). A test or function that the docs name in backticks (a snake name of four or more words) must be a `fn` in `crates/` or `fuzz/`. In a `//`, `///` or `//!` comment, a snake name (`a_b`) must be a name that the Rust code defines (an item, field, variant, parameter or module) or uses in a way that only an item can be used (after `.` or `::`, or in a `use`). In both, each segment of a path (`KeyAlg::of_spki`) must pass the same test. So the names of std, cryptoki and other dependencies pass without a list, and so does a path that starts at another crate. Every `docs/*.md` file and every Rust source (`crates/…/*.rs`) cited from the docs, the sources, the scripts or Nix must exist, and every relative Markdown link must resolve. A script must not keep its own copy of the exit-code table. The script lists the names of software that the code never names, and the paths of other software, each with what it is; an entry that no citation needs fails |
| `checks.claims` | sandbox | `nix/claims.py` and its fixture tests (`nix/claims-test.py`). A line of CAKEYS, CAMIGRATE, CAPROBE or DESIGN.md that speaks for every case (every, never, always, the one way, …) about a security subject (a PIN, the lock, a slot, plaintext, …) must be registered in `docs/claims.toml`, either with the tests that hold it (each a `fn`) or as descriptive with the reason, or it is counted against `max-unregistered`. The check fails when the count is above that number and when it is below it, so the number changes only in a diff. The fixture tests keep the number at or below its first value. Each bullet of DESIGN.md §8.1, "Enforced (with tests)", must name in backticks a test that holds it (a `#[test]` fn, or a NixOS test as `checks.<name>`) |
| `checks.ledger` | sandbox | `nix/ledger.py` and its fixture tests (`nix/ledger-test.py`). Every file that `profiles/LEDGER.toml` records from a run on hardware or a cloud must be the file that the ledger records, every hand edit since the run must be listed, and the code on the file's path must be the run's code or an acknowledged change. Every module profile must have an entry. Every regeneration must be `caprobe regenerate`, which probes RSA up to `[regen] rsa-max-bits`. Every golden file (a file that a build regenerates and compares with) must be the file that a record names, and that record may list only rows that moved, each with a written reason (CAPROBE.md, "The ledger") |
| `checks.formatting` | treefmt | `nix fmt` would change nothing. The check runs the formatters and linters in `treefmt.nix`: rustfmt with `rustfmt.toml`, nixfmt, taplo, shfmt, rumdl, keep-sorted, statix, deadnix, shellcheck and typos |
| `checks.test-count` | sandbox | No test binary may have fewer tests in its source than `nix/test-count.toml` gives it (`nix/test-count.py`; its own tests in `nix/test-count-tests.py` run first). See "No test goes unnoticed" below |
| `checks.oracle-count` | sandbox | No integration test file may have more prose assertion sites than `nix/oracle-count.toml` gives it, and a file that the manifest does not name may have none. A prose assertion site is an assert whose subject calls `.contains(…)` on a tool's stderr, stdout or rows. Exit-code sites are counted but not limited (`nix/oracle-count.py`; its fixture tests in `nix/oracle-count-tests.py` run first). A test of a refusal asserts the exit code, the rule that its row names and the state that it left, through `Workdir::refused` (`crates/cli/tests/common/state.rs`), instead of the prose. The check also fails when a number is above its file's count, so a diff that removes a site also lowers the manifest, as `claims` does. `--write` lowers the numbers and never raises them |
| `checks.mutants-scopes` | sandbox | Every source file of a workspace crate must be in a scope of one of the mutation gate's tiers, or be left out with a reason. Every pattern in `nix/mutants-scopes.toml` must match a source file, and every part of a scope's `re` must match a function (`nix/mutants-scopes.py`; its fixture tests in `nix/mutants-scopes-tests.py` run first). So a new crate, a new file, or a renamed file or function fails the check until the scopes decide it ("Mutation testing" below) |
| `scripts/xversion.sh` | by hand, for each refactor | A lock recorded by one build verifies, compares and records again byte-identically with another build, for every object class |

`tests/yubikey.rs` and the camigrate YubiKey import (`crates/camigrate/tests/yubikey.rs`) are
opt-in, and so is the real-TPM attestation test (`CAKEYS_FTPM_ATTEST=1`, through
`nix/ftpm-test-env.sh`). `packages.test-nspawn` needs the `uid-range` system feature, so it is
not in `checks`.

A test that cannot run in the current environment skips through one helper, `skip` in
`crates/test-skip.rs`. The helper fails instead of skipping when the test's `*_REQUIRE` variable
is set. It also fails when `CAKEYS_REQUIRE_ALL` is set and the variable does not belong to a
hardware or cloud suite (the `HARDWARE` list; in a build without `tpm2`, the swtpm's variables
count as hardware too). cakeys' harness test fails on a skip written any other way. The software
tokens' variables are `CAKEYS_TEST_REQUIRE` (SoftHSM), `CAKEYS_KRYOPTIC_REQUIRE`,
`CAKEYS_P11KIT_REQUIRE`, `CAKEYS_TPM_REQUIRE` (swtpm), `CAKEYS_TPM_VENDOR_REQUIRE` (the
tpm2-pkcs11 vendor module on swtpm) and `CAKEYS_FAULT_REQUIRE`. `test_env` (`nix/token-env.sh`)
sets them, and `CAKEYS_REQUIRE_ALL`, for the Nix builds and for `scripts/local-tests.sh` (the
swtpm's two only where the caller has the TPM modules). It sets them once for the whole run,
separately from the routing in `nix/test-tokens.sh`, so a suite that the routing misses fails.
The hardware suites' variables are `CAKEYS_YUBIKEY_REQUIRE` (with `CAKEYS_TEST_YUBIKEY_PIN` and
`_MGM`), `CAKEYS_FTPM_REQUIRE` (with `CAKEYS_FTPM_MODULE` and `CAKEYS_FTPM_PROFILE`) and
`CAKEYS_FTPM_ATTEST_REQUIRE` (with `CAKEYS_FTPM_ATTEST=1`). The cloud suite's variable is
`CAKEYS_CLOUD_REQUIRE`. A suite's opt-in variables must be set all together or not at all. When a
suite's require variable is set without them, the suite fails, instead of passing after it ran
nothing. `scripts/coverage-full.sh` sets each require variable together with its suite's
variables, and only for that suite's pass.

**No test goes unnoticed.** `checks.test-count` counts each test binary's tests in the source and
fails where a binary has fewer than `nix/test-count.toml` gives it. `nix/test-count.py` counts
every `#[test]` that the binary's root reaches through `mod` and `#[path]`, whatever its `cfg`,
under nextest's name for the binary. When a test goes away, bring it back, or lower the manifest
(`--write`) in the same diff and say why. A new test needs no edit. The check runs on every system
in seconds: `nix develop -c python3 -I nix/test-count.py .` names the tests that are gone since the
manifest's commit (or since `--base <rev>`). At run time, nextest writes every test that it ran to
`<target>/nextest/default/junit.xml` (`.config/nextest.toml`), and `skip` logs each skip to
`$CAKEYS_SKIP_LOG` (`test_env`). After the check phase and after `scripts/local-tests.sh`,
`nix/test-count.py --junit` prints each binary's counts of tests run and skipped, and the skips by
name. It fails when a binary that the run's cargo arguments build ran other tests than its source
has, which means that a binary was lost or a test was left out. When `scripts/local-tests.sh` is
given nextest arguments, it only reports. Every nextest run that the builds and the scripts start
passes `--no-tests=fail`.

### Mutation testing

A mutant is a small change that cargo-mutants makes to the code, such as `==` replaced by `!=`,
or a function body replaced by a default value. A test run that fails on the mutant catches it.
A mutant with which every test still passes is a survivor, and it marks a decision in the code
that no test checks. The mutation gate compares the survivors with a list of the survivors that
may stay, so that a change cannot add an unchecked decision without a reason.

**What is mutated.** `nix/mutants-scopes.toml` lists the source files in two tiers, and
`nix/package-crane.nix` reads it.

- The unit tier holds code whose own package's tests can catch its mutants: `cakeys-core`,
  `cakeys-names`, `cakeys-profile`, camigrate's plan, bundle, file, transport, side and trust files
  and its function `refuse_admin_in_nix_build`, the tpm2-pkcs11 attestation verifiers and
  `fix_ec_point` (Linux only), kmsp11, aws-cloudhsm and ykcs11's attestation verifier.
  cargo-mutants runs only the mutated package's tests, so a mutant takes seconds. The tier has
  about 2,400 mutants.
- The token tier holds code that only the token suites reach: pkcs11's token operations and
  rules, camigrate's verbs, caprobe's probes, cli-common, and tpm2-pkcs11's plaintext import
  through tpm2_ptool (`crates/tpm2-pkcs11/src/ptool.rs`, Linux only). cargo-mutants first runs the
  mutated package's own tests. For each mutant that those tests miss, it then runs every crate's
  tests under cargo-nextest with a token set per test, except the kryoptic, p11-kit, surface and
  harness test binaries. A mutant takes minutes there. The tier has about 1,900 mutants.
- The table `left-out` gives the reason for every other source file.
- `checks.mutants-scopes` (T0) compares the file with the workspace. A new crate, a new file, and
  a renamed file or function fail that check until the file lists them.

**The baseline.** `nix/mutants-baseline.toml` lists the survivors that may stay, by file, and
`nix/mutants-baseline.py` (`nix run .#mutants-gate`) compares a report with it.

- An entry's key is `<function>: <genre> <original>→<replacement>`, with a space and `#k` added
  for the k-th identical key in one function. A mutant outside any function, such as a constant's
  value, has no `<function>:` part. The key holds no line number, so an edit above a mutant does
  not change its key.
- An entry's value is the reason that the mutant may stay: a string for a reviewed entry, or
  `{ why = "seeded <date>", reviewed = false }` for an entry that a sweep added and that no one
  has reviewed yet.
- The gate fails on a survivor that the baseline does not list. The weekly run also fails on an
  entry whose mutant the run caught. The monthly sweep also fails on an entry whose mutant the run
  caught or no longer has, for example because the function changed. `--write` removes such
  entries.
- The gate fails when the baseline has more entries than `max`. `--write` never raises `max`, so
  a new entry needs `max` raised by hand in the same diff, with the entry's reason.
- Timeouts and unviable mutants are listed in the output and never fail the gate.
- While the baseline sets `enforce = false`, the gate is in report mode: it prints what would
  fail and exits 0. The commit that adds the seeded baseline sets `enforce = true` (the steps
  are below).

**CI** (`.github/workflows/mutants.yml`, x86_64 Linux):

- On a pull request, the gate mutates only the lines that the change touches (`--in-diff`). The
  unit tier is the job `unit`, which is meant to become a required check beside `checks / light`.
  The token tier is T1, in 4 shards. It fails when the first pass leaves more than 120 mutants,
  instead of testing a sample. In that case, split the change, or run the token tier on a Linux
  builder (below) and record the run in `Ran:`.
- Every Monday at 02:00 UTC, both tiers run on the last week's changes to `main`. On the first
  Monday of a month, the sweep runs instead: every mutant of both tiers, with the unit tier in 4
  shards, the token tier's first pass in 4 and its second pass in 16. The sweep publishes the
  README's badge (the caught mutants as a share of the viable ones).
- Every gate writes `missed.md`. It lists the survivors by file and function, each function with
  the `Check` and `Rule` variants that its code names, and each survivor with its baseline status
  (new, not reviewed, or reviewed). A pull request's and a week's `missed.md` are in the job
  summary. The sweep uploads its `missed.md` as the artifact `mutants-missed`, and a review starts
  from it ([REVIEWING.md](REVIEWING.md), "Start from the survivors").
- By hand: `gh workflow run mutants.yml -f run=sweep`, `-f run=weekly` or `-f run=calibrate`.
  The calibration runs both passes of the token tier over `crates/pkcs11/src/token/policy.rs`
  (67 mutants on 2026-11-26) and writes the time per mutant into the summary of each `tokens` job.

**Locally.**

- `scripts/mutants-diff.sh [--tokens] [BASE]` runs a pull request's gate on this machine's Linux
  builder, over the diff since BASE (`origin/main` by default). It runs the unit tier, and with
  `--tokens` the token tier too.
- On darwin, the unit tier also runs outside Nix, for every crate except cakeys-tpm2-pkcs11, which
  darwin does not build: `nix develop -c cargo mutants -p <crate> --in-diff <(git diff origin/main)`.
- `cakeys-crane.mutantsOf { package; files; re ? null; }` runs one scope with the token suites
  (`nix/package-crane.nix` shows the command).

**When the gate fails on a survivor,** write a test that fails on the mutant, and see it fail by
applying the mutant by hand. If the mutant changes nothing that a test can observe, add its entry
with that reason instead, and raise `max` by one in the same commit.

**Seeding the baseline.** This is done once, and the gate stays in report mode until it is done.

1. Run `gh workflow run mutants.yml --ref main -f run=calibrate`, and read the time per mutant
   in the summaries of its two `tokens` jobs. Each of the sweep's 16 token shards must end within
   the job limit of 355 minutes, after a build of about 30 minutes. A shard's time is about 1,900
   mutants, less those that the first pass catches, divided by 16, times the time per mutant. If
   that is more than about 300 minutes, raise the third number in the `sweep` case of the `plan`
   job (`set -- 4 4 16`) before step 2.
2. Run `gh workflow run mutants.yml --ref main -f run=sweep`. The sweep's gate passes in report
   mode, and the job `sweep` uploads two artifacts: `mutants-baseline-seeded` (the baseline with
   every survivor listed as `{ why = "seeded <date>", reviewed = false }` and `max` set to their
   count) and `mutants-missed`. The job `sweep` runs only when every shard succeeded. If a shard
   ran out of time, raise that tier's shard count and run the sweep again.
3. Run `gh run download <run-id> -n mutants-baseline-seeded -D /tmp/seed`. Copy
   `/tmp/seed/mutants-baseline.toml` over `nix/mutants-baseline.toml`, change
   `enforce = false` to `enforce = true`, run `nix fmt -- nix/mutants-baseline.toml`, and commit
   with the run's URL in `Ran:`. Commit it before other Rust changes reach `main`, because the
   seed lists the survivors of the commit that the sweep ran on.
4. In the repository's settings, make the job `unit` of the workflow `mutants` a required status
   check for `main`.

### Golden files

A golden file is a file that a build regenerates and compares with: the object matrix's tables
(`spec-coverage/objects/`), the profiles of the software tokens, `spec-coverage/cakeys.toml` and
the baseline. The code under test writes these files, so a test that compares with one detects a
change, but it cannot tell whether the change is an error (review 2026-11-24 C-8). Three measures
protect them:

- **The ledger records each change.** `profiles/LEDGER.toml` has a `[golden."<path>"]` entry for
  each file (CAPROBE.md, "The ledger"). Every change adds a record that names the file that it
  made and each row that moved, with the row's old value and the reason that the new value is
  right. `checks.ledger` fails on a file that no record names, on a reason left as `"TODO"`, and
  on a listed row that did not move. On a pull request, `nix/golden-rows.py --base <rev>` fails
  when the record lists other rows than the diff moved, and it writes those rows, old and new, to
  the job summary. `nix develop -c python3 -I nix/golden-rows.py --stub` prints the record to fill
  in.
- **A regeneration is written beside the file.** Every writer of a golden file
  (`caprobe probe --out`, each `CAKEYS_UPDATE_*` test, the regeneration scripts) goes through
  `cakeys_profile::regenerate`. A file that differs from the new text is replaced only when the
  regeneration is accepted, by `caprobe probe --accept` or by `CAKEYS_ACCEPT=1` (for a test or a
  script). Otherwise, the text is written beside the file as `<file>.new`, which git ignores and
  `golden-rows.py --stub` reads. The baseline is formatted after it is written, so run the stub
  once the baseline is accepted and formatted.
- **Properties check the tables and the profiles.** A property states what a golden file must say
  whatever the code produces. It is derived from PKCS #11, from DESIGN.md or from the module's own
  documentation, and never from the file. The properties are in
  `crates/cli/tests/object_matrix/properties.rs` for the object matrix (each token's fresh table
  before it is compared or regenerated, and every committed table without a token), in
  `crates/profile/tests/properties.rs` for the software tokens' profiles, and in
  `every_regenerated_yes_says_by_whom` for the profiles' provenance. Each property is seen failing
  when its row is flipped in a copy of the file. When a regeneration breaks a property, that is a
  finding; the property is never changed to fit the regeneration.

## Verification beyond tests

Up to 2026-11-14, the bugs came from three places. The first was the design: an identity taken
from an unbound public object, a forged `CKA_PUBLIC_KEY_INFO` that was accepted, and a per-device
attestation stored per object. The second was the behavior of modules and bindings: ykcs11's
delete, tpm2-pkcs11's P-521 point, cryptoki's HMAC constants, and p11-kit's dropped mechanisms.
Very few bugs came from the pure logic. Only tests against real modules catch the second kind,
and a proof of the Rust code would target the kind with the fewest bugs. So the order of work is
this: the reference tokens and the cross-reference tests (done), proptest and cargo-fuzz (done),
then models of the design, and Kani proofs for small pure functions (three so far, in
`checks.kani`). The models are Quint for the lock rules (begun, below), Alloy for the lock's
structure and its merge rule, and Tamarin for proof of possession and attestation
([OPEN.md](OPEN.md)). Verus or Aeneas would come only for a small part of the code that is
separated from the rest, after a model states what that part must satisfy.

### The lock model and the Rust

`crates/core/spec/lock.qnt` states what `reconcile`, `compare` and `record` do to an abstract lock.
The abstract lock holds objects with their type, IDs and label, and realisations with their mode,
binding, attestation, schemes, policy, immutables and spec digest. The model has one `realise`
step per cakeys run. It also states the properties that the rules exist for:

- a failed run or a compare writes nothing;
- no run overwrites a locked ID or type;
- all of an object's IDs are of one material;
- a class has one object per material;
- a realisation's schemes are among its object's IDs;
- a successful run never lowers a recorded mode, binding, attestation, scheme set or immutable;
- what a write recorded compares without a difference and records again unchanged.

The model's header lists what the model leaves out, among them imports and provenance,
observations, pairs, locators, and labels other than the default.

The model supports two different claims, and this section keeps them apart:

- **The model satisfies its properties.** `checks.quint` simulates the model, and Apalache proves
  the properties for every run of up to two steps from the empty lock. This is a proof about the
  model, within that bound.
- **The Rust behaves like the model.** This is tested, not proven. `lock_mbt.rs` replays
  simulated traces through the real `reconcile` and compares the state, the verdict and the
  deciding rule after every step. Three results show that the test can detect a difference.
  First, every rule is reached: `checks.quint` fails when a `decidedBy` witness is never seen,
  and the test itself fails when its own 500 traces never reach one. Second, a rule taken out of
  the model makes the test fail. Third, cargo-mutants was run over `reconcile.rs` with this test
  as the only test (archive/COVERAGE_PLAN.md, "The lock model"), and each surviving mutant was
  either behavior that the model leaves out or a change to no observable behavior.

The projection (`State::from_driver`) is the part of the test that nothing else checks, so the
test's result depends on it being right. It maps the lock, as serialised, onto the model's shape,
field by field. It refuses anything that the model does not name, instead of dropping it: every
field of the serialised lock is either read or named as one that the model leaves out (the
locator, the observations), so a new field fails the test. A refusal maps to a rule of the model
by the check that the refusal names (`cakeys_core::Check`, docs/CAKEYS.md "Rules and checks").
The model's rule is the check's name without `lock.`, and `identity.material` maps to `mismatch`.
A refusal that names no check, or that names a check that the model leaves out, fails the step.

A change to a lock rule that the model's traces reach fails `lock_mbt.rs` unless the model
changes with it. A rule that depends on what the model leaves out or fixes is never reached, so a
change to that rule passes (review 2026-11-24 A-6). The model's header lists what it leaves out
or fixes: imports, locators and `publicOnly`, pairs, and, in its fixed keys.toml, no RSA key and
no object that two specs share. The test `every_lock_rule_is_modelled_or_left_out` lists the
checks that the model leaves out (`LEFT_OUT`: `lock.import-ids` and `lock.same-object`). It
requires that every lock check by which `reconcile.rs` refuses is either a rule of the model or
one of those checks, and never both. It also requires that a second spec of one object on one
token, which is the case of A-6 that the model leaves out, is refused by `lock.same-object`.
