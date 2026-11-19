# Review: nix/package-crane.nix (349 lines)

Reviewed 2026-11-18 [read]. Summary: the crane build the checks use (deps built once), with
passthru clippy, doc, msrv, Kani, minimal, mutation reports and coverage. The check phase runs
the suites under nextest with a token set per test, then again traced through p11-fault to
regenerate and compare spec-coverage. Careful work; the comments explain every non-obvious step.

## Findings

### F1. `minimal` hand-writes its feature list and leaves out `cakeys-pkcs11/rv-value` — practice

`nix/package-crane.nix:72-77`. `cargoExtraArgs = "--locked --no-default-features --features
camigrate/kwp,caprobe/kwp,cakeys-pkcs11/sign-after-init"`, where `common.features`
(nix/package-common.nix:77-82) also has `cakeys-pkcs11/rv-value`. What uses `minimal`: only
`checks.minimal` (checks.nix:33); it is not a flake package, `doCheck = false`, and no probe,
test or script runs its binaries (searched for `minimal` across nix/, scripts/, workflows). So
no wrong profile or error text is produced today. But the omission is undocumented: the comment
promises only "without the tpm2 and ykcs11 features", and a caprobe built this way names module
failures without their `CK_RV` (`crates/pkcs11/src/token/mod.rs:257-273`), so it would record
different evidence than the regular build. Derive the list instead:
`lib.filter (f: !lib.hasSuffix "/ykcs11" f && !lib.hasSuffix "/tpm2" f) common.features`, or, if
compiling the no-`rv-value` branches is the point, say so in the comment. [read]

### F2. Kani runs with no memory bound beside the VM tests — risk

**Verification:** confirmed (risk, unquantified). nix/package-crane.nix:256-272 runs `cargo kani` with no limit and no dependency on the crane artifacts, so it may build alongside everything in `nix flake check` (flake-check.yml:44); peak 5.7 GB per docs/OPEN.md:297. "Three VMs 2 GB each" is overstated: only nix/module-test.nix:150 sets 2048, the vm and tpm tests use the 1 GB default. Duplicate of REVIEW_.github_workflows_flake-check.yml.md F1. [read]
`nix/package-crane.nix:251-272`. The comment notes fix_ec_point's proof needs 5.7 GB; the
derivation sets no limit, and `nix flake check` on the CI runner (16 GB) builds it concurrently
with the three VM tests (2 GB each, nix/module-test.nix:150) and the crane build. An OOM kill
there fails CI with no pointer to the cause. Uncertain: depends on the runner's max-jobs. Run it
with `systemd-run --scope -p MemoryMax=8G` where available, or give it `requiredSystemFeatures =
[ "big-parallel" ]`/schedule it in its own CI job. [read]

**Fixed (2026-11-18):** Kani is CI's `kani` job, alone on its runner (checks.yml).

### F3. The uncovered-functions pipeline fails the build when nothing is uncovered — nit

`nix/package-crane.nix:339-342`. `... | grep -v '::<_\(, _\)*>$' | sort > ...`: `grep -v`
exits 1 when it outputs no line, and stdenv runs with `pipefail`, so a run where every function
is entered (or every remaining one is a generic stub) fails `packages.coverage`. Use
`{ grep -v ... || true; }`. [read]

### F4. The `mutantsOf` usage example never expands `$PWD` — nit

`nix/package-crane.nix:277-278`. The expression is in single quotes, so `getFlake
"git+file://$PWD"` receives a literal `$PWD` and fails. scripts/regen-profiles.sh:13-14 uses
double quotes correctly. [read]

## Design

- The traced second pass doubles the check phase's test time on every build; it is the price of
  keeping spec-coverage generated, and the comment says so.
- `mutants` filters features by package name prefix (lines 115-131) for the same reason as
  Cargo.toml F1: the patched-cryptoki features are not one name.

## Checked, no issue

- `cargoVendorDir` patches only `cryptoki` at exactly `common.cryptoki.version` (lines 31-41);
  clippy, doc and msrv inherit `base`, so they see the patched cryptoki and the full feature set.
- The mutants exit-code handling (0/2/3 are reports, anything else fails) is correct.
- Coverage reuses `preCheck`/`postCheck` and the test runner, so it measures what the check phase
  runs.
