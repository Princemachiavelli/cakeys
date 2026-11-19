# Review: checks.nix (317 lines)

Reviewed 2026-11-18 [read]. Summary: the `nix flake check` set: the crane build with its
suites, clippy, doc, msrv, minimal, deny, demo, the two SoftHSM repros, the Quint model, the
profile query answers, the Nix library's assertions, and on Linux fuzz, the three VM tests and
the examples. Most checks state what they prove and fail on any deviation; `profiles` and
`lib` are precise.

## Findings

### F1. The Quint witness guard is a negative match on output text — practice

`checks.nix:96-100`. The check fails only if `quint run` prints `witnessed in 0 trace`. If a
Quint release rewords that line, or stops printing per-witness counts, the guard passes
vacuously. Count the positive lines instead: one "witnessed in N trace(s)" line per name in
`witnesses`, each with N > 0. [read]

**Fixed (2026-11-18):** a positive `witnessed in N trace(s)` line, N > 0, per witness; a reworded or missing line fails. Test: the guard run against the stored run.txt, a zeroed count and a reworded line (both fail).

### F2. `checks.minimal` builds a feature set no other check names — practice

`checks.nix:31-33` -> `nix/package-crane.nix:72-77`. The comment promises "without their `tpm2`
and `ykcs11` features", but the crane `minimal` list also drops `cakeys-pkcs11/rv-value` (see
REVIEW_nix_package-crane.nix.md F1). Nothing runs those binaries (no tests, no probe), so the
effect is only that this check, and no clippy run, compiles the `not(feature = "rv-value")`
branches. Say so here if it is intended. [read]

**Fixed (2026-11-18):** Verified fixed (2026-11-18), unmarked until now.

## Design

- `softhsm-unwrap-value-len` and `softhsm-pkcs11-provider` end in `| tee $out`; stdenv's
  setup.sh sets `pipefail` (verified in the pinned nixpkgs), so a failing repro fails the check.
- The `lib` check (lines 149-294) does its work as evaluation-time `assert`s, right for a pure
  library, and covers shell quoting of hostile names.

## Checked, no issue

- `profiles`: `expect` keeps the exit code under `set -e` (`|| code=$?`).
- ISSUES.md N2 "Done": `lib` asserts the lock's canonical type, and keys.toml's alias before a
  lock (lines 221-245). Present and correct.
- Fuzz, VM tests and examples are gated on `isLinux`; Kani on `cakeys.kani != null`.
- The Quint check's Apalache is bundled by nixpkgs' quint, so `quint verify` needs no network.
