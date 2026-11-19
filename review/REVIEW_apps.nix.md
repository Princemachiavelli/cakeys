# Review: apps.nix (146 lines)

Reviewed 2026-11-18 [read]. Summary: the flake's `apps`: camigrate, caprobe, the demo,
deny-online, coverage-full, fuzz, and on Linux pkcs11-check-compare, pcsc-probe and
pcsc-sandbox-probe. Thin wrappers; each `writeShellApplication` gets `set -euo pipefail` and
shellcheck.

## Findings

### F1. `apps.fuzz` description lists 4 of the 12 targets — nit

`apps.nix:77`. "Run a cargo-fuzz target (public_key, certificate, lock, config)"; nix/fuzz.nix
has twelve. Say "a cargo-fuzz target (nix/fuzz.nix lists them)" or generate the text from the
target list. [read]

**Fixed (2026-11-18):** the description lists `fuzz.targets`, nix/fuzz.nix's one list.

## Design

- `pkcs11-check-compare` pins `SOFTHSM_MODULE` to the patched SoftHSM and says the profiles were
  probed on it (line 103); scripts/regen-profiles.sh's instructions take stock SoftHSM (see
  REVIEW_scripts_regen-profiles.sh.md F1). One of the two is wrong.

## Checked, no issue

- `pcsc-sandbox-probe` builds with `--impure` and `builtins.storePath` on purpose; the paths it
  names are in the app's own closure, so they exist locally.
- `coverage-full` refuses to run outside the repository root and passes this rustc's own
  llvm-cov/llvm-profdata, as packages.coverage does.
- `deny-online` and `fuzz` take their logic from nix/deny.nix and nix/fuzz.nix (one copy each).
