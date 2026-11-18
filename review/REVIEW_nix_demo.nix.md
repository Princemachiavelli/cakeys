# Review: nix/demo.nix (39 lines)

Reviewed 2026-11-18 [read]. Summary: wraps nix/demo.sh as `apps.demo`, and runs it straight
through as `checks.demo`. Small.

## Findings

### F1. The check unsets `NIX_BUILD_TOP` to get past cakeys' sandbox refusal — nit

`nix/demo.nix:36`. It works because cakeys detects a build by that variable (the reference suites
do the same). If cakeys' detection gains another signal (`NIX_STORE`, the build user), the demo
check fails for a reason unrelated to the demo. The examples check uses the documented switch,
`CAKEYS_ALLOW_NIX_STORE_KEYS=1`, which its comment says lifts the lock-write refusal
(nix/examples.nix:57-59); use the same here. [read]

## Design

- Act 2 (the Nix evaluation) is skipped in the sandbox, so checks.demo never exercises the part of
  the demo that shows nix/lib.nix; checks.lib covers the library itself.

## Checked, no issue

- `pipefail` (redundant with stdenv) keeps the demo's exit code through `tee`.
