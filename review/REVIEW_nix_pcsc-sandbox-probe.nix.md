# Review: nix/pcsc-sandbox-probe.nix (23 lines)

Reviewed 2026-11-18 [read]. Summary: a raw `derivation` that runs pcsc-probe in the build
sandbox and records `id`, the probe output and its exit code; a nonce makes it rebuild every time.

## Findings

### F1. The header says the exit code is the build's result; the build always succeeds — nit

`nix/pcsc-sandbox-probe.nix:1-2`, `:19-20`. The probe's status is captured into `exit=$rc` in
`$out` and the builder exits 0. That is the right behaviour for a diagnostic (the output is
wanted even on failure), but the comment should say the code is recorded in the output, not that
it is the build's result. [read]

## Design

None.

## Checked, no issue

- Built only through `--impure` with `builtins.storePath`, so it needs no nixpkgs or source tree
  in evaluation.
