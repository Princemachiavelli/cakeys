# Review: nix/pcsc-probe.nix (16 lines)

Reviewed 2026-11-18 [read]. Summary: compiles nix/pcsc-probe.c against pcsc-lite with `$CC` and
pkg-config. Nothing to report.

## Findings

None.

## Design

None.

## Checked, no issue

- `meta.mainProgram` set, so `lib.getExe` works in apps.nix.
