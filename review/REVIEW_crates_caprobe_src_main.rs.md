# Review: crates/caprobe/src/main.rs (7 lines)

Reviewed 2026-11-18 [read]. Summary: the binary entry point, `caprobe::main` over the default
registry. Nothing to review beyond that.

## Findings

None.

## Design

None.

## Checked, no issue

- Returns the library's `ExitCode`, so the documented codes reach the shell unchanged.
