# Review: crates/cli/src/main.rs (7 lines)

Reviewed 2026-11-18 [read]. Summary: the `cakeys` binary entry point, `cakeys::main` over the
default registry.

## Findings

None.

## Design

None.

## Checked, no issue

- Returns the library's `ExitCode`, so the documented codes reach the shell unchanged.
