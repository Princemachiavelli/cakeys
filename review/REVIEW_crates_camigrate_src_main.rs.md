# Review: crates/camigrate/src/main.rs (7 lines)

Reviewed 2026-11-18 [read]. Summary: the binary's entry point. It calls `camigrate::main` with the
default provider registry. No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- The library entry (`camigrate::main(&Registry)`) lets a downstream binary add provider crates,
  as the lib.rs header says.
