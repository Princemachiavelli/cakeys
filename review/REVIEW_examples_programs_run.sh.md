# Review: examples/programs/run.sh (32 lines)

Reviewed 2026-11-18 [read]. Summary: creates a key on SoftHSM, signs with it from Python through
the URI `cakeys check` returns, verifies with the public key alone, then plants another key and
expects the program to refuse (10). Nothing to report.

## Findings

None.

## Design

None.

## Checked, no issue

- The swap step deletes both halves and generates under the same label and ID, so the refusal is
  the identity check's, not "not found".
