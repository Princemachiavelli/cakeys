# Review: crates/core/src/hex.rs (29 lines)

Reviewed 2026-11-18 [read]. Summary: one hex rule for every caller, `base16ct` lower-case
encode and mixed-case decode of whole bytes. Correct; proven for short inputs by Kani and
fuzzed (`fuzzing.rs`). No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- Q18 (Done): one `hex::encode` for the workspace.
- `decode("")` is `Some(vec![])`; callers that need a non-empty `CKA_ID` check it themselves
  (`config.rs:1572` for `probe.scratchId`). The locator's `CKA_ID` does not get that check at
  load (see REVIEW config.rs F3).
