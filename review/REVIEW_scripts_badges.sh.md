# Review: scripts/badges.sh (49 lines)

Reviewed 2026-11-18 [read]. Summary: reduces a coverage or mutants report to a shields.io
endpoint JSON (percentage in tenths, rounded down, colour by threshold). Correct and defensive.

## Findings

None.

## Design

None.

## Checked, no issue

- Division guarded by `all > 0`; rounding down so 99.96% never shows as 100%.
- Timeouts count against the score and unviable mutants are excluded, as the comment says.
- Usage refused unless the second argument is a directory.
