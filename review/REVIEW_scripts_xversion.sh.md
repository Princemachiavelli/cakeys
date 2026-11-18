# Review: scripts/xversion.sh (133 lines)

Reviewed 2026-11-18 [read]. Summary: the cross-version lock check: one cakeys build records a lock
over objects of every class on a fresh SoftHSM token; another verifies, compares, re-records and
diffs it byte for byte. A useful format-drift test the integration suites cannot be.

## Findings

### F1. The mode argument is executed as a command — nit

`scripts/xversion.sh:133`. `"$mode"` runs whatever `$1` names: `record` and `check` as intended,
but also `km`, `rm`, or any binary on PATH, with no usage message for a typo. Use a `case` with a
usage branch. [read]

### F2. `record` deletes its directory argument unguarded — nit

`scripts/xversion.sh:24`. `rm -rf "$dir"` on `$3` as given; `scripts/xversion.sh record ./cakeys .`
removes the working directory. Refuse a non-empty directory that has no `base.lock`. [read]

### F3. A failing re-record exits silently — nit

`scripts/xversion.sh:124`. `km lock ... >/dev/null 2>&1` under `set -e`: a failure ends the run
with no message saying which spec. Keep stderr, as the other steps do. [read]

## Design

None.

## Checked, no issue

- `resolve` output and the re-recorded lock are both diffed, so format and content drift are
  caught.
