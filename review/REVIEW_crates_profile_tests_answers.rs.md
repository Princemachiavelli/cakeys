# Review: crates/profile/tests/answers.rs (119 lines)

Reviewed 2026-11-18 [read]. Summary: a golden test: for every embedded profile, the rows
consumers read directly plus `Effective`'s generation, curve and OAEP verdicts over the whole
baseline are rendered to text and compared with `tests/answers.txt`; `CAKEYS_WRITE_ANSWERS=1`
regenerates it. It uses `Set::embedded()` rather than the process-global active set, so it is
independent of activation order. Two weaknesses: the regenerate switch turns the test into a
pass, and the mismatch message is poor when one text is a prefix of the other.

## Findings

### F1. With `CAKEYS_WRITE_ANSWERS` set, the test overwrites the golden file and passes — risk

**Verification:** confirmed (downgraded to practice). `answers.rs:105-108` does write and `return` whenever the variable is present; but nothing in the repository sets it (only the doc comment at `:5` names it), the Nix check's sandbox cannot inherit it and compares against the committed `answers.txt`, and `scripts/local-tests.sh` runs on a tree copy (`:13`), so its rewrite never reaches the repository. A regression is accepted only if a developer's lingering shell variable rewrites the file and the diff is then committed unread. [read]
`crates/profile/tests/answers.rs:105-108`. Any run with the variable present (a developer's
shell after regenerating once, a CI job that exports it, `scripts/local-tests.sh` inheriting the
environment) rewrites `answers.txt` with whatever the code now says and reports `ok`, so a
profile regression is accepted silently and shows only if someone reads the diff before
committing. Fix: after writing, `panic!("answers.txt rewritten; review the diff and re-run
without CAKEYS_WRITE_ANSWERS")`, so a regeneration run is never green; or refuse to write when
`CI` or `NIX_BUILD_TOP` is set. [read]

### F2. A truncated or extended output reports `<end>` vs `<end>` — nit

`crates/profile/tests/answers.rs:110-117`. When one text is a prefix of the other, `zip` finds no
differing line and the fallback prints `now: <end>` and `pinned: <end>` at the shorter length,
not which side has more lines. Fix: print the first extra line of the longer text and both
line counts. [read]

### F3. Verdicts filtered by their message text — nit

`crates/profile/tests/answers.rs:72`, `:79`. "no module profile selected" and "records no {kt}
generation" are matched in `Verdict`'s `Display` output to decide what to print and when to skip
the per-curve and per-size questions. A wording change alters the golden output and fails the
test loudly, so nothing is hidden; a `Verdict` accessor (unknown-because-no-module, no-row) would
make the intent explicit (cf. ISSUES.md Q3). [read]

## Design

- None.

## Checked, no issue

- Uses `Set::embedded()` (no `OnceLock`), so it is unaffected by ISSUES.md Q24's activation order
  and safe beside other tests in the process.
- Lists are sorted before printing (`sorted`), so the pinned text does not depend on row order
  the consumers do not read.
- Both modes are covered: observed profiles over the baseline, delta layers alone.
