# Review: crates/cli/tests/common/surface.rs (60 lines)

Reviewed 2026-11-18 [read]. Summary: the command-line surface floor the three tools share. It
collects every verb and long flag clap defines, then requires each to appear as a quoted literal
in that tool's test sources or the shared harness. The code is small and clear, and the
stale-exception check is a good touch. As its doc says, it is a floor; the floor is lower than the
doc suggests.

## Findings

### F1. The text match counts comments and the shared harness for every tool — practice

`common/surface.rs:24-34, 47-53`. `sources` concatenates whole files, comments and doc comments
included, and `:49` appends the shared `cli/tests/common` for every tool. Consequences:

- a flag quoted only in a comment (`// run with "--foo"`) counts as tested;
- caprobe flags used only by the shared `assert_profile_conforms` (`common/mod.rs:303`:
  `"--write"`, `"--rsa-max-bits"`, `"--diff"`, `"--out"`) count for whichever tool defines them;
- a verb (`"lock"`, `"check"`, `"create"`) appears as a string in almost every test, so the verbs
  are always covered.

Fix: strip `//` comments before matching, and say in the doc that verbs are trivially covered.
[read]

### F2. Any file named `surface.rs` is skipped, at any depth, and cakeys reads its harness twice — nit

`common/surface.rs:30` skips `common/surface.rs` itself and every tool's `tests/surface.rs`, but
also any future `tests/<suite>/surface.rs`. For cakeys, `:48` already walks `tests/common`, and
`:49` reads it a second time (harmless). [read]

### F3. Aliases and short flags are outside the surface — nit

`common/surface.rs:11-21`. Only `get_long()` and subcommand names are collected, so the `verify`
alias (`visible_alias`) and `-c`/`-l` are not checked. Many tests use `verify` anyway. [read]

## Design

None.

## Checked, no issue

- Stale `untested` entries (gone from clap, or tested after all) fail (`:58-59`).
- `help`/`version` are excluded on both the flag and the subcommand side (`:13, 17`).
- `"--name="` and `"--name "` forms count (`:53`), so `"--module={path}"` is seen.
