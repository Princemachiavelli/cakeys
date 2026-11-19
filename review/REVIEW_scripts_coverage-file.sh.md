# Review: scripts/coverage-file.sh (24 lines)

Reviewed 2026-11-18 [read]. Summary: regenerates spec-coverage/cakeys.toml: a traced run of
every suite through local-tests.sh, then the coverage unit test in update mode, then a diff stat.
Short.

## Findings

### F1. `rm -rf` on a user-supplied directory — nit

`scripts/coverage-file.sh:15`. `trace=$(realpath -m "${1:-...}")`, then `rm -rf "$trace"`. A
mistyped argument (`.`, `~`, a source directory) is deleted without a question. Refuse a
directory that exists and does not look like a trace (no `shims/` inside), or only ever write
under `target/`. [read]

**Fixed (2026-11-18):** refuses a non-empty directory without shims/.

### F2. The second step builds the workspace again, unpatched — nit

`scripts/coverage-file.sh:21-22`. `cargo test -p caprobe --lib` runs in the repository with the
default target directory and no features, after the traced run used local-tests' tree copy and
`target/local-tests/target`: a second full build. The test does not depend on the patched
features, so only time is lost; running it through `CAKEYS_LOCAL_TESTS_THEN` or with
`CARGO_TARGET_DIR=target/local-tests/target` would reuse the build. [read]

**Fixed (2026-11-18):** the rewrite runs through local-tests (same build) and the file is copied back from the tree copy.

## Design

None.

## Checked, no issue

- The filter excludes the same tests nix/test-tokens.sh leaves untraced and the coverage test
  itself, matching nix/package-crane.nix's `postCheck`.
