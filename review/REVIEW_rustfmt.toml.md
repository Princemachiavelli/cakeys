# Review: rustfmt.toml (3 lines)

Reviewed 2026-11-18 [read]. Summary: `max_width = 120`, `use_small_heuristics = "Max"`, shared by
`cargo fmt`, editors and treefmt (taplo's column width matches). Nothing to report.

## Findings

None.

## Design

None.

## Checked, no issue

- Width agrees with treefmt.nix's taplo `column_width = 120`.
