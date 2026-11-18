# Review: deny.toml (30 lines)

Reviewed 2026-11-18 [read]. Summary: cargo-deny configuration: yanked allowed offline, a
license allow-list. The header says the check covers "licenses, duplicate crates and sources",
but only advisories and licenses are configured.

## Findings

### F1. Duplicates and sources are only warnings: those parts of `checks.deny` cannot fail — practice

`deny.toml:1-4` (and nix/deny.nix:3-6). With no `[bans]` and no `[sources]` table, cargo-deny's
defaults apply: `multiple-versions = "warn"`, `wildcards = "allow"`, `unknown-registry = "warn"`,
`unknown-git = "warn"`. A second copy of a crate, or a dependency from a git URL or another
registry, prints a warning and `cargo deny check` still exits 0. The comment's claim that these
are checked is wrong. Set `[sources] unknown-registry = "deny"`, `unknown-git = "deny"` and choose
`[bans] multiple-versions` deliberately (`deny` with a `skip` list, or keep `warn` and drop the
claim). [read]

## Design

- Advisory freshness is decided by the flake.lock's advisory-db input alone; see
  REVIEW_nix_deny.nix.md F1.

## Checked, no issue

- The license list covers each named crate's choice; `yanked = "allow"` is lifted by
  `apps.deny-online` with `--deny yanked`.
