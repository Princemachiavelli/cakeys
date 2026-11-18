# Review: crates/cli/tests/common/xref.rs (251 lines)

Reviewed 2026-11-18 [read]. Summary: the cross-reference harness. It finds every reference token
whose suite variables are set, writes one keys.toml naming them all, and runs `cakeys` or
`camigrate` against it. Each moving `camigrate` run is preceded by its `--dry-run` twin, which must
change nothing and whose verdict the real run must keep. The twin is a strong, cheap property. Its
"changed nothing" comparison has two blind spots.

## Findings

### F1. The dry-run twin compares no token when a run names only `kryoptic-der` — risk

**Verification:** confirmed, and broader than stated. `named` (common/xref.rs:160-161) drops every `Plant::Shared` reference, so kryoptic's database is never compared when the token is named as `kryoptic-der`. `public_moves_do_what_the_plan_says` (camigrate/tests/dry_run.rs:284-289, :351) really runs `migrate --from softhsm --to kryoptic-der` (and the reverse) through the twin, where the uncompared side is the target a dry-run write would hit. (The dry_run.rs:78 case the finding cites already passes `--dry-run`, so it has no twin.) [read]
`common/xref.rs:160-161`. `named` keeps the references whose name is in the arguments and drops
`Plant::Shared` ones. A `camigrate` move whose only token argument is `kryoptic-der` (a target or
source name) therefore compares no token: the lock and the output file are still compared, the
token kryoptic-der shares with `kryoptic` is not. `camigrate/tests/dry_run.rs:78` plans moves to
`kryoptic-der`. If any of them goes through `run` as a real move, a dry run that wrote to the token
would pass. Fix: map a `Shared` reference to the reference whose token it reads instead of
dropping it. [read]

### F2. kryoptic's token is compared by its main database file only — risk

**Verification:** withdrawn. The pinned kryoptic (1.5.4, nixpkgs pkgs/by-name/kr/kryoptic/package.nix:17) issues only `PRAGMA secure_delete = ON`; its library has no `journal_mode`/WAL string, so the database stays in SQLite's default rollback-journal mode, where every commit reaches the main file and the twin's hash (common/xref.rs:224-232) sees it. Each cakeys/camigrate run is a separate process that has exited before the hash is read. [read]
`common/xref.rs:224-232, 247-251`. The twin hashes the sqlite file `dbargs` names. If kryoptic's
sqlite runs in WAL mode, or a process exits without checkpointing, a write lands in
`kryoptic.sql-wal`, the main file's bytes stay the same, and the twin misses a token write. Whether
kryoptic enables WAL was not checked. With the default rollback journal, commits reach the main
file and the comparison holds. Fix: include any `-wal`/`-journal` sibling in the hash, or force a
checkpoint (`PRAGMA wal_checkpoint`) before reading. [read]

### F3. `module` duplicates `suite_var`, and `km_in_nix_build` duplicates `run_once` — complexity

`common/xref.rs:39-43` is `common/mod.rs:49-56` without the message; `:99-117` is `:182-202` with
two environment changes. See common/mod.rs F5 for the shared runner. [read]

## Design

- `run` (`:135-147`) asserts the dry-run verdict rule (a dry run that passed may end in 0, 10 or
  13; one that refused must refuse the same way) on every camigrate move any test makes. This
  property should stay in the harness rather than in individual tests.

## Checked, no issue

- Objects listed by `pkcs11-tool` are sorted before comparison (kryoptic's order varies).
- `env` asserts each module whose require variable is set; the "fewer than two" skip happens only
  when they are all unset.
- `spec` adds `origin = "adopt"` only when `extra` names no origin.
