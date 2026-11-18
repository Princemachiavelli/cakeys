# Review: crates/cli/src/lib.rs (550 lines)

Reviewed 2026-11-18 [read]. Summary: the `cakeys` command line: clap definitions, `dispatch`
(load keys.toml, decide whether the run writes, take the lock and its guard), and one method per
verb over `ops`. Thin and readable since Q14; the lock is read under its guard before any token
opens and saved through `save_changed`. One real ordering problem in `create`'s error path and a
few stdout/stderr and doc inconsistencies.

## Findings

### F1. A failed lock save after `create` hides what was created and the pair's own error — risk

**Verification:** confirmed. cli/src/lib.rs:537-540 runs `self.save(done.changed, notes)?` (cli-common `save_changed` → `save_lock`, lib.rs:210-216) before `print(&done.created)?` and before returning `done.failed`, so a save error drops both; only the per-key `notes.say("created …")` on stderr (ops.rs:611) survives. [read]
`crates/cli/src/lib.rs:537-540`.
`self.save(done.changed, notes)?` runs before `print(&done.created)?` and before
`done.failed` is returned. If the save fails (disk full, the directory's permissions changed
after `read_lock`'s up-front check, a rename refused by the filesystem), the run exits 1 with the
I/O error: the JSON array of created objects — the only machine-readable record of keys now on
the token but in no lock — is never printed, and the pair failure that stopped the run (e.g. 19,
14) is dropped. The stderr notes still say "created …" per key, so a human can recover, but a
caller parsing stdout cannot. Fix: print `done.created` first, then save, and when both the save
and `done.failed` fail, report the save error with the pair's error as context (or the
pair's code, whichever the docs prefer). [read]

**Fixed (2026-11-18):** `create_selected` saves through `persist` after each created pair; a failed
save ends the run as `failed`, and `create` prints `done.created` before returning any error. Test:
`a_create_killed_part_way_has_recorded_what_it_made` (the save-failure path has none).

### F2. `gc` writes the lock by its own path, not `save_changed` — nit

`crates/cli/src/lib.rs:300-313`.
`gc --apply` calls `save_lock` and its own `eprintln!`s directly, while the other writing verbs
go through `Run::save` → `save_changed` and `notes`. The messages bypass `Notes`, so they appear
before the run's notes rather than with them, and the "updated <lock>" wording differs from the
other verbs'. Use `self.save(!stale.is_empty() && *apply, notes)` and notes for the two
messages. [read]

### F3. `validate` prints per-pair lines on stdout before deciding the run fails — nit

`crates/cli/src/lib.rs:447`, `:466-479`.
`{spec} on {token}: mode {mode}` goes to stdout for every pair, also when the gate then refuses
(15); CAKEYS.md says "stdout carries only the result". A script reading stdout of a failing
`validate` gets a partial listing. Either document the listing as `validate`'s output in both
outcomes or move it to notes. [read]

### F4. `check` takes `&mut self` and re-resolves the address — nit

`crates/cli/src/lib.rs:324-365`.
`check` never mutates `self` (only `create`, `lock`, `delete` and `gc` do), and it resolves the
address with `cfg.address` (348) to validate `--format`/`--uri-pin`, after which
`ops::check_open` resolves the same reference again. Harmless now; two resolutions of one address
can drift if either grows a rule. Take `&self`, and pass the resolved pair to `check_open` if its
signature allows. [read]

## Design

- The update guard is held from `read_lock` in `dispatch` (255) to the end of the verb,
  including every token operation of a long `create` over many tokens. That is what M3 wants
  (no lost update), but it serialises unrelated `lock`/`create` runs on different tokens for as
  long as the slowest token takes (an RSA-4096 generation on a TPM). Taking the guard only around
  "reload, merge, save" would need `ops` to merge into a freshly read lock; worth recording as
  the trade-off it is.
- An unwritable lock is refused as `PreconditionFailed` (14) through `cli_common::read_lock`;
  CAKEYS.md defines 14 as "the realisation moved", so a caller retrying on 14 "after review"
  meets a filesystem problem under that code. See the cli-common review.

## Checked, no issue

- `writes` is false for `create --dry-run`, and for `--no-update-lock` on `lock`/`create`/
  `delete`; `gc` writes only with `--apply`, refused up front when the lock cannot be written.
- `_update_guard` is a named binding (255), so the guard lives to the end of `dispatch` (the `_`
  pattern would have dropped it at once).
- B1 (Done): `lock` opens with `Access::Scratch` (284).
- `check --token` alone refuses `--format`, `--uri-module` and `--uri-pin` (17) before any token
  opens, and maps per-pair failures to 20 with one stderr line each; the empty-token case (17)
  is decided in `ops::check_token` (not reviewed here).
- `--format pkcs11-provider-pem` on a non-private-key object is 15 before any token opens;
  `--uri-pin` reads the PIN reference before the check, so an unset `pinEnv` is 17 without
  touching the token.
- B8 (Done): `--at` and `--ignore-validity` conflict in clap; `chain_time` notes the skip and
  never reads `SOURCE_DATE_EPOCH`; the time is set on every token `check` opens (`checked_open`).
- `create`'s planning prints refusals and stops with 15 before any token opens unless
  `--skip-unsupported`; `--dry-run` prints the plan and writes nothing.
