# Review: crates/cli-common/src/lib.rs (226 lines)

Reviewed 2026-11-18 [read]. Summary: what the three binaries share: the default provider
registry, profile activation (Q24), the `main` wrapper that prints notes and maps errors to exit
codes, `--module` parsing, token opening (`Opener`, Q14), and the lock's read-with-guard and save.
Small and clear. Findings are a wrong exit code in a doc comment, loose `--module` parsing, and a
double parse of the embedded profiles.

## Findings

### F1. `read_lock`'s doc gives the wrong exit code — practice

`crates/cli-common/src/lib.rs:192`.
The doc says an unwritable lock is "`PreconditionFailed` (18)"; `KmError::exit_code` maps
`PreconditionFailed` to 14 (`crates/core/src/error.rs:141`), and 18 is `FirstUse`. A reader
writing a wrapper from the doc would handle the wrong code. Fix the number; consider whether 14
("the realisation moved", CAKEYS.md) is the right code for a filesystem refusal at all (see
Design). [read]

### F2. `--module` overrides are not validated — practice

`crates/cli-common/src/lib.rs:83-88`.
`module_overrides` accepts `=path`, `token=` (empty path) and an override naming a token
keys.toml does not have; a repeated token silently keeps the last. A typo
(`--module sofhsm=/path`) is a silent no-op and the run uses keys.toml's module, which on a host
with several builds of one module is the wrong library with no warning. A malformed override is
an `anyhow` context error, so it exits 1 rather than 2 (usage) or 17 (invalid config) as
CAKEYS.md's table would suggest. Fix: reject empty halves and duplicates in a clap
`value_parser`, and have `Opener::load` refuse (17) an override naming no keys.toml token.
[read]

### F3. The embedded profile set is parsed twice when `profileDirs` is set — nit

`crates/cli-common/src/lib.rs:44-50`.
`activate_profiles` builds `Set::embedded()` to learn the built-in names, then `Set::activate`
builds it again. Every embedded profile (and the baseline) is parsed twice per run. Return the
added names from `Set::activate` (or compare against the active set's own provenance) instead.
[read]

## Design

- 14 for an unwritable lock (`read_lock`, `:196`) overloads "precondition failed: the
  realisation moved", whose documented remedy is "after review". A distinct reading (17 for a
  sandboxed run, 1 for a filesystem permission) would keep 14 for identity changes only. Not a
  bug: the code is frozen (DESIGN §10) and the message is explicit.
- The guard file is `<lock path as given>.lck`, created next to the path the user typed
  (`core::config::lock_for_update`); two spellings of one lock through a symlink take different
  guards, and `write_whole`'s rename replaces a symlinked lock with a regular file. That is in
  core (for the core reviewer); `read_lock` is where the CLI could canonicalise the path once.
- `Opener` owning `cfg`, `modules` and `registry` beside the verb's `&mut lock` resolves Q14's
  borrow problem cleanly; caprobe, whose config is optional, still uses the free functions.

## Checked, no issue

- Q14 (Done): `Opener::load` (overrides, config, activation), `open`/`open_quiet`, `read_lock`
  (unwritable check before the guard, guard before load) and `save_changed` exist and are what
  cakeys uses.
- Q24 (Done): `activate_profiles` is the one activation path, with or without `profileDirs`, and
  names the profiles the directories added.
- `main` prints notes before the error line, so a failure never loses them; `downcast_ref` finds
  a `KmError` under `anyhow` context, so contextualised errors keep their code.
- `default_registry` registers code providers before p11-kit, the order detection relies on.
- `read_lock` takes no guard for a reading verb; reads see a whole lock thanks to the rename in
  `save_lock`.
