# Review: crates/profile/src/lib.rs (442 lines)

Reviewed 2026-11-18 [read]. Summary: the profile `Set` (embedded files plus directories), the
process-global active set (`OnceLock`), and lookups by name, family and manufacturer. Small and
readable; the Q24 fix is in place and correct. Findings are edge cases of directory loading.

## Findings

### F1. `collect` follows symlinked directories with no cycle guard — risk

**Verification:** confirmed (downgraded to nit). lib.rs:243-252 does follow links via `is_dir()`, but no stack overflow occurs: Linux stops path resolution after 40 symlinks (ELOOP), so `is_dir()` turns false at depth 41 (a link to an ancestor nested exactly 40 deep, checked in a scratch dir), and each `.toml` is collected 41 times, which `adding_dir` reports as "already loaded" (:107-109). Two such links would make the walk exponential (2^40), a hang rather than an abort. [run]
`crates/profile/src/lib.rs:243-252`. `path.is_dir()` follows symlinks, so a `profileDirs` entry
(keys.toml, runtime) containing a link to an ancestor recurses until the stack overflows (an
abort, not an error with exit 17). Unlikely in a Nix store path, possible in a hand-made dir.
Use `entry.file_type()` (does not follow) or track canonical paths.
[read]

**Fixed (2026-11-18):** `collect` reads each real directory once, so a link to an ancestor ends and a second link to a directory already read loads nothing twice. Test: `a_symlink_loop_in_a_directory_ends`.

### F2. A baseline added from a directory is accepted and then never used — practice

`crates/profile/src/lib.rs:95-100` and `:178-180`. `with_dir` (caprobe's `--profiles`) pushes a
directory's baseline after the embedded one, but `baseline()` always returns the first, so
`caprobe supports --profiles dir` with a newer baseline in `dir` silently answers against the
embedded one. The doc says selection "comes with phase 2". Either refuse a baseline in `with_dir`
as `adding_dir` does, or let a loaded baseline replace by name.
[read]

**Fixed (2026-11-18):** a directory's baseline replaces the loaded one of its name and is the one answered with; one of another name is refused. Test: `a_directory_baseline_is_used_or_refused`.

## Design

- Q24's `OnceLock` makes `activate` once-per-process; any in-process caller of
  `caprobe::main_from` or a CLI `main` that runs twice in one test binary gets "already in use".
  Today only one such test exists (`caprobe/tests/template_hook.rs`). Worth a line in the doc of
  `main_from`.
- caprobe holds two sets at once: the active one (for opening tokens) and a local
  `profile_set(--profiles)` for `supports`/`--diff` (`caprobe/src/lib.rs:205`), so a `--profiles`
  directory affects answers but not the token's resolved stack. Probably intended; not stated.

## Checked, no issue

- ISSUES.md Q24 (Done 2026-11-17): `Set::active` errors when nothing activated it (`:127-133`);
  `activate` refuses a second activation (`:146`); `activate_embedded` repeats, returning
  whatever is active (`:157-163`, race-free via `get_or_init`); cli-common activates with or
  without `profileDirs` (`cli-common/src/lib.rs:40-50`). The pinning test exists and is the only
  activating test in this crate's unit-test binary.
- `adding_dir` refuses baselines, non-`observed` profiles and any name already loaded, including
  a duplicate within the same directory or across two directories.
- Directory order is sorted, so replacement is deterministic.
- `find`: exact name first, then family; several versions is an error naming them.
