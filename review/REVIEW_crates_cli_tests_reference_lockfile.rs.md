# Review: crates/cli/tests/reference/lockfile.rs (443 lines)

Reviewed 2026-11-18 [read]. Summary: the lock file. Provenance and observations change no verdict
but warn; field classes; load-time invariants (17) and downgrades (14); the `.lck` sidecar
serialising writers; lock writes refused where impossible (Nix sandbox, read-only lock or
directory); the commitment label read from the lock; what the lock pins (type, spec digest,
provenance, unknown schemes). Mostly strong. The sidecar test's "waits" half rests on a fixed
500 ms sleep and cannot fail in the fault-shim binary.

## Findings

### F1. "An updater waits for the sidecar lock" is a 500 ms sleep: vacuous behind the fault shim — bug

**Verification:** confirmed (downgraded to risk). The updater takes `<lock>.lck` before any token work (crates/cli-common/src/lib.rs:194-202), so the 500 ms check (reference/lockfile.rs:241-243) only fails a regression if a whole `lock --update-lock` run finishes inside 500 ms: not behind the fault shim (the test's own note, :225-226) and probably not on kryoptic either (common/xref.rs:217-219 says its login alone takes over a second). The SoftHSM binary can still catch it, so the property is not wholly untested, but detection depends on machine load. [read]
`reference/lockfile.rs:241-245`. The test starts the updater while the test holds `keys.lock.lck`,
sleeps 500 ms, and asserts the updater has not finished. The same test notes (`:225-226`) that "a
debug build behind the fault shim takes over a second" per run. In the `fault` binary, which
includes this suite (`tests/fault.rs:10`), an updater that never takes the lock is still opening
the module, logging in and proving possession at 500 ms. So `try_wait().is_none()` holds and the
test passes with the sidecar lock removed. In the direct SoftHSM and kryoptic binaries it catches a
regression only if a full `lock --update-lock` run finishes in under 500 ms. Fix: time the reader,
which ran the same work while the lock was held (`:227-238`), and assert the updater is still alive
after several times that. Better, have cakeys print a note when it starts waiting for
`<lock>.lck` and wait for that line. [read]

**Fixed (2026-11-18):** an updater that finds `<lock>.lck` held says
`note: waiting for <lock>.lck: another run is updating the lock` before it blocks
(`lock_for_update`'s `waiting`). The test waits for that line, not a timer. An updater that
never takes the lock now fails in all three binaries, the fault one included.

### F2. Exit 1 and the `CAKEYS_CONFIG`/`CAKEYS_LOCK` variables are untested — practice

`reference/lockfile.rs:255-302` (the lock-write cases) and `crates/cli/src/lib.rs:30-33`. No test
in `crates/cli/tests` asserts exit 1 (docs/CAKEYS.md: "I/O or other — the lock unreadable"), and
none sets `CAKEYS_CONFIG` or `CAKEYS_LOCK`, the documented alternatives to `--config`/`--lock`. A
lock that exists but cannot be read (mode 000) and the two variables belong next to the
read-only-lock cases here. [read]

### F3. Comments say first use is 10; the code asserts 18 — nit

`reference/lockfile.rs:250` ("first use is then 10") and `:267` ("first use is 10 and the lock is
not created") contradict `:268-269` (18) and docs/CAKEYS.md (10 is a mismatch, 18 first use). They
are left over from before V3 split the codes. [read]

### F4. The read-only branches skip silently as root — nit

`reference/lockfile.rs:287-290, 297-302`. Skipping is correct (root may write anyway), but nothing
is printed, and a container CI running as root would drop both checks without notice. Print a skip
line. [read]

## Design

- Timing-based concurrency tests with a fixed sleep are calibrated to the fastest configuration.
  This suite runs in three binaries whose speed differs by an order of magnitude (F1).

## Checked, no issue

- `observed_and_provenance_never_change_a_verdict`: stripping `observed`, `observation` and
  `provenance` changes no verdict, a dangling observation is 17, and a wrong ID is still 10. The
  field classes are real.
- `lock_invariants_are_checked`: each mutation goes through `toml::Value`, not text, and the good
  lock verifies again at the end, so the earlier 17s were not caused by a broken fixture.
- `lock_is_written_by_default_and_refused_where_it_cannot_be`: the sandbox case refuses `delete`
  too, and `check` and compare still work there.
- The module path recorded is the canonical file for both a symlink given with `--module` and a
  bare name found through `LD_LIBRARY_PATH`.

## Resolutions (2026-11-18)

- F2 **Fixed (2026-11-18):** `CAKEYS_CONFIG`/`CAKEYS_LOCK` name the files, the flags win over them, and a mode-000 lock is 1. Test: `the_variables_name_the_files_and_an_unreadable_lock_is_an_io_failure`.
- F3 **Fixed (2026-11-18):** the comments say 18.
- F4 **Fixed (2026-11-18):** both root branches print a skip line. Test: `lock_is_written_by_default_and_refused_where_it_cannot_be`.
