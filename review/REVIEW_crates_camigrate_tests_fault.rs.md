# Review: crates/camigrate/tests/fault.rs (159 lines)

Reviewed 2026-11-18 [read]. Summary: camigrate with the p11-fault shim in front of SoftHSM as
the source or target of a move: ten single-call faults (KEK generation, transport-key load,
each wrap/unwrap, creation, the proof or commitment after import, a lying certificate type),
each asserted by exit code, a message substring, the trace showing exactly one rule fired, an
empty target locator and unchanged lock bytes; then a refused clean-up and a no-fault control.
Well built: the "rule fired once" check makes a misplaced call-count rule fail loudly rather
than pass for the wrong reason.

## Findings

### F1. The source side is never checked for leftovers — practice

`crates/camigrate/tests/fault.rs:135-145`. For the four `out` cases (softhsm is the source, the
fault hits its KEK generation, transport-key load or wraps) the test checks the *target*
(kryoptic) is empty and the lock unchanged, but not that the source token holds only what it
held before. A KEK or a loaded transport key created as a token object and not destroyed on the
error path would pass. `SessionObject` should make that impossible (ISSUES.md Q5/Q6), and this
is the test that would show it. Fix: snapshot the source's object list (as
`common::xref::objects` does for the dry-run twin) before each case and compare after. [read]

### F2. The no-fault control checks only the exit code — nit

`crates/camigrate/tests/fault.rs:154-158`. "With no plan, the same moves then succeed" asserts
exit 0, not that the lock now records the realisation or that `cakeys verify` accepts it, as
dry_run.rs does after every ready move. A shim that broke the move silently (exit 0, nothing
recorded) would pass here, though `tests/fault.rs` in cli covers transparency. Fix: add `cakeys
verify --spec <o>-dst` per move. [read]

### F3. Call-number rules depend on the implementation's call count — nit

`crates/camigrate/tests/fault.rs:121-130`. `call = 3`/`4`/`6` select one call among the move's
`C_WrapKey`/`C_UnwrapKey`/`C_Sign` calls. An added or removed call (e.g. another proof) moves the
fault to another step. The `fired == 1` and message assertions catch that loudly, so this is a
maintenance cost, not a hole; a comment on each case naming which calls come before it (as
`:123-124` does for unwrap) would make the next fix quicker. [read]

### F4. Workdir setup duplicated a third time — complexity

`crates/camigrate/tests/fault.rs:24-27` repeats `test_dir` + `remove_dir_all` + `create_dir_all` +
the PIN file from `common::Workdir::new` (`crates/cli/tests/common/mod.rs:353-359`) and
`common::xref::env` (`crates/cli/tests/common/xref.rs:66-69`). An `Env::new(name, refs)` in
`xref.rs` would serve this file and `env()`. The `Box::leak` for the env pairs (`:91-93`) is the
same workaround as dry_run.rs F8. [read]

## Design

- None beyond the harness points above.

## Checked, no issue

- Skip: `suite_var` with `CAKEYS_FAULT_REQUIRE`/`CAKEYS_KRYOPTIC_REQUIRE`, which
  `nix/test-tokens.sh:78` and `nix/package-common.nix:189` set; a missing variable fails there.
- A missing trace file reads as empty, so `fired == 1` fails rather than passes when the shim
  is not loaded.
- `km_alone` (no dry-run twin) is deliberate: the plan counts this run's calls.
- The refused clean-up case asserts 16, the "still on the token" message, the object left, and
  the lock unchanged.
- `on_target` reads SoftHSM directly (`real`), not through the shim, so the check sees the token.
