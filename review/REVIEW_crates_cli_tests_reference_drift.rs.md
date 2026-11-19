# Review: crates/cli/tests/reference/drift.rs (537 lines)

Reviewed 2026-11-18 [read]. Summary: conflicts and drift. Policy mismatch, duplicate labels and
IDs (12), wrong key type, downgrades (14), undeclared policy drift and a replaced object (14),
`CKA_ALLOWED_MECHANISMS` and `publicAttributes`, the H1/H1b swaps, an unrecorded token (S3), a
`publicOnly` flip (S4), and a retargeted spec (S8). Each scenario is set up on the token directly
and checked by exit code plus a specific reason. No real issues.

## Findings

### F1. Edits made by string replacement on the serialised lock — nit

`reference/drift.rs:93` and `:295` change the lock by replacing text in the TOML that `toml`
serialised (`"\"wrap-rebind\""`; an array spelled over four lines). If the writer's layout changes,
the replacement silently does nothing. `downgrade_is_an_error` would then fail loudly (0, not 14).
`an_undeclared_mechanism_list_is_observed_policy` would also fail, but only on its stderr check.
Editing through `toml::Value` (as `reference/lockfile.rs:95-134` does) is robust. [read]

**Fixed (2026-11-18):** the lock is edited as `toml::Value` (`e.lock()` / `e.write_lock`), the field asserted before it is changed. Tests: `downgrade_is_an_error`, `an_undeclared_mechanism_list_is_observed_policy`.

### F2. Stale "the token is shared between runs" clean-up — nit

`reference/drift.rs:200-206, 264-269`. See common/mod.rs F6. [read]

**Fixed (2026-11-18):** the stale clean-up and its comments are gone (common/mod.rs F6's resolution). No test.

## Design

None.

## Checked, no issue

- `policy_drift_and_replaced_objects_are_refused`: the replaced object keeps its IDs but loses
  `CKA_LOCAL`, so the refusal is shown to come from the immutables, not the material.
- `the_live_object_must_be_what_the_spec_says`: the softhsm and kryoptic branches (`:436-440`)
  assert both outcomes, so neither is skipped silently.
- `a_second_private_key_under_the_same_id_is_ambiguous`: the public-session pass shows the session
  kind recorded in the lock matters.
