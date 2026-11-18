# Review: crates/p11-fault/src/plan.rs (453 lines)

Reviewed 2026-11-18 [read]. Summary: the fault plan's TOML (`[[rule]]`), validated into one
action per rule, plus per-function atomic call counters and rule matching. Validation is
thorough (unknown fields, functions, names, actions on the wrong function, two actions, `call
= 0`) and well tested. One gap in the "a typo never tests nothing" goal.

## Findings

### F1. Slot flags and token flags are accepted interchangeably and collide by value — risk

**Verification:** confirmed. plan.rs:266-277 resolves every name against the one `names::flag` table and allows the rule on either `C_GetTokenInfo` or `C_GetSlotInfo`; p11-names/src/lib.rs:302-325 lists slot flags (`CKF_TOKEN_PRESENT`, `CKF_REMOVABLE_DEVICE`, `CKF_HW_SLOT`) beside token flags with the same bit values (1, 2, 4), so a slot flag on a token rule sets a token bit with no error. [read]
`crates/p11-fault/src/plan.rs:266-277` with `p11-names/src/lib.rs:293-323`. `set_flags` and
`clear_flags` resolve against one table of slot *and* token flags, and the rule is allowed on
either `C_GetSlotInfo` or `C_GetTokenInfo` whatever the names. The two flag words reuse bits:
`CKF_REMOVABLE_DEVICE` = `CKF_WRITE_PROTECTED` = 2, `CKF_HW_SLOT` = `CKF_LOGIN_REQUIRED` = 4,
`CKF_TOKEN_PRESENT` = `CKF_RNG` = 1. So `fn = "C_GetTokenInfo"`, `set_flags =
["CKF_HW_SLOT"]` silently sets `CKF_LOGIN_REQUIRED`, and the test fires (`"rule"` is set) on
the wrong thing. Split the table into slot and token flags and check the names against the
rule's function.
[read]

## Design

None.

## Checked, no issue

- Counters: `AtomicU64` per function, `Relaxed` is enough (each counter is independent; `n`
  only needs to be unique per call).
- `matching` filters by function and optional call number, numbering rules from 1 as the trace
  reports them.
- `before`/`after`: the first `rv` rule of that timing wins; hook actions do not shadow them.
- `unhex` checks ASCII before slicing, so no char-boundary panic; odd length refused.
- `of_label` only with `attribute`/`use_label`; `when` only with `rv`.
