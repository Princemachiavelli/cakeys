# Review: crates/core/src/attrs.rs (143 lines)

Reviewed 2026-11-18 [read]. Summary: one table of the boolean attributes each object class
carries, marked declarable, observed or both, and the `CKA_ALLOWED_MECHANISMS` rule. Clear and
pinned by test (the observed vector is part of every lock). No real issues.

## Findings

### F1. The lint exemption's reason describes a two-variant enum; `Use` has three — nit

`crates/core/src/attrs.rs:30-33`. "the tables read as Both/Declared, cakeys' own two-variant
enum" — `Use` is `Both`, `Observed`, `Declared`, and the tables use `Both` and `Declared`.
Misleading only to the next reader of the exemption. [read]

**Fixed (2026-11-18):** the reason now reads "the tables read as Both/Declared, cakeys' own
`Use` variants".

## Design

None.

## Checked, no issue

- The declared/observed differences are exactly the two the module doc names (`CKA_TOKEN`
  observed only; secret-key `CKA_SIGN_RECOVER`/`CKA_VERIFY_RECOVER` declared only), and the
  test `declarable_differs_from_observed_only_where_documented` checks them.
- Immutables (`CKA_LOCAL`, …) are not declarable; `CKA_ALLOWED_MECHANISMS` only on key classes.
- `observed` returns attributes in table order; the pinned-vector test guards lock stability.
