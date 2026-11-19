# Review: crates/core/tests/refusals.rs (626 lines)

Reviewed 2026-11-18 [read]. Summary: table-driven tests of what keys.toml, the lock, the
planner, PKCS#8 parsing and the proof verifiers refuse, plus a few small views and tables. The
tables are broad (every binding, both sides of most rules, every branch of the lock's pair and
transport-key invariants) and the file has no skips, sleeps or temp state. Its main weakness is
that most refusals are identified only by a substring of the message, not by exit code, while
exit codes are cakeys' stable contract.

## Findings

### F1. Most refusal tables pin message prose and never the exit code — practice

`crates/core/tests/refusals.rs:30-38` (`refusal` returns only `e.to_string()`), used by
`:72-75`, `:343-346`, `:402-405`; also `token_and_creation_rules_are_checked_at_load`
(`:134-137`) and `what_create_never_makes_cannot_say_origin_create` (`:423-424`). About 60 cases
assert `said.contains(why)` with no code. Several of them are documented as a specific code:
`what_create_never_makes_...` says "(17 at load)" (`:408`), and the table at `:63`/`:70`
(`CKO_SECRET_KEY/CKK_EC`, `CKO_SECRET_KEY/CKK_RSA`) is an unsupported pairing, 15 by
`every_object_is_typed_at_load`'s own rule (`:79-80`). A change from 17 to 15 (or to 1 through
a stray I/O-style error) passes, while rewording a message fails. `refusal` also cannot tell a
load-time from a plan-time refusal, though some rules are documented as load-time. Fix: make
`refusal` return `(exit_code, message)` and the tables carry the expected code, as
`every_object_is_typed_at_load` (`:84-96`) and `lock_objects_keep_their_invariants`
(`:456-459`) already do; keep a short `why` only where the code is shared by several rules. [read]

**Fixed (2026-11-18):** `refusal` returns the exit code with the message and `refused_with`
asserts both; the mixed table carries each case's code (17 invalid, 15 a type cakeys does not
manage), the tables of one code assert it, and `what_create_never_makes_...` checks its
documented 17. Mutation-checked: the unsupported curve as 17 fails the table.

### F2. A weak substring makes one lock case match any `publicKey` error — nit

`crates/core/tests/refusals.rs:225`. The case (a `publicKey` with only a `certhash` ID) expects
`"publicKey"`, which every `publicKey` refusal contains, including the two below it (`"is not
base64"`, `"hashes to"`). If the rule "publicKey needs an rfc7093m4 ID" were removed and the
value then failed the hash check, this case still passes. Fix: match the rule's own wording
(whatever `check_public_key` says for a missing `rfc7093m4`). [read]

**Fixed (2026-11-18):** the case matches "publicKey without an rfc7093m4 ID".

### F3. `Target::new` on an unknown spec checks only `is_err` — nit

`crates/core/tests/refusals.rs:107`. The neighbouring cases match the variant and message; this
one would pass on any error. Fix: `matches!(e, KmError::NotFound(_))` (or whatever it is). [read]

**Fixed (2026-11-18):** `NotFound` naming the spec; the undefined object's case also asserts 17.

### F4. `the_value_length_bound_is_inclusive` duplicates properties.rs — nit

`crates/core/tests/refusals.rs:619-626` vs `crates/core/tests/properties.rs:353-359`. Same
bound; this one is the better test (both edges). See properties.rs F6. [read]

**Fixed (2026-11-18):** the duplicate in properties.rs is gone; this test also asserts exit 17. Test: `the_value_length_bound_is_inclusive`.

## Design

- Exit codes are the contract (docs/CAKEYS.md, `KmError::exit_code`), messages are not; the
  core refusal tests mostly pin the opposite. A shared helper `assert_refused(result, code,
  why)` in a core `tests/common` (with lock_mbt.rs/properties.rs fixtures, see lock_mbt.rs F4)
  would make the code the primary check everywhere.

## Checked, no issue

- `refusal` panics when a spec is accepted (`:35`), so a rule that stops refusing fails the
  test rather than passing vacuously.
- `pairs = ["c1", "elsewhere"]` (`:468`) loading is intended: `check_pairs` skips a name the lock
  does not hold (`config.rs:1070`), and docs/LOCK.md:281 says pairs are "mutual where both sides
  are present".
- ISSUES.md "Transport keys" (Fixed since): the "token naming a spec not realised on it" case is
  present (`:170-174`) and reaches that branch of `check_transport_keys`.
- `what_create_never_makes_...` re-loads each case with `origin = "adopt"` (`:425`), proving the
  refusal is specific to `create`.
- `load_lock` on a directory is exit 1 (`:237-238`), not an empty lock.
- No skips, sleeps, temp dirs or global state in this file.
