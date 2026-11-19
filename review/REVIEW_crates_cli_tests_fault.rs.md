# Review: crates/cli/tests/fault.rs (424 lines)

Reviewed 2026-11-18 [read]. Summary: the reference suite runs a third time through p11-fault, and
on top of that the shim's own contract is tested (tracing, stacking tagged copies), along with
cakeys' answers to a lying module: each lie refused with its exit and reason, ECDH and OAEP
fallbacks counted call by call, and a failed creation undone or reported. These tests discriminate
well: every row pins exit, reason and "the rule fired", so a regression that refuses for another
reason or never reaches the faulted call fails. Two claims made in comments are not checked.

## Findings

### F1. "A refused run changed the lock" cannot fail: no row writes the lock — practice

`fault.rs:282, 291`. The lock bytes are compared after all rows, but every row is a `verify`
(`:208`) or `create … --no-update-lock` (`:218`). Neither ever writes keys.lock, refused or not.
The assertion passes with a broken refusal path. The test's point (a lie never reaches the lock)
needs at least one `lock --update-lock` row and one `create` row that would update the lock. [read]

### F2. "Never a second key made" is not counted — nit

`fault.rs:392-399`. The comment claims that when the new key vanishes from every search, "never a
second key [is] made", but the test asserts only exit 11 and the message. A retry that generated
again would also end in 11 ("vanished") and pass. Count the objects labelled `new` (with the shim
off), as the "kept" case does with `left()` (`:390`). [read]

### F3. OAEP's exit 16 is decided by the module, not by the rule — nit

`fault.rs:351`. The rule refuses only the first `C_DecryptInit` (`call = 1`). Whatever happens to
the two later hashes (the module refusing them, or a decryption under the wrong hash failing the
proof) decides the 16, not the rule. A module that behaves differently there changes the exit, and
the test fails although cakeys is right. The discriminating part is `inits == 3`. Refuse every call
(drop `call = 1`) to make the exit independent of the module, or comment on the coupling. [read]

### F4. Trace lines matched by a JSON substring — nit

`fault.rs:346`: `l.contains("\"fn\":\"C_DecryptInit\"")` depends on the shim writing JSON without
spaces. A format change fails loudly (0 calls), not silently. `fired` (`:236-242`) already parses
the lines, and this could too. `drop(w)` at `:69` is a no-op. [read]

## Design

- The fault suite is where the "a test that cannot fail" check matters most, and it is mostly
  right: `!fired(&trace).is_empty()` per row (`:289`) makes each refusal attributable to its lie.
  Asserting only "not empty" is enough here because exit and reason are also pinned.

## Checked, no issue

- `the_shim_traces_and_fails_what_its_plan_says`: exactly one rule fired, on `C_GetSlotList`.
- The by-name generation test counts generations = 1 (`:423`), so the ISSUES.md B18 fix ("Done
  2026-11-17", no retry on a refused name) would fail on the old retry.
- The ECDH fallback asserts the exact fired counts (6, 1).
- `lying()` gates on `P11_FAULT_MODULE` with `CAKEYS_FAULT_REQUIRE`, which `nix/test-tokens.sh:78`
  sets for this binary, and test-tokens.sh leaves `fault/*` untraced so the plan here is the only
  one.

## Resolutions (2026-11-18)

- F1 **Fixed (2026-11-18):** the lock bytes are compared after every row. The write-protected row is `create --update-lock`; three lies also run as `lock --update-lock`. A closing unfaulted `create --update-lock` shows the lock does change on a write. Test: `a_lying_module_is_refused`.
- F2 **Fixed (2026-11-18):** the hidden case counts one `C_GenerateKeyPair` in the trace and 4 objects labelled `new`. Test: `a_creation_that_cannot_be_identified_is_undone_or_reported`.
- F3 **Fixed (2026-11-18):** the OAEP and unwrap rules refuse every call. Test: `an_oaep_proof_tries_the_next_hash_only_when_refused_before_it_began`.
- F4 **Fixed (2026-11-18):** `calls()` parses the trace's JSON, and the no-op `drop(w)` is gone. Test: as F3.
