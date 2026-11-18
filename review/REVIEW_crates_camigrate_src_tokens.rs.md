# Review: crates/camigrate/src/tokens.rs (891 lines)

Reviewed 2026-11-18 [read]. Summary: the bridge between tokens, profiles, the lock and the
planner. It builds a `Side` from a live token, the lock's observation, or a transport file. It
asks providers about the templates a move sends, collects the materials to plan, makes and
checks the transport key, and runs `plan_moves`. Logic is sound. The main problems are errors
turned into "absent", and the transport-key rule kept in three copies.

## Findings

### F1. Resolution errors are swallowed and reported as something else — practice

`crates/camigrate/src/tokens.rs:52` (`side_from_lock`: `resolution::resolve(…).ok()?`), `:80`
(`side_from_transport`: same), `:581-584`. A profile that fails to resolve (a malformed profile
directory, two families claiming one manufacturer) turns into `None`. For the lock path the user
then sees the token's open error. For a transport file they see "provider '…' is not in this
build", which is false: the provider is linked, its resolution failed. Return the `Result` and
only map "no provider" to `None`. [read]

### F2. The transport-key rule exists in three places — complexity

`crates/camigrate/src/tokens.rs:440-457` (`transport`: RSA private, `CKA_UNWRAP`, not
`CKA_EXTRACTABLE`, from the lock's policy), `:669-698` (`transport_spec`: the same three, from
the lock), and `crates/core/src/config.rs:1614-1640` (`check_transport_keys`, from keys.toml).
`transport` is always reached through a spec that `transport_spec` already accepted, except from
`camigrate transport` without `--trusted` (lib.rs:284-287), which goes `transport_named` →
`tokens::transport`. One `is_transport_key(lock, spec, token)` used by both, with
`transport` calling it, would keep the camigrate copies in step. [read]

### F3. "Which realisation is the source" is decided twice — nit

`crates/camigrate/src/tokens.rs:409-418` (`materials`: the first realisation of the object on the
token, in spec order) and lib.rs:1484-1488 (`realised_target`: the first such spec keys.toml still
has). The two agree unless a spec in the lock is gone from keys.toml. Then `materials` plans from
one realisation's policy, and the move reads the other's. That is unlikely, since one object has
one material, but the plan and the run could name different specs. [read]

## Design

- The capability side has three sources (token, lock observation, transport file) with one
  shape (`Side`), which is the right design. Note that the transport file's `provider` and
  `mechanisms` are not covered by its `rfc7093m4`, so they are unauthenticated planning input.
  An edited file can change the planned method or hash, though never the key it seals to (that is
  `pinned`, once lib.rs F3 is fixed).

## Checked, no issue

- `plan_moves` blocks sealed plans when the transport key is unnamed or unrealised, when the
  target is planned from the lock without a recorded `publicKey`, or when a transport file is not
  pinned by the lock.
- `template_refusal`: source session keys under the export's own `shares_kek` condition, and the
  target's unwrap or create template, public half, import KEK and proof or commitment session
  keys. The test pins the order and the first-refusal stop.
- `locked_transport` re-checks the recorded key's size.
- `Moves::ready` gives 15 with every blocked object's reasons.
