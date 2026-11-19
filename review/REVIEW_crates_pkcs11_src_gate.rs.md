# Review: crates/pkcs11/src/gate.rs (294 lines)

Reviewed 2026-11-18 [read]. Summary: the static capability gate: a token's profile stack
resolved from keys.toml and the lock without opening it (`stack`), and per-target refusals and
notes (`check`) from `ops::needs`, the provider's templates (`ops::plan_templates`), the proof
and generation rows. It reuses the run's predicates rather than re-implementing them, which is
the right design. Two quiet degradations.

## Findings

### F1. A provider name neither registered nor a profile family silently skips the attestation and template checks — nit

`crates/pkcs11/src/gate.rs:133`, `:150-154`, `:172-185`. `registry.named(&stack.provider)` is
`None` only for a name that is no registered provider and no module profile family
(`Registry::named_in` falls back to `Set::module_family_names`, so an in-tree provider missing
from a minimal build still resolves to its `Data` family and is checked). The case left is a
downstream custom provider (the `custom-provider` example) recorded in a lock that stock cakeys
reads: then `check_attestation` and `plan_templates` are skipped without a note, and an
`attestation = true` spec passes `validate` to be refused only when the token opens. Fix: push
a note when the lookup returns `None`. [read]

**Fixed (2026-11-18):** a provider name no registry entry carries is a note ("provider '<p>' is
not in this build: its attestation and templates are checked only when the token opens"), never
a silent skip. Test: `a_provider_this_build_lacks_is_said`.

### F2. `stack` discards the recorded-answers note when the lock has no module recorded — nit

`crates/pkcs11/src/gate.rs:67-77`. `with_answers` pushes "N answer(s) recorded ... decide
before profile ..." into `resolved.notes`, then `resolved.notes = vec![...]` replaces every note
when `recorded` is `None` (an observation with capabilities but no module/token, e.g. an older
lock). Fix: replace only the notes resolution produced (clear before `with_answers`, or push the
"chosen by provider alone" note instead of assigning). [read]

**Fixed (2026-11-18):** (lead) `stack` keeps the recorded-answers note when the provider-alone
note is added. Test: `the_recorded_answers_note_survives_the_provider_alone`.

## Design

- `check`'s generation verdict uses `t.object.curve` as written in keys.toml (`:205`,
  `on`, `:91-96`); it is canonical after load (core), and `the_profiles_name_every_curve_cakeys_has`
  holds the profile names to core's, so this works; the dependency on load-time
  canonicalization is implicit.

## Checked, no issue

- `stack`: an unknown `tokens.<t>.profiles` entry is a config error (17); several recorded
  observations defer to the open; no provider and no record skip with a reason.
- `check`: a provider's `generation` refusal short-circuits (kmsp11); a profile *no* refuses, an
  *unknown* is a note, per mechanism group and for the generation; the proof's recorded or
  profiled *no* refuses with its evidence.
- `proof_capability`/`generate_capability` build the same keys `ops::answers` records and the
  probe writes (tests `the_profiles_know_every_key_type_and_proof_cakeys_has`,
  `the_profiles_name_every_curve_cakeys_has`).
- `the_gate_asks_the_provider_about_a_generation`: the provider is asked about both halves only
  when creating.
