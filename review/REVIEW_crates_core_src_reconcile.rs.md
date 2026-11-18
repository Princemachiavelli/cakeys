# Review: crates/core/src/reconcile.rs (1182 lines)

Reviewed 2026-11-18 [read]. Summary: the lock rules — `compare` (type, spec drift, downgrades,
object drift, IDs, realisation present) and `record` (one object per material, object entry,
realisation, observations, pairs). Pure and well unit-tested; the verdict order and the "a write
says what it re-recorded" notes match DESIGN.md §4.2. One real gap: the downgrade and
replacement checks compare against the previous realisation even when it was of another object.

## Findings

### F1. `no_downgrade` judges a retargeted spec by its previous object — bug

**Verification:** confirmed. `compare` calls `no_downgrade` for any realisation of (spec, token), on the write path too, with no `prev.object == t.object_name` test (reconcile.rs:198-206); mode, binding, attestation, lost schemes and `weakened_since` (CKA_LOCAL etc., config.rs:1234-1243) are all judged against the other object's record, while `record` does gate provenance on the object (reconcile.rs:529-532) and DESIGN.md:195-199 says an object change is re-recorded with a note. The s8 test (drift.rs:515-540) only runs `verify`, never `lock`, after retargeting. [read]
`crates/core/src/reconcile.rs:198-207` (and `:257-329`). `compare` runs `no_downgrade(t, r, prev, …)`
whenever the lock has a realisation of `(spec, token)`, with no check that `prev.object ==
t.object_name`. DESIGN.md:194-199/552 and LOCK.md:101 say a spec retargeted to another object
is a keys.toml change that `lock` re-records with a note (`spec_diff` does list
`object 'a' -> 'b'`), and `record` itself already gates provenance on `prev.object ==
t.object_name` (`:529-532`), so the file knows `prev` may be another object. Failure scenarios,
all under `cakeys lock` after pointing spec `s` from object `a` to object `b`:

- `a` was generated (`CKA_LOCAL = true`), `b` was imported (`CKA_LOCAL = false`): refused 14,
  "'b' … was replaced since it was realised … a new object needs a new name" — it has one.
- `a` and `b` both attested under the same anchor: `was.id != now.id` → `HashMismatch` (10),
  a security-event code for two different objects behaving as designed.
- `a` attested, `b` on a spec that dropped `attestation`: "identity downgrade" (14), though
  DESIGN.md:370 says the remedy for stopping attestation *is* a new object name.
- `a` a certificate (`certhash`, `rfc7093m4`), `b` a key: `lost` schemes → downgrade.
The user's only way out is to hand-edit or delete the realisation from the lock. The existing
test (`crates/cli/tests/reference/drift.rs:515`, `s8_a_retargeted_spec_is_a_spec_change`)
retargets between two identical fresh objects and never runs `lock` afterwards, so it does not
reach this. Fix: in `compare`, run `no_downgrade` (and `warn_observed`'s object-specific parts)
only when `prev.object == t.object_name`; or decide explicitly that a (spec, token) slot never
weakens and say so in DESIGN.md, with messages that do not tell the user to rename what they
already renamed. [read]

### F2. `record_object` overwrites a differing `commitmentLabel` — nit

`crates/core/src/reconcile.rs:453-458`. The doc comments (`:445`, `:483-484`) say `record` only
fills gaps and "never overwrites an ID", but a `commitment_label` that differs from the entry's
replaces it while the commitment IDs computed under the old label stay. Today unreachable:
the only producer (`pkcs11::ops::compute_ids`) takes the label from the lock
(`reconcile::commitment_label`), and a different label would have failed `compare_ids` first.
Fix: set it only when `entry.commitment_label.is_none()`, or refuse a change; the unit test
`the_recorded_label_is_the_label_used` (`:1066`) pins the overwrite and would change with it. [read]

## Design

- `compare` and `record` disagree on what `prev` is: `record` treats it as "this (spec, token)
  slot, possibly another object" (provenance gate), `compare` as "this object". The design docs
  describe both a per-slot rule ("a realisation that should stop attesting needs a new object
  name") and a per-object one ("a new object needs a new name"); one sentence in DESIGN.md §4.2
  fixing which one downgrades are judged by would settle F1.
- The lock's write path relies on `compare` having run before `record` (record never compares
  IDs itself). That holds because `record` is private and only `reconcile` calls it; worth a
  comment on `record` so a future caller does not skip `compare`.

## Checked, no issue

- Exit-code order in `compare`: type change (14) before IDs; mismatch (10) before first use (18)
  before "no realisation recorded" (14); first use only when no scheme matched.
- `compare_ids`' shared-scheme rule: a write never attaches IDs that no shared scheme compared
  (`:380-394`), and a scheme added on write is recorded only after another matched.
- Empty `r.ids` cannot slip through as a silent pass: `pkcs11::ops::commits` refuses an empty
  usable set and every `Direct` path inserts an ID; with a hand-edited lock whose object has no
  IDs, `compare_ids` still returns `FirstUse`.
- `binding` Some→None cannot occur for a private key: `check_realisations` requires a binding
  on every private-key realisation and `plan::binding` always returns one, so `publicOnly`
  flips are caught as `pop-*` → `token-asserted` (rank 0 → 1).
- One object per material in `record` (`:494-510`) matches `check_one_object_per_material`
  (certificate `rfc7093m4` exempt in both).
- Observation merge: `append` makes this run's answers win; the key excludes `capabilities`.
- Import without locked IDs is refused before anything is recorded (`:144-156`), files exempt.
