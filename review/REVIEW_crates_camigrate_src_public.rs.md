# Review: crates/camigrate/src/public.rs (225 lines)

Reviewed 2026-11-18 [read]. Summary: the `public` method. A certificate, public key or data object
is read and verified on the source, created on the target under the spec's template, recorded
through `ops::lock_import`, and rolled back by handle. It also holds the helpers the other paths
share (`Moved`, `already_there`, `roll_back`, `origin`). Small, clear and correct. No significant
findings.

## Findings

### F1. `preflight` duplicates `host::free_locator` — nit

`crates/camigrate/src/public.rs:170-184`, `crates/camigrate/src/host.rs:122-135`. See the host.rs
review, F3. [read]

### F2. `value` drops the module's return value — nit

`crates/camigrate/src/public.rs:219-224`. A `C_GetAttributeValue` failure becomes a bare
`Unavailable` with cryptoki's text. The token layer's `ck`/`rv_of` (ISSUES Q3) would carry the
`CK_RV` as the other module calls do. [read]

## Design

None.

## Checked, no issue

- `create_as`: `ops::check_import` and the provider-adjusted template both run before
  `C_CreateObject`. A public key object a key's import already made (`Occupied::public_half`) is
  recorded, not duplicated, and nothing is rolled back for it on failure (`created` empty).
- `material`: a certificate's `CKA_VALUE` is parsed as X.509 before it travels (13 otherwise). A
  public key travels as its canonical SPKI from `Token::spki`, which cross-checks it.
- `already_there`: a pair the lock records is verified, not recreated, so re-runs are no-ops.
