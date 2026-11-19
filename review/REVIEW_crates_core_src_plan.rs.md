# Review: crates/core/src/plan.rs (446 lines)

Reviewed 2026-11-18 [read]. Summary: the static plan of a (spec, token) pair — `Target`, its
schemes, the binding and its validity, the assurance table, declared-attribute shape, the
identity mode, and the commitment order. Logic is right and the strength orders are pinned;
the binding check has one hole for contradictory `publicOnly` settings.

## Findings

### F1. `publicOnly` silently overrides a configured `pop-ecdh`/`pop-decrypt`/`pop-unwrap` — practice

`crates/core/src/plan.rs:88-90`, `:162-164`. `binding(t)` returns `TokenAsserted` whenever
`publicOnly = true`, and `check_binding` refuses only the combination with
`binding = "pop-sign"`. `publicOnly = true, binding = "pop-decrypt"` (or `pop-ecdh`,
`pop-unwrap`) matches none of the later arms (they all test `binding(t)`, now `TokenAsserted`)
and passes `plan_mode`; the realisation is recorded `token-asserted`, `assurance = public`, while the
author asked for a proof. Fix: refuse any `Some(b)` with `b != TokenAsserted` under
`publicOnly`, as for `pop-sign`. [read]

**Fixed (2026-11-18):** `check_binding` refuses (17) any configured binding other than
`token-asserted` beside `publicOnly`, with the message pop-sign already had ("publicOnly cannot
prove possession (binding = …)"); DESIGN.md and CONFIG.md say so. Test:
`public_only_refuses_every_configured_proof`.

### F2. The Ed448 check matches curve strings, one of which can no longer occur — nit

`crates/core/src/plan.rs:165`. `t.object.curve == "edwards448" || == "Ed448"`: keys.toml
curves are canonicalized at load (`ObjectCfg::canonicalize`), so `"Ed448"` never reaches here,
and the check bypasses the `ObjectKind`/`Curve` parse that load already did. Fix: match
`t.object.kind()` (or `Curve::from_cfg`) against `Curve::Ed448`. [read]

**Fixed (2026-11-18):** the check matches the parsed `ObjectKind` against `Curve::Ed448`.
Test: `ed448_cannot_prove_by_signing`.

### F3. `plan_mode` re-parses the object type and re-wraps its error by hand — nit

`crates/core/src/plan.rs:258-261`. `ObjectCfg::kind()` already ran for every object at load;
here it is called again and its `Validation` re-prefixed, while an `Unsupported` is passed
through unprefixed. Either store the parsed `ObjectKind` on the object at load, or prefix both
kinds the same way. [read]

**Fixed (2026-11-18):** `plan_mode` parses the kind once and prefixes any error kind with the
target (`KmError::prefixed`), then hands the kind to `check_binding`. Test:
`a_refused_object_type_names_its_target`.

## Design

- `plan_mode` holds static checks (binding, attribute shapes, `publicOnly`, attestation class,
  identity mode) that depend on keys.toml alone yet run only when a pair is planned (exit 17
  from a verb), not at load. See REVIEW config.rs F5: running `plan_mode` for every pair in
  `parse_config_with` would give one place where keys.toml is refused.
- `Target::schemes` (`:57-69`) and `plan_mode` (`:277-313`) both derive "which commitments"
  from the same inputs by separate code paths (`declared_commits` vs the `(Some(all), d)`
  match). They agree today; a shared `fn identity(t) -> (Mode, Vec<Commit>)` would make that
  structural.

## Checked, no issue

- Assurance table matches the replay analysis; `tpm-certify` upgrades any class to `Proof`.
- Binding rules: `pop-sign-pin` is never configurable; `pop-ecdh` only on Weierstrass EC with
  `CKA_DERIVE`; `pop-decrypt`/`pop-unwrap` only on RSA with their usage bit;
  `CKA_ALWAYS_AUTHENTICATE` only with `pop-sign`.
- Commitment order (CMAC, KCVs, KW; DES3 KCVs only) pinned by test, and `declared_commits`
  narrows by a declared `CKA_ALLOWED_MECHANISMS` before the mode is chosen.
- `Target::new` returns `NotFound` / `Validation` as documented; transport detection compares
  the token's `transportWith` with the spec name.
