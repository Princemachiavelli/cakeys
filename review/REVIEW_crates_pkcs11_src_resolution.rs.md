# Review: crates/pkcs11/src/resolution.rs (631 lines)

Reviewed 2026-11-18 [read]. Summary: profile resolution for a token: the binding layer, a
forwarder named by the module, the configured layers, and the module profile of the provider's
family ranked by version, then hardware; notes for every weak match; recorded answers layered on
top (`with_answers`). Q13's split into named steps reads well and is well tested. One silent
tie and one inconsistency between families of one and of several profiles.

## Findings

### F1. Profiles that tie on every match key resolve silently when a token is open — practice

`crates/pkcs11/src/resolution.rs:193-208`, `:356-358`. `module_profile` notes a tie only when
there is no token (`tied.len() > 1 && token.is_none()`, `:200`). With a token, profiles whose
match keys are identical (both `aws-cloudhsm/5.18+hsm2m-*` and both `kmsp11/1.9+hsm*`:
manufacturer, version, model and firmware all equal, checked in `profiles/modules/`) resolve to
`tied[0]` with no note at all, although the `Resolved::notes` doc says "a resolved stack is
never a silent guess". Failure scenario: a NON_FIPS CloudHSM cluster without `moduleProfile`
resolves to the FIPS profile, so an Ed25519 key is refused (15) naming the FIPS profile, and
`caprobe caps` shows no note explaining that a second profile fit equally. docs/CAPROBE.md
documents the tie-break, but the run does not say it happened. Fix: when `tied.len() > 1`, always
note the tie and that `moduleProfile` picks the other; clear the hardware rows only when there is
no token, as now. [read]

## Design

- A family with one module profile and one with several treat an unrecorded module version
  differently. With one candidate, `choose` returns it (`:342`) with `unversioned = false`, so
  `weak_match` only notes "matched by manufacturer alone" and every generate/wrap/unwrap/decrypt
  row stays decisive. With two or more and none at this version, `nearest_version` clears those
  rows as unknown (`:197-199`, `:214-224`). So `softhsm/2.7` decides for a SoftHSM 2.8 module,
  while a tpm2-pkcs11 1.11 module gets nothing decided, and adding a second softhsm profile
  later would silently flip SoftHSM 2.8 to the latter behaviour. The module doc states the
  one-profile rule ("matches by manufacturer alone, flagged low-evidence"), but the two rules
  answer the same question (a version nobody probed) and should be one.
- `with_answers` is applied by the gate and camigrate's plan, never at `Token::open`; ISSUES.md
  B18's "the lock's recorded answers included" is therefore not true of the live token (see
  `REVIEW_crates_pkcs11_src_token_generate.rs.md` F2). Either is defensible; the docs should
  say which consumers see recorded answers.

## Checked, no issue

- Q13 (done 2026-11-17): `resolve` is the named steps (`layer`, `add_forwarders`,
  `add_configured`, `hidden_module`, `module_profile`), and the note texts are as the tests pin.
- `Nearness`: derived `Ord` ranks unknown < above < at-or-below, the highest at-or-below and the
  lowest above nearest (`Reverse`), numeric per component (`1.10 > 1.9`); unit-tested.
- `module_candidates`: a `moduleProfile` naming no observed profile is an error (17 at open).
- `clear_hardware_rows` drops every row the hardware decides, `reported` ranges included.
- `hidden_module`: a passthrough is hidden unless keys.toml names a provider other than the
  passthrough's own family or profile.
