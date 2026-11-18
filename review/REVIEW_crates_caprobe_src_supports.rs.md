# Review: crates/caprobe/src/supports.rs (132 lines)

Reviewed 2026-11-18 [read]. Summary: the `supports` query: picks a module profile (by
`--profile`, or a keys.toml token's `moduleProfile`/`provider`), stacks the binding layer and
`--layer`s on it, and asks the effective-support algebra; the outcome maps no to 15 and unknown
to 16. Short and correct for `--profile`; `--token` answers over a different stack than the
token's own resolution.

## Findings

### F1. `supports --token` leaves out the token's configured layers — bug

**Verification:** confirmed. supports.rs:96 passes `token.profiles` only to `find_module`'s `+hardware` suffix match, and the stack (:103-109) holds the binding layer and `--layer`s only, whereas token resolution pushes each configured name (`add_configured`, pkcs11/src/resolution.rs:167-175), and core/src/config.rs:143-148 documents `profiles` as delta layers to compose. [read]
`crates/caprobe/src/supports.rs:88-110`; `crates/pkcs11/src/resolution.rs:167-175`.
For `--token t`, the token's `profiles` (keys.toml delta layers) are used only to choose a
`+hardware` pair in `find_module` (96); they are never pushed onto the stack, which holds the
binding layer and the command line's `--layer`s only (103-109). Token resolution
(`resolution::add_configured`) and `cakeys validate` (`gate::stack`) do compose them. Scenario:
`tokens.t = { provider = "softhsm", profiles = ["p11-kit/0.26"] }` (a configured layer, e.g. for
a proxy cakeys cannot detect) — `caprobe supports --token t CKM_EDDSA` answers yes from SoftHSM's
profile, while `cakeys validate` refuses an EdDSA commitment on that token with 15, naming
p11-kit. The same holds for a site layer added under `--profiles`. Separately (lib.rs F1), the
set searched omits `profileDirs`, and the lock's recorded module and answers are not consulted.
Fix: build the stack for `--token` with `gate::stack(name, cfg, &lock)` (or the same
`resolution` steps), adding `--layer`s on top; if keys.toml's layers are deliberately ignored,
say so in the `--token` help. [read]

### F2. The hardware-pair fallback matches by name suffix — nit

`crates/caprobe/src/supports.rs:74-85`.
`find_module` falls back to a family member whose name ends with `+{layer}` for any layer named,
which is a naming convention rather than the `[match]`/hardware relation resolution uses
(`choose`); a layer called e.g. `fips` would pick `aws-cloudhsm/5.18+hsm2m-fips` only if the
names happen to align. Acceptable for a query tool, but a comment pointing at the convention
(D10: pairs named `<module>+<hardware>`) would help. [read]

## Design

- `supports` is the operator's view of what the gate decides; giving it its own reduced
  resolution (F1, lib.rs F1) is the drift risk. `gate::stack` already produces the stack the gate
  uses from keys.toml and the lock without opening a token.

## Checked, no issue

- B15 (Done): `--token` takes `moduleProfile` before `provider` (91).
- The binding layer is always first and an explicit `--layer cryptoki/0.12` is not added twice
  (106).
- `outcome`: any no is 15 before any unknown is 16, as documented; an unknown class lists the
  baseline's classes in its 17.
