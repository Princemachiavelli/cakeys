# Review: crates/core/src/types.rs (138 lines)

Reviewed 2026-11-18 [read]. Summary: `ObjectClass` and `KeyType` generated from one macro, each
with its PKCS#11 name as its serde form, `ALL`, `Display` and `FromStr`, plus a few class and
type predicates. Small and correct.

## Findings

### F1. `FromStr`'s error names the Rust type — nit

`crates/core/src/types.rs:33-38`. `"CKK_DES2".parse::<KeyType>()` fails with
"unknown KeyType: CKK_DES2" (`stringify!($ty)`). keys.toml goes through serde (whose message
lists the variants), so this reaches users only through `FromStr` callers (CLI, tests); the
wording should be "unknown key type" / "unknown object class". [read]

## Design

None.

## Checked, no issue

- Serialized names are the PKCS#11 names, round-trip tested; DES2 and single DES are absent on
  purpose (docs/OPEN.md).
- `fixed_value_len` only for DES3 (24), pinned by test; `is_asymmetric` agrees between class
  and key type, which `ObjectCfg::kind` relies on.
