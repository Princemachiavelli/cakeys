# Review: crates/pkcs11/src/provider.rs (875 lines)

Reviewed 2026-11-18 [read]. Summary: the `Provider` trait (repairs, the template hook,
replaceable operations, probe-only hooks), its request types (`Template`, `Declared`,
`Create`, `Destroy`, `ImportCtx`, `AttestCtx`), `ChainTime` (B8), `Generic`, `Data` and the
`Registry` with selection. The trait is small and well documented, defaults are plain PKCS#11,
and selection is tested. Findings are documentation drift and an edge of `ChainTime`.

## Findings

### F1. `Data`'s doc names aws-cloudhsm as a data provider — nit

`crates/pkcs11/src/provider.rs:641-643`. "`softhsm`, `kryoptic` and `aws-cloudhsm` are these."
aws-cloudhsm is a code provider crate (`crates/aws-cloudhsm`, `repair` and `stand_in`;
docs/ARCHITECTURE.md "Providers"), registered by `cli-common`, so a real run selects the code
provider, never `Data("aws-cloudhsm")`. The unit test at `:850` selecting `Data` for CloudHSM is
right only because that registry has no aws-cloudhsm provider. Fix: drop aws-cloudhsm from the
sentence. [read]

**Fixed (2026-11-18):** the sentence names `softhsm` and `kryoptic`.

### F2. `ChainTime::now` takes a clock before 1970 as the epoch, silently — nit

`crates/pkcs11/src/provider.rs:580-583`. `duration_since(UNIX_EPOCH)` failing becomes
`At(0)`, so every chain is "not yet valid" with no hint that the clock is the problem. A
pre-epoch clock is rare; see the design note for the realistic variant. Fix: return an error
(or a note) naming the system clock. [read]

## Design

- B8's `check` judges attestation chains by the system clock (`ChainTime::now`). The NixOS
  module runs `cakeys check` as a unit other services require (`nix/module.nix`,
  `requiredBy`), typically early in boot; on a machine without a battery-backed RTC before time
  sync, "now" is far in the past and a YubiKey attestation chain fails as not yet valid, keeping
  the dependent service down. The check's failure message (in `cakeys-ykcs11`) should name the
  clock, and the module docs should say to order the unit after `time-sync.target` when
  attestation is used, or point at `--ignore-validity`/`--at`.
- `AttestCtx::chain_time` (and `Token::chain_time`) default to `Unchecked`: see
  `REVIEW_crates_pkcs11_src_token_mod.rs.md`, Design (fail-open default).
- `impl dyn Provider` (`:309-366`) is where `repair`'s single enum hook is unpacked into typed
  helpers (`ec_point`, `key_type`, `policy_flag`): a repair returning another variant is ignored
  silently. Acceptable for in-tree providers; a debug assertion would catch a provider bug.

## Checked, no issue

- `ChainTime::parse` uses der's RFC 3339 parser (UTC `Z` only), errors are 17.
- `Registry::select_in`: explicit name first (code provider, `generic`, or a profile family;
  a profile name is refused), then the first matching code provider, then a single family by
  manufacturer, several families refused; tested.
- `Registry::named` errors when no profile set is active (Q24), never "no such provider".
- `Attributes` keeps one attribute per type (`set` replaces in place); tested.
- `ImportCtx` has no `Debug` (it carries plaintext and the PIN).
- `AttestCtx::required_spki` refuses an asymmetric class without SPKI.
- `keygen_mechanism` covers exactly the parameterless generations `Generation` and `BoundKey`
  name.
