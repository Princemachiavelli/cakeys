# Review: crates/ykcs11/src/lib.rs (347 lines)

Reviewed 2026-11-18 [read]. Summary: the ykcs11 provider: PIV slot placement check for `create`,
refusal of key deletion, the `CKA_DERIVE` repair, the probe's scratch-slot guard, and the
`piv-attestation` hook that finds the slot and f9 certificates and hands them to `attest.rs`.
Small, clear, and touches only the `Provider` surface. One detection risk.

## Findings

### F1. `matches` claims every Yubico module, YubiHSM 2's included — risk

**Verification:** confirmed. yubihsm-shell's `pkcs11/yubihsm_pkcs11.c` defines `YUBIHSM_PKCS11_MANUFACTURER "Yubico (www.yubico.com)"` and `YUBIHSM_PKCS11_LIBDESC "YubiHSM PKCS#11 Library"` for `C_GetInfo` (GitHub master, fetched, so the "from memory" caveat is settled); `select_in` takes the first registered provider whose `matches` is true before any profile family is consulted (provider.rs:744-746), and ykcs11's test is `starts_with("Yubico")` (ykcs11 lib.rs:101-103). Only an explicit `provider` avoids it (provider.rs:732). [read, run]
`crates/ykcs11/src/lib.rs:101-103`. `m.manufacturer.starts_with("Yubico")`. To my knowledge
(not verified here: no yubihsm-shell in the store) `yubihsm_pkcs11` reports the same
`manufacturerID`, "Yubico (<https://www.yubico.com>)", as ykcs11 (the ykcs11 profile's `[match]` records
exactly that string, `profiles/modules/ykcs11/2.7.toml:41`). Auto-detection would then put a
YubiHSM 2 under the ykcs11 provider: `manages_as_so` demands an SO credential for every create
and destroy, `create` refuses any locator that is not a PIV slot `CKA_ID` (17), key deletion is
refused with `ykman piv keys delete` advice (15), and `CKA_DERIVE` is forced true on EC keys.
The user would have to know to set `provider = "generic"`. Also match `C_GetInfo`'s library
description (ykcs11's is, from memory, "PKCS#11 PIV Library (SP-800-73)"; the profile does not
record it), which `ModuleInfo::description` already carries, or the profile's `model`. [read]

**Fixed (2026-11-18):** `matches` also requires the description "PKCS#11 PIV Library"; both
libraries' `C_GetInfo` strings read from their binaries [run]. Test: `only_the_piv_module_is_ykcs11`.

### F2. A failed `CKA_LABEL` read is silently skipped — nit

`crates/ykcs11/src/lib.rs:230-233`. `Err(_) => None` drops the certificate from consideration
without saying why; if every read fails the user gets "no attestation certificate … imported keys
have none", which misattributes a module error to the key's origin. Map the error to
`Unavailable` like the other reads in this function. [read]

**Fixed (2026-11-18):** `read_attribute`, as tpm2-pkcs11's attest mod F1, makes a failed
`CKA_LABEL` read unavailable (16) with the module's `CK_RV`; the `CKA_ID` and `CKA_VALUE` reads
go through it too, so they now carry the `CK_RV` as well. Test:
`a_failed_attribute_read_is_unavailable`.

## Design

- §4(b) holds for this crate: it imports only `cakeys_core`, `cakeys_pkcs11::{Token, provider::*,
  token::ModuleInfo, ChainTime}` and cryptoki/x509 types; outside its own crate only
  `cli-common`'s registration and the fuzz target reference it.
- `check_create` and `keeps_destroyed_keys` are `pub` inherent methods, but every caller is in
  this crate (`create`, `destroy`, tests). They could be private, keeping the crate's public
  surface the `Provider` impl and `fuzzing`.

## Checked, no issue

- `piv_slot` (`:211-218`): one hex byte, 01–04 → 9a/9c/9d/9e, 05–18 → 82–95; `0x82 + (n - 5)`
  cannot overflow for n ≤ 0x18; f9 (0x19) and multi-byte IDs refused. Tested.
- `find_attestation_cert` requires exactly one certificate under the key's `CKA_ID` whose label
  has a non-empty slot suffix; `find_device_cert` exactly one with the bare label; several are
  `Ambiguous`, none `Unsupported`. Both reach `attest.rs`, which does all verification on the host.
- `attest` requires the material SPKI (`required_spki`), so an asymmetric key is never attested
  without the cross-check; `ChainTime` passed through unchanged.
- `scratch_occupant`: only ykcs11's self-issued serial-0 placeholder for that slot, optionally
  with that slot's attestation, counts as scratch; unparsable DER, other subjects, or a bare
  attestation do not. Tested against real fixtures.
- `repair`: short-circuits so the key-type closure is read only for `CKA_DERIVE` reported false.
- Lazy anchors/pool: `expect` only on embedded, build-pinned files (`build.rs`).
