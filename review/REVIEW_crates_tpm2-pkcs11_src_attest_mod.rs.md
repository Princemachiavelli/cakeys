# Review: crates/tpm2-pkcs11/src/attest/mod.rs (402 lines)

Reviewed 2026-11-18 [read]. Summary: orchestration of `tpm-certify`: provider options
(`tcti`, `tpm2Store`, `akHandle`), the store directory search, TCTI selection, the version gate,
finding the store row by `CKA_ID`/label/class, and the final `CKA_LOCAL`/`CKA_EXTRACTABLE`
cross-check. Clear and well-tested; findings are minor.

## Findings

### F1. A failed `CKA_LABEL` read silently widens the row search — nit

`crates/tpm2-pkcs11/src/attest/mod.rs:239-245`. `Err(_) => None` drops the label, so the store
row is chosen by `CKA_ID` and class alone. `Store::find` still refuses several matches
(`Ambiguous`), and for asymmetric keys the material cross-check catches a wrong row, but for a
secret key (no SPKI) two rows that differ only by label would turn a module read error into an
`Ambiguous` (12) that names no cause. Propagate the error as `Unavailable`, as the `CKA_ID`
read does three lines above. [read]

**Fixed (2026-11-18):** `read_attribute` makes a failed `CKA_LABEL` (and `CKA_ID`) read
unavailable (16) with the module's `CK_RV`. Test: `a_failed_attribute_read_is_unavailable`.

### F2. The store-search order is a claim about db.c that nothing pins — nit

`crates/tpm2-pkcs11/src/attest/mod.rs:125-166`. The doc says the order mirrors tpm2-pkcs11's
`db_for_path` (`$TPM2_PKCS11_STORE`, `/etc/tpm2_pkcs11`, XDG, `~/.tpm2_pkcs11`, cwd). The `/etc`
directory is a build-time `TPM2_PKCS11_STORE_DIR` in tpm2-pkcs11, which a distribution can
change; a mismatch only makes attestation read another store and fail its cross-checks (no false
pass: `TPM2_Load` and the Name/SPKI checks bind the row to the live object), so the effect is a
confusing error. Say in the error which directory was read, and consider `tpm2Store` required
when the module is not at its default path. [read]

**Fixed (2026-11-18):** the order is the pure `store_candidates`, pinned by a test; the
not-found error lists every directory searched, and `find`'s errors name the store file.
`tpm2Store` stays optional: a wrong store fails the cross-checks, never passes them. Test:
`the_store_is_looked_for_in_the_modules_order`.

## Design

- `Tpm2Options::of` runs twice per attestation (`check_options` at open, again at `:248`) and
  once more in `ptool::import`; harmless, but a provider-owned parsed-options value on the token
  would avoid re-parsing and keep one source of truth.
- The `fuzzing` module is `pub` inside `pub mod attest`, and `attest`, `esys`, `store` are all
  `pub` (`esys::certify_key`, `wrapping_key`, `unwrap_objauth`, `Store::open` …). Only
  `cli-common` (the `Tpm2Pkcs11` provider) and the fuzz targets use the crate, so most of that
  surface could be `pub(crate)`, with the fuzz entry points behind a feature, keeping the
  provider crate's public API the `Provider` impl (ISSUES.md §4(b)'s spirit). Also
  `Certified.local` is `pub` but `extractable` `pub(crate)` (`esys.rs:46-48`).

## Checked, no issue

- `check_version`: only 1.10.x is read; others refused (15) naming the version.
- `ak_handle`: `0x`-prefixed hex in the owner persistent range, validated at token open (17).
- `normalize_tcti`: library names and paths reduced to `<name>:<conf>`; tested.
- The final cross-check compares the module's `CKA_LOCAL`/`CKA_EXTRACTABLE` with the certified
  attributes and is a conflict (13) on mismatch; both reads are required (`Unavailable` if
  absent). (Where those certified attributes are read from: see
  REVIEW_crates_tpm2-pkcs11_src_attest_esys.rs.md F1.)
- `required_spki` is applied, so an asymmetric key is never certified without its SPKI.
- `Attested.root` is the AK SPKI's SRI; `id` is `tpm_certify_id(name, qualified_name)`, the nonce
  kept out (`id.rs`, length-prefixed fields).
