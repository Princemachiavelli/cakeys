# Review of c556ac9 — attestation commitments (§3.7)

Findings from the review of the HEAD commit, ranked by severity. "Confirmed" means traced in the
code; "plausible" means it follows from the code but was not reproduced.

## Fix before merge

### 1. The `tpm-certify` ID is per-device but stored per-object (confirmed)

- The ID hashes the attested Name and the qualified Name. The qualified Name depends on the
  parent, so it differs per TPM (and per token primary). For imported symmetric keys the Name
  differs too: tpm2 import picks a random `seedValue` each time.
- The ID was written into `objects.<name>.ids`, which holds one value per scheme for the whole
  object; the anchor (`attestation.root`) is stored per realisation.
- Failure: realise the same material on a second tpm2 token with `attestation = true`. The
  `commitment` scheme matches, then `tpm-certify` hits `Some(want) => HashMismatch`
  (`crates/pkcs11/src/ops.rs:653`) and exits 10, though the second value is correct for that TPM.
- `tpm2_attested_material_travels_to_a_second_hsm` cannot catch it: its second token is SoftHSM.
- DESIGN §3.7 and the commit message say a copy on a second HSM "was *imported* there: it can
  never attest". That is wrong for TPMs: `TPM2_Certify` certifies imported objects, and the test
  attests a key brought in with `tpm2_ptool import`. `tpm-certify` proves residence in that TPM,
  not on-device generation.
- Fix: keep each realisation's attestation ID on the realisation, beside `root`; the copies link
  through the shared portable scheme.

### 2. "Once locked, a run that cannot attest fails (14)" does not hold (confirmed)

- `resolve` calls `tok.attest(...)?` (`ops.rs:461`) before reconcile, so the provider's own error
  comes back: TPM unreachable / missing PIN / bad store → `Unavailable` (16); no PIV attestation
  certificate → `Unsupported` (15).
- The downgrade check at `ops.rs:566` (14) fires only when `attestation = true` is removed.
- Untested.

### 3. `Store::open` opens the store read-write and can create it (confirmed)

- `crates/tpm2-pkcs11/src/attest/store.rs:83` uses `Connection::open`, contradicting the
  "Read-only" comment.
- A `tpm2Store` / `$TPM2_PKCS11_STORE` / `~/.tpm2_pkcs11` directory without a database gets an
  empty `tpm2_pkcs11.sqlite3`, which tpm2-pkcs11 may later pick up; the user sees "no such table"
  instead of not-found.

### 4. TPM transient objects are never released (confirmed in code; TPM effect plausible)

- `certify_key` never flushes the loaded key (`esys.rs:398`).
- A freshly created AK's transient copy is never flushed after `evict_control` (`esys.rs:98–116`).
- The seal object is flushed only on success; a failed unseal (`esys.rs:148–155`) leaks it.
- Masked by tpm2-abrmd and `/dev/tpmrm0` (flush on disconnect). With `swtpm:port=…` or
  `device:/dev/tpm0` (no resource manager) they accumulate across runs until
  `TPM_RC_OBJECT_MEMORY`.

### 4b. The store reads another token's seal and objects (found while fixing 1)

- `Store::open` looked up `sealobjects` and `tobjects` by `tokid = tokens.pid` — the *primary*
  object's id. Both tables reference `tokens.id` (tpm2-pkcs11 db.c schema). It only worked
  while token 1 sat on primary 1; a second token on the same primary (`addtoken --pid=1`) read
  token 1's rows and failed with "no certifiable store object" (11). Caught by the new
  `tpm2_each_token_pins_its_own_attestation`.

## Medium

### 5. An existing key at the AK handle is reused without validation (confirmed)

- `attestation_key` (`esys.rs:63–67`) accepts whatever is at `0x81000016`. A non-restricted,
  empty-auth signing key there can sign a forged `TPMS_ATTEST`, and TOFU pins it; DESIGN's "a
  restricted key signs only TPM-generated structures" is unenforced.
- Related: `resolve`, `verify` and `check` create a persistent TPM object as a side effect.

### 6. The Yubico intermediate pool admits non-PIV chains (confirmed from the pool's contents)

- `roots/yubico-intermediate.pem` also holds the FIDO, OPGP, SD and YubiHSM attestation CAs;
  `chain_to_anchor` (`crates/ykcs11/src/attest.rs:229`) accepts any of them above the f9 device
  certificate.
- No `basicConstraints` / `pathlen` check (the FIDO CAs carry `pathlen:0`).
- A malicious module could present a YubiHSM attestation chain and have it accepted as
  `piv-attestation`.
- (The pool has no duplicate subject names, so "first name match wins" is harmless today.)

### 7. ECDSA verification ties the hash to the curve (confirmed)

- `verify_signed_by` (`attest.rs:259–279`) accepts `ecdsa-with-SHA256` only from a P-256 key,
  SHA-384 only from P-384, and so on: a P-384 key signing with SHA-256 is rejected.
- `the_yubico_roots_are_pinned` exercises only RSA intermediate→root links.

### 8. The attestation path may not use the module's TCTI or store (plausible)

- Without `tokens.<t>.tcti` it reads tss-esapi's `TPM2TOOLS_TCTI`/`TCTI`, not the module's
  `TPM2_PKCS11_TCTI`; the test harness's `TPM2TOOLS_TCTI` is not even parseable by tss-esapi.
- The store lookup takes the first directory that exists, not the first holding the database.
- For secret keys nothing else ties the certified TPM object to the PKCS#11 object beyond the
  `CKA_LOCAL`/`CKA_EXTRACTABLE` agreement.

## Minor

- With `spki = None` both providers skip the material cross-check silently (`esys.rs:427`,
  `attest.rs:203`); asymmetric classes should require it.
- `AttestationCap.kind` is never read (ops uses `id_kind` / `ATTESTATION_KINDS`): two sources of
  truth. `Certified.key_spki` is unused.
- `resolve` does not check that `Attested.scheme` matches `cap.scheme`.
- The user PIN is kept as a plain `String` on every `Token` (`token.rs:40`), not only on
  attestation opt-ins; neither it nor the unsealed wrapping key / object auth is zeroized.
- `verify_signature` (`esys.rs:299–301`) panics instead of erroring when `r` or `s` exceeds 32
  bytes.
- `from_environment_variable().map_err(|_| …)` (`attest/mod.rs:69`) reports a malformed TCTI
  as "no TCTI".
- `ak_handle` accepts only a lowercase `0x` prefix and reads a bare number as hex.
- The CLI `--scheme` gate adds both attestation schemes regardless of provider; `schemes_on`
  narrows right after, so only the first error message misleads.
- rusqlite's `bundled` feature makes the nix `sqlite` input redundant.
- Opting out of attestation is impossible even under `--update-lock` (the downgrade check is not
  gated on it). Apparently intended; DESIGN should say so.
- PIV certificate discovery (labels, shared `CKA_ID`, minting at session open) is unverified on
  hardware (DESIGN §8.2); other docs read as if verified.

## Resolution (on branch `attestation-commitments`, after c556ac9)

| # | Fix |
|---|---|
| 1 | Attestation IDs moved to the realisation: `attestation = { kind, root, id }`. `objects.<name>.ids` never holds an attestation scheme (17 on load); a realisation with an attestation must also hold a portable scheme (17). Reconcile compares the anchor (14) and the ID (10), both also under `--update-lock`. `resolve` JSON carries the ID in `attestation.id`, not `ids`. New swtpm test `tpm2_each_token_pins_its_own_attestation`. DESIGN §3.7 corrected: `tpm-certify` proves residence, not generation, and attests imported keys. |
| 2 | `ops::attest`: once the lock pins the realisation's attestation, `Unavailable`/`Unsupported`/`NotFound` from the provider become a downgrade (14); `Conflict`/`Ambiguous` keep their codes. Tested (missing AK → 14). |
| 3 | `Connection::open_with_flags(SQLITE_OPEN_READ_ONLY)`. |
| 4 | `flushing()` flushes the loaded key, the seal (on every path) and the AK's transient copy after `evict_control`. |
| 4b | Seal and object rows read by `tokens.id`. |
| 5 | A key at the AK handle must match cakeys' template (attributes, scheme/curve, nameAlg, empty policy) or it is refused (13); tested with a storage primary at 0x81000018. Only `realise` provisions the AK (`AttestCtx::provision`); `resolve`/`verify`/`check` never change the TPM — tested. |
| 6 | `piv_pool` keeps only the PIV and generic intermediates; every issuer must be a CA within its `pathLen` (`issuers_must_be_cas_within_their_path_length`). |
| 7 | ECDSA verification takes the curve from the key and the hash from the signature algorithm (prehash). |
| 8 | TCTI: `tcti`, then `$TPM2_PKCS11_TCTI`, `$TPM2TOOLS_TCTI`, `$TCTI`; TCTI library names reduced to `name:conf` (the swtpm tests now use the harness's `$TPM2_PKCS11_TCTI` with no `tcti` set). Store search mirrors tpm2-pkcs11's `db_for_path` (env unconditionally; then `/etc/tpm2_pkcs11`, XDG data dir, `~/.tpm2_pkcs11`, cwd — each only if the db file exists). |
| minor | SPKI required for asymmetric classes (`AttestCtx::required_spki`); a symmetric/asymmetric mismatch between store and module is 13. `AttestationCap.kind` and `Certified.key_spki` removed (kinds come from `id::attestation_kind`). Provider scheme checked against the capability. PIN kept only when the provider attests, as `Zeroizing<String>`; wrapping key and object auth zeroized. Signature padding errors instead of panicking. TCTI parse errors name their source. `akHandle` requires `0x` and the owner persistent range. CLI `--scheme` gate no longer lists both attestation schemes, and `check <obj>.id.<attestation>` looks at the realisation. Opt-out-is-a-downgrade and the hardware-unverified PIV discovery are spelled out in DESIGN §3.7/§8.2. |
| not changed | rusqlite `bundled` vs the nix `sqlite` input: not redundant — nixpkgs' Rust builder sets `LIBSQLITE3_SYS_USE_PKG_CONFIG`, which overrides `bundled` (removing the input fails the link). The comment in `nix/package.nix` now says so. |

## Found on hardware (YubiKey 5C NFC FIPS, firmware 5.7.4, ykcs11 2.7.3)

| Finding | Fix |
|---|---|
| PIV attestation certificates need no login; the code and DESIGN said minting them needs the management key. | Wording corrected (`crates/ykcs11/src/lib.rs`, DESIGN §3.7, §8.2). §8.2 now lists what was verified by hand. |
| `autoCreate` could never work on ykcs11: it generates only after `C_Login(CKU_SO)` with the management key, and cakeys only logged in as the user (raw `CKR_USER_TYPE_INVALID`, 15). | `tokens.<t>.mgmKeyFile`/`mgmKeyEnv` (main's names, from 4e4587c; may be `$NAME`; needs a user PIN, 17). Used only by providers that declare `manages_as_so` (ykcs11), refused (17) elsewhere; read just before generating, zeroized after; user logged out, SO in, step, SO out, user back in. `admin_credential_is_refused_where_the_user_creates_keys`; on hardware `autoCreate` → 10 `got:` → `--update-lock` 0 → `verify`/`check` 0, a wrong SO key 16 with nothing created. |
| ykcs11 places a generated key by `CKA_ID` and ignores `CKA_LABEL`; a labelled locator would generate, then fail to find the key. | `Provider::check_create`: ykcs11 needs a locator of `CKA_ID` alone naming a key slot (01-04, 05-18), else 17 before anything is created (`cka_ids_map_to_piv_slots`). |
| ykcs11's `C_DestroyObject` clears only the slot's certificate and hides the slot's objects for the session; the key stays and is listed again by the next process. `delete` would have claimed success. | `Provider::keeps_destroyed_keys`: `delete` of a key on ykcs11 is refused (15), naming `ykman piv keys delete <slot>`; the cleanup after a failed `realise` says the key is still there instead of "removed". |
