# Checkpoint: 2026-11-11

Work on the design-review tiers. The lock stays `version = 1`, a draft. Native TPM, PQ and attestation are deferred.

## Committed on main (each passed `nix flake check`, `nix build .#test-nspawn` and the read-only YubiKey verify; IDs unchanged)

| Commit | What |
|---|---|
| fe3fed0 | `pubkeyhash` renamed to `rfc7093m4`; the old name is still accepted as an input alias |
| d0e5a60 | known-gap reproduction tests (H1b, S3, S4, S8) |
| a5f4cfb | SPKI read from key material first; `CKA_PUBLIC_KEY_INFO` is only a cross-check (fixes H1b) |
| 4bce419 | **P0-1** proof of possession, sign path (`crates/core/src/pop.rs`); per-realisation `binding` (`pop-sign` / `token-asserted`); a downgrade exits 14; a failed proof exits 13 |
| 4dc74b8 | **P0-3/P0-4** a realisation record is required (14); `object` and `locator` recorded; a change to object, locator, `publicOnly` or spec digest exits 14 (fixes S3, S4, S8, S9) |
| 9e93589 | **P1-5/P1-6** `version` required; realisation split into compared fields, `observed` and `provenance` |
| e63e5ca | **P1-7** full boolean `policy` vector and `immutables`; drift exits 14; a weakened immutable exits 14 even with `--update-lock` |
| 4b9d88b | **P1-8** load invariants (17): SRI syntax, label syntax, one object per material, `pairs`, per-realisation `schemes` (computing fewer is a downgrade) |
| 7f1b3a1 | **P1-9** `serial=` in the URI; with a login, a second private key under the same CKA_ID exits 12; `observed.session` recorded |
| f221638 | `pairs` survive lock split and join (an absent partner is allowed); `binding` required for private-key realisations only |
| f20025a | **P2-10 digest shape** typed `AttrValue`, `certificateType` on certificates, canonicalized curve aliases, `publicAttributes`, `CKA_ALLOWED_MECHANISMS` (read-only once set; joins the policy vector when observed), cert digest pin changed |
| 9db72a4 | **P2-10 non-digest** per-class attribute validation (17), every settable boolean, certificate policy attributes, `CKA_ALWAYS_AUTHENTICATE` refuses pop-sign (17), `CKA_TRUSTED` refuses autoCreate (17), templates/category documented as unexpressible |
| 7e17eae | **P0-1 remainder** `pop-ecdh` (CKM_ECDH1_DERIVE into a non-extractable session secret, HMAC on both sides) and `pop-decrypt` (host RSA-OAEP-SHA1 challenge — SoftHSM implements no other OAEP — token decrypts); all pop-* share rank 0; capability per binding validated (17) |
| c0f1496 | **M3** exclusive std file lock on `<lock>.lck` across `--update-lock` runs' read-modify-write; readers never take it |
| ea57f7a | **D3** `gc` prints stale table names (`realisations.<spec>.<token>` whose spec or token is gone, `objects.<name>` absent from the config); `gc --apply` removes exactly what it printed; live objects keep their ids |
| 1463327 | **S15** DESIGN §3.1 scheme-strength table per class + deprecation policy: `DEPRECATED_SCHEMES` (empty, pinned), reconcile warns on deprecated locked schemes, `--update-lock` never records a new identity under one; AES order pinned |
| 3177781 | (user) `CHECKPOINT.md`, `reports/` and `research_notes/` committed — resolves the commit-or-gitignore question |
| 4032ca5 | **Docs pass + diagrams** staleness fixes (pop-decrypt is OAEP-SHA1; H1 fixed for every pop-*; locking/GC exist; new unit pins named) and `docs/diagrams.md` (5 Mermaid views: model, realise lifecycle, binding tree, schemes, Nix loop — all render via mermaid-cli); PLAN TODO list added |
| e8c2c78 | **D1** autoCreate refused up front (14) when the lock already pins the object's material; `ec_lifecycle` tail and the VM caveat reworked; `autocreate_never_fights_a_locked_identity` |
| f4f4a59 | **config** `$NAME`/`${NAME}` path references in `pinFile`/`module` (unset or malformed → 17 at load, naming it); every spec's `object` reference validated at load; the flat spec layout kept (config is a graph; answer recorded here 2026-11-12) |
| 4e4587c | **RW YubiKey** `mgmKeyFile`/`mgmKeyEnv` (admin credential: hex mgm key, or the PIN on PIN-protected-mgm devices — the SO login then also verifies the PIN, so generate + pop-sign work in one unattended run); provider `login` hook; opt-in `tests/yubikey.rs` (scratch slot `0x95`, full lifecycle, every run bounded — no touch needed, checked on hardware first); production slots untouched, re-verified 6/6 |
| db51e74 | **Nix API** one calling convention: `keys.<object> { token?, spec?, scheme? }` → plain data (`id`, `uri`, `mode`, `specDigest`, `module`, `tokenInfo`, `functions`, `rsf`, `check`); call-time resolution errors; `check`/`id`/`type`/`rsf` stay usable before first lock |
| c556ac9 | **P2-11 attestation** (branch `attestation-commitments`) `piv-attestation` (Yubico chain verified on the host to embedded roots) and a native `TPM2_Certify` `tpm-certify` (tss-esapi + the module's sqlite store, cakeys-provisioned AK), always beside a portable scheme; `attestation = true` opt-in; swtpm tests |
| b9eecc3 | **Attestation review fixes** (ISSUES.md): attestation IDs per realisation (`attestation = { kind, root, id }`; anchor 14, ID 10); a lost attestation is a downgrade (14); TPM store read-only, found like tpm2-pkcs11, rows by `tokens.id`; transients flushed; AK validated, provisioned only by `realise`; module TCTI by default; PIV pool PIV-only with CA/pathLen checks; ECDSA hash from the signature; PIN/secrets zeroized |
| 1b9c1f4 | **ykcs11 on hardware** (YubiKey 5C NFC FIPS, fw 5.7.4): the admin credential used only around the SO step (user out, SO in, generate, SO out, user back), refused (17) on providers that create as the user, needs a user PIN (17); creation needs a `CKA_ID`-only locator naming a PIV slot (17); `delete` of a key refused (15, ykcs11 would keep it); attestation certificates need no login |
| 57287ef | **Merge** `attestation-commitments` into main: main's `mgmKeyFile`/`mgmKeyEnv` names with the branch's SO-scoped rules (the `login` hook replaced by `manages_as_so`/`check_create`/`keeps_destroyed_keys`); `tests/yubikey.rs` opts into attestation and expects `delete` → 15; RW suite passed on the device, and generation with the PIN as SO credential checked by hand on 9a |
| a6ae39d | **Lock writes by default** (user decision 2026-11-12): `realise`/`delete` write the lock unless `--no-update-lock` (`--update-lock` = the explicit default; both → usage error); writes still only fill gaps; refused (14) up front, before any token, inside a Nix build sandbox (`NIX_BUILD_TOP` without `IN_NIX_SHELL`) or with an unwritable lock/directory (`access(2)`); `check`/`verify`/`resolve` unaffected; test harnesses clear `NIX_BUILD_TOP` |
| 6a599ff, 3e5d06f | **Refactor R0/R1** (docs/REFACTOR-2026-11-12.md): `scripts/xversion.sh` cross-version lock check (c58cb2b-recorded locks of every class verify, compare and re-record byte-identically); `LazyLock` anchors, `Lock::realisation`, mechanism names computed once, `Display` for `Target`/`Locator`/`Immutables`/`ObjectCfg` in messages |
| 3e26201 | **Refactor R2**: one boolean-attribute table (`cakeys_core::attrs`: per class, declarable vs observed; one macro row per attribute maps it to cryptoki); observed vectors pinned |
| 6715c81 | **Refactor R3**: one signature verifier module (`cakeys_core::sig`: ECDSA raw/DER over every supported curve, Ed25519, RSA PKCS#1 v1.5 generic over the digest) behind pop, the PIV chain and the TPM AK; ykcs11/tpm2 drop direct p256/p384/p521/rsa deps |
| ea2fa0e | **Refactor R4**: edition 2024, `rust-version = 1.89`, let chains at eleven sites; `load_config_with` takes the env lookup (no `set_var` in tests) |
| 72a373a | **Refactor R5**: typed `ObjectClass`/`KeyType` (serde-renamed, digests unchanged) and `Scheme` (lock maps stay `String`-keyed); unknown class/key type now 17 at load (was 15 at use); YubiKey read-only verify 6/6 |
| a1f7c76 | **Refactor R6**: core returns only `KmError` (`Io` variant, exit 1, with the file named); `anyhow` only in the CLI |
| 5394c10 | **Refactor R7a**: the spec-only model (`Target`, `plan_mode`, binding and attribute checks, declared commitments) moves to `cakeys_core::plan`; `ObjectCfg::{curve, checked_key_type}` |
| ea130db | **Refactor R7b**: `cakeys_core::reconcile` (`compare` + `record`, `LockWrite`, `Facts`); `Notes` replace the library `eprintln!`s and print on success and error; `Observed.session` is an enum; four HSM-free lock-rule unit tests; YubiKey read-only verify 6/6 |

## Done (uncommitted; passes the local gate): (empty — next task below)

- Notes kept for reference: this YubiKey's mgm key is PIN-protected (fw 5.7), so `mgmKeyFile` may name the PIN file; `yubikey_data/piv_mnmgt_key.current.txt` holds the hex key read from the device (2026-11-12) — `piv_mnmgt_key.txt` is for another device. ykcs11 cannot erase a PIV key (`C_DestroyObject` clears only the slot's certificate; the next session lists the key again), so `delete` refuses (15); `ykman piv keys delete <slot>` erases on fw 5.7 — with `certificates delete`, pass `--no-update-chuid` to keep the CHUID.

## Then (follow-up commits)

- **P3 ops, by user decision (2026-11-12), in order — all three done:**
  - **M3 (committed c0f1496):**
  - **D3 (committed ea57f7a):**
  - **S15 (committed 1463327):**
- **PLAN TODO additions:** attestation (P2-11), native TPM, PQ/kryptic.
- **Final report to the user:**
  - Answer the in-toto/Terraform question. Neither manages or identifies PKCS#11 or TPM objects: in-toto hashes artifacts and signs metadata; Terraform's lock hashes provider packages. The securesystemslib PKCS#11 signer point is unverified recall.
  - ~~Ask whether to commit or gitignore `reports/` and `research_notes/`~~ — committed by the user (3177781).
  - **Tell the user:** stock tpm2-pkcs11 1.10.1 cannot sign with P-521 keys at all (C_SignInit → CKR_HOST_MEMORY). The upstream patch fixes it, and `upstream/tpm2-pkcs11/PR.md` is corrected. Their signed commit in `~/srcs/tpm2-pkcs11` could gain one line about it.

## Notes

- **Local test loop:** `export SCRATCH=/tmp/opencode SOFTHSM2_CONF=$SCRATCH/shsm/softhsm2.conf HOME=$SCRATCH` (tokendir `$SCRATCH/shsm/tokens`), `CAKEYS_TEST_MODULE=<softhsm in the devshell>/lib/softhsm/libsofthsm2.so`, then `cargo test --test softhsm -- --test-threads=1`. A failed run leaves objects on the shared token: `rm -rf $SCRATCH/shsm/tokens` and re-init (`softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678`) before rerunning. `hmac_key_types…` fails locally because cryptoki is unpatched; that is expected.
- **YubiKey verify:** build the binary to a scratch link (`nix build .#default -o $SCRATCH/cakeys`), because `./result` gets replaced by the nspawn build.
