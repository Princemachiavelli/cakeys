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

## Done (uncommitted; compiles and passes the local gate): (empty — next task below)



## Then (follow-up commits)

- **P3 ops, by user decision (2026-11-12), in order — all three done:**
  - **M3 (committed c0f1496):**
  - **D3 (committed ea57f7a):**
  - **S15 (committed 1463327):**
- **PLAN TODO additions:** attestation (P2-11), native TPM, PQ/kryptic.
- **Final report to the user:**
  - Answer the in-toto/Terraform question. Neither manages or identifies PKCS#11 or TPM objects: in-toto hashes artifacts and signs metadata; Terraform's lock hashes provider packages. The securesystemslib PKCS#11 signer point is unverified recall.
  - Ask whether to commit or gitignore `reports/` and `research_notes/`.
  - **Tell the user:** stock tpm2-pkcs11 1.10.1 cannot sign with P-521 keys at all (C_SignInit → CKR_HOST_MEMORY). The upstream patch fixes it, and `upstream/tpm2-pkcs11/PR.md` is corrected. Their signed commit in `~/srcs/tpm2-pkcs11` could gain one line about it.

## Notes

- **Local test loop:** `export SCRATCH=/tmp/opencode SOFTHSM2_CONF=$SCRATCH/shsm/softhsm2.conf HOME=$SCRATCH` (tokendir `$SCRATCH/shsm/tokens`), `CAKEYS_TEST_MODULE=<softhsm in the devshell>/lib/softhsm/libsofthsm2.so`, then `cargo test --test softhsm -- --test-threads=1`. A failed run leaves objects on the shared token: `rm -rf $SCRATCH/shsm/tokens` and re-init (`softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678`) before rerunning. `hmac_key_types…` fails locally because cryptoki is unpatched; that is expected.
- **YubiKey verify:** build the binary to a scratch link (`nix build .#default -o $SCRATCH/cakeys`), because `./result` gets replaced by the nspawn build.
