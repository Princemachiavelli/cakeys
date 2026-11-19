# Review: crates/cli/tests/tpm2.rs (946 lines)

Reviewed 2026-11-18 [read]. Summary: the CLI against swtpm through tpm2-pkcs11. Keys it generates
checked against the DER oracle; refusals for what tpm2-pkcs11 cannot do (15, nothing created);
attestation (`tpm-certify`) recorded and verified, with the AK edge cases; HMAC imports; the object
matrix; the transient primary. Thorough, and it respects the swtpm-only rule in most places. One
block creates a persistent handle without the guard, and several skips ignore the suite's require
variable.

## Findings

### F1. A persistent handle is made outside the swtpm guard — risk

**Verification:** confirmed, and wider than stated. tpm2.rs:458-465 runs `tpm2_createprimary`/`tpm2_evictcontrol … 0x81000018` through a raw `Command`, outside the `on_swtpm()` guard (:446) and bypassing `tpm2_tool`'s assert (:873-874); but the same test already provisions a persistent AK through `cakeys create … attestation = true` at :403 with no guard at all. So only convention (the suite's `CAKEYS_TPM_MODULE` comes from tpm2-test-env.sh) keeps `tpm2_keys_attest_their_tpm_residence` off a real TPM. No shipped script points `--test tpm2` at ftpm-test-env.sh, so risk. [read]
`tpm2.rs:458-465` (`tpm2_keys_attest_their_tpm_residence`). `tpm2_createprimary` and
`tpm2_evictcontrol -C o -c storage.ctx 0x81000018` are run with a raw `Command`. This bypasses
`tpm2_tool` (`:873`), whose `assert!(on_swtpm())` exists for exactly this. It is also outside the
`if on_swtpm()` block above (`:446-455`), which guards only a read-only compare. The file's own
note (`:857-860`) says the suite can be pointed at a real TPM and that state-changing steps run only
on swtpm. `ftpm.rs:17-18` states that "tpm2.rs's attestation tests make persistent ones, so they run
on swtpm only". Failure scenario: someone runs `--test tpm2` with `CAKEYS_TPM_MODULE` set inside
`nix/ftpm-test-env.sh`. The host TPM keeps a new persistent object at 0x81000018 forever (the hardware
rules in docs/DEVELOPMENT.md require persistent handles to be recorded and compared). The shipped
scripts do not do this, since `scripts/coverage-full.sh` runs only `binary(ftpm)`, so this is a
risk, not a bug. Fix: run both through `tpm2_tool`, which asserts swtpm, or put the rest of the test
under `if on_swtpm()`. [read]

**Fixed (2026-11-18):** the attestation test, and every `tpm2_tool` step in it, runs only
on swtpm; the persistent-handle compare runs on every TPM.

### F2. The HMAC attestation half is skipped without regard to `CAKEYS_TPM_REQUIRE` — risk

**Verification:** confirmed (downgraded to nit). tpm2.rs:473 passes `false`, unlike :243, :505, :554. But the scenario (Nix check with an unpatched cryptoki) cannot be silent: those three calls in the same binary, with `CAKEYS_TPM_REQUIRE=1` (nix/package-common.nix:213), and every reference binary's HMAC test would fail loudly at once. Only this one block's skip is quiet. [read]
`tpm2.rs:473`: `if cryptoki_hmac_types_fixed(false)`. Elsewhere in this file (`:243, 505, 554`)
the require flag is passed. Here, an unpatched cryptoki in the Nix check (for example after a
`Cargo.lock` update drops the patch) silently drops the HMAC `tpm-certify` assertions while the
test passes. Fix: pass `std::env::var("CAKEYS_TPM_REQUIRE").is_ok()`. [read]

**Fixed (2026-11-18):** every call, the attestation half's included, is `hmac_types_fixed("CAKEYS_TPM_REQUIRE")`. Test: `no_opted_in_suite_skips_an_unpatched_build`.

### F3. `on_swtpm()` is a D-Bus address substring, and two tests return early on it — risk

**Verification:** confirmed. `on_swtpm` (tpm2.rs:861-863) matches `unix:abstract=cakeys-tpm-`, which only nix/tpm2-test-env.sh:25 produces; every use is a quiet skip (:446, :841, :930) and every `tpm2_tool` call (:937-943) sits after the :930 return, so a rename there drops the object matrix, the AK cases and the handle compare with no failure even under `CAKEYS_TPM_REQUIRE`. [read]
`tpm2.rs:861-863`, used at `:446` (compare), `:841` (`tpm2_object_matrix_is_the_committed_one`
returns early, reported as passed) and `:930` (the AK cases). The detection relies on
`nix/tpm2-test-env.sh` naming its bus `unix:abstract=cakeys-tpm-$$-$PORT`. If that script renames
the bus or stops using abrmd, the object matrix and the AK cases leave CI silently while
`CAKEYS_TPM_REQUIRE` is set. Fix: have tpm2-test-env.sh export `CAKEYS_TPM_SWTPM=1` and check
that; under `CAKEYS_TPM_REQUIRE`, assert `on_swtpm()` instead of skipping. [read]

**Fixed (2026-11-18):** nix/tpm2-test-env.sh exports `CAKEYS_TPM_SWTPM=1`, and `on_swtpm()`
also needs `tpm2_getcap properties-fixed` to report swtpm's vendor strings. The marker on
another TPM, or `CAKEYS_TPM_REQUIRE` without swtpm, fails; a config that asks for attestation
is written only on swtpm. Removing the marker fails 8 tests under `CAKEYS_TPM_REQUIRE`.

### F4. An upstream module bug is the trigger for the failure test — practice

`tpm2.rs:202-213`. `tpm2_identity_failure_after_create_leaves_nothing` relies on tpm2-pkcs11
returning a malformed P-521 point. When the patched module lands, the test fails loudly (the key
then identifies). That is the right direction, but the test's name describes cleanup, not the
module bug. Note the dependency in the doc, or use p11-fault to corrupt the point (`corrupt` rule),
which does not depend on tpm2-pkcs11's version. `:211` asserts without a message. [read]

### F5. Two hand-rolled `cakeys` runs and a duplicated `ptool` — complexity

`tpm2.rs:807-815` and `:905-912` copy `Workdir::km_env` (`common/mod.rs:371`) only to add
`env_remove`. `ptool` (`:53-61`) equals `references.rs:55-63`, and inline variants are at `:509-512`
and `ftpm.rs:126-136`. `env` (`:31-44`) re-implements `suite_var` (see common/mod.rs F5). [read]

**Fixed (2026-11-18):** D9: one `Suite` type replaces each suite's `Env`, `suite_var`/`required_var` are the only skip gates, one `Run` builder starts every tool run, and `ptool`/`ptool_in`/`tpm2_store` and `swap_private_key` replace the copies. Here `env` is `suite_var("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE", ..)` returning a `Suite`, every `tpm2_ptool` run is common's `ptool`, and the two hand-rolled `cakeys` runs are gone (runs go through `km_env`). Test: `the_harness_helpers_are_written_once`.

## Design

- Hardware guards are spread out: `tpm2_tool` asserts, `on_swtpm()` gates, and raw `Command`s
  do neither. One rule ("every `tpm2_*` call goes through `tpm2_tool`") enforced by a grep in
  `surface`-style tests would keep F1 from recurring.

## Checked, no issue

- Every refusal (15) asserts the exit code and that nothing was created on the token.
- Generated keys' identities match the DER oracle, not cakeys' own encoder.
- The attest-store rows edited through rusqlite are only in the per-test store (a token set per
  test), and the transient primary leaves no persistent handle (compared on swtpm).
- 0x81000017/0x81000018 are per-test swtpm handles. The protected 0x81000001/0x81000002/0x81010001
  are never named.

## Resolutions (2026-11-18)

- F4 **Fixed (2026-11-18):** the orphan case truncates a P-256 key's `CKA_EC_POINT` through p11-fault (on token `tpm`, label `orphan-p256`) rather than relying on tpm2-pkcs11's P-521 bug. It expects 13, "removed 2 object(s) just created" and nothing left. Test: `tpm2_identity_failure_after_create_leaves_nothing`. It has not been run on swtpm yet.
