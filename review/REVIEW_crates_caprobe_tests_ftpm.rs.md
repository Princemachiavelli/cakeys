# Review: crates/caprobe/tests/ftpm.rs (44 lines)

Reviewed 2026-11-18 [read]. Summary: one opt-in test, the conformance check on the host's real
TPM: a fresh `caprobe probe --write` through tpm2-pkcs11 must reproduce the committed pair
profile (`CAKEYS_FTPM_PROFILE`) byte for byte (`common::assert_profile_conforms`). The header
documents the TPM safety rules well. Its skip logic makes the documented way of running it a
no-op.

## Findings

### F1. The documented `cargo test` command skips the only assertion and reports a pass — risk

**Verification:** confirmed. The header's own command (`ftpm.rs:9-15`) is a plain `cargo test`; the workspace `Cargo.toml` has no `[patch]` (the cryptoki patches are applied only in `nix/package-common.nix:61-66`), so `cryptoki_hmac_types_fixed(false)` (`ftpm.rs:37`; `crates/cli/tests/common/mod.rs:172-180`) prints a skip line and the test passes with nothing compared. Only `scripts/coverage-full.sh:110-122` runs it correctly; the doc comment at `:27-28` concedes "a cargo build skips the diff", which contradicts the header's instructions rather than excusing them. [read]
`crates/caprobe/tests/ftpm.rs:7-14`, `:38-40`. The header's console example runs
`cargo test -p caprobe --test ftpm` from a `nix shell` of tools. Cargo builds use the unpatched
cryptoki (the workspace `Cargo.toml` has no `[patch]`; the HMAC key-type fix is applied only by
the Nix build and `scripts/local-tests.sh`), so `cryptoki_hmac_types_fixed(false)` returns false,
prints a skip line, and the test returns: the user set both opt-in variables, ran the documented
command, and got `ok` with nothing compared. The `require` argument is a literal `false`
(the swtpm twin, `tpm2.rs:35`, passes `CAKEYS_TPM_REQUIRE`). Fix: once the user has opted in
(both variables set), pass `true`, so an unpatched build fails with the message naming the
patch; and change the header to run it through `scripts/coverage-full.sh` (which does,
`:110-126`) or `scripts/local-tests.sh`. [read]

**Fixed (2026-11-18):** once opted in, the test requires the patched cryptoki
(`cryptoki_hmac_types_fixed(true)`), and the header runs it through `nix run .#coverage-full`.
caprobe's two `YubiKey` probes had the same skip and now fail the same way. Test:
`no_opted_in_suite_skips_an_unpatched_build` refuses a literal `false`, and any local copy of
the check, in every test source.

### F2. A partial opt-in is a silent pass — practice

`crates/caprobe/tests/ftpm.rs:31-36`. Setting `CAKEYS_FTPM_MODULE` without
`CAKEYS_FTPM_PROFILE` (or the reverse) skips with a stderr line. Since either variable alone
can only mean the user wants this test, the half-set case should fail. Same pattern as
camigrate's yubikey.rs F2. [read]

**Fixed (2026-11-18):** the opt-in is `opted_in(FTPM_OPT_IN)`: half set or required without variables fails (verified FIXED)..

## Design

- Hardware opt-in skips are hand-written per file; see camigrate's yubikey.rs review (Design).

## Checked, no issue

- The test touches only the harness's fresh store (no persistent handle, NV, AK or wrong PIN),
  as its header says; the probe runs with `--write` on token `ftpm`, which `ftpm_tokens` marks
  `probe = { scratch = true }`.
- `assert_profile_conforms` asserts exit 0 for `--diff`, byte equality after regeneration,
  exit 0 for a read-only diff, 17 for a read-only `--out`, and that the file was not overwritten.
- One probe per run, as `assert_profile_conforms` documents for tpm2-pkcs11 leftovers.
