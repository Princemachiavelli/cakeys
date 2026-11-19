# Review: crates/cli/tests/ftpm.rs (159 lines)

Reviewed 2026-11-18 [read]. Summary: opt-in tests against the host's real TPM through tpm2-pkcs11
in the harness's fresh store. Generation, the object matrix against the committed profile, and,
only with `CAKEYS_FTPM_ATTEST=1`, attestation with an AK at 0x81000016. Careful about the hardware.
The header makes a promise about tpm2.rs that tpm2.rs does not keep.

## Findings

### F1. The header's claim about tpm2.rs is false — practice

`ftpm.rs:17-18`: "tpm2.rs's attestation tests make persistent ones, so they run on swtpm only".
`tpm2_keys_attest_their_tpm_residence` makes 0x81000018 without a swtpm guard (`tpm2.rs:458-465`;
see tpm2.rs F1). Someone reading this header could reasonably run `--test tpm2` inside
`ftpm-test-env.sh`. Fix tpm2.rs, or correct the sentence. [read]

**Fixed (2026-11-18):** the header is now true: tpm2.rs's attestation test runs only on the suite's swtpm (tpm2.rs F1). Test: `tpm2_keys_attest_their_tpm_residence`.

### F2. No require variable: a misconfigured hardware run passes empty — practice

`ftpm.rs:39-45`. Opt-in by design. `scripts/coverage-full.sh` runs `binary(ftpm)` and records
which suites ran, but if `CAKEYS_FTPM_MODULE` is not exported into the nextest run, all three tests
pass having skipped. A `CAKEYS_FTPM_REQUIRE` set by coverage-full would make that a failure. [read]

### F3. `ptool`-style import inlined; `env`/`Env` copied — nit

`ftpm.rs:126-136` and `:26-51`: see tpm2.rs F5 and common/mod.rs F5. [read]

## Design

None.

## Checked, no issue

- No wrong PIN is ever sent (the store's PIN 1234 is the harness's own), and the AK at 0x81000016
  is made only under `CAKEYS_FTPM_ATTEST=1` with a printed skip otherwise.
- `--test-threads=1` is documented in the header and used by coverage-full (`--test-threads 1`).
- No persistent handle, NV index or the protected handles are touched outside the opt-in attest
  test.

## Resolutions (2026-11-18)

- F2 **Fixed (2026-11-18):** the opt-in has a require variable (`CAKEYS_FTPM_REQUIRE`, `OptIn::require`); set alone, it fails. Test: `a_half_set_opt_in_fails` (validate.rs).
- F3 **Fixed (2026-11-18):** the inline `tpm2_ptool` import uses common `ptool`.
