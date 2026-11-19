# Review: crates/caprobe/tests/tpm2.rs (40 lines)

Reviewed 2026-11-18 [read]. Summary: caprobe on tpm2-pkcs11 over swtpm: `caps` names the
provider and the EC/AES generation mechanisms, and the committed `tpm2-pkcs11/1.10+swtpm`
profile conforms to a fresh probe. Gated by `suite_var` with `CAKEYS_TPM_REQUIRE`, which the Nix
check sets, and the HMAC-fix skip is tied to the same REQUIRE variable. Small and sound.

## Findings

### F1. `caps` exit code not asserted — nit

`crates/caprobe/tests/tpm2.rs:23`. The JSON is parsed from stdout and the exit ignored. A failing
`caps` prints nothing on stdout, so the `from_str(..).unwrap()` panics and the test still fails,
but with a JSON parse error instead of the CLI's message and code. Fix: keep the `Output`,
assert `code == 0` with `stderr` in the message, then parse. [read]

**Fixed (2026-11-18):** `caps` asserts exit 0 with stderr before parsing. Test: `caps_names_the_provider_and_what_the_module_offers` (not run).

### F2. Mechanism presence checked as a substring of the serialized list — nit

`crates/caprobe/tests/tpm2.rs:25-26`. `caps["mechanisms"].to_string().contains("CKM_AES_KEY_GEN")`
would also match a longer name such as `CKM_AES_KEY_GEN_SOMETHING` if one were listed; comparing
array elements (`as_array().iter().any(|m| m == "CKM_AES_KEY_GEN")`) is exact. Harmless with
today's names. [read]

**Fixed (2026-11-18):** mechanisms compared as whole array elements..

## Design

- None.

## Checked, no issue

- Skips depend on `CAKEYS_TPM_MODULE` with `CAKEYS_TPM_REQUIRE` (set in `nix/package-common.nix:213`
  and `scripts/local-tests.sh:119`), and the HMAC-fix skip uses the same REQUIRE: no silent skip
  in the gated runs.
- The conformance test uses `assert_profile_conforms`, whose checks are byte-exact (see ftpm.rs
  review).
