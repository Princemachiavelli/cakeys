# Review: crates/cli/tests/references.rs (427 lines)

Reviewed 2026-11-18 [read]. Summary: the cross-reference tests. One keys.toml names every
reference token available (SoftHSM, kryoptic, p11-kit, swtpm), the same imported key identifies
alike on all, swapped keys conflict everywhere, and `create` happens only where `origin` says. The
cross-check means something because the references are independent implementations.

## Findings

### F1. `create_happens_where_origin_says_create` skips without regard to the require variables — risk

**Verification:** confirmed (downgraded to nit). The skip at references.rs:405-408 ignores the require variables, but `xref::env` (common/xref.rs:39-52) already asserts on a missing `CAKEYS_TEST_MODULE`/`CAKEYS_KRYOPTIC_MODULE` when their `*_REQUIRE` is set, and both are set in the Nix check (nix/package-common.nix:179, :189) and scripts/local-tests.sh:107, :110; dropping either reference from the environment fails `env()` before this line. The skip can fire only where those variables are deliberately unset. [read]
`references.rs:405-408`. It returns early, with only a printed note, unless both SoftHSM and
kryoptic are present. In the Nix check both are required elsewhere, so today it runs. A change that
drops one reference from this binary's environment (for example test-tokens.sh's per-test set)
would remove the test silently. Assert when `CAKEYS_TEST_REQUIRE` and `CAKEYS_KRYOPTIC_REQUIRE` are
set. [read]

### F2. `assert_one_identity` compares the references only with each other — practice

`references.rs:32-50`. If every reference computed the same wrong identity (a shared cakeys
encoder bug), this test would pass. The oracle comparison is in `reference/identity.rs`, which
covers SoftHSM and kryoptic only. Comparing one value to `oracle_spki` here would cover p11-kit and
swtpm too, at no cost. [read]

### F3. `ptool` duplicated; swap setup repeated — complexity

`references.rs:55-63` equals `tpm2.rs:53-61`. `:372-383` is the fifth copy of the swap-the-private-key
setup (see reference/mod.rs F2). `--userpin` on the command line is accepted in ISSUES.md for test
PINs. [read]

## Design

None.

## Checked, no issue

- `xref::env` asserts each module whose require variable is set, so a missing reference under the
  Nix check fails rather than shrinking the comparison.
- Swapped keys are refused (13) on every reference, not only where the proof runs.

## Resolutions (2026-11-18)

- F2 **Fixed (2026-11-18):** `assert_one_identity` takes a host oracle and checks every scheme it computed, at least one:
  - `rfc7093m4` from the SPKI;
  - the AES commitments, and `commitment` for the secret and HMAC keys;
  - `certhash`;
  - `valuehash`.
  Test: the asymmetric, secret, certificate and data tests in references.rs.
- F1 **Fixed (2026-11-18):** create-on asks for its references through `xref::Env::needs`, and its skip asserts that neither `CAKEYS_TEST_REQUIRE` nor `CAKEYS_KRYOPTIC_REQUIRE` is set.
- F3 **Fixed (2026-11-18):** `ptool` and the swap setup come from common (`ptool`, `swap_private_key`).
