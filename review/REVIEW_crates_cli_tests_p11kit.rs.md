# Review: crates/cli/tests/p11kit.rs (217 lines)

Reviewed 2026-11-18 [read]. Summary: cakeys through the p11-kit RPC (`p11-kit server` in front of
SoftHSM). The same key reads the same identity through the RPC and directly, what the RPC drops is
refused (15, nothing created), and each client logs in for itself. Sound tests.

## Findings

### F1. `env`/`Env` duplicate the shared gate — complexity

`p11kit.rs:16-43`: see common/mod.rs F5. [read]

### F2. The direct path's module is required with `expect`, not through the gate — nit

`p11kit.rs:35`. With `CAKEYS_P11KIT_MODULE` set and `CAKEYS_TEST_MODULE` unset, the test panics
instead of skipping. That is the right outcome under `CAKEYS_P11KIT_REQUIRE`, but it differs from
the other suites. [read]

## Design

None.

## Checked, no issue

- Each refusal asserts 15 and that nothing was created on the SoftHSM token behind the RPC.
- Identities through the RPC equal the direct path's, so an RPC rewrite of attributes shows.
- `CAKEYS_P11KIT_REQUIRE` is set by the Nix check (`nix/package-common.nix`) and p11-kit is
  started per test by `nix/test-tokens.sh`.
