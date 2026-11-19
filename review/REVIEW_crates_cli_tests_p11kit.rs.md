# Review: crates/cli/tests/p11kit.rs (217 lines)

Reviewed 2026-11-18 [read]. Summary: cakeys through the p11-kit RPC (`p11-kit server` in front of
SoftHSM). The same key reads the same identity through the RPC and directly, what the RPC drops is
refused (15, nothing created), and each client logs in for itself. Sound tests.

## Findings

### F1. `env`/`Env` duplicate the shared gate — complexity

`p11kit.rs:16-43`: see common/mod.rs F5. [read]

**Fixed (2026-11-18):** D9: one `Suite` type replaces each suite's `Env`, `suite_var`/`required_var` are the only skip gates, one `Run` builder starts every tool run, and `ptool`/`ptool_in`/`tpm2_store` and `swap_private_key` replace the copies. Here `env` reads both modules through `suite_var` under `CAKEYS_P11KIT_REQUIRE` and returns a `Suite`; the file's own `Env`/`Deref` is gone. Test: `the_harness_helpers_are_written_once`.

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

## Resolutions (2026-11-18)

- F2 **Fixed (2026-11-18):** the direct module (`CAKEYS_TEST_MODULE`) goes through `suite_var` under `CAKEYS_P11KIT_REQUIRE`, as the client does, no longer an `expect`. Test: every p11kit test's `env`.
