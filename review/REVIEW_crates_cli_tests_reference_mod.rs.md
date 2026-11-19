# Review: crates/cli/tests/reference/mod.rs (136 lines)

Reviewed 2026-11-18 [read]. Summary: the reference suite's own harness: the `Env` gate
(SoftHSM, kryoptic or the fault shim, chosen by the including binary's `REF`), the EC fixture, a
secret-key planter, the swapped-key verdict check, and a module configuration that hides one
mechanism. Small and readable. Its gate and the swapped-key setup are duplicated elsewhere.

## Findings

### F1. `env` re-implements `suite_var` — complexity

`reference/mod.rs:46-51` is `common/mod.rs:49-56` with `REF`'s variables. See common/mod.rs F5.
[read]

**Fixed (2026-11-18):** D9: one `Suite` type replaces each suite's `Env`, `suite_var`/`required_var` are the only skip gates, one `Run` builder starts every tool run, and `ptool`/`ptool_in`/`tpm2_store` and `swap_private_key` replace the copies. Here `env` is `suite_var(REF.module_var, REF.require_var, name)` returning a `Suite`. Test: `the_harness_helpers_are_written_once`.

### F2. The "swap the private key under its locator" setup is written five times — complexity

The same sequence (generate another key pair, destroy the original private key, relabel the new
one) appears at `reference/proofs.rs:150-169`, `reference/proofs.rs:243-261`,
`reference/drift.rs:313-331`, `reference/drift.rs:457-472` and `references.rs:372-383`. Only the
usage bit and the extra attribute (`CKA_PUBLIC_KEY_INFO`) differ. A
`swap_private_key(s, label, usage, extra)` helper here, next to `assert_swapped_key_conflict`,
would make each test show only what it varies. [read]

**Fixed (2026-11-18):** D9: one `Suite` type replaces each suite's `Env`, `suite_var`/`required_var` are the only skip gates, one `Run` builder starts every tool run, and `ptool`/`ptool_in`/`tpm2_store` and `swap_private_key` replace the copies. Here common's `swap_private_key` replaces the five setups (proofs.rs twice, drift.rs twice, references.rs once). Test: `the_harness_helpers_are_written_once`.

### F3. `hiding` is copied out by hand in check.rs — nit

`reference/mod.rs:128-135` against `reference/check.rs:104-107`, which builds the same file
inline. [read]

**Fixed (2026-11-18):** check.rs uses `e.hiding("CKM_AES_CMAC")` instead of an inline copy (reference/check.rs F5's resolution). Test: `scheme_the_token_lacks_is_refused_before_create`.

## Design

None beyond common/mod.rs.

## Checked, no issue

- `assert_swapped_key_conflict` (`:122-126`) pins the exit code (13) and accepts exactly the two
  documented routes (a failed proof, or the `CKA_PUBLIC_KEY_INFO` cross-check), so it cannot pass
  on an unrelated 13.
- `write_lock_keeping_realisations` keeps `realisations` and `observations` together, so a
  hand-written `objects` table never leaves a dangling observation reference.
