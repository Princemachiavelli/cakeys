# Review: crates/caprobe/tests/template_hook.rs (61 lines)

Reviewed 2026-11-18 [read]. Summary: ISSUES.md §4(c)'s test that the write probes make their
scratch secret keys through `Provider::template`. It runs `caprobe::main_from` in-process on
SoftHSM with a provider that refuses every secret-key generation template, then asserts the
RSA proofs ran and that no `wrap.rsa-oaep.*` row was written. The idea is right; the decisive
assertion is an absence with no control, and the in-process entry point can run only once per
process.

## Findings

### F1. The only decisive assertion is an absence, with no control in the same run — risk

**Verification:** confirmed (downgraded to practice). The decisive check is the absence at `template_hook.rs:60`, and the probe writes an unasserted note for any missing transport/AES key (`crates/caprobe/src/probe.rs:728-731`), so the cause is not pinned; but the transport key is the 2048-bit one at either `--rsa-max-bits` (`probe.rs:1114-1119`), wrap probes vanishing for another reason would also fail `tests/reference.rs`'s conformance against the committed SoftHSM profile, and the hook bypass itself makes wrap rows appear and fails this test, so masking needs two regressions at once. [read]
`crates/caprobe/tests/template_hook.rs:59-60`. The test passes when
the profile has no `wrap.rsa-oaep.` row. That is also the outcome if the wrap probes do not run
at `--rsa-max-bits 2048` for any other reason (a size gate on the transport key, a refactor
that skips wrap probes when an earlier probe fails, a mechanism filter). The header points at
the committed SoftHSM profile as the control, but that profile is generated with
`--rsa-max-bits 4096` (`common::assert_profile_conforms`), not this command line. ISSUES.md
records a [run] mutation check from when the test was written; nothing keeps it true later.
Fix: also assert the probe's note naming the refusal (the provider's message, "the test
provider refuses secret-key generation", or whatever undetermined line the probe writes for
the missing AES key), so the absence is shown to come from the hook; or add a control run with
the default registry and the same arguments that does write `wrap.rsa-oaep.SHA-1` (as a
subprocess of `BIN`, see F2). [read]

**Fixed (2026-11-18):** a control run of the binary with the default providers and the same arguments must write `wrap.rsa-oaep.SHA-1` yes; the provider also records the move probes' templates. Test: `the_write_probes_make_their_secret_keys_through_the_provider` (not run).

### F2. `main_from` can be called once per process, a trap for the next in-process test — risk

**Verification:** confirmed (downgraded to practice). The chain is as described: `main_from` (`crates/caprobe/src/lib.rs:160-185`) → `activate_profiles` (`crates/cli-common/src/lib.rs:40-43`) → `Set::activate`, whose `ACTIVE.set` fails the second time (`crates/profile/src/lib.rs:141-147`); but `template_hook.rs:54` is the only `main_from` caller in any test, so nothing fails today. A latent trap, the residual edge of ISSUES.md Q24 (marked Done). [read]
`crates/caprobe/tests/template_hook.rs:52`; `crates/caprobe/src/lib.rs:160-185`;
`crates/cli-common/src/lib.rs:40-43`; `crates/profile/src/lib.rs:141-147`. `main_from` activates
profiles through `cli_common::activate_profiles`, which calls `Set::activate`, which fails ("the
profile set is already in use") when the process-global set is already active. This binary has
one test, so it works. A second `main_from` test added here (for instance the control run of
F1) passes under nextest (a process per test) and fails under `cargo test` (one process, the
second activation refused with 17), or the reverse depending on which runs first.
`Set::activate_embedded` (ISSUES.md Q24) is repeatable but is not what `main_from` calls. Fix:
document on `main_from` that it may run once per process, or let `activate_profiles` accept an
already-active set that equals the one it would build. [read]

**Decided (2026-11-18):** the header documents one `main_from` per process and why the control is a subprocess; the fix belongs in caprobe's lib.rs (another owner)..

## Design

- `caprobe::main_from(registry, args)` exists so tests can inject a provider in-process, but
  the global profile `Set` makes it single-use. Passing the active set (or the registry with its
  set) through `main_from` instead of a `OnceLock` would make in-process tests independent; this
  is ISSUES.md Q24's remaining edge.

## Checked, no issue

- ISSUES.md §4(c) "Done" spot-check: the test exists and runs the probe in-process with a
  provider whose `template` refuses `Template::Generate(_, Half::Key)` for secret keys only; the
  positive assertion (`prove.pop-unwrap.CKK_RSA.1024 = yes`) shows the write probes did run.
- Skip via `suite_var` with `CAKEYS_TEST_REQUIRE`.
- `matches` returns false, so the provider is used only where keys.toml names it.
