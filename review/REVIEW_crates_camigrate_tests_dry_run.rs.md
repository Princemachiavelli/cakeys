# Review: crates/camigrate/tests/dry_run.rs (2055 lines)

Reviewed 2026-11-18 [read]. Summary: camigrate's cross-reference suite: the export plan matrix,
transport files, the public/sealed/host move matrices ("the dry run's verdict is the outcome"),
bundle tampering, key files, `enforced`, RSA-AES key wrap, the host path's guards and the
refusals around plans. Every move run goes through `common::xref::Env::km`, whose dry-run twin
(`crates/cli/tests/common/xref.rs:131-180`) re-runs it with `--dry-run` first and asserts the
lock, the output file and the named tokens unchanged. Assertions are mostly strong (exit code
plus lock bytes plus token contents plus `cakeys verify`). Weak spots: the host matrix only tests
the rows it already agrees with, one helper bypasses the shared PKCS#11 context, and the file
repeats the same skip block and matrix scaffolding many times.

## Findings

### F1. The host-move matrix skips every row that is not already a ready host move — risk

**Verification:** confirmed. `dry_run.rs:1744-1746` `continue`s on any non-host or non-ready plan without checking the dry run's exit, unlike the sealed matrix (`:648-678`, ready→0, blocked→15 with lock and target unchanged); the only floors are `:1767-1772` (host-raw, tpm2-ptool), none for host-pkcs8. The sealed matrix runs the same kinds of pairs without `--allow-host-plaintext`, so it does not cover a host row wrongly blocked *with* the flag. [read]
`crates/camigrate/tests/dry_run.rs:1737-1746`. For each (key, source, target) the test reads the
dry run's plan and `continue`s unless the method is `host-*`/`tpm2-ptool` *and* `ready == true`.
So, unlike `public_moves_do_what_the_plan_says` (`:337`) and `sealed_moves_do_what_the_plan_says`
(`:650`), it never checks that the dry run's exit agrees with its plan, and never runs a blocked
host row to see it refused with 15 and nothing left. A planner regression that marks a host
row blocked (or picks a sealed method instead) silently drops it from the test; the only floor
is `:1767-1772`, one `host-raw` row when softhsm and kryoptic are present and one `tpm2-ptool`
row when tpm2 is. `host-pkcs8` (the p11-kit rows the doc comment names, `:1694`) has no floor at
all. Fix: run every row as the sealed matrix does (ready → 0, origin, verify; blocked → 15, lock
and target unchanged), and add floors for the methods the doc comment promises (`host-pkcs8`
when p11kit is present). [read]

**Fixed (2026-11-18):** every row runs. The dry run's exit must match its plan; a ready row
moves and verifies, with `host` exposure exactly when its method is a host method; a blocked
row is 15 with the lock and target unchanged. Each floor needs a ready row, and `host-pkcs8`
into p11-kit gained one. The planner blocking `host-pkcs8` now fails the test.

### F2. `plant_trusted_key` initializes and finalizes the module outside the shared context — risk

**Verification:** confirmed (downgraded to practice). `dry_run.rs:1662-1690` does bypass `common::Module` (`crates/cli/tests/common/mod.rs:644-691`), but its caller (`:1542`) holds no session at that point and every supported runner is nextest, one process per test (`.config/nextest.toml`, `scripts/local-tests.sh:130`); ISSUES.md:45 records that plain `cargo test` with tokens "stays unsupported", so the failure needs an unsupported runner. [read]
`crates/camigrate/tests/dry_run.rs:1662-1690`. It calls `Pkcs11::new` + `initialize` + `finalize`
on SoftHSM directly, bypassing `common::Module` (`crates/cli/tests/common/mod.rs:644-691`),
which exists because one holder finalizing a module under another's session crashed parallel
`cargo test` runs (ISSUES.md, "Token suites crash under a parallel cargo test", fixed by that
registry). Under nextest (one process per test, `nix/test-tokens.sh`) nothing else holds the
module, so it is fine today; under a plain parallel `cargo test` with tokens, a concurrent
`open_session` on SoftHSM makes `initialize` fail (`CKR_CRYPTOKI_ALREADY_INITIALIZED`, panic) or
this `finalize` pulls the context from under the other thread. Fix: add an
`open_so_session(module, label, so_pin)` beside `open_session` in `common/mod.rs` that uses
`Module::open`, and use it here. [read]

**Fixed (2026-11-18):** `plant_trusted_key` uses `common::open_so_session` on the shared context. Test: `enforced` test (not run).

### F3. The same skip block and matrix scaffolding repeated across tests — complexity

`crates/camigrate/tests/dry_run.rs:33-37`, `:122-126`, `:387-391`, `:469-473`, `:690-694`,
`:913-917`, `:998-1002`, `:1170-1174`, `:1198-1202`, `:1257-1261`, `:1440-1444`, `:1493-1497`,
`:1590-1594`, `:1953-1957` (the `named` closure plus "needs the softhsm and kryoptic references",
14 times); `:580-588` vs `:1701-1709` (`generates`, `same_token`, the `pairs` cross product);
`:282-284` (`same_token` a third time); `:1007-1010` vs `:1229-1232` (the `refused` closure). A
helper `env_with(name, &["softhsm", "kryoptic"]) -> Option<(Env, [&Ref; 2])>` in
`common/xref.rs` and a `matrix(e, generates)` function here would remove about 100 lines and
the chance that one copy's filter drifts from another's. [read]

**Fixed (2026-11-18):** `Env::needs` (common/mod.rs) replaces the 19 skip blocks; `matrix`, `same_token`, `generates` are written once. Test: the suite (not run).

### F4. Constants and helpers duplicated with the shared harness, one shadowing it — complexity

`crates/camigrate/tests/dry_run.rs:181-182` (`P384_PARAMS`, `ED25519_PARAMS`) are
`common::P384` and `common::ED25519` (`crates/cli/tests/common/mod.rs:543-544`) byte for byte;
`:1922` `P256_PARAMS` is also in `crates/cli/tests/references.rs:396` and
`crates/cli/tests/object_matrix/mod.rs:673`. `:196` defines a local `spki(cert)` while
`use common::*` (`:13`) imports `common::spki(algorithm, key)`, a different function with the
same name; the local one silently wins in this file. Fix: one set of OID constants in
`common/mod.rs` (add P-256), and rename the local helper `cert_spki`. [read]

**Fixed (2026-11-18):** the OIDs are common's `P256`/`P384`/`ED25519`; the local helper is `cert_spki`. Test: the suite (not run).

### F5. `a_move_lands_only_on_an_import_pair` accepts either 15 or 17 for all four runs — practice

`crates/camigrate/tests/dry_run.rs:1182-1187`. Without `--spec` the plan is blocked (15); with
`--spec k-kry` naming an adopt pair the refusal is presumably invalid input (17). The test
allows both codes for every variant, so a regression that swaps them, or turns the `--spec`
case into a blocked plan, passes. The twin only holds dry and real to the same code. Fix:
expect `[15, 15, 17, 17]` (or whatever CAMIGRATE.md specifies) per variant. [read]

**Fixed (2026-11-18):** each run asserts its own code: 15, 15, 17, 17 (camigrate lib.rs: a plan block without names, `Validation` naming the adopted pair). Test: `a_move_lands_only_on_an_import_pair` (not run).

### F6. The dry run's own exit is unchecked in two tests — nit

`crates/camigrate/tests/dry_run.rs:1424-1426` (`oaep-sha256`) and `:1522-1525` (`enforced`'s
`plan` closure) parse the JSON plan and ignore the exit code; `plans[0].ready` is asserted in
the latter but not in the former. The real run and twin cover the outcome, so this is only a
missed cheap check that the dry run's exit and its `ready` agree, as `:337`/`:650` do. [read]

**Fixed (2026-11-18):** both dry runs assert their exit against their plan's `ready`. Test: `sealed_moves_wrap_with_oaep_sha256_between_kryoptic_tokens` (not run).

### F7. Partial token clean-up suggests shared tokens the supported runner does not have — nit

`crates/camigrate/tests/dry_run.rs:1004` ("The tokens are shared with the tests before this
one") and the `clear` calls at `:392-394`, `:475-477`, `:808-810`, `:1880-1882`. Under nextest each
test has its own token set, so these are dead; under a plain `cargo test` they are not enough
(`bundles_are_checked_against_the_lock` and `bundles_carry_every_key_of_an_export` both
`create` `xb-ek1` on SoftHSM via `bundle_keys` without clearing it, so the second to run gets
exit 19). Either drop them and say nextest is required, or clear every label each test makes.
[read]

**Fixed (2026-11-18):** the dead pre-test clears and the stale comment are gone; the header says each test has its own tokens (nextest) and plain `cargo test` with tokens is unsupported..

### F8. `Box::leak` to get `'static` env strings — nit

`crates/camigrate/tests/dry_run.rs:1385`, `:1408`. Harmless in a test process, but `Ref::env`
being `&'static [(&str, &str)]` (`common/xref.rs`) is what forces it; an owned
`Vec<(String, String)>` would remove the leak. [read]

**Decided (2026-11-18):** `Ref::env` is `&'static` in common/xref.rs, outside this file; the leaks now go through one helper, `common::ref_env`. An owned environment in `Ref` would remove them..

## Design

- The dry-run property is enforced in two places: per test (public/sealed matrices compare the
  dry run's `ready` with its exit) and globally by the twin in `common/xref.rs` (every moving
  `km` call). The twin skips tokens of `Plant::Shared` (`xref.rs:160-161`), so a move whose target
  is `kryoptic-der` (`:1139`, `:2045-2053`) is not checked for leaving the kryoptic database
  unchanged in its dry run, because the arg names `kryoptic-der`, not `kryoptic`. Mapping a
  shared ref to the ref whose token it reads would close that.
- Message substrings are asserted alongside codes throughout (`contains("...")` about 60 times).
  Here that is mostly appropriate, since the reasons are the user-facing plan output, but it
  makes rewording a plan reason a test change in this 2000-line file.

## Checked, no issue

- Silent skips: `env()` and every per-test "needs X" skip depend only on suite variables whose
  `*_REQUIRE` twins the Nix check phase and `scripts/local-tests.sh` set
  (`nix/package-common.nix:179-213`, `common/xref.rs:45-65`), so a missing token fails there;
  under plain `cargo test` the skip prints a line.
- The public and sealed matrices assert dry-run exit vs plan, real exit, `provenance.origin`,
  `cakeys verify`, idempotent re-run (lock bytes), and for blocked rows 15, unchanged lock bytes and
  an empty target locator; each ends by requiring at least one ready row.
- Bundle tampering (`:688-770`) checks each refusal's code, empty target and unchanged lock bytes.
- Key files: mode 0600 asserted (`:1997-2001`), wrong passphrase 17 with nothing left, dry run
  leaves the lock bytes.
- No sleeps; temp state lives under `CARGO_TARGET_TMPDIR` per test name (`common::test_dir`).
- docs/CAMIGRATE.md:52-57 exit codes: each is asserted at least once here — 0, 10 (`:722`,
  `:758`), 13 (`:740`, `:458`), 14 (`:727`, `:736`), 15 and 17 (throughout); 16 too (`:1344`, `:1873`).
