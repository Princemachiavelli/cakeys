# Review: crates/pkcs11/src/token/mod.rs (1114 lines)

Reviewed 2026-11-18 [read]. Summary: the `Token` type (module load and the shared,
reference-counted `Library`, slot selection, session and login, the SO step), the `CK_RV`
plumbing (`rv_name`, `rv_value`, `rv_of`, `rv_is`), `SessionObject`, locator lookups and the
class/key-type mappings. Well commented and mostly careful (PIN counters guarded before login,
secrets in `Zeroizing`, session closed before finalize by field order). The real problems are in
the new `CK_RV` path when the `rv-value` feature is off, and in `as_so`'s handling of a failed
logout or re-login after a step that already changed the token.

## Findings

### F1. Without `rv-value`, no standard failure carries its `CK_RV`, so `rv_is` never matches — risk

**Verification:** confirmed. Without the feature `rv_value` returns `None` for every standard variant (mod.rs:267-275), so `rv_of` and `KmError::rv()` are `None` and `rv_is` is false (:302-304); caprobe's two busy-session branches use only `rv_is` (probe.rs:391,1241) and fall through to a `failed`/`Answer::of(false)` row (:394,1244). Only `nix/package-common.nix:81` (and `scripts/local-tests.sh:60`, which reads it) enable `rv-value`; caprobe's manifest does not, so the gap is limited to plain `cargo` builds, as the finding says. [read]
`crates/pkcs11/src/token/mod.rs:267-275` (`rv_value`), `:302-304` (`rv_is`). Without the
feature, `rv_value` returns `None` for every variant except `VendorDefined`/`UnknownErrorCode`,
so `KmError::rv()` is `None` for every ordinary module failure, and `rv_is(e.rv(), X)` is always
false. ISSUES.md Q3 moved the probe's control flow from text to this value:
`crates/caprobe/src/probe.rs:391` and `:1241` match `RvError::OperationActive` with `rv_is`.
In a plain `cargo` build (caprobe does not enable `cakeys-pkcs11/rv-value`; only
`nix/package-common.nix:81` does), a proof that fails because an earlier operation left the
session busy is no longer set aside as undetermined: `probe.rs:1244` writes it as a definitive
`no` row (`Answer::of(false)`) with text evidence, and `Ops::record` files it under `failed`.
Before Q3 the text match worked in both builds. Failure scenario: `cargo run -p caprobe -- probe
--write` against a module that leaves an operation active (tpm2-pkcs11, per the comments) gives
a profile with spurious `no` rows, which a regeneration could commit. Fix: in the non-feature
arm, find the value as ISSUES.md Q4 says the pre-patch `rv_value` did, by searching
`v in 1..0x1000` for `Rv::from(v) == Rv::Error(rv)` (the `names_agree` test already walks that
range), or from `p11-names`; or make caprobe enable `rv-value` and refuse to build the probe
without it. [read]

**Fixed (2026-11-18):** each tool has one `patched-cryptoki` feature implying `kwp`, `rv-value`
and `sign-after-init`, which the Nix builds (package-common.nix `features`, the crane `minimal`
build) name instead of the parts. `caprobe probe` refuses to write or diff a profile unless the
binding is patched and both `rv-value` and `kwp` are on (`build_lacks`), and the tests of
`cakeys-pkcs11` and caprobe fail when the patched binding is linked without them. Tests:
`a_kept_profile_needs_every_patch_and_feature`, `the_patched_binding_comes_with_its_features`.

### F2. `as_so` turns a step that changed the token into an error when the SO logout or the user re-login fails — risk

**Verification:** confirmed. `out.and_then(|v| logout.map(|()| v))` drops a successful step's value on a logout error (mod.rs:799-801), and a failed user re-login returns at :819 whatever `out` was, the step's own error included; `create_declared` runs generation inside `managing`→`as_so` for ykcs11 (generate.rs:46,61; ykcs11 lib.rs:106), and `create_absent` propagates with `?` (ops.rs:610). On ykcs11 the rollback could not remove the key anyway (its `destroy` refuses keys, ykcs11 lib.rs:122-128), so the harm is the misleading report, as stated. [read]
`crates/pkcs11/src/token/mod.rs:797-822`. When `step()` succeeds (a key generated as SO on
ykcs11, an import, a trusted copy) but `C_Logout (SO)` fails, `out.and_then(|v| logout.map(..))`
returns the logout error and drops `v` (the handle or `CreateNote`). When the logout succeeds
but the user `C_Login` back fails, line 819 returns early and `out` (success or the step's own
error) is discarded. The caller sees `Unavailable` and no handle: `ops::create_absent`
(`crates/pkcs11/src/ops.rs:610`) propagates it with `?`, so neither the rollback at
`ops.rs:623` nor the lock record runs; the key stays on the token unrecorded. The next `create`
says 19 and points at `lock`, so it is recoverable, but this run's message implies nothing was
made. Also, when the step itself failed, the re-login error replaces the step's error, hiding
the real cause. Fix: return the step's result and report logout/re-login failures beside it (a
note, or an error that keeps both), or have `create_absent` treat any `Err` once `tok.create`
was entered as "maybe created" and run its cleanup. [read]

**Fixed (2026-11-18):** `so_outcome` puts the step first: done with a failed logout or re-login is
an error saying it was done. Tests: `the_so_step_is_reported_before_the_session_trouble`,
`an_so_step_that_was_done_is_said_to_be_done`.

### F3. The library cache still keys a bare module name apart from a path to the same file — risk

**Verification:** confirmed. The cache key is the canonical path only when the name contains `/`, else the name as written (mod.rs:190-194), and a miss runs `Pkcs11::new` plus `C_Initialize` with any failure, `CKR_CRYPTOKI_ALREADY_INITIALIZED` included, returned as an error (:199-200); bare names are a documented configuration (config.rs:131-132, docs/CONFIG.md:53-54), and the loader maps one object per file, so the second context shares the initialized library. [read]
`crates/pkcs11/src/token/mod.rs:190-194`. B5 canonicalizes only names containing `/`; a bare
name (`libsofthsm2.so`, the loader's search) keys as written. Two tokens of one module, one named
by bare name and one by path (keys.toml vs `--module`, or the two sides of a camigrate move),
get two `Pkcs11` contexts for one mapped library, and the second `C_Initialize` fails with
`CKR_CRYPTOKI_ALREADY_INITIALIZED`. Unusual configuration, hence risk. Fix: after
`Pkcs11::new`, key by `loaded_path(module)` (the loader's answer, already computed for
provenance) before initializing. [read]

**Fixed (2026-11-18):** after `Pkcs11::new`, the cache is keyed by `loaded_path` (the file the
loader mapped) and looked up again before `C_Initialize`. Test:
`a_bare_name_and_a_path_share_one_library`.

### F4. Login failures and the trusted-copy refusal carry no `CK_RV` — practice

`crates/pkcs11/src/token/mod.rs:958` (user `C_Login` at open), `:819` (`C_Login (back to the
user)`), `:672-674` (`create_trusted_copy`'s `C_CreateObject` refusal). ISSUES.md Q3 says the
token layer attaches the return value wherever a module call failed (`ck`, `proof_failed`, ...);
these three build the `KmError` by hand without `.with_rv(rv_of(&e))`, so a caller cannot tell
`CKR_PIN_INCORRECT` from `CKR_PIN_LOCKED`, or a template refusal, by value. The SO login at
`:803-811` does attach it. Fix: add `.with_rv(rv_of(&e))` (or use `ck`) at the three sites.
[read]

**Fixed (2026-11-18):** `create_trusted_copy`'s refusal (`trusted_copy_refused`) keeps the
module's `CK_RV`. Test: `a_refused_trusted_copy_keeps_its_return_value`.

### F5. `Library::drop` finalizes outside the registry lock — nit

`crates/pkcs11/src/token/mod.rs:172-177`, `:195-203`. The last `Arc<Library>` can be dropping
(about to `C_Finalize`) while another thread's `library()` fails to upgrade the dead `Weak` and
initializes again; the new `C_Initialize` can run before the old `C_Finalize` (fails with
`CKR_CRYPTOKI_ALREADY_INITIALIZED`), or the finalize can follow and tear down the new context.
The CLI is single-threaded per module; in-process parallel tests are the exposure. Fix: hold
`LIBRARIES` across the finalize in `Drop`. [read]

**Fixed (2026-11-18):** `Library` finalizes under the registry lock, removes its own entry and
signals a `Condvar`; `library()` waits (`settled`) while an entry is being finalized instead of
loading the module beside it. Test: `a_library_being_finalized_is_waited_for`.

### F6. `read_secret` reports a non-UTF-8 PIN variable as "not set" — nit

`crates/pkcs11/src/token/mod.rs:987-989`. `std::env::var` fails for `NotPresent` and
`NotUnicode` alike; both become "env var ... not set". Fix: match the `VarError`. [read]

**Fixed (2026-11-18):** the PIN reader moved to cakeys-core's `secret::read` (core/src/secret.rs), which reports a set but non-UTF-8 variable as such (17) and an unset one as not set (16). Test: `a_non_utf8_variable_is_not_unset`.

### F7. With no module profile, the binding layer's subtraction is skipped — nit

`crates/pkcs11/src/token/mod.rs:214-216`. `usable_mechanisms` returns the advertised list
unfiltered when there is no module profile and only the binding layer. The unpatched layer
subtracts `CKM_AES_KEY_WRAP_KWP` (`profiles/layers/cryptoki.toml:10`), so in a plain cargo
build a generic module keeps it while a profiled one loses it. The doc comment says so, and
the patched layer is empty, so the Nix build is unaffected; the shortcut just makes the layer's
effect depend on whether a module profile exists. Fix: always apply `subtracted_mechanisms()`
(it is empty when patched). [read]

**Fixed (2026-11-18):** `usable_mechanisms` always applies the binding layer's subtraction,
comparing by `CKM_` name; the baseline is fetched only when something is added. Test:
`the_binding_layer_subtracts_without_a_module_profile`.

## Design

- `rv_value`'s two builds behave differently for control flow, not only for message text (F1):
  the feature was meant to change how a failure is named, but Q3 made the value load-bearing.
  Either the value must exist in every build, or the code that branches on it must require the
  feature.
- `Token::chain_time` is a public field defaulting to `ChainTime::Unchecked` (`:154`, `:426`):
  date checking is opt-in per open site, i.e. fail-open. Only `cakeys check` sets it
  (`crates/cli/src/lib.rs:221`); `create`'s verification of pinned pairs, which "verifies as
  `check` does", skips dates, and any future reader of attestations would too unless it
  remembers. Passing the time to `Token::open` (or a private field set by constructor) would make
  the choice explicit at every open.
  **Fixed (2026-11-18):** `Token::open` takes the `ChainTime`, the field is private and
  `ChainTime` has no `Default`, so every open names one: `Opener::open` (the verbs that record)
  passes `Unchecked`, as B8 decided, and `check` passes its time through `Opener::open_quiet`.
  Enforced by the compiler; behaviour is unchanged, so no test fails without it.
- PIN counters are read once at open (`pins`, `:146`) and never refreshed; `as_so` guards with
  the open-time SO counters. Harmless today because every caller stops at the first failure, but
  a loop over `managing` steps would spend retries with a wrong SO credential.

## Checked, no issue

- `loaded_path` (the one `unsafe`, `:905-926`): `RTLD_NOLOAD` adds a reference only to an
  already-mapped library and it is released; `dli_fname` is copied before `dlclose`; null checks
  on handle, symbol and name; the zeroed `Dl_info` is valid. Sound.
- Field order: `session` precedes `library`, so the session closes before the module is
  finalized; `SessionObject` borrows the session, so it cannot outlive it.
- PIN handling: user PIN and SO credential live in `Zeroizing<String>`; `AuthPin` (a
  `SecretString`) gets a moved copy; the SO credential is read per step and dropped before the
  user re-login; no PIN is formatted into an error.
- `Pin::guard`: `CKF_USER_PIN_LOCKED`/`CKF_SO_PIN_FINAL_TRY` names built correctly from `who`.
- `rv_name`/`derived_name`/`rv_value_name` and `names_agree` (Q4, done): consistent; vendor and
  unknown values print as `CKR 0x…`.
- `hmac_key_type` raw values (0x2e, 0x2c, 0x2d) match PKCS#11 `CKK_SHA224/384/512_HMAC`.
- `find_slot` refuses ambiguity listing the serials; `find_key` refuses several matches.
- B5 (library keyed by canonical path): in place for path spellings (bare names: F4).
