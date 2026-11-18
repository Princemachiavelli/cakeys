# Review: crates/core/src/config.rs (2615 lines)

Reviewed 2026-11-18 [read]. Summary: the keys.toml schema and its load-time rules (names,
object kinds, value lengths, tokens, origins, transport keys, `$NAME` references), the
keys.lock schema and its invariants, atomic save, the `.lck` guard, the "lock unwritable"
check, `gc`, and address selection. The individual rules are careful and well tested; two
validation bugs (`gc` can write a lock that no longer loads; one invariant checks only the
first entry), some validation that happens at token open instead of load, and a file that has
grown to hold five concerns.

## Findings

### F1. `gc --apply` can write a lock that fails to load — bug

**Verification:** confirmed. `gc` keeps a realisation whenever its (spec, token) is still named (config.rs:1924,1937) and drops `objects.<o>` by keys.toml alone (:1940), never looking at `r.object`; the CLI saves via `save_lock` with no validation (cli/src/lib.rs:300-308, config.rs:1798), and every later `read_lock`→`load_lock`→`validate` refuses at :927-929, `gc` included (cli/src/lib.rs:255). [read]
`crates/core/src/config.rs:1923-1944`. `gc` keeps every realisation whose (spec, token) keys.toml
still names, and drops every `objects.<o>` keys.toml no longer defines — without looking at the
`object` the kept realisations record. Failure scenario: rename object `a` to `b` in keys.toml
(spec `s` now says `object = "b"`), then run `cakeys gc --apply` before `lock`. `gc` removes
`objects.a`; `realisations.s.t.object = "a"` stays; `save_lock` writes it
(`crates/cli/src/lib.rs:300-312`, no validation). Every later `load_lock` fails 17 in
`check_realisations` ("object 'a' is not in the lock", `:927-929`) — including the `lock` run
that would have re-recorded it and `gc` itself — so the user must hand-edit the lock. Fix:
keep an object any surviving realisation names (or collect the realisation too when its
recorded object is gone from keys.toml), and have `save_lock` run `Lock::validate` before
writing so no verb can persist an invalid lock. [read]

### F2. `check_observations` validates only the first module hash — bug

**Verification:** confirmed. `find_map` stops at the first observation that has a module hash and `.filter` judges only that one (config.rs:979-983); a malformed hash in any later entry loads. Impact is as stated: the hash is only compared for the replaced-module warning (reconcile.rs:652). [read]
`crates/core/src/config.rs:979-983`.
`self.observations.values().find_map(|o| o.module.as_ref()?.hash.as_ref()).filter(|h| !is_sri(h))`
takes the *first* observation that has a module hash and checks only that one; a malformed
`hash` in any later entry loads. Low impact (observations never change a verdict, and a
malformed hash only weakens the "replaced in place" warning in `reconcile::warn_module`), but
the check exists to refuse exactly that and silently does not for all but one entry. Fix: `.filter_map(|o| o.module.as_ref()?.hash.as_ref()).find(|h| !is_sri(h))`. [read]

### F3. Locator and secret-key length are checked at token open, not at load — practice

`crates/core/src/config.rs:651-660` (`Locator`), `:1539-1554` (`check_value_len`). A locator with
neither `CKA_LABEL` nor `CKA_ID`, or a non-hex `CKA_ID`, loads and is refused only when a token
is searched (`crates/pkcs11/src/token/mod.rs:606-625`, `uri.rs:138`) — after a token was opened
and logged in, and never by `validate`. `CKA_ID` hex is also not normalized, so changing
`"0A"` to `"0a"` in keys.toml is reported as a locator change (14 until `lock`,
`reconcile.rs:242-244`) though it names the same object. Likewise an AES `valueLen` other than
16/24/32 (or 0 for any secret key) loads and fails at `create`. Review V5 moved type checks to
load for exactly this reason. Fix: in `parse_config_with`, refuse an empty locator and a
non-hex or empty `CKA_ID`, store `CKA_ID` in lower case, and check AES lengths beside the DES3
rule in `check_value_len`. [read]

### F4. The Nix-store guard skips `passphraseFile` and is a plain prefix test — practice

`crates/core/src/config.rs:1678-1682`, `:1970-1979`, `:1996-2004`. `in_store` is applied to
`migrate.file` only; `migrate.passphraseFile` — the secret that decrypts that file — may sit
in the world-readable store unchallenged, at load or when `object_passphrase_file` resolves
it. The test is `path.starts_with("/nix/store")` on the unresolved path, so `./result/k.pem`,
`/run/current-system/sw/…` or any symlink into the store passes. Fix: apply `in_store` to the
passphrase file too, and test the canonicalized path when the file exists (at use). [read]

### F5. config.rs holds five concerns in 2,600 lines — complexity

`crates/core/src/config.rs` as a whole. It holds (1) the keys.toml schema and its eleven load
rules (`:1477-1742`), (2) the lock schema and its five invariants (`:785-1122`), (3) the
observation model (`:1298-1447`), (4) file I/O policy — atomic write, `flock` guard,
`access(2)` and Nix-sandbox detection (`:1791-1915`), and (5) `gc` and address selection
(`:1917-2070`), plus 500 lines of tests. Each changes for different reasons (Q12's checks,
review A3's observations, M3's guard). Validation is also split across files: object type at
load here, binding/attribute shape in `plan::plan_mode`, locator at token open (F3), and the
Ed448 curve check by string in `plan.rs:165`. Fix: split into `config/{keys,lock,observation,
fs}.rs` with `gc`/`select` beside the lock, and make "everything keys.toml alone can refuse is
refused by `parse_config_with`" the rule (call `plan_mode` for every pair at load, as
`ObjectCfg::kind` is called for every object). [read]

### F6. `$NAME` errors lack the file name every other load error carries — nit

`crates/core/src/config.rs:1482,1498,1501,1505,1515`. These `env_ref(...)?` calls return
`Validation("token 't': pinFile: …")` without the `"{path}: "` prefix `invalid` adds to every
other load error, so the message does not say which keys.toml. `:1482` also converts
`profileDirs` through `to_string_lossy`, replacing non-UTF-8 bytes in a path. [read]

### F7. `write_whole` replaces a symlinked lock with a regular file — nit

`crates/core/src/config.rs:1812-1834`. `persist` renames over the link itself, and `lock_dir`
and `unwritable` look at the link's directory, not the target's. A keys.lock symlinked into a
checked-out repository (a common NixOS deployment layout) is silently replaced by a copy and
the repository's file never changes. Fix: resolve a symlink before choosing the temp
directory and rename target, or refuse a symlinked lock with a message. [read]

### F8. Two unit tests share fixed directories under `/tmp` — nit

`crates/core/src/config.rs:2368-2370`, `:2425-2427`. `cakeys-load-config-test` and
`cakeys-load-types-test` are `remove_dir_all`'d and recreated; two concurrent test runs
(nextest across worktrees, CI matrix on one host) race. The neighbouring tests already use
`tempfile::tempdir()`. [read]

## Design

- `save_lock` writes whatever it is given; only `load_lock` enforces the invariants. Validating
  on save (F1) turns every future "a verb wrote a lock that does not load" bug into a refused
  write with the old lock intact.
- The lock's `type` is compared whole (`ObjectCfg: PartialEq`, `reconcile.rs:186-197`), so adding
  an optional field such as `modulusBits` to an adopted object (which `create` would need) is
  "different material, needs a new object name", also under `lock`. Intended by DESIGN.md
  ("A changed object type … is refused"), but optional descriptive fields and identity-bearing
  ones are not distinguished.
- A spec naming a token `[tokens]` lacks loads (tested in `tests/refusals.rs:105-108`) and is
  refused only when used; `gc`'s `named` (`:1924`) counts such a pair as live. Consistent, but
  a second instance of "load accepts what every use refuses" (F3).

## Checked, no issue

- Q12 (Done): `parse_config_with` calls `check_value_len` and `check_token`.
- Q18 (Done): `write_whole` is the one whole-file writer (temp beside target, `sync_all`,
  rename, directory sync); `save_lock` uses it.
- Q28 (Done): `Said` keeps an unknown word as read and writes it back.
- `check_origins`: one `create` pair per object, `publicOnly` only adopts, `CKA_TRUSTED` never
  generated, a file-born object never created; tests cover each branch.
- `check_transport_keys` and the lock invariants have full branch coverage in
  `crates/core/tests/refusals.rs` (ISSUES.md "No unit test in core…" is fixed).
- `check_one_object_per_material` and `check_pairs` agree with `reconcile::record`.
- `Observation::digest`'s `expect`: only called on observations built by `pkcs11::ops` with an
  empty `extra`, so a loaded `nan` in `extra` cannot reach it.
- `lock_for_update` holds `File::lock` for the guard's life; readers rely on the rename.
