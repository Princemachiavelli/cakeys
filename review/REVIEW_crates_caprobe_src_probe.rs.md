# Review: crates/caprobe/src/probe.rs (1946 lines)

Reviewed 2026-11-18 [read]. Summary: the profile compiler: read-only probes (match keys,
advertisement, reported RSA sizes), the scratch guard, and the write probes (generation per curve
and RSA size, operations, proofs, ECDH, secret keys, OAEP and key-wrap round trips, delete rows),
plus `generate`, `drift` and `keep_claims` for the `probe` verb. The Q2/Q3/Q26 refactors are in
and mostly hold; the weak spots are cleanup on error paths, a build-feature dependency the
write gate does not check, leftover text parsing, and several 70–110-line functions.

## Findings

### F1. Scratch objects are not destroyed when a write probe returns an error — risk

**Verification:** confirmed (downgraded to practice). `write_probes` reaches `destroy_all` (probe.rs:737) only past the `?`s of `probe_curves`, `probe_rsa` and `moves::probe_moves` (:713-735), and `Made::create`'s `one(…)?` (:660) can fail after a key was made; `Scratch` has no `Drop`. But it happens only on a token keys.toml marks scratch, and the next run's `Scratch::clear_stale` (:701) removes the leftovers, so the cost is a stale-object note, not a lasting effect. [read]
`crates/caprobe/src/probe.rs:698-753`, `:737`; `:660`; `crates/caprobe/src/probe/moves.rs:103,111,113,198,205,287-288,621-622`.
`write_probes` reaches `destroy_all(made, profile)` (737) only when nothing before it returned
`Err`; `Scratch` has no `Drop`. On a `Labels` target the outer errors that can fire are: in
`Made::create`, after `Token::create` succeeded, `one(ObjectClass::PUBLIC_KEY)?` /
`one(ObjectClass::PRIVATE_KEY)?` (660) propagate any `Token::find` failure (`C_FindObjects`
error, device removed, session closed); `create_for_use` reaches it once per curve and per RSA
size through `create_curves` (1039) and `probe_rsa` (1108); and `moves::probe_moves` propagates
`locator_attrs`/`public_object_attrs` errors from `import_private`, `public_half` and
`create_public`. Any panic does the same. Scenario: a module that errors on one `C_FindObjects`
midway through the RSA sizes leaves every key generated so far (up to 16384-bit pairs), plus the
just-created untracked pair, on the token; the run exits with the error and no `delete.*` rows.
The next run's `Scratch::clear_stale` removes them (and then reports them as "an interrupted
probe left"), so the damage is bounded to a scratch token, but CAPROBE.md says "Every run
destroys what it made" and ISSUES.md Q26 consolidated the cleanup into one `destroy_all`.
Fix: run the probe body in an inner function and call `Scratch::destroy_all` on both arms
before propagating (or give `Scratch` a guard that destroys on drop unless disarmed). [read]

### F2. The write probes' `CKR_OPERATION_ACTIVE` handling silently depends on `cakeys-pkcs11/rv-value` — risk

**Verification:** confirmed; same root cause as REVIEW_crates_caprobe_Cargo.toml.md F1. probe.rs:391 and :1241 match only `rv_is(e.rv(), OperationActive)`, which is always false without `rv-value` (token/mod.rs:270-273), and the write/diff guard at probe.rs:1843-1852 checks only `binding::patched()`; the `minimal` crane build is patched but lacks `rv-value`. [read]
`crates/caprobe/src/probe.rs:391`, `:1241`, `:551`, `:1843-1853`; `crates/pkcs11/src/token/mod.rs:267-275`; `nix/package-crane.nix:75`.
`Ops::record` (391) and `prove` (1241) turn a busy-session failure into "undetermined, never a
row" via `token::rv_is(e.rv(), RvError::OperationActive)`. Without the `rv-value` feature,
`rv_value` returns `None` for every standard `RvError`, so `Msg::rv()`/`KmError::rv()` is
always `None` and `rv_is` is always false. The only gate on writing/diffing a profile is
`binding::patched()` (1843), which checks the HMAC key-type patch, not `rv-value` (nor `kwp`,
whose absence makes `CKM_RSA_AES_KEY_WRAP`/`_KWP` rows "refused" or unprobed: `:1723`,
`moves.rs:424`). The crane `minimal` package applies the cryptoki patches but enables only
`camigrate/kwp,caprobe/kwp,cakeys-pkcs11/sign-after-init` — not `rv-value`. Scenario: that
binary probing tpm2-pkcs11 on the AMD fTPM (`--write --out`) records the `CKR_OPERATION_ACTIVE`
outcomes after a failed SHA-384 `C_Sign` as mechanism failures: extra `subtract` rows and `no`
`prove.*` rows, and `refused()` falls back to prose evidence (551), so the profile differs from
the committed one with no module change. Uncertain whether anything runs probes from `minimal`
(it may only be a build check). Fix: make `generate`'s `kept` guard require every feature the
probe's correctness depends on (`rv-value`, `kwp`), e.g. a `binding::probe_ready()` that
reports which is missing. [read]

### F3. `Made::create` loses track of a key pair it did make — risk

**Verification:** confirmed. After `self.tok.create` succeeded, a missing half returns `Ok(Err(NotFound(..)))` before `scratch.track` (probe.rs:659-665), and both callers turn any inner `Err` into a `cannot` row with "generation refused" evidence (:1066-1070, :1122-1126), so a module that generated the pair gets a `no` row; the untracked objects are left for the next run's `clear_stale`. [read]
`crates/caprobe/src/probe.rs:654-666`.
When `Token::create` succeeds but either half is not found under the fresh label, the function
returns `Ok(Err(NotFound("the key pair it made is not under its locator")))` without
`scratch.track`. The caller records a generation refusal (`create_curves` 1066-1070,
`probe_rsa` 1122-1126: `cannot` row) for a key the module generated, and whatever half was
made is neither destroyed this run nor counted in the `delete.*` rows or the leftover note
(they only look at tracked labels). Scenario: a module that keeps no public-key token object
for a generated pair gets `generate.<kt>.<curve> = no` with evidence "not found". Fix: track the
label before the lookups (`scratch.track(&[], &label)` plus whatever handles were found), and
record "generated, but the pair is not under its locator" as undetermined rather than a
refusal. [read]

### F4. `keep_claims` grafts any file's hand claims onto the new profile — risk

**Verification:** confirmed (downgraded to nit). `keep_claims` (probe.rs:1884-1897) copies `migration`, `manual` and unprobed rows with no comparison of `old.profile` to the generated name, and `write_profile` (lib.rs:300-313) calls it for any existing `--out`. It needs a wrong `--out` path, and every probed row and the `profile` name then change in the same file, so the mistake shows plainly in the diff; only the grafted claims are subtle. [read]
`crates/caprobe/src/probe.rs:1884-1897`; `crates/caprobe/src/lib.rs:306-307`.
`--out <file>` keeps the existing file's `[migration]`, `[manual]` and `move.*` rows without
comparing its `profile` name (or family) with the profile just generated. Scenario: probing
kryoptic with `--write --out profiles/modules/softhsm/2.7.toml` (a wrong path in a
regeneration script) writes a kryoptic profile carrying SoftHSM's `[migration]` claims and
`move.secret-unwrap = no`, silently, and the diff never compares those rows (diff.rs: claims are
not compared). Fix: refuse when the existing file's family differs from the generated one's
(after `--name`/`--diff` naming), unless the operator passes the name explicitly. [read]

### F5. Delete rows read a failed lookup as "deleted" — practice

`crates/caprobe/src/probe.rs:760-779`, `:490-497`.
`destroy_all`'s `count` uses `find_objects(..).unwrap_or_default()` and `Scratch::leftovers`
uses `is_ok_and(|found| !found.is_empty())`. If `C_FindObjects` fails after the destroys (for
example the module's session went bad, the same condition that can stop F1), `after` is empty:
every class probed gets `delete.<class> = yes` and no leftover note. An error is reported as the
strongest positive answer. Fix: on a failed count after destroying, mark the rows undetermined
(push to `made.undetermined`) instead of writing them. [read]

### F6. Proof and import evidence still cut out of cryptoki's `Display` text — practice

`crates/caprobe/src/probe.rs:1254-1284` (used at 1242, 1245, `moves.rs:121,241,301,342,445,507,523,596,638`).
ISSUES.md Q3 is done for control flow (`Ops::record`, `prove`, `refused` use the `CK_RV`), but
`evidence()` still produces the evidence of every `prove.*` row and most move rows by finding
`": PKCS11 error:"` in `KmError`'s message and balancing parentheses, and by string-replacing the
token's keys.toml name (`'{name}'` → "the token", which also rewrites any other quoted word equal
to it — the probe's own object is named `probe`). Committed profiles pin this text byte for byte
(`every_committed_profile_is_what_the_emitter_writes`), and no unit test pins `evidence`'s
output (`notes_name_the_return_value_not_the_prose` tests `ckr`). A cryptoki release that
rewords its error prose, or a token named like a word in a message, changes regenerated profiles
with no behaviour change. Fix: build evidence from `KmError`'s context plus `rv_value_name(rv)`
where `rv()` is set (as `refused` does), and add a test over representative messages. [read]

### F7. The read-only ECDH probe swallows a failed destroy — practice

`crates/caprobe/src/probe.rs:1452`.
`derived_once` does `let _ = ro.destroy_object(h)`, while the read-write path (1344-1351) records
the same failure as the `derive.destroy` note because tpm2-pkcs11 persists derived secrets.
The read-only derivation on that module leaves a store row with no note. Fix: route it through
the same `destroy` closure/note. [read]

### F8. `derive` is 110 lines with a four-state result encoded in nested Options — complexity

`crates/caprobe/src/probe.rs:1327-1436`, esp. `:1372-1395`.
`mac: Option<Result<Vec<u8>, Option<CkError>>>` encodes "no HMAC, sealed" (`None`), "MAC'd"
(`Some(Ok)`), "HMAC failed" (`Some(Err(Some))`) and "not sealed, no HMAC" (`Some(Err(None))`);
`sealed_path` is then a `Result<Result<(), Msg>, Msg>` whose two error levels mean "fall back" and
"a real outcome". Hard to verify which case reaches `derive.sealed = Some(true)`. Fix: a small
enum for the sealed attempt's outcome and two helpers (`try_sealed`, `try_extractable`). Same
pattern of length: `probe_key_wraps` (1690-1787, ~100 lines), `probe_curves` (928-1007, whose
Montgomery branch 958-1005 re-implements `create_curves`' can/cannot/by-name/first-key logic
inline, see the §4(c) note in ISSUES.md for why it stays raw), `probe_bound` (790-861), `probe`
(100-170). The file holds `Draft`, `Ops`, `Scratch`, `Made` and every probe; splitting
`Draft`/`Ops`/`Scratch` into their own modules would make the probe bodies easier to find. [read]

### F9. `cakeys-probe-unbound` is tracked by handle only — nit

`crates/caprobe/src/probe.rs:870-874`.
`probe_unbound` pushes into `scratch.handles` but not `scratch.labels`, so a module that does
generate there gets no `delete.*` count or leftover check for that key (only the next run's
`clear_stale` sees it by prefix). Use `scratch.track(&[private, public], "cakeys-probe-unbound")`.
[read]

### F10. Small inconsistencies — nit

- `:113`: the default profile name uses `tok.module.version` raw, while the match key two lines
  up uses `clean(..)`; a NUL-padded version would name the profile with control characters.
- `:112`, `:120`: `tok.advertised()` is built twice; `:1731` calls it once per wrap and
  compares names, where Q9 moved the rest of the probe to `tok.lists(MechanismType)`.
- `:971`: by-name detection by `std::ptr::eq(params, oid)`; an index or a bool from the
  iterator says it without relying on pointer identity.
- `:1651-1653`: if the second `wrap_key` fails, the `unwrap.template.CKA_VALUE_LEN` row stays
  unprobed with no note, unlike the other failures in that function.
- `:1110-1119`: only the 2048-bit key gets the RSA operation probes and becomes the transport
  key; a module that refuses 2048 (or `--rsa-max-bits` below it) gets no RSA operation, wrap or
  move probes, with only a generic undetermined line.

## Design

- The scratch guard's promise at `:226-228` ("a typo must never overwrite a real key") is only
  as strong as `Provider::scratch_occupant`: ykcs11's accepts a slot whose only certificate is
  its own placeholder (`crates/ykcs11/src/lib.rs:154-172`), which is also what any ykcs11
  generation leaves before a real certificate is installed. A real key generated by `cakeys
  create` but not yet given a certificate would pass the guard. Uncertain how often that state
  exists in practice; for the ykcs11 reviewer.
- Correctness of probe output depends on three build features (`patched()`, `rv-value`, `kwp`)
  but only one is checked at run time (F2); the feature set should be one predicate the probe and
  the build share.
- Cleanup is a separate pass at the end rather than an RAII owner of the scratch objects (F1),
  unlike the verbs, which moved to `SessionObject` (Q5, Q6).

## Checked, no issue

- Q2 (Done): no `"CKK_*"` literal left in the probe's code; key kinds are `KeyKind`.
- Q3 (Done): `CKR_OPERATION_ACTIVE` matched by value in `Ops::record` (391) and `prove` (1241);
  `refused` names by value; the `CKA_VALUE_LEN` and key-wrap refusals match `RvError` variants.
  The SO-login check (`token::SO_LOGIN`, 656) still reads text, as ISSUES.md says.
- Q26 (Done): `Scratch` with `label`/`track`/`destroy_all`/`leftovers`/`clear_stale`; `Draft` has
  no `Deref`; `rsa_ops`' raw block is the key's modulus size (1480).
- The scratch guard runs before any write: `target` (scratch flag, `scratchId` only for SO-only
  providers, admin credential) then the login check, then `check_slot` (unreadable certificates
  count as not the placeholder).
- `pair`'s policy-default retry drops only `is_policy_default` attributes and only on a template
  refusal (unit test at 1907).
- `Ops::finish`: a mechanism is subtracted only when it failed on every key and is listed;
  unlisted-and-working ones go to `add`.
- `keep_claims` refuses an unparsable existing file and any read-only overwrite.
