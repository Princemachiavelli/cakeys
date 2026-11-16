# Code review findings

Review of `origin/main` at `5c2a0bd`, 2026-11-16. The easy items are fixed in the working tree
("Fixed in this pass", uncommitted); everything under "Bugs and behaviour" and "Poor practices"
is still open. Evidence tags as in [docs/CAPROBE.md](docs/CAPROBE.md): **[run]**
reproduced or measured in this review, **[read]** from the code, not run. Every item is [read]
unless it says otherwise.

Checks at the start of the review: `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace --no-fail-fast` both pass [run]. The token suites skip under plain
`cargo test`, and no Nix check was run.

## Coverage of the review

| Read in full | Skimmed or searched | Not read |
|---|---|---|
| Every `src/` file of `core`, `pkcs11`, `profile`, `camigrate`, `cli`, `cli-common`, `ykcs11`, `tpm2-pkcs11`, `kmsp11`, `aws-cloudhsm`; `caprobe/{probe,lib,diff,emit,coverage,supports}.rs`; `p11-fault/{lib,hooks,forward,trace,plan}.rs`; `nix/lib.nix`, `nix/sandbox-hook.sh`, `nix/test-tokens.sh`; `.github/workflows/checks.yml` | The unit tests inside those files; `nix/module.nix` (options only); the other two workflows (permissions and pins); three of the seven fuzz targets; the integration tests (searched for sleeps, ignores and the surface lists) | `caprobe/baseline.rs` (the header parser); `p11-fault/names.rs` (name tables); the integration test bodies (`crates/*/tests/`, about 13k lines); the rest of `nix/`; `scripts/`; the Terraform under `scripts/cloud/` |

## Issues flagged in docs: are they fixed?

| Source | Item | Status |
|---|---|---|
| REVIEW-2026-11-15 | V1: `check` creates and provisions | Fixed: read-only session, never provisions |
| | V2: `realise` does three things, `autoCreate` | Fixed: `lock` verb, `origin` per pair; `autoCreate` and `createOn` are unknown fields |
| | V3: exit 10 means two things | Fixed: `FirstUse` is 18 |
| | V4: two address grammars | Fixed: one `Address`; `verify` is an alias of `check` |
| | V5, C6: object types validated per target | Fixed: `ObjectKind` parsed at load |
| | C1: two specs create one object | Fixed: at most one `create` pair per object |
| | C2, N3: no name grammar, unescaped shell | Fixed: `check_names`, `escapeShellArg` |
| | C3, C4, C5: tool settings in the core schema, `provider` overloaded, label-only selection | Fixed: `probe`/`migrate`/`nix` tables, `moduleProfile`, `tokenSerial`, `soCredential*` |
| | N1: the view exposes the unverified URI | Fixed: `uri` removed |
| | N2: the library re-implements rules | Mostly fixed: view shrunk, lock version asserted. `type` is still raw keys.toml, so `curve = "P-256"` is not canonicalized |
| | P1: a missing profile is fatal at open | Fixed: nearest profile with a note |
| | P2: a profile row picks the ECDH protocol | Fixed: sealed is tried, extractable is the fallback |
| | §4 (a): collapse the `Provider` trait | Done: two repairs, four operations |
| | §4 (b): kmsp11 and aws-cloudhsm touch nothing outside their crates | Not verified. kmsp11's refusals have drifted from the generic proof code (B11) |
| | §4 (c): the probe calls the verbs' operations | Partly: proofs and EC/RSA generation go through `Token::prove_binding` and `Token::create`. `bound_keys`, `scratch_occupant`, `stand_ins` remain, and Montgomery, secret-key and wrap probes keep their own templates |
| | §4 (d): one capability row type | Done (`Capability`, `Row`). The emitter is still hand-written (Q27) |
| | §4 (e): per-deployment answers in the lock | Done (`observations.*.capabilities`) |
| | E1: two tests red under plain `cargo test` | Fixed [run] |
| PLAN.md A2 | `uri.rs` leaves `/` unescaped | Fixed in this pass (B3) |
| PUBLISH_REVIEW | Profiles embedded from outside the crate; no `LICENSE` per crate | Not fixed (`publish = false` still) |
| | READMEs, `keywords`, docs.rs metadata, `pkcs12` rc pin | Not fixed |
| OPEN.md, Engineering | Split the reference suite | Not done, and it grew: 3,085 to 3,625 lines, 62 to 76 functions |
| | Token suites crash under a parallel `cargo test` | Not fixed (TODO at `crates/cli/tests/common/mod.rs:683`) |
| | No unit test in `core` for the lock's load-time invariants or the transport-key rules | Partly: observations are tested (`config.rs:1764`, `:1796`); `check_pairs`, `check_one_object_per_material` and `check_transport_keys` have no unit test a search finds |
| | Fuzz the remaining parsers (PIV chain, P-521 fix-up, profile emit and parse) | Not done: the seven targets are unchanged |
| | `tpm2_ptool` takes the PIN on its command line | Not fixed (accepted for now) |

The lock design review's S-items (`reports/`) were not re-verified one by one; the ones crossed
on the way (S3, S4, S7, S8, S9, S10, S12) are fixed.

## Fixed in this pass

Uncommitted, on top of `5c2a0bd`. Checked with clippy, `cargo test --workspace` and
`scripts/local-tests.sh` (492 tests, all passing, after the last change) [run]; no Nix check
was run. B1, B5, B9, B14
and B17 have no test of their own: no reference token is write-protected or pads a modulus,
and the others need a second step that fails or a second spelling of a module path.

| Item | Fix |
|---|---|
| B1 | `cakeys lock` opens with `Access::Scratch`, so a write-protected token can be pinned (`crates/cli/src/lib.rs`); `docs/FAULT_SHIM.md` says `create` |
| B3 | `/` is escaped in URI path attributes and kept in query attributes, as RFC 7512 §2.3 has it [run: the RFC's ABNF], with a unit test (`crates/pkcs11/src/token/uri.rs`) |
| B4 | `wrap_rebind` adds a usage attribute only if the template lacks it (`token/identity.rs`) |
| B6 | An empty PIN is not "redacted" out of `tpm2_ptool`'s message (`tpm2-pkcs11/src/ptool.rs`) |
| B7 | `aes` and `sha2` dropped from `cakeys-pkcs11`, `serde` from `cakeys` |
| B9 | A key-file import saves the lock before it reports a failed certificate import (`camigrate/src/lib.rs`) |
| B12 | `MatchInfo`, `Subtract`, `Restrict` and `AcceptRow` refuse unknown keys, with a unit test (`profile/src/profile.rs`, `lib.rs`) |
| B14 | `caprobe probe --out` overwrites only a file that is absent or readable (`caprobe/src/lib.rs`) |
| B15 | `caprobe supports --token` takes `moduleProfile` before `provider` (`caprobe/src/supports.rs`) |
| B2 | `create` never finds a key: one already under its locator is `Exists`, exit 19, before any capability is asked of the token (`pkcs11/src/ops.rs`, `core/src/error.rs`); three reference tests and `docs/CAKEYS.md` follow. `lock_as` lost its `create` flag (Q11, in part) |
| B5 | The library cache is keyed by the canonical path of a module named by path (`pkcs11/src/token/mod.rs`) |
| B10 | The PKCS#12 MAC key takes 600,000 iterations, as the encryption does (`camigrate/src/file.rs`) |
| B11 | kmsp11 no longer refuses `pop-decrypt` or `pop-sign` on PSS and SHA-512 keys; `pop-unwrap` and `pop-ecdh` stay refused. **Not run against Cloud KMS** (see "To test") |
| B16 | EC and Edwards scalars, the ECDH shared secret and the unwrap secret are wiped (`core/src/plaintext.rs`, `core/src/pop.rs`). The `--userpin=` argument is left: it is on `tpm2_ptool`'s command line either way |
| B17 | The RSA size check ignores leading zero bytes (`pkcs11/src/token/policy.rs`) |
| B19 | A key file's scrypt parameters are bounded (N × r up to 2²³, p up to 16), with a unit test. Verified first: this build's `pkcs5` does decrypt scrypt |
| Q1 | The dead `CKK_EC`/`CKK_EC_EDWARDS` branches are gone from `probe_curves`; `operate`'s fallthrough message no longer says ECDH |
| Q9, in part | `Token::runnable` compares mechanism types, not formatted names |
| Q15, in part | `read_mgm` is `read_so_credential`, and its error says "SO credential" |
| Q18, in part | caprobe's `ckr` calls `token::rv_name` |
| Q30, in part | "unsupported policy attribute" names its target, as the errors beside it do |
| Q5, Q6 | `SessionObject` destroys a session object when dropped; `sealed::export`, `wrap_rebind`, the proofs and `Token::extract` use it, and `export` works on `Found` and `Wrapped` structs in a plain loop. Two destroys stay explicit in the probe, which records their failure |
| Q7, Q8 | `prove_ecdh` has one fallback closure and one sealed-secret template; the OAEP loops count hashes instead of ending in `unreachable!` |
| Q9, in part | One `sorted_names` for the three places that list mechanisms by name |
| Q10 | `delete` picks its scheme and expected ID in one step |
| Q11 | `Provision` and `Verb` enums in `ops.rs`; `prove_sign` takes the binding |
| Q12 | `parse_config_with` calls `check_value_len` and `check_token` |
| Q14, in part | `ops::split_reference` parses `<object>.id.<scheme>` for the CLI and the verb |
| Q18, in part | One table each for OAEP parameters (`token::oaep_params`, `oaep_of`), the `DigestInfo` prefix, hex encoding (`core::hex::encode`), the proof name (`Binding::proof_name`), capability keys (`gate::proof_capability`, `generate_capability`), the Nix-sandbox check, whole-file writes (`config::write_whole`, now synced), the binding layer's name and `Scheme::Rfc7093m4.name()` |
| Q21 | `Profile::new` and `TokenCfg::labelled` replace the 14-field literals |
| Q22 | kmsp11 parses `keys.json` once, behind a `LazyLock` |
| Q25 | `host.rs` shares `source_key` and `hand_over`; `public::origin` builds the provenance record; camigrate has `Run::save` |
| Q26, in part | The probe's `Oaep` and `Refused` wrappers are plain options |
| Q29 | ykcs11 reads a certificate's value in one helper |
| Q30 | `Mode::rank` and `name`, `Binding::name`; `keeps_destroyed_keys` returns a `String`; the lone serde alias is gone |
| Q31 | The planner collects `Candidate`s in a `Ways`; the CLI's enum is `Destination`; the capability source is the `Known` enum, not a string |
| Q15, in part | `target_target` is `import_target` |
| Stale comments | `profile/src/lib.rs`, `core/src/migrate.rs`, `camigrate/src/tokens.rs` (the removed `migration` hook), `Cargo.toml` (two `unsafe` exemptions) |

Withdrawn: `profile/src/effective.rs` saying no and unknown exit 15 and 16 is correct
(`caprobe supports` does).

## To test

- **Key-file timing.** With the PKCS#12 MAC at 600,000 iterations, a debug build takes
  seconds per file (the three `file::tests` take 15 s together, with the KDF crate built
  optimised); a release build was not timed.
- **B11 on Cloud KMS.** `create` of a PSS key, a SHA-512 key and an OAEP decrypt key with their
  `pop-sign` and `pop-decrypt` bindings. The opt-in test (`crates/cli/tests/cloud.rs`) still
  creates its decrypt key `token-asserted`; `scripts/cloud/gcp/cakeys.toml` says which pair to
  switch. Its "refused before creating" case is now a `pop-unwrap` key, so no label is spent.
- **`create` and exit 19 in the Nix tests.** `nix/test.nix`, `nix/module-test.nix` and
  `nix/demo.sh` call `create` once per key, so they should be unaffected; not run.

## Bugs and behaviour

Still open.

- **B8. The PIV attestation chain is verified without a validity-period check.**
  `chain_to_anchor` (`crates/ykcs11/src/attest.rs:210`) checks signatures, the name links and
  `basicConstraints` with path length, never `notBefore`/`notAfter`. Parked in
  [docs/OPEN.md](docs/OPEN.md), "To decide": `check` would enforce it with an override; whether
  `lock` and camigrate may depend on the wall clock is undecided.
- **`create` flags** (from B2). `create` now stops with 19 at the first key that exists. A flag
  such as `--only-new`, to skip those and create the rest, is parked in docs/OPEN.md.
- **B13. `probe_unbound` records `cannot` for a curve that generated.** On a module whose keys
  are bound to one purpose (libkmsp11), the probe makes one key per binding, then tries a
  generation with no binding at all to see what the module says about the curves and sizes no
  binding covers (`crates/caprobe/src/probe.rs:839-877`). It expects a refusal and writes it as
  the evidence of a `cannot` row for each. If the module instead generates, the "refusal" text
  becomes "generated without a binding" and the rows are still written `cannot`, each with
  that sentence as its evidence. libkmsp11 refuses first, so no committed profile has this.
  A fix has to choose what such a run means. The bare template names only a label, so nobody
  knows which curve or size was generated: `can` cannot be written for any of them. The honest
  row is none (unknown), with a line in the probe's "undetermined" list saying the module
  generated without a binding and is not purely purpose-bound. That is a five-line change;
  it changes no committed profile.
- **B18. The by-name curve fallback retries after any failure**
  (`crates/pkcs11/src/token/generate.rs:141`), not only a refusal of the parameters. Left:
  narrowing it needs the return value ykcs11 gives an Edwards OID, which the profile records as
  "by-name" without the code, and the hardware rules keep that from being measured here.

## Poor practices and hard-to-read code

Still open. Each says why it was not done with the rest.

### Need a decision

- **Q3. Control flow read out of error text**, in the probe: `contains("CKR_OPERATION_ACTIVE")`
  (`crates/caprobe/src/probe.rs`, twice), `contains("C_Login (SO)")`, `refused` and `evidence`
  cutting `CKR_*` and cryptoki's prose out of a formatted `KmError`, and the `create` note
  scanned for `CKA_PRIVATE = false`. Fixing it means `KmError` carries the return value and
  `Token::create` returns a typed note: a change to the public error type and to the
  `Provider::create` signature.
- **Q4. `rv_name` derives `CKR_*` names from cryptoki's `Debug` output**, which committed
  profiles pin. cryptoki 0.12 has no conversion from `RvError` back to its number, so the
  alternative is a hand-kept table of about ninety variants.
- **Q24. The profile set is process-global and order-dependent** (`Set::activate` after
  `Set::active` fails; `Registry::named` hides a set that does not parse).
- **Q27. The profile emitter re-implements taplo's layout** (`crates/caprobe/src/emit.rs`), so
  generated profiles survive `nix fmt` byte for byte.
- **Q28. String-typed fields kept for forward compatibility**: `Capability`'s `binding` and
  `key_type`, `Answered::answer`, `Restrict::operation`, `BoundKey::kind`/`on`.
- **Q20. Key type dispatch by trial parsing** (`spki_canonical`, `spki_of_pkcs8`,
  `ecdh_challenge`, `verify_with`). Dispatching on the OID changes which parser sees a
  malformed key, and with it some error texts and the `public_key` fuzz target's fixed point.

### Refactors left for a pass of their own

- **Q2. Key types as strings in the probe** (31 `"CKK_*"` literals). Montgomery has no
  `KeyType`, so this needs a probe-local kind enum threaded through `operate`, `prove` and the
  generation rows; the conformance tests would catch a slip, but it is a rewrite of the
  probe's spine.
- **Q26. The probe's `Made`** (12 fields) and `Draft`'s `Deref` to `Profile`; `rsa_ops` signs a
  fixed 256-byte block whatever the key's size.
- **Q13. `resolution::resolve` is 127 lines.**
- **Q14. CLI setup is still duplicated** between `cakeys` and `camigrate`: the `Run` struct, the
  load-and-guard prologue, `(cfg, modules, registry)` at each `open_token`. A shared opener
  collides with the `&mut self.lock` both hold across those calls.
- **Q9. `Token` still keeps four views of the mechanism list.**
- **Q18, the rest.** The public half's defaults are written in `generate.rs` and `sealed.rs`;
  curve lists live in `core::id`, `profile::baseline` (independent by design) and the probe.
- **Q15. Naming**: `EcdsaHash` is also the RSA hash type (about forty uses);
  `RsaPadding::OaepSha512` sits beside `Oaep(OaepHash)` because `OaepHash` names frozen
  transport methods.

## Unsafe code and other tools

Every unsafe site is in `p11-fault` (four files, about 80 sites) plus `loaded_path` in
`crates/pkcs11/src/token/mod.rs` [run]. All four p11-fault files with unsafe code were read;
nothing a client can trigger was found. Each pointer read is guarded by a null check and a
length check against the structure's size, and panics stop at `guard`. The one soundness gap is
that `find_objects` and `mechanism_list` (`crates/p11-fault/src/hooks.rs:82`, `:132`) trust the
count the real module writes back.

RAPx would cover only that crate and needs a pinned nightly: not run. An ASan build of the fuzz
targets (`checks.fuzz` runs without a sanitizer today) covers the same ground more cheaply.
cargo-machete found the unused dependencies (B7).

## What held up

Worth saying, since the list above is long: the identity core (`reconcile.rs`, `identity.rs`,
`possession.rs`), the TPM attestation path and the PIV chain verifier check what they claim to,
with host-side verification throughout and no stored proof. Errors carry stable exit codes,
`unsafe` is confined, CI pins every action by commit with read-only permissions, and no
production `unwrap` on external input was found outside kmsp11's embedded table (Q22).
