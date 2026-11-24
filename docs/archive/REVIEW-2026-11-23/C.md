# Area C: Command lines, camigrate, Nix/CI

Reviewer C, 2026-11-23, repo `~/srcs/cakeys` @ 4304989. Read-only: no cargo or nix build was run.

## Summary

The camigrate key paths are careful: plaintext goes through `Zeroizing` buffers (file.rs, keyfile.rs, `Token::extract`, the `Secret` template wrapper), key files are written 0600 through an atomic rename, and the KDF cost of untrusted PKCS#8/PKCS#12 input is bounded. Each imported object is recorded in the lock before the next one is touched, and a failed import removes what it made. The 2026-11-18 findings for this area are fixed, except one fix that is incomplete (C-14).

The biggest risk is C-1. An offline export (`export --transport FILE`) seals keys to any RSA identity the lock pins. The code never checks that the identity is the target's transport key, and `--transport-key` is silently ignored on that path. Anyone who can swap the transport file in transit and holds the private half of another pinned RSA key can unwrap the exported keys. For example, a dev SoftHSM's transport key in a lock shared with a production HSM is enough.

The second-largest group is CLI consistency:

- `--token` means the source, the target, or an address filter, depending on the verb.
- There are three spellings of "don't write" and several silently ignored flags.
- `verify` is documented as its own verb but is an alias of `check`.
- `--json` exists in one tool only.
- `import --in` chooses its parser by whether `--passphrase-file` is present.
- Notes are buffered to the end of the run, so a killed `migrate` prints nothing.

The biggest simplification wins:

- Move the ~450 lines of plan rules out of camigrate's lib.rs. ARCHITECTURE.md says "the CLI only parses, reads and writes files, and prints"; that is not what the file does.
- Keep one Nix build instead of two. The shipped `packages.default` is the regular build, which no check and no CI job builds.
- Use one key-file reader instead of two.
- Generate the exit-code list in each tool's `--help` from one table.

## Findings

### C-1. A transport file may name any RSA key the lock pins, not only the target's transport key. — high — 2 — verified

`crates/camigrate/src/tokens.rs:772-778`, `:594-601`, `:613-630`; `crates/camigrate/src/lib.rs:558-564`, `:845-848`

**What the check does.** For an offline export, D3 says the source wraps only to the target's transport key, with the lock as the authenticated channel. `tokens::pinned` checks only two things: the file's `object` names some lock object, and its `rfc7093m4` equals that object's.

**What it skips.** The token path does these checks through `transport_spec` and `transport_fault`. On the `Dest::Transport` path none of them is made:

- that the object is a transport key at all (RSA private key, `CKA_UNWRAP = true`, non-extractable);
- that the object is realised on the file's `token`;
- that the object is that token's `transportWith` or the `--transport-key` given.

`--transport-key` is passed into `Request.transport_key`, but `plan_moves` reads it only for `Dest::Token`. The file's `token`, `provider` and `mechanisms` are taken as given: they become the plan's target name and the target's capabilities.

**Trigger.** One lock pins two targets' transport keys, `tk-prod` on the HSM and `tk-dev` on a SoftHSM. An attacker who controls the transport file in transit rewrites it as `object = "tk-dev"`, with tk-dev's real `rfc7093m4` and `spki`, and keeps `token = "prod-hsm"`.

**Consequence.** `camigrate export … --transport f.toml` plans "ready". It writes a bundle whose keys are sealed to tk-dev. Anyone with the dev SoftHSM's files unwraps them. Prod's import then fails (14: the transport key is not realised there), but the bundle already exists and has been handed over. Any pinned RSA identity of at least 2048 bits is enough: a certificate's subject key, or an extractable RSA key.

This is untested: `transport_files_and_bundle_entries_are_checked` (dry_run.rs:1215) only tries an object the lock does not pin. The read-once test's "rogue" file keeps the wrong `rfc7093m4`.

**Fix.** In `pinned`, resolve the spec as `--transport-key`, else keys.toml's `tokens.<t.token>.migrate.transportWith`. Then require `transport_spec(lock, &t.token, Some(spec))` to pass (`transport_fault`), with `lock.realisation(spec, &t.token).object == t.object`. Honour `--transport-key` there. Add the dev/prod substitution as a refusal test.

### C-2. `migrate --dry-run` accepts a `--spec` that the real run refuses (17). — medium — 1/6 — verified

`crates/camigrate/src/lib.rs:348-351` against `:675-683`; `:1126-1143`

The dry-run arm calls only `specs_import`. That function skips a name keys.toml does not have, and a spec of an object that is not moving (`cfg.specs.get(name)` is `None`, or the spec is not on `to`). Only the real `migrate` calls `specs_select` after planning, which refuses both with 17.

So `migrate k --from a --to b --spec typo --dry-run` prints "ready" and exits 0, and the same command without `--dry-run` exits 17. This breaks D9: "the real run … exits as the dry run did".

There is a second, latent divergence of the same kind. The real run refuses any method that is not `built` (`:684-704`, e.g. `Method::Vendor`), and the dry run does not check that.

Fix: run `specs_select` in `plan_opening` for a `Dest::Token`, which serves both arms. Move the `built` check into the plan as a blocking reason.

### C-3. `verify` is an alias of `check`, but the docs describe it as a separate verb. — medium — 5/6 — verified

`crates/cli/src/lib.rs:100-106`; `README.md:27`, `:41`; `docs/ARCHITECTURE.md:83`, `:112`; `docs/CAKEYS.md:21`, `:38`, `:42`

`#[command(visible_alias = "verify")]` makes `verify` exactly `check`: it prints the URI, and it enforces the attestation dates. The docs say otherwise in several places:

- README lists `verify` and `check` as separate verbs, and presents `verify` as the way to recheck a backup.
- ARCHITECTURE's verb table gives `verify` its own row.
- CAKEYS.md:42 says "every other verb (`lock`, `create`, `verify`, `resolve`, camigrate) judges the same dates but only warns: `check` is what enforces". That is false for `verify`.

A script that runs `cakeys verify x` and expects nothing on stdout gets a URI.

Fix: drop the alias and say `check` everywhere. The tests, demo.sh and the custom-provider example use `verify`: about 30 call sites, all mechanical. If the name is wanted, make `verify` a real verb that is `check` without stdout.

### C-4. Flags that do nothing, or that are silently ignored. — medium — 6 — verified

- **cakeys `--update-lock`** (`crates/cli/src/lib.rs:207-209`): a no-op, "kept so existing scripts can say it". The tool is unpublished and its lock format is a draft. The only users are the repo's own tests: `nix/module-test.nix:201,203`, `nix/test.nix:141,154,175,184` and `crates/cli/tests/fault.rs:117,176,210,220`. The surface test keeps the flag alive by counting those uses.
- **`export --passphrase-file` without `--to-file`** (`crates/camigrate/src/lib.rs:161-164`, `:337`): ignored for a bundle export. It has no `requires = "to_file"`.
- **`--transport-key` with `--transport FILE` or `--to-file`** (`:845-848`; `tokens.rs:614`): ignored (see C-1).
- **`--json` on a real `export`**: ignored, because the plan is never shown (`:512`, `show = false`).
- **`--allow-host-plaintext` on a bundle export** (`--target` or `--transport`): changes nothing. `limit_bundle_plans` (`:1019-1029`) blocks every host method either way.
- **`export --to-file` without `--out` or `--passphrase-file`**: caught at run time as 17 (`:329-334`) rather than by clap.

Fix:

- Delete `--update-lock`.
- `#[arg(requires = "to_file")]` on `--passphrase-file`.
- `conflicts_with_all = ["transport", "to_file"]` on `--transport-key`, until C-1 makes it apply to `--transport`.
- `requires = "dry_run"` on `--json`.
- `requires_all = ["out", "passphrase_file"]` on `--to-file`, except with `--dry-run` (an `ArgGroup`).

### C-5. Which token a flag names depends on the verb, and arity and repeatability differ. — medium — 6/5 — verified

`crates/camigrate/src/lib.rs:140-238`; `crates/cli/src/lib.rs:155-166`; `crates/caprobe/src/lib.rs:119-196`

| Flag | Verb | Means |
|---|---|---|
| `--token` | `camigrate export` | the source |
| `--token` | `camigrate import` | the target |
| `--token` | `camigrate transport` | where the transport key is |
| `--token` | cakeys verbs | narrows an address |
| `--token` | `caprobe caps`, `probe` | required, the token measured |
| `--token` | `caprobe supports` | profile lookup |
| `--from`/`--to` | `migrate` | source and target |
| `--target` | `export` | the target |
| `--trusted` | `transport` | the source |

Other inconsistencies:

- `migrate` takes one positional object. `export` and `import` take several, and `migrate a b` is a usage error.
- `--spec` is single in cakeys and `transport`, and repeatable in `import` and `migrate`.
- Three verbs that point a token at another token spell that three ways.

A user who switches between `migrate` and `export` and `import` has to relearn which flag is the source. See "CLI surface" below for one scheme.

### C-6. The flag `--passphrase-file`, not the file, decides how `import --in` parses its file; key files have two readers. — medium — 6/4 — verified

`crates/camigrate/src/lib.rs:185-197`, `:339-347`; `crates/camigrate/src/file.rs:166-182`; `crates/camigrate/src/keyfile.rs:66-104`

`--in X` is read as a bundle unless `--passphrase-file` is given:

- A PEM key file passed without the flag fails as a TOML parse error (17).
- A DER key file fails as "reading X" (1, not UTF-8).
- With the flag, only an encrypted PKCS#8 PEM or a PKCS#12 is read, through `file::read`.

So a plain `PRIVATE KEY`, PKCS#1 or SEC1 file cannot come in through `--in` at all. Yet `keyfile::read`, which `import` uses without `--in`, reads every format, encrypted ones included, "recognised by content, never by extension" (FILE.md F4). A bundle passed with `--passphrase-file` gets "neither an encrypted PKCS#8 PEM nor PKCS#12".

Fix:

- Tell a bundle from a key file by content: TOML with `format = "cakeys-export"`, else a key file.
- Read key files only through `keyfile::read` (one reader). `--passphrase-file` then only supplies the passphrase.
- This also simplifies `reads_key_file` in `dispatch` (`:291-292`).

### C-7. Notes are held until the run ends. A killed or crashed run prints nothing, and stderr comes out of order. — medium — 6/1 — verified

`crates/cli-common/src/lib.rs:71-84`; `crates/core/src/reconcile.rs:63-89`; `crates/camigrate/src/lib.rs:641-652`, `:755-766`; `crates/cli/src/lib.rs:397-399`, `:469-471`, `:506`

`Notes` collects lines in a `Vec`, and `cakeys_cli_common::main` prints them after `dispatch` returns. That loses output in several cases:

- **camigrate.** `import` and `migrate` put nothing on stdout. Their only per-object report is the `imported …`/`moved …`/`… not moved` notes. A run killed by SIGINT, OOM or a module crash (OPEN.md has a SoftHSM `C_Sign` crash) prints none of them. `an_import_killed_part_way_has_recorded_what_it_made` (camigrate fault.rs:234) shows that the lock is right, but the operator sees an empty terminal.
- **Long runs.** `caprobe probe` (minutes at 16384-bit RSA) and `create` over several tokens show no progress at all.
- **Ordering.** Lines written directly with `eprintln!` appear first: `validate`'s refusals, `create`'s refusals, `check --token`'s failures, and `read_lock`'s "waiting" line. The buffered notes from before them follow, so stderr does not match the order of events.

Fix:

- Stream each note to stderr when it is added: give `Notes` a sink, and keep the buffer only for tests.
- Have `import`, `migrate` and `delete` print a JSON result per object (object, spec, token, outcome, method, exit code), as `create` already does (`crates/cli/src/lib.rs:546`).

### C-8. The shipped package is the regular build, which no check and no CI job builds; on first use it runs the whole token suite. — medium — 8/3 — verified

`flake.nix:99`, `:123`, `:193-207`; `pkgs.nix:22`, `:31`, `:86`; `checks.nix:16-19`; `nix/package.nix:1-62`; `nix/package-crane.nix:30-47`; `.github/workflows/checks.yml:29-33`

These all come from `nix/package.nix` (`buildRustPackage`):

- `packages.default` and `packages.cakeys`;
- `nixosModules.default`'s default `services.cakeys.package`;
- `packages.caprobe`, `packages.camigrate` and `packages.p11-fault` (`inherit (cakeys) …`);
- `apps.caprobe`, `apps.camigrate` and `apps.demo` (`local.demo` is built on the regular `cakeys`).

Every check and every CI job builds `cakeys-crane` instead. `nix flake check --no-build` only evaluates the regular build.

Consequences:

- What users install has never been built in CI.
- The first `nix run .#camigrate` or `nix run .#demo` runs the regular build's own check phase: every integration suite, with nextest, p11-kit and swtpm. That is minutes to hours, uncached.
- cryptoki is patched two different ways: a `postPatch` loop over `$cargoDepsCopy` against crane's `overrideVendorGitCheckout`. They can drift, and nothing would notice.

README.md:163 also says `checks-crane-only` is "the same without the fuzz smoke run, on the crane build". It leaves out Kani as well, and every check is the crane build anyway.

Fix: make `packages.cakeys` the crane `buildPackage` with `doCheck = false`, since `checks.cakeys` runs the tests. Move `passthru.patchedCryptoki` there; `scripts/local-tests.sh:54` reads it. Delete `nix/package.nix` and fold `package-common.nix` into the crane file.

### C-9. A PC/SC or TPM grant reaches every card or the whole TPM, not only "that token". — medium — 2/5 — verified

`nix/module.nix:51-55`, `:280-296`, `:302-315`; `README.md:141-143`; `docs/CAKEYS.md:163-172`

`tokens.<n>.pcscd = true` adds `/run/pcscd` to `<prefix><n>`'s grant. The pcscd socket serves every reader on the host. The polkit rule allows `access_pcsc` and `access_card` to every build user for every reader. A token whose `sandboxPaths` list `/dev/tpmrm0` hands over the whole TPM.

So a build that requires `token-yubikey-a` can talk to `yubikey-b`, or to an admin's card that is plugged in. README says the module gives "pcscd or the TPM, only to builds that require that token's feature". That reads as per-token isolation, which the module cannot give.

This is not the known gap "features are self-declared" (DESIGN §8.2). That gap is about who may claim a feature; this one is about how much a feature grants. The module is "for testing only" (decision on prior F3/F4), but the README states this as a security property.

Fix: say in README, CAKEYS.md and the option descriptions that a pcscd or TPM grant is host-wide. Alternatively, refuse two `pcscd = true` tokens with an assertion.

### C-10. The exit codes in each tool's `--help` are three hand-written lists, and cakeys' is missing 21. — low — 5 — verified

`crates/cli/src/lib.rs:19-25`; `crates/caprobe/src/lib.rs:101-102`; `crates/camigrate/src/lib.rs:112-115`, `:1365-1370`

- cakeys lists 0 and 10–20, and leaves out 21. Yet `read_lock` returns 21 for any writing verb (`cli-common/src/lib.rs:250`), and `save_lock` returns it too.
- caprobe lists five codes.
- camigrate's list is tested, but only against a set hard-coded in the test.
- None of the three mentions 2 (usage).

Fix: put one `EXIT_CODES` table in cli-common, render it into each command's `after_long_help`, and test it against CAKEYS.md's table, which `crates/core/tests/exit_codes.rs` already parses.

### C-11. Help text uses jargon and internal review IDs; `caprobe probe --write` reads as "write the profile". — low — 6 — verified

`crates/cli/src/lib.rs:100`; `crates/camigrate/src/lib.rs:198`, `:218-220`, `:247`, `:254`; `crates/caprobe/src/lib.rs:163`, `:173-179`, `:187`

- `check` is introduced as a "Pseudo-FOD pre-use check".
- camigrate's flags cite "(docs/CAMIGRATE.md D2)" and "(D3)".
- caprobe's `--profiles` cites "(D11)".

None of these mean anything to a user without the repository. In caprobe, `probe --write` means "also run the probes that create and delete objects", right beside `--out` ("write the profile here").

Fix: plain-language one-liners, with the design IDs kept in docs only. Rename the caprobe flag to `--write-probes` (or `--destructive`).

### C-12. Inside a Nix build, camigrate exits 14 for some verbs and 21 for others; the 21 message offers no way out. — low — 5/6 — verified

`crates/camigrate/src/lib.rs:294-312`; `crates/camigrate/tests/dry_run.rs:1094-1095`

`export`, an import of a key file and `transport --trusted` are refused as `PreconditionFailed` (14). `migrate` and `import` are refused by `read_lock` as 21, with the reason "moving keys records them there". That reason does not say what to do; cakeys' equivalent says "pass --no-update-lock". The cause is the same, `in_nix_build()`, but there are two codes. CAKEYS.md defines 14 as "the realisation moved, retry after review".

Fix: one code for "refused inside a Nix build". The codes are frozen (DESIGN §10), but lock v1 is still a draft. Make the 21 message say "run outside the sandbox, or pass --dry-run".

### C-13. The `tpm2_ptool` path writes the key into the TPM before checking its identity on the host. — low — 2 — verified

`crates/camigrate/src/host.rs:161-188`, against `:44-50` and `:65-85`

`host::import` and `create_and_record` run `check_identity` (10 before anything is written) between `hand_over` and the write. `import_ptool` does not: it runs `to.import_plaintext(...)` (`tpm2_ptool`, with the user PIN on its command line) first. Only after a reopen does `lock_import` find a mismatch, which `destroy` then undoes. tpm2-pkcs11 can delete, so nothing is left behind. But a lying source module costs a write into the TPM and a PIN on argv for nothing, and the path differs from the documented rule (CAMIGRATE.md D6: "On every `host` path the identity is checked on the host first").

Fix: call `check_identity(dst, lock, &plain)?` before `import_plaintext`.

### C-14. Prior F6's fix is incomplete: an empty `passphraseEnv` is not refused. — low — 7 — verified

`crates/camigrate/src/file_verbs.rs:283-289`, `:303-311`; `crates/core/src/secret.rs:19-35`

The 2026-11-18 fix says "the empty passphrase is refused in one place". It is refused only in `read_passphrase`, which handles files. The `passphraseEnv` branch returns `secret::read(...)` directly, so `X=""` passes. The run then fails as "it does not open under this passphrase" (17), which hides the real cause.

Fix: one `non_empty` check after `file_passphrase`, or in `secret::read`.

### C-15. `pub mod bundle` and its `pub` items are used only inside the crate. — low — 7 — verified

`crates/camigrate/src/lib.rs:6`; `crates/camigrate/src/bundle.rs:24-26`, `:31`, `:53`, `:119`, `:236-301`

The fuzz targets use `camigrate::fuzzing`, which is in-crate. Nothing outside the crate names `camigrate::bundle`, yet `Bundle`, `Entry`, `parse`, `to_toml`, `encode` and the accessors are public API.

Fix: make it `pub(crate)`.

### C-16. A `--lock` path that does not exist is read as an empty lock; `lib.mkKeys` refuses the same thing. — low — 6 — verified

`crates/core/src/config/io.rs:12-18`; `nix/lib.nix:66-71`; `crates/cli/src/lib.rs:236`

`cakeys lock x -l keys.look` (a typo) writes a new one-object lock beside the real one and exits 0. `check -l typo` reports a first use (18), and camigrate reports "no realisation" (14). `lib.mkKeys` throws on the same mistake.

Fix: an explicit `--lock` naming a missing file is 17 for a verb that does not write. A writing verb notes "creating <path>".

### C-17. The planner competes vendor methods that nothing produces. — low — 4 — verified

`crates/camigrate/src/plan.rs:142-151`, `:768-794`; `crates/core/src/migrate.rs:332`; `crates/camigrate/src/lib.rs:684-704`

`Side.vendor` is only ever `vec![]` (`Side::pkcs11`); no profile or provider fills it. Even so:

- the planner offers vendor methods, notes their declared level, and has a test for that;
- `migrate` keeps a `built` allow-list whose purpose is to refuse them after planning (see C-2).

Phase 7 (D10) is not built.

Fix: delete the vendor loop, its test and `VendorMethod` until a provider declares one. Keep `Method::Vendor`'s name parsing only if the frozen lock names need it. About 40 lines in camigrate, plus core's.

### C-18. FILE.md has drifted from the code. — low — 5 — verified

`docs/FILE.md:93-94`, `:322-323`, `:362-365`

- **Load rule.** FILE.md lists "`attestation = true` on a `file` pair is refused when the provider cannot attest" among its load rules (17). It is a run-time check (`ops::check_import` → `check_imported_attestation`, prior F2); `check_origins` has no such rule.
- **Wrong file.** "`from_its_file`, `crates/camigrate/src/lib.rs`": it is in `file_verbs.rs`.
- **"Not built" items that are built.** "A `keyfile` fuzz target": `fuzz/fuzz_targets/key_file.rs` exists. "The capability profile in the dry run": `from_its_file`'s dry run calls `import_checks` (`file_verbs.rs:390`).

CAMIGRATE.md:19 shows `--out <bundle>` as required, but it defaults to stdout. Fix the text.

### C-19. The test-environment variables are written out twice. — low — 8/4 — verified

`nix/package-common.nix:197-236`; `scripts/local-tests.sh:112-130`

The `CAKEYS_*_MODULE`, `*_REQUIRE`, `CAKEYS_TOKEN_TEMPLATE`, `CAKEYS_P11KIT_ENV_SH`/`CAKEYS_TPM_ENV_SH`, `CAKEYS_P11KIT_CLIENT` and `CAKEYS_PKCS11_PROVIDER_DIR` exports, and the template copy, appear in both files. A new suite variable has to be added to both, or the local runner silently skips that suite. `nix/token-env.sh` already unifies the token initialisation.

Fix: a `test_env <softhsm> <kryoptic> <p11kit> <tpm2> <tpm2-vendor> <provider-dir>` function in token-env.sh, used by both.

### C-20. The transport key's 2048-bit minimum is counted in bytes. — low — 2 — verified

`crates/camigrate/src/sealed.rs:765-773`

`bits = rsa_parts(spki)?.0.len() * 8` counts the modulus's bytes, so a key of 2041–2047 bits counts as 2048 and passes. Practical weakening is nil, but the rule says "at least 2048 bits".

Fix: use `key.n().bits()`.

### C-21. After a failed per-object save, the remaining objects and the earlier failure are dropped without a recovery hint; the lock is also saved twice. — low — 6/4 — verified

`crates/camigrate/src/lib.rs:449-468`, `:641-643`, `:756-758`

When `Run::record` fails, the run returns 21 at once: "X is on the token, but the lock could not record it". The objects not yet tried are skipped, and the tally's first failure is lost. The message does not name the recovery (`cakeys lock --spec S --token T` records it, without provenance). The next camigrate run hits 13 at the locator, again with no hint.

`Tally::finish` also saves the lock again after every object was already saved: an extra temporary file, fsync and rename, done only to print "updated".

Fix: name the `cakeys lock` command in both messages. Have `finish` only print.

### C-22. A PKCS#12 with a plain `keyBag` is refused confusingly, and its key is left unzeroized. — low — 2/7 — plausible

`crates/camigrate/src/file.rs:205-224`, `:252-266`

`encrypted_octets` returns the decrypted SafeContents in a plain `Vec`. Take a file from `openssl pkcs12 -export -keypbe NONE`, whose unencrypted `keyBag` may sit in an encrypted container. Its key bytes are decrypted, never zeroized, and skipped, because only the shrouded bag OID is read. The file is then refused as "a PKCS#12 without a shrouded key bag".

I did not build such a file to confirm where OpenSSL puts the bag.

Fix: return `Zeroizing<Vec<u8>>`, and refuse `PKCS_12_KEY_BAG_OID` by name ("an unencrypted key bag; re-export with a key PBE").

### C-23. camigrate's lib.rs holds the planner's rules: about 450 lines that ARCHITECTURE says the CLI does not have. — medium — 3/4 — verified

`crates/camigrate/src/lib.rs:470-490`, `:770-1217`; `crates/camigrate/src/file_verbs.rs:5-9`; `docs/ARCHITECTURE.md:88`

ARCHITECTURE.md:88 says "The CLI only parses, reads and writes files, and prints". lib.rs contains, among others: `plan_opening`, `landing_checks`, `no_import_pair`, `import_target`, `specs_select`, `specs_import`, `no_export`, `unprovable`, `limit_bundle_plans`, `limit_file_plans`, `transport_target`/`transport_choice`/`locked_spki`, `realised_target` and `import_checks`. They block plans in a third layer, after `plan::plan` and `tokens::plan_moves`. The same `p.ready = false; p.reasons.push(...)` appears about 8 times.

Related duplication:

- `Destination` (lib.rs:407) and `tokens::Dest` (tokens.rs:475) are near-identical enums, converted at `:827-848`.
- `plan` is a two-line wrapper over `plan_opening`.
- Four functions carry `#[expect(clippy::too_many_arguments)]`: lib.rs:473, `:793`, `:812` and file_verbs.rs:15.
- `file_verbs.rs` reaches into lib.rs with `#[allow(clippy::wildcard_imports)] use super::*`.

C-2 shows the cost: the dry-run arm and the run assemble their checks differently.

Fix:

- A `landing.rs`, or `plan.rs` grown, holding every blocker as one ordered list over `(Plan, MoveCtx)`.
- One `Dest` enum, and a `MoveCtx { objects, from, dest, specs, how }` struct.
- lib.rs left as clap plus routing.

## Complexity reduction proposals (ranked, with estimated lines saved)

1. **camigrate planner out of lib.rs** (C-23, C-2).
   - Move the ~450 lines of rules into `landing.rs`/`plan.rs` as one ordered blocker list.
   - Merge `Destination` and `Dest` (~30 lines), and `plan` into `plan_opening` (~15).
   - A `MoveCtx` struct replaces four 8–9-argument signatures and their `#[expect]`s.
   - Net about −80 lines. lib.rs goes from 1,371 to about 850. The dry run and the run share one entry, which closes C-2 by construction.
2. **One Nix build** (C-8).
   - Delete `nix/package.nix` (62) and fold `package-common.nix` into `package-crane.nix` (about −60 more).
   - One cryptoki patching mechanism.
   - Users get the artifact CI builds, without a first-use test run.
3. **One key-file reader and content-sniffed `--in`** (C-6).
   - Drop `file::read`'s PEM branch and `import_file`'s separate decrypt path (about −40).
   - Drop `reads_key_file`'s passphrase rule.
   - `import_file` then shares `from_its_file`'s read, check and create flow (about −60).
4. **Exit codes from one table** (C-10).
   - Three hand-written help lists and camigrate's hard-coded test (about −25) become one cli-common constant, tested against CAKEYS.md.
5. **Delete dead or no-op surface** (C-3, C-4, C-17).
   - The `--update-lock` flag and its 10 test uses.
   - The `verify` alias, or a real verb.
   - `MoveArgs.json`, replaced by a global `--json`.
   - Vendor-method planning (about −40 in camigrate; core's `VendorMethod` about −30).
6. **Test-environment contract in token-env.sh** (C-19): about −20 lines across `package-common.nix` and `local-tests.sh`.
7. **`Tally::finish` only prints** (C-21): a few lines, and one fsync per run.

## CLI surface

### Today: every verb and flag

Global flags:

| Tool | Global flags |
|---|---|
| cakeys | `-c/--config FILE` (required, env `CAKEYS_CONFIG`) · `-l/--lock FILE` (env `CAKEYS_LOCK`, default `<config>.lock`) · `--module TOKEN=PATH`… |
| caprobe | `-c/--config` (optional: only `supports --profile` runs without it) · `--module`… · no `--lock` |
| camigrate | as cakeys |

Verbs:

| Tool | Verb | Positional | Flags | stdout | Writes |
|---|---|---|---|---|---|
| cakeys | `validate` | — | — | text `<spec> on <token>: mode M` (on pass only) | — |
| cakeys | `resolve` | `[object]` | `--spec` `--token` | JSON | — |
| cakeys | `lock` | `[object]` | `--spec` `--token` `--no-update-lock` `--update-lock` (no-op) | JSON | lock by default |
| cakeys | `create` | `[object]` | `--spec` `--token` `--dry-run` `--skip-unsupported` `--no-update-lock` `--update-lock` (no-op) | JSON array (the plan, as JSON, with `--dry-run`) | token + lock |
| cakeys | `delete` | `[object]` | `--spec` `--token` `--if-match ID` `--no-update-lock` `--update-lock` (no-op) | nothing | token + lock |
| cakeys | `gc` | — | `--apply` | text entries | lock only with `--apply` |
| cakeys | `check` (alias `verify`) | `[object \| object.id.scheme]` | `--spec` `--token` `--format uri\|pkcs11-provider-pem` `--uri-module` `--uri-pin source\|value` `--at TIME` `--ignore-validity` | URI, PEM, or module path (`--token` alone) | — |
| caprobe | `caps` | — | `--token` (required) | JSON | — |
| caprobe | `supports` | `[NAME]` | `--profile`\|`--token` `--layer`… `--class` `--oaep` `--bits` `--profiles DIR` | text; exit 0/15/16 | — |
| caprobe | `probe` | — | `--token` (required) `--write` `--out FILE` `--name` `--diff P` `--profiles DIR` `--rsa-max-bits` | TOML profile or diff | the scratch token with `--write`; a file with `--out` |
| camigrate | `export` | `[object…]` | `--token SRC` (required) `--target T`\|`--transport FILE`\|`--to-file pkcs8\|pkcs12` `--out` `--passphrase-file` `--dry-run` `--json` `--transport-key SPEC` `--allow-host-plaintext` | bundle TOML, or the plan (table or JSON) | file |
| camigrate | `import` | `[object…]` (not with `--in`) | `--token T` (required) `--spec`… `--in FILE` `--dry-run` `--passphrase-file` `--allow-host-plaintext` | "ready" lines (dry run); else nothing | token + lock |
| camigrate | `migrate` | `[object]` (one) | `--from` `--to` (required) `--spec`… `--dry-run` `--json` `--transport-key` `--allow-host-plaintext` | the plan (table or JSON), also on a real run | token + lock |
| camigrate | `transport` | `[object]` | `--spec` `--token T` (required) `--out FILE` \| `--trusted SOURCE` | transport TOML | file, or the source token (as SO) |

Judgements:

- **Naming.** `--token` has six roles (C-5). Moving between tokens is spelled `--token/--target`, `--token`, `--from/--to` and `--token/--trusted`. `--transport` (a file) sits beside `--transport-key` (a spec name) and the `transport` verb. `probe --write` sits beside `--out` (C-11).
- **Positional or flag.** The object is positional everywhere, which is good. Its arity is not: one in `migrate`, many in `export` and `import`, and one (optional) in cakeys verbs, where `create` alone selects every pair. Tokens are flags everywhere, which is also good.
- **Single or repeatable.** `--spec` is repeatable only in `import` and `migrate`. `--module` and `--layer` are repeatable, consistently.
- **Required or optional.** caprobe's `--config` is optional, the others' required. The constraints around `export --to-file` are checked at run time (C-4).
- **No-op flags.** `--update-lock`; `export --passphrase-file` for a bundle; `--transport-key` with a file target; `--json` on a real export; `--allow-host-plaintext` on a bundle export (C-4).
- **`verify`/`check`.** One verb with two names, documented as two (C-3).
- **JSON.** `--json` exists only on camigrate's `export` and `migrate`. cakeys is JSON for resolve, lock and create (including `create --dry-run`, the cakeys counterpart of camigrate's plans), and text for validate and gc. caprobe is JSON for caps, TOML for probe and text for supports. `import --dry-run` cannot produce JSON.
- **"Don't write".** Spelled `--no-update-lock` (lock, create, delete), `--dry-run` (create, camigrate), or by leaving out `--apply` (gc). `delete` and `lock` have no dry run.
- **Streams.** The rule "stdout is the result" holds, but camigrate's real runs have no result on stdout. Notes are buffered (C-7).
- **Exit codes.** Three different `--help` lists, cakeys' missing 21 (C-10). In a Nix build camigrate gives 14 or 21 for the same cause (C-12). Usage errors are clap's 2 everywhere: caprobe through `try_parse`, the others through `Cli::parse()` inside `dispatch`.
- **Actionable errors.** Mostly good: they name the flag, spec or config key. The weak spots are a TOML parse error for a key file given to `--in` (C-6), the camigrate 21 reason, and the recovery after a failed save (C-21).

### Proposed consistent surface

**Shared**, defined once in cli-common:

- `-c/--config` and `-l/--lock` for cakeys and camigrate; caprobe takes `-c` only.
- `--module TOKEN=PATH`…
- A global **`--json`**: stdout is one JSON document for every report verb — validate, gc, the dry-run plans, import/migrate/delete results, supports. The verbs whose output is data keep their single format: resolve, lock and create (JSON), check (URI or PEM), export (bundle), transport and probe (TOML).
- Every verb that writes a token or the lock takes **`--dry-run`**: open read-only, write nothing, print what it would do.
- Notes stream to stderr.
- `--help` renders the one exit-code table.

**An object address** is the same everywhere: `<object>…` positional, zero or more, with `--spec S`… (repeatable) and `--token T` naming *where the object is*. `--token` never means a source or a target.

**cakeys:**

- `validate`, `resolve`, `lock`, `create`, `delete`, `gc` and `check`, with no `verify` alias.
- `--update-lock` removed.
- `--no-update-lock` kept on `create`, for the first-use flow OPEN.md keeps.
- `lock`, `delete` and `gc` gain `--dry-run`. `gc` writes by default like the other lock verbs, with `--dry-run` replacing `--apply`.
- `check`'s output flags unchanged.

**camigrate.** The direction is always explicit:

- `export <object>… --from SRC (--to TOKEN | --to-transport-file FILE | --to-key-file pkcs8|pkcs12 --passphrase-file F) [--transport-spec S] [--out FILE] [--allow-host-plaintext] [--dry-run]`
- `import [<object>…] --to TOKEN [--in FILE] [--spec S]… [--passphrase-file F] [--allow-host-plaintext] [--dry-run]`. `--in` is a bundle or a key file, told apart by content.
- `migrate <object>… --from SRC --to DST [--spec S]… [--transport-spec S] [--allow-host-plaintext] [--dry-run]`
- `transport [<object>] [--spec S] --token T [--out FILE]`, and `transport … --trust-on SOURCE` (renamed from `--trusted`).

The flags clap ties together: `--passphrase-file` requires a key-file direction, and `--transport-spec` conflicts with `--to-key-file`.

**caprobe:**

- `caps --token T`
- `supports [NAME] (--profile P | --token T) …`
- `probe --token T [--write-probes] [--out FILE] [--diff P] …`

## Still open from the 2026-11-18 review (one line each)

- **Incompletely fixed:** camigrate lib.rs F6, the empty passphrase → C-14.
- **Decided, not re-reported:**
  - flake.nix F1 (CI builds x86_64 only);
  - nix/deny.nix F1 (staleness guard off in the sandbox);
  - nix/module.nix F3/F4 (the module is for testing only; see C-9 for the README claim this contradicts);
  - camigrate tokens.rs F3 (moot);
  - dry_run.rs F8 (`Box::leak`);
  - camigrate surface.rs F1;
  - nix/fuzz.nix F2 (no ASan).

## Cross-area notes (issues seen in another agent's files; one line each, no deep dive)

- **core (A):** `Notes` (reconcile.rs:66) is a buffer by design, which is the root of C-7.
- **core (A):** `secret::read` accepts an empty value from the environment (C-14).
- **core (A):** `load_lock` reads a missing explicit path as an empty lock (C-16).
- **caprobe (D):** its `--help` exit codes list 0, 15, 16, 17 and 1 only.
- **caprobe (D):** `probe --write` naming (C-11).
- **caprobe (D):** `main_from` parses with `try_parse_from`, while cakeys and camigrate exit from inside `dispatch`, so only caprobe is testable in-process.
- **docs:** ARCHITECTURE.md:88 ("the CLI only parses…") is contradicted by camigrate lib.rs (C-23).
- **docs:** ARCHITECTURE.md:83 and :112 present `verify` as its own verb (C-3).
- **pkcs11 (B):** `ops::verify` is the library verb camigrate uses; the CLI has no verb of that name, only an alias of `check`.
- **docs/OPEN.md:** "Dropping `--no-update-lock`: deferred" says nothing about the no-op `--update-lock` (C-4).

## Files reviewed (every file in scope, with one line each: "clean" or finding IDs)

**crates/cli, crates/cli-common**

- `crates/cli/src/lib.rs`: C-3, C-4, C-7, C-10, C-11, C-16
- `crates/cli/src/main.rs`: clean
- `crates/cli/examples/custom-provider.rs`: clean (uses `verify`, see C-3)
- `crates/cli-common/src/lib.rs`: C-7, C-10

**crates/camigrate/src**

- `lib.rs`: C-1, C-2, C-4, C-5, C-6, C-7, C-12, C-15, C-17, C-21, C-23
- `plan.rs`: C-17
- `tokens.rs`: C-1
- `sealed.rs`: C-20
- `keyfile.rs`: C-6 (the reader itself is clean: bounded, zeroized, no panics on input)
- `file.rs`: C-6, C-22
- `file_verbs.rs` (new since the last review): C-14, C-23
- `bundle.rs`: C-15
- `host.rs`: C-13
- `public.rs`: clean
- `transport.rs`: C-1 (its `parse` is fine; the gap is in `pinned`)
- `main.rs`: clean

**crates/camigrate/tests**

- `dry_run.rs`: C-1 (missing test); otherwise sound: the `*_REQUIRE` guards prevent silent skips, though many tests assert on message text
- `fault.rs`: clean
- `from_files.rs`: clean
- `surface.rs`: clean
- `yubikey.rs`: clean
- `fixtures/sample.bundle.toml`, `fixtures/keyfiles/*` (including `make.sh`): clean

**Flake and top-level Nix**

- `flake.nix`: C-8
- `checks.nix`: C-8
- `apps.nix`: C-8
- `pkgs.nix`: C-8
- `treefmt.nix`: clean

**nix/**

- `package-common.nix`: C-8, C-19
- `package.nix`: C-8
- `package-crane.nix`: C-8
- `lib.nix`: C-16
- `module.nix`: C-9
- `module-test.nix`: C-4 (uses `--update-lock`)
- `test.nix`: C-4 (uses `--update-lock`)
- `tpm-test.nix`: clean
- `vm-common.nix`: clean
- `sandbox-hook.sh`: clean (the protocol's trailing blank line is correct; errexit is off inside `grant` by design)
- `fuzz.nix`, `kani.nix`, `kani/library-Cargo.lock`: clean
- `deny.nix`: clean (decided item)
- `demo.nix`: C-8 (the app is on the regular build)
- `demo.sh`: clean (uses `verify`, see C-3)
- `test-tokens.sh`, `token-env.sh`, `p11kit-test-env.sh`, `tpm2-test-env.sh`, `ftpm-test-env.sh`: clean
- `doc-references.py`: clean (it does not check CLI flags in docs; see proposal 4)
- `kmsp11.nix`, `kmsp11-release-key.pem`, `cloudhsm.nix`, `cloud-tools.nix`: clean
- `examples.nix`: clean
- `pkcs11-check.nix`, `mezura.nix`: clean
- `pcsc-probe.c`, `pcsc-probe.nix`, `pcsc-sandbox-probe.nix`: clean
- `softhsm-unwrap-value-len.nix`, `tpm2-pkcs11-vendor.nix`: clean
- `patches/cryptoki-*.patch` (4): clean (not reviewed hunk by hunk; ARCHITECTURE covers what each is for)

**CI and repository configuration**

- `.github/workflows/checks.yml`: C-8 (the regular build is never built)
- `.github/workflows/reports.yml`: clean
- `.config/nextest.toml`: clean
- `deny.toml`: clean

**scripts/**

- `local-tests.sh`: C-19
- `coverage-full.sh`, `coverage-file.sh`, `badges.sh`, `regen-profiles.sh`, `xversion.sh`, `pkcs11-check.sh`, `pkcs11-check-compare.py`: clean
- `yubikey-empty-slots.py`: clean. Nit: the docstring says "the user's own slots", but it compares slots 82–84 only. That is harmless: deletion is restricted to 90–95.
- `cloud/aws.sh`, `cloud/gcp.sh`, `cloud/{aws,gcp}/main.tf`, `cloud/{aws,gcp}/cakeys.toml`: clean (skimmed)

**Docs**

- `docs/CAKEYS.md`: C-3, C-10
- `docs/CAMIGRATE.md`: C-18 (synopsis), C-13 (D6 claim)
- `docs/FILE.md`: C-18
- `README.md`: C-3, C-8, C-9
