# Work plan: three tools, one lock change, then the docs (2026-11-13, at a11e92d)

This file is written for the model that executes it. It assumes no knowledge of the
conversations that produced it. Work through the stages in order, one branch and one commit (or
a few) per stage, and stop where a stage says to stop.

The detail of each feature lives in other files; this file gives the order, the boundaries and
the rules. Read these before starting:

- `docs/ARCHITECTURE.md`: the crate map and control flow.
- `docs/SCOPE.md` and `docs/DESIGN.md` §3–§6: identities, the lock rules, the verbs.
- `MIGRATE.md`: the migration design, its decisions (D1–D10), phases and tests.
- `docs/PROVIDERS.md`: capability profiles and the probe.
- `docs/REVIEW-2026-11-13.md`: findings A1–A11; A3, A5, A6 and A8 are built here.
- `NEXT.md`: the earlier task list. This file replaces its ordering.

## Decisions (made by the user; do not reopen)

| | Decision |
|---|---|
| D1 | **`cakeys` pins and verifies.** It keeps `validate`, `resolve`, `verify`, `realise`, `create`, `delete`, `gc`, `check`, the Nix library, the NixOS module and the sandbox hook. |
| D2 | **`caprobe` measures modules.** It takes `probe`, `supports` and `caps`, the profile emitter and diff, the baseline generator, `scripts/regen-profiles.sh` and the hardware harnesses. It is the only tool that creates and destroys scratch objects. |
| D3 | **`camigrate` moves keys.** It takes `export`, `import`, `migrate` and `transport`. It is the only tool that handles key material. A `cakeys` build carries no migration code (review A5). |
| D4 | **TPM attestation stays in `cakeys-tpm2-pkcs11`,** behind the `tpm2` feature. It is finished (stage 5), not restructured. |
| D5 | **The lock format changes once, in place, and stays `version = 1`.** The format is an unpublished draft. The observation table (review A3), the resolved profile name (PROVIDERS D8) and `provenance.origin` (MIGRATE D7) land together in stage 1. There is no reader for the old layout. |
| D6 | **One workspace, one flake, three binaries.** Nothing moves to another repository. |
| D7 | **No live-token profile check inside `cakeys`** (NEXT.md §1 "D5"). The operator runs `caprobe probe --diff`. Delete that NEXT.md item. |
| D8 | **`tpm-certify` may be tested on this machine's real TPM,** under the rules in "Hardware rules" below. |

## Working rules

**Environment.** NixOS. There is no system `cargo`, `python3` or `perl`.

- Build and test with `nix develop -c cargo …`. Get any other tool with
  `nix shell nixpkgs#<name> -c …`.
- Use `rg`, not `grep`. Shell scripts start with `#!/usr/bin/env bash`.
- Format with `nix fmt -- --no-cache` (the cache has missed files before).
- The gate for every stage is `nix flake check`, all checks passing. It takes several minutes;
  run `nix develop -c cargo clippy --workspace --all-targets -- -D warnings` and the unit tests
  first. Clippy is pedantic: a function that can panic needs a `# Panics` section, and
  exemptions are per-site `#[expect(lint, reason = "…")]`.
- `nix flake check` sees only files git knows: `git add` new files before running it.
- The token test suites (SoftHSM, kryoptic, p11-kit, swtpm) run only in the Nix build's check
  phase. Under plain `cargo test` they skip. A change to token behaviour is not tested until
  `nix flake check` has run.
- Generated profiles must be byte-identical to the committed ones, and only the Nix-built
  binary carries the patched cryptoki the probe needs. The header of
  `scripts/regen-profiles.sh` gives the commands. The baseline is regenerated with
  `CAKEYS_UPDATE_BASELINE=1`, then `nix fmt`.
- Port 23211 on this machine belongs to another process's swtpm. Do not kill it; pass another
  port (`TPM_PORT`, or the third argument of `nix/tpm2-test-env.sh`).

**Git.** One branch per stage, named `<stage>-<date>`, branched from `main`. Commit when the
stage's exit condition holds. Do not push and do not merge into `main`: report, and the user
decides. Match the surrounding code's style and comment density.

**Scope.** Each stage lists what it changes. If finishing a stage seems to need something
outside that list, stop and report instead of widening it. Do not add features, options or
abstractions the stage does not name.

**Frozen names.** Scheme names, method names, exposure levels, the bundle format and exit codes
are pinned by tests (`scheme_definitions_are_pinned`, `method_names_are_pinned_and_round_trip`,
`spec_digests_are_pinned`). If one of those tests fails, the change is wrong, not the test.

**Reporting.** At the end of each stage say what was done, what was verified and how, what was
not verified, and anything that differed from this plan. If tests fail, show the output.

## Hardware rules

Two real devices are attached. Both hold things the user depends on. These rules have no
exceptions; if a task cannot be done within them, stop and report.

**The TPM (AMD fTPM, firmware 3.87).** It unlocks the disk and backs secure boot.

- Never run `tpm2_clear`, change a hierarchy auth, use the lockout auth, extend a PCR, or
  define, write or undefine NV indices.
- Never evict or change the existing persistent handles `0x81000001`, `0x81000002` and
  `0x81010001`. Record `tpm2_getcap handles-persistent` before and after any TPM work and
  compare.
- Never send a wrong PIN or auth value. The dictionary-attack counter is shared with disk
  unlock (31 failures, currently 0). Check `TPM2_PT_LOCKOUT_COUNTER` is still 0 afterwards.
- Reach the TPM through `nix/ftpm-test-env.sh` (tpm2-abrmd over `/dev/tpmrm0`), never
  `/dev/tpm0`.
- The one permitted write is in stage 5: one persistent Attestation Key at `0x81000016`.

**The YubiKey (5C NFC FIPS, firmware 5.7.4).**

- Slots 82, 83 and 84 hold the user's keys. Never write to them, never generate, import or
  delete there, and do not run a proof of possession on them. `examples/yubikey-secureboot.*`
  describes those keys: do not `realise` it against the device.
- Test keys go in retired slots 90–95 only (`CKA_ID` 13–18). The scratch slot for write probes
  is `scratchId = "17"`.
- The credentials are files in `/data/srcs/waste/yubikey_data`: `PIN.txt` is the PIN and
  `piv_mnmgt_key.current.txt` is the management key, used as the Security Officer credential.
  Pass them as file paths (`pinFile`, `mgmKeyFile`). Never print them, copy them into the
  repository, or put them in a commit, a log or a report.
- The PIN has 3 tries. Never guess; if a login fails once, stop.
- MIGRATE phase 5's import test overwrites slot 95. Ask the user before running it.

The Solokey and the Google security key are FIDO-only and out of scope.

## Order

| Stage | Work | Depends on | Stop for the user? |
|---|---|---|---|
| 0 | Record the decisions in the docs | — | No |
| 1 | Lock format change | 0 | No |
| 2 | Split out `caprobe` | 0 | No |
| 3 | Create `camigrate` around the existing planner | 2 | Yes, after it |
| 4 | Migration phases 2–5, inside `camigrate` | 1, 3 | After each phase |
| 5 | Finish TPM attestation | 1 | Before the real-TPM test |
| 6 | Reduce and clean up the docs | all | Yes, with a proposal first |

Why this order: `camigrate` reads the token's module from the lock and writes `origin` into
it, so the lock changes first. `caprobe` splits before migration is built because both tools
need the same shared-library boundary, and it is cheaper to draw it before MIGRATE.md's
estimated 2,200 lines of phases 2–5 are written against it. The phases are built in `camigrate`
from the start, so nothing is written in `cakeys` and then moved.

## Stage 0: record the decisions

Docs only.

- [ ] `docs/SCOPE.md`: three tools and what each may do (D1–D3).
- [ ] `docs/ARCHITECTURE.md` §3, §4, §6 and §11: mark the planned crate map and which binary
      owns each verb. Say "planned" until the stage that builds it lands.
- [ ] `NEXT.md`: a line at the top pointing here for ordering; delete the "D5" item (D7).
- [ ] `docs/REVIEW-2026-11-13.md`: A3 and A5 marked decided, naming the stage.

Do not rename commands in `MIGRATE.md`, `docs/PROVIDERS.md` or `README.md` yet. Each split
stage renames its own commands when the binary exists, so the docs never describe a command
that does not run.

Exit: `nix flake check` passes (the formatter covers Markdown).

## Stage 1: lock format change

Design: `docs/REVIEW-2026-11-13.md`, section "A3: the observation table". Code:
`crates/core/src/config.rs` (`Lock`, `LockRealisation`, `Observed`, `Provenance`),
`crates/core/src/reconcile.rs`, `crates/pkcs11/src/gate.rs`, `crates/pkcs11/src/migrate.rs`,
`nix/lib.nix`.

- [ ] `[observations."sha256-…"]`: one entry per distinct value of module info, token info,
      provider, cakeys version and mechanism list, keyed by the SRI SHA-256 of its own
      canonical form. Use `serde_jcs` for that form, as `spec_digest` does.
- [ ] A realisation names its entry (`observation = "sha256-…"`). `uri` and `session` stay on
      the realisation.
- [ ] `provenance.origin` (MIGRATE.md D7, "Frozen names and formats") is added to the schema
      and stays on the realisation: it is one object's history. Nothing writes it until
      stage 4.
- [ ] The resolved profile name (PROVIDERS D8) is recorded in the observation.
- [ ] Unknown keys are kept on rewrite in the observation entry, as `Provenance.extra` does
      today (`unknown_provenance_keys_are_kept_on_rewrite`). Unknown keys elsewhere are still
      refused.
- [ ] `gc` drops entries no realisation references. A realisation naming a missing entry is
      an invalid lock (17).
- [ ] One function answers "this token's observation" and replaces the scans in `gate.rs` and
      `pkcs11/src/migrate.rs`. When a token's realisations name different entries it returns
      that fact, and the caller says so and names `realise`.
- [ ] `nix/lib.nix` reads `module`, `tokenInfo` and `functions` through the table. Its
      assertions in `checks.nix` (`lib`) keep passing with the same values.
- [ ] The rule "removing observed and provenance changes no verdict" still holds and still has
      its test; extend it to removing the whole table.
- [ ] Convert the committed locks without touching a token: `crates/cli/tests/fixtures/*.lock`
      and `examples/yubikey-secureboot.lock`. The change is pure deduplication, so do it with a
      throwaway conversion (a temporary test or script that is not committed). Every identity,
      policy and scheme in the converted files must equal the original.
- [ ] `docs/LOCK.md` and `docs/DESIGN.md` §4.2 describe the new layout.
- [ ] `scripts/xversion.sh` compares against older commits; read it and adjust what it expects,
      since older binaries cannot read the new layout.

Exit: `nix flake check` passes. Report the line counts of `examples/yubikey-secureboot.lock`
before and after.

## Stage 2: `caprobe`

- [ ] New crate `crates/caprobe` with a binary `caprobe`. It owns
      `crates/pkcs11/src/probe.rs`, `crates/pkcs11/src/supports.rs`, the `caps` verb, and the
      argument parsing for all three (now in `crates/cli/src/lib.rs`).
- [ ] `cakeys-profile` splits by use. `cakeys` keeps linking what reads and resolves:
      `Profile`, `Set`, `Effective`, the embedded data, and whatever `gate.rs`,
      `resolution.rs` and the providers call (for example `derive.sealed`). The emitter,
      `diff.rs` and the baseline generator go behind a cargo feature that only `caprobe`
      enables, or move into `caprobe`. Choose whichever leaves fewer `pub` items.
- [ ] `cakeys-pkcs11` exports what the probe uses from the token layer (`extra_session`,
      `as_so`, `has_admin`, `material_spki`, `raw`, `Provider::scratch_occupant`) as public
      API with doc comments. List what you exported in the report.
- [ ] The provider registry (now built in the `cakeys` CLI crate) moves somewhere all three
      binaries share. `crates/cli/examples/custom-provider.rs` must still work.
- [ ] `probe.rs` imports `OaepHash` from `cakeys_core::migrate`. Move that type to a neutral
      module of `cakeys-core` so `caprobe` does not depend on migration code.
- [ ] Tests move with the code: the probe conformance tests in `crates/cli/tests/`
      (`references.rs`, `tpm2.rs`, `yubikey.rs`, `ftpm.rs`, `p11kit.rs`'s use of `caps`) and
      the `profiles` check in `checks.nix`. Keep the shared harness (`tests/common`) usable by
      both crates without copying it.
- [ ] `nix/package.nix`, `pkgs.nix` and `apps.nix`: `caprobe` is built and exposed. Decide
      between one derivation with several binaries and one per tool by what keeps the
      `cakeys` closure free of probe code; say which you chose and why.
- [ ] `scripts/regen-profiles.sh`, `docs/PROVIDERS.md`, `docs/PROVIDER_PROFILE.md`,
      `docs/DESIGN.md` §5 and `README.md` call `caprobe`.

Exit: `cakeys --help` lists no `probe`, `supports` or `caps`. `nix flake check` passes, which
includes every committed profile regenerating byte-identically. On the hardware, within the
rules above: the opt-in YubiKey and fTPM conformance tests pass (`crates/cli/tests/yubikey.rs`
and `ftpm.rs` document their environment variables).

## Stage 3: `camigrate`, around the planner

No new behaviour: `--dry-run` works exactly as it does today, from a new binary.

- [ ] New crate `crates/camigrate` with a binary `camigrate`. It owns
      `crates/pkcs11/src/migrate.rs`, the planner in `crates/core/src/migrate.rs`, and the
      `export`, `migrate` and `transport` verbs.
- [ ] What the lock schema names stays in `cakeys-core`: the method names and exposure levels
      that appear in `provenance.origin`, with their pinning test. `cakeys` must load a lock
      `camigrate` wrote.
- [ ] The import and export capability hooks (MIGRATE D10) stay on the `Provider` trait. The
      provider crates must not depend on `camigrate`.
- [ ] Recording a realisation after an import will go through the library function
      `cakeys realise` uses (`ops`), so one code path writes `keys.lock`. Make sure that
      function is reachable from `camigrate`; do not copy it.
- [ ] Tests: the dry-run matrix in `crates/cli/tests/references.rs` moves.
- [ ] `MIGRATE.md`, `README.md` and `docs/DESIGN.md` §5 call `camigrate`.

Exit: `cakeys --help` lists no migration verb, and `cargo tree -p cakeys` shows no
`camigrate`. `nix flake check` passes.

**Stop here and report.** The user reviews the three-tool layout before migration is built.

## Stage 4: migration phases 2–5

`MIGRATE.md` is the specification: "Decisions", "Frozen names and formats", "Command line",
"Phases" and "Tests". Build one phase per branch, in this order, and stop after each for
review. Every phase ends with its rows of the dry-run property passing over the reference
matrix: the plan's verdict equals the outcome.

- [x] **Phase 2** `public`: certificates, public keys, data objects.
- [x] **Phase 3** `sealed`: `transport`, RSA-OAEP + AES-KWP and direct OAEP, bundles, import
      with identity check and cleanup, `migrate`. Writes `provenance.origin`.
- [x] **One creation token per object** (NEXT.md §2, "Multi-token objects"), with phase 3.
      keys.toml names where an object is born; `create` and `autoCreate` generate only there,
      and `autoCreate` on another token is invalid (17). This changes `cakeys`, not only
      `camigrate`: propose the keys.toml field name and stop for agreement before building it.
- [ ] **`pop-unwrap` on hardware**, before stage 4 is done. It is observed on SoftHSM and
      kryoptic only. tpm2-pkcs11: an unwrap-only RSA key in the test store, reached through
      `nix/ftpm-test-env.sh` (never the persistent handles). YubiKey: an RSA key in a retired
      slot (90–95) beside the `pop-decrypt` row of `tests/yubikey.rs`. ykcs11 may not implement
      `C_UnwrapKey` at all; then the proof is unsupported there (15), a YubiKey transport key
      keeps `pop-decrypt`, and the profile records the finding.
- [ ] **Phase 3b** `enforced`: the admin credential, `transport --trusted`,
      `CKA_WRAP_WITH_TRUSTED`.
- [ ] **Phase 4** `host`: `--allow-host-plaintext`, zeroized buffers, `tpm2_ptool` import.
- [ ] **Phase 4b** `file`: `pkcs8-pbes2` and `pkcs12`, `--passphrase-file`.
- [ ] **Phase 5** YubiKey import through ykcs11 as Security Officer. Ask before running the
      hardware test (it overwrites slot 95).
- [x] A fuzz target and a property test for the bundle parser (`fuzz/`, `nix/fuzz.nix`).

Rules specific to this stage:

- Key material on the host exists only on the explicit `host` and `file` paths, in
  `Zeroizing` buffers, and is never written in plaintext, logged or put in an error message.
- An import that fails leaves nothing behind on the target, and the lock unchanged.
- An identity mismatch after import is exit 10 and the imported object is removed.
- Before adding a dependency, check `Cargo.lock` for a crate that already does the job, and
  that its license is in `deny.toml`. Update `fuzz/Cargo.lock` too.

Parked: native `tpm-duplicate` (phase 6) and vendor methods (phase 7). Do not start them.

## Stage 5: finish TPM attestation

Code: `crates/tpm2-pkcs11/src/attest/`. The crate is not restructured.

- [ ] **Version guard** (review A8): refuse (15) on a tpm2-pkcs11 version the store reader was
      not tested with, naming the version. Tested versions: 1.10.x. Unit tests exist on rows
      the module wrote (`crates/tpm2-pkcs11/tests/fixtures`).
- [ ] **Fuzz targets** for the store row parser and `TPMS_ATTEST` verification.
- [ ] **A real-TPM harness.** `nix/ftpm-test-env.sh` builds a store with a transient primary,
      which `tpm-certify` refuses by design. Add a mode whose store uses the existing storage
      root key as its parent: `tpm2_ptool init --primary-handle=0x81000001`. That handle is a
      standard RSA storage key (restricted, decrypt, `noda`, empty auth). Used as a parent it
      is only read, and nothing new is made persistent for the primary.
- [ ] **Stop and report before the first run on the real TPM.** State the exact commands, and
      what the run will leave on the TPM. Then, on the user's go-ahead:
  - Record persistent handles and the lockout counter.
  - Run the attestation test. It creates one persistent Attestation Key at `0x81000016` in
    the owner hierarchy. The owner auth is not set, so no auth value is involved. Four
    persistent slots are free.
  - Verify: the three original handles are byte-identical (`tpm2_readpublic` names), the only
    new handle is `0x81000016`, the lockout counter is 0, and no transient objects remain.
  - The key stays: the scheme is trust-on-first-use, so the lock pins it. Tell the user how to
    remove it (`tpm2_evictcontrol -C o -c 0x81000016`).
- [ ] Add the opt-in test to `crates/cli/tests/ftpm.rs` and record the result in
      `docs/PROVIDERS.md` and `docs/ARCHITECTURE.md` §11.
- [ ] **Secret keys** (NEXT.md §2c, first item): check that a TPM-held secret key certifies and
      resolves with `assurance = "proof"`; add the test on swtpm and, if the step above ran, on
      the real TPM.

Not in this stage: the EK certificate chain. Leave the scheme labelled experimental and say in
`docs/DESIGN.md` §8.2 exactly what it proves without the chain ("the same TPM as at first
use").

Why this does not affect disk unlock or secure boot: disk unlock releases a secret sealed
under the storage root key against PCR values. A new persistent object in the owner hierarchy
changes neither the root key nor any PCR, and creating keys under the root key does not alter
it. The risks are the ones the hardware rules forbid: clearing, evicting existing handles,
filling the lockout counter.

## Stage 6: reduce and clean up the docs

**Propose first.** Write the target layout (which files exist afterwards and what each holds)
and stop for agreement before moving anything.

- [ ] One document per tool: what it does, its command line, its exit codes.
- [ ] `docs/DESIGN.md` keeps the identity and lock design; migration and profile design move
      to their tool's document.
- [ ] `PLAN.md`, `NEXT.md`, `MIGRATE.md`, `docs/PROVIDERS.md` and this file: results are
      folded into the documents above. What remains is one short list of open and parked items.
- [ ] The dated files (`docs/REVIEW-*`, `docs/REFACTOR-*`, `docs/REDUCE.md`) and
      `docs/working/` move to an archive directory.
- [ ] Remove from the config schema what no verb implements (review A6): the identity modes
      `commit-at-creation`, `host-at-import` and `token-specific`, and `identity.allow`. This
      is a code change; `spec_digests_are_pinned` must still pass.
- [ ] One owner for `systemFeature` (review A6): propose which, with the proposal above.
- [ ] Doc comments in the code that cite a moved section are updated.
- [ ] Target: under half of today's roughly 8,000 lines of Markdown, not counting the archive,
      `reports/` and `research_notes/`.

## Not in this plan

- `autoCreate` on `check` (review A7): open by the user's choice.
- PROVIDERS phase 5 (FIPS mode as a match field), X25519 keys, the challenge bank, lock
  signing, a published JSON schema: parked or undecided.
- The two minor items left in NEXT.md §1 (profiles parsed once per process; token suites
  under parallel `cargo test`): do them when the surrounding code is open, in their own commit.
