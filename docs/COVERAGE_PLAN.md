# Coverage plan

Where the tests do not reach, and the order in which to get them there. Written 2026-11-14,
at 89.9% of lines (1,177 of 11,638 uncovered; 83.5% of functions). After tiers 2 and 3, the
same day: 91.9% (949 of 11,640 uncovered; 84.6% of functions); after the burn-down below,
93.7% (738 of 11,763; 86.1% of functions); with the fault shim and its first tables
(FAULT_SHIM.md), 94.0% (744 of 12,382, the shim's own 614 lines included; 86.2% of functions);
with the shim in front of camigrate and caprobe, 94.4% (701 of 12,469; 86.7% of functions);
with direct tests of camigrate's refusals, 94.7% (663 of 12,606; 87.3% of functions).
The mutation report
(`nix build .#mutants`) comes after this: it asks whether the tests *check* what they run, and
is only worth reading once they run it.

## Reading the report

`nix build .#coverage` runs every test, the token suites included, in a few minutes
([DEVELOPMENT.md](DEVELOPMENT.md), "Testing"). In the result:

| File | Use |
|---|---|
| `summary.txt` | each source file's line, region and function coverage |
| `missing.txt` | each file's uncovered line numbers |
| `html/index.html` | every source file with its uncovered lines and regions marked |
| `uncovered-functions.txt` | the functions no test entered |

## Rules

- **A test asserts behaviour.** Each new test checks an exit code, a message or a state, as the
  existing ones do. A line run by a test that would pass whatever the line did is not covered
  in any sense that matters; the mutation report will say so later.
- **Unreachable code is removed, not tested.** Where the only way to reach a branch is to
  break an invariant a caller already holds, the branch goes (the candidates are listed below).
- **Refusals first.** Most of what is uncovered is a refusal. An untested refusal is a claim in
  DESIGN.md §8.1 that nothing holds to.
- **What a tier cannot reach is left for the next tier**, and named here, never papered over
  with a mock of the thing under test.

## Tiers

| Tier | Runs where | Reaches | Expected total |
|---|---|---|---|
| 1 | plain `cargo test` | pure code: loaders, planners, emitters, parsers | 89.9% (done) |
| 2 | the reference tokens (SoftHSM, kryoptic, p11-kit, swtpm) | refusals and paths a well-behaved module can be led into | 91.9%, with tier 3 (done) |
| 3 | SoftHSM named `provider = "ykcs11"` | the YubiKey provider's lookups and its refusals | (in tier 2's figure; done) |
| 4 | a module that misbehaves on request ([PLAN.md](PLAN.md) A3) | what only a faulty or lying module triggers | about 96% |
| 5 | a real YubiKey reached from the Nix sandbox | PIV generation as SO, a real attestation, the probe's scratch slot | the rest that is reachable |

The totals after tier 3 are estimates, not measurements. Several tier 2 items moved to tier 4
(each section says which and why).

## Tier 2: the reference tokens

Done 2026-11-14. Each bullet below says what reached it, or why it moved to tier 4.

### Proof of possession that fails (`pkcs11/src/token/possession.rs`)

- **A private key that is not the public key's.** `pop-ecdh` on both paths: sealed
  (`derive_and_decrypt_only_keys_prove_possession`) and extractable, with `CKM_SHA256_HMAC`
  hidden (`proofs_fall_back_to_what_the_token_has`). `pop-decrypt` and `pop-unwrap` stay with
  tier 4: an RSA private key carries its own modulus, so a swapped key is another identity (10)
  before any proof runs.
- **A token without the proof's mechanism**: `proofs_the_token_cannot_give_are_refused`. Without
  the curve's hashed ECDSA, `pop-sign` falls back to raw `CKM_ECDSA` and still passes.
- **A key the token will not use for the proof**: keys planted with `CKA_ALLOWED_MECHANISMS`
  leaving the proof's mechanism out, for `pop-ecdh`, `pop-decrypt` and `pop-unwrap` (15, the
  usage bit named) (`proofs_the_key_will_not_give_are_refused`). A spec declaring a usage bit
  over a key without it is a policy conflict before any proof, so it cannot reach this arm.
- **`CKA_ALWAYS_AUTHENTICATE`**: `pop-ecdh` (16), raw `CKM_ECDSA` and undeclared `CKM_EDDSA`
  (15; a declared one is refused at planning, 17), and no PIN configured (16). The last runs on
  kryoptic only: SoftHSM refuses `CKA_ALWAYS_AUTHENTICATE` on a key that is not `CKA_PRIVATE`,
  and only such a key is visible without login.
- **Tier 4**: a context-specific login that fails, a multi-part signature refused with another
  code, an HMAC over the derived or unwrapped secret that fails, a derived secret with no
  value, and an unwrap the module allows only read-write (no reference unwraps that way).

### Moving keys (`camigrate`)

- **The host path's guards** (`host_moves_refuse_what_they_cannot_check`, into SoftHSM behind
  p11-kit): an occupied target locator (13); a public half already there but not what the
  target's `publicAttributes` say, so the private key just created is removed again (13); a
  target without a user PIN (16). A key whose identity is not the locked one (10) cannot be
  reached: the source is verified against the lock just before. The tpm2-pkcs11 target's own
  guards (`import_ptool`) need a public object planted on tpm2-pkcs11, which it does not
  create: tier 4.
- **`enforced`**: the warning when the source's SO trusts another key too, from `transport
  --trusted` and from `export`. The missing trusted copy (14) cannot be reached: the planner
  checks the same copy just before and blocks the move (15). It stays, as the security
  check's own guard.
- **A bundle against the wrong lock**: another type (14), another transport key (10), and a
  lock that pins nothing, for a wrapped key (its transport key has no realisation, 14) and a
  certificate (no IDs to check against, 14). "Another object's entry" was unreachable: the
  import picks the target by the entry's own object. Removed.
- **The sealed path with OAEP SHA-256**: between kryoptic and a second kryoptic token the test
  initialises in a slot of its own
  (`sealed_moves_wrap_with_oaep_sha256_between_kryoptic_tokens`). It needed the fix below.
- **Planning from the lock** with no observation and with two that differ: the plan fails as
  the open did (16).
- **Public objects**: tier 4. A certificate value that is no certificate, a data object with no
  value and two objects under one locator are each refused by `ops::verify` before `public.rs`
  reads the object; only a module that changes between the two calls reaches its own arms.

### The verbs and the token layer

- **Type of the live object**: an RSA key of another size and an AES key of another length (13)
  (`the_live_object_must_be_what_the_spec_says`). A certificate of another type needs a module
  that stores one: SoftHSM and kryoptic create X.509 certificates only. Tier 4.
- **Public key objects**: none under the locator (11, SoftHSM, whose EC private keys carry no
  public key; kryoptic's carry their own), several (12), and a public key cakeys cannot read
  beside an RSA key (13: P-224 on SoftHSM, X25519 on kryoptic).
- **Two tokens with one label** (12, SoftHSM, which keeps a free slot; kryoptic has the slots
  its configuration lists) and **a PIN from an unset environment variable** (16)
  (`tokens_that_cannot_be_opened_as_named_are_refused`). **A write-protected token**: no
  reference can be made write-protected. Tier 4.
- **`create` skips** a certificate and a `publicOnly` pair, each with its reason.

### TPM (`tpm2-pkcs11/src/attest/`)

`tpm2_attestation_refuses_a_store_that_disagrees`, by editing the test's store:

- `CKA_EXTRACTABLE` true in the store row of a key the TPM certified as fixed (13);
- another key's TPM blobs and auth under a row's attributes: the TPM certifies another public
  key than the module shows (13);
- a token on a transient primary (`tpm2_ptool init --transient-parent`): no persistent parent
  to load under (16).

A key at the AK handle that is not cakeys' template was already covered
(`tpm2_keys_attest_their_tpm_residence`). **No TCTI** cannot be reached here: the module reads
`TPM2_PKCS11_TCTI` too, so it cannot reach the TPM without what cakeys would find. It needs the
module behind a p11-kit server with an environment of its own.

### Found on the way

- **`camigrate migrate` between two tokens of one module failed** (16, after a dry run said
  ready): it opens source and target together, and the second open initialised the module
  again (`CKR_CRYPTOKI_ALREADY_INITIALIZED`). Tokens of one module open at once now share its
  library, finalized with the last of them (`token/mod.rs`, `library`). This is the common case
  of two partitions behind one HSM module.
- **A dry run promised moves into a token without a user PIN**, which the move then refused
  (16). `migrate` and `import` now refuse such a target before planning, dry run included
  (`needs_login`), and the two in-path checks that guarded the same thing are gone.
- **The planner promised a proof of possession the target then refused** [run]: a target spec
  declaring `CKA_ALWAYS_AUTHENTICATE` on an EC key, moving kryoptic → SoftHSM, was planned
  ready, and the move failed its proof (15) after the import, because the per-use login signed
  in parts and SoftHSM signs ECDSA in one part only. Two fixes:
  - the cause of the divergence: the planner (`unprovable`), `cakeys` before it creates a key,
    and the proof itself each had their own partial idea of what a proof needs (mechanisms; the
    profile's `unwraps`; nothing about the per-use login). They now ask one check,
    `token::proof_refusal`, of the binding the spec implies (`plan::expected_binding`).
    `cakeys` also refused a missing proof mechanism only after generating the key;
  - the instance: cryptoki gets a single-part `C_Sign` after `C_SignInit`
    (`nix/patches/cryptoki-sign-after-init.patch`), so the per-use login works for every
    signing mechanism, Ed25519 and raw ECDSA included (`per_use_pin_targets_move_as_planned`).
    Without the patch the proof and the plan refuse it alike.

  What still only the move can show: the material (10, 13, which the dry-run twin allows),
  and an attribute the module sets on its own, such as a PIV slot whose PIN policy makes an
  imported key `CKA_ALWAYS_AUTHENTICATE` undeclared (with the patch, that key proves anyway).

## Tier 3: SoftHSM posing as a YubiKey

Done 2026-11-14 (`piv_attestations_are_found_by_slot_and_chain_to_yubico`, on SoftHSM and
kryoptic alike). The fixtures planted under ykcs11's `CKA_ID`s and labels reach the slot and
device certificate lookups, each "none" (15) and "several" (12), and the refusal of a chain
that does not end at a pinned Yubico root (13). Beside them, the provider reports
`CKA_DERIVE` true for an EC key whose token says false, and a key to create is refused
without an SO credential (15).

Does not reach: a successful attestation (needs a certificate Yubico signed), generation and
import in an SO session (SoftHSM's SO creates no private objects), and the probe's scratch
slot. Those are tier 5.

## Burn-down (2026-11-14)

After tiers 2 and 3, the gaps the reference tokens and plain unit tests could still reach,
from 91.8% to 93.7% of lines:

- **Pure code, unit tests**: what a lock compare reports around a realisation; a `Config`
  naming an undefined object; SPKI canonicalisation per curve; a `--profiles` directory; the
  probe diff's one-sided rows; the TPM attestation's Name per `nameAlg`, wrapped object auth
  and AK signature checks; a malformed primary `ESYS_TR`.
- **Token-free CLI**: `caprobe supports` without a module profile; `validate`'s gate refusals
  and notes.
- **Reference tokens**: a commitment `verify` cannot compute; `publicAttributes` over a doubled
  or swapped public half; the probe's scratch guard and slot probes (SoftHSM and kryoptic named
  `ykcs11`); PIN counters (kryoptic counts down: count-low, final try, locked) and a refused SO
  credential; `probe --diff` drift; camigrate's `--spec` and empty-lock refusals.
- **swtpm**: P-384, P-521 and RSA attestations; a store found through the module's search
  path, a TCTI from the options, a store of another token, a secret key's blobs under an EC
  key's row.

Found on the way, and fixed:

- **An export's plan said ready for a move through the host**, which the export then refused
  (15): a bundle carries sealed keys and public objects only. The destination now says the verb
  (`Dest::Bundle` for `export --target`), and the plan blocks other methods with that reason.
- **A hint named an impossible fix**: for a module version no profile records, resolution
  advised naming the profile in `provider`, which no token open accepts (docs/CONFIG.md: the
  module profile is chosen, not named). The branch for an exact profile name was unreachable
  and is removed; the hint says to probe the module, or realise once.
- **Unreachable, removed**: `generate.rs`'s refusal of a class `plan.rs` refuses first.

What remains, by kind (about 740 lines):

- **Tier 4, a misbehaving module**: most of it. `map_err` arms of calls a correct module never
  fails (a context-specific login after a good one, `C_Sign` with a derived or unwrapped secret,
  an attribute read after a find), and the proofs that run and fail for RSA keys
  (`pop-decrypt`, `pop-unwrap`), which need a module showing one key and using another. The
  shim (FAULT_SHIM.md) now covers the swapped-key proofs, lied attributes and flags; the
  `map_err` arms remain as rows to add.
- **Tier 5, a real YubiKey**: a successful PIV attestation, SO-session generation and import.
- **Guards of invariants a caller holds**, kept on purpose: the empty deprecation register's
  warnings (`reconcile.rs`, until a scheme is deprecated); camigrate's `unreachable!` arms and
  the refusals behind plan checks (`export_file`'s one-key check, `sealed.rs`'s missing trusted
  copy); `public.rs`'s reads behind `ops::verify`; a store row ambiguity the token layer refuses
  first.
- **Environment the suites do not set up**: no TCTI at all (the module reads the same variable;
  needs it behind a p11-kit server with an environment of its own), `tpm2_ptool` missing from
  `PATH`, a write-protected token.
- **Test code** in `#[cfg(test)]` modules (the `panic!` arms of `let … else`).

## Tier 4: a module that misbehaves on request

[PLAN.md](PLAN.md) A3: a forwarding shim in front of SoftHSM or kryoptic, driven by a fault plan
(decided 2026-11-14; about 1–1.5k lines, not a module of its own). What is left after tier 3
is mostly `map_err` arms on a call that a correct module never fails: `C_FindObjects` failing,
an attribute read failing after the object was found, a login failing after the session
opened, a derived secret with no value, a key that vanishes between creation and resolution,
a certificate with no readable value. The shim returns a chosen `CKR_*` on the n-th call of a
function and can drop or alter an attribute; each arm becomes one line of test table.

A module reporting `CKF_USER_PIN_FINAL_TRY` or `CKF_USER_PIN_LOCKED` was listed here; kryoptic
counts down, so the burn-down covers both on a reference token
(`pin_counters_stop_cakeys_before_it_spends_a_try`).

## Tier 5: a real YubiKey from the sandbox

Later, by decision of 2026-11-14: let the checks reach a YubiKey through the build sandbox.
The NixOS module already grants pcscd to builds that require a token's feature
(`services.cakeys.sandbox.pcscd`, [CAKEYS.md](CAKEYS.md)); what is missing is a check that
requires that feature and the opt-in suites wired to it.

- It stays outside `checks`: a build that needs a device is not one every machine can run.
- The hardware rules bind it ([DEVELOPMENT.md](DEVELOPMENT.md)): scratch slots 90–95 only, the
  credentials as granted file paths, never a wrong PIN, slots 82–84 never touched.
- Reaches: `ykcs11`'s SO-session generation and import, a real `piv-attestation`, the probe's
  `Target::Slot` path (most of `caprobe/src/probe.rs`'s 142 lines), `policy_flag`.

## Code to remove rather than cover

Found while reading the report, and looked at again before deleting (2026-11-14): a branch
unreachable today may be the guard that keeps a later change honest.

- `caprobe/src/supports.rs`, "name what to ask": removed. `Query` asks one of a name, a class or
  the OAEP hashes (`Ask`), so a query that asks nothing cannot be built; clap's requirement is
  an `unreachable!` where the arguments become a query.
- `core/src/plan.rs:43`, "unknown token": **kept, and tested**. Loading keys.toml does not
  check a spec's token names against `[tokens]`, so a spec on an undefined token loads and is
  refused here (17) when used.
- `core/src/plaintext.rs:58`: removed. The match is on the (key type, curve) pair, so an
  Edwards curve under `CKK_EC` falls to the refusal of a type with no parser.
- `pkcs11/src/token/identity.rs`: the caller no longer filters out `token-asserted` before
  `prove_binding`, whose own arm for it was dead.
- `camigrate/src/sealed.rs`, "the bundle's key is object …": removed (see tier 2).
- `camigrate/src/host.rs` and `public.rs`, "a session without login": removed; `needs_login`
  refuses such a target before planning.
- Kept: `camigrate/src/lib.rs`'s `unreachable!` arms and its "later phase" refusal (reachable
  only for methods the planner never returns ready today), and `possession.rs`'s refusal of a
  key type with no proof (a private key is EC, Edwards or RSA by the time it is planned). Each
  is the guard of an invariant a later change could break.

## Not counted

- Test code inside `#[cfg(test)]` modules shows in the report (the `panic!` arms of
  `let … else` in tests). It is not a gap.
- The real-TPM suite (`CAKEYS_FTPM_ATTEST=1`) stays opt-in and by hand: it runs against the
  machine's own TPM, under the hardware rules.
