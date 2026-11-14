# Coverage plan

Where the tests do not reach, and the order in which to get them there. Written 2026-11-14,
at 89.9% of lines (1,177 of 11,638 uncovered; 83.5% of functions). The mutation report
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
| 2 | the reference tokens (SoftHSM, kryoptic, p11-kit, swtpm) | refusals and paths a well-behaved module can be led into | about 92% |
| 3 | SoftHSM named `provider = "ykcs11"` | the YubiKey provider's lookups and its refusals | about 93% |
| 4 | a module that misbehaves on request ([PLAN.md](PLAN.md) A3) | what only a faulty or lying module triggers | about 96% |
| 5 | a real YubiKey reached from the Nix sandbox | PIV generation as SO, a real attestation, the probe's scratch slot | the rest that is reachable |

The totals after tier 1 are estimates from the line counts below, not measurements.

## Tier 2: the reference tokens

In this order: the first two are security claims with no negative test.

### Proof of possession that fails (`pkcs11/src/token/possession.rs`, 81 lines)

`pop-sign` has a swapped-key test; the other bindings have only the passing case.

- **A private key that is not the public key's.** `pop-ecdh` has the test (the sealed path). For
  `pop-decrypt` and `pop-unwrap` no reference can be led there: an RSA private key carries its
  own modulus, so a swapped key is another identity (10) before any proof runs. A proof that
  runs and fails needs a module that shows one key's public material and uses another's
  private half: tier 4.
- **A token without the proof's mechanism** (`lacks_for_proof`): the harness can already hide
  a mechanism from a reference (`hide_mechanism`); hide `CKM_ECDH1_DERIVE`, then
  `CKM_RSA_PKCS_OAEP`, and expect 15 with the opt-out named.
- **A key the token will not use for the proof** (`proof_failed`, the unsupported arm): a spec
  declaring `CKA_DERIVE = true` over a key created without it.
- **`CKA_ALWAYS_AUTHENTICATE` with a binding that cannot log in per use**: `pop-ecdh` on such a
  key is 16; raw `CKM_ECDSA` and `CKM_EDDSA` under `pop-sign-pin` are 15; no PIN configured
  is 16.
- **`pop-ecdh` on a module that derives only into an extractable secret**: the extractable
  path's own failure cases, on a reference with the `derive.sealed = false` row set through
  `--profiles`.

### Moving keys (`camigrate`: `sealed.rs` 85, `lib.rs` 83, `tokens.rs` 45, `host.rs` 34, `public.rs` 25)

- **The host path's guards**: an occupied target locator (13), a target session without login
  (16), a key whose identity is not the locked one (10), and the rollback after a failed
  record. The host path is only planned where the sealed one is not, so these run against
  p11-kit or tpm2-pkcs11 as the target.
- **`enforced` without its preconditions**: no trusted copy of the transport key (14), and the
  warning when the source trusts other keys too.
- **A bundle against the wrong lock**: another object's entry (17), a type that is not the
  lock's (14), a transport key that is not the one realised (10). Some exist as unit tests of
  the parser; none reaches `check_against_lock`'s own arms.
- **The sealed path with OAEP SHA-256.** SoftHSM implements SHA-1 only, and two kryoptic
  references cannot be opened in one process. With a token set per test this is now possible:
  a second kryoptic token in the same test's database. Needs the harness to initialise two
  slots.
- **Planning from the lock** when a token does not open, with one observation, several, and
  none (`tokens.rs`).
- **Public objects**: a certificate whose value is no certificate, a data object with no
  value, two objects under one locator (`public.rs`).

### The verbs and the token layer (`ops.rs` 33, `token/mod.rs` 54, `policy.rs` 29, `identity.rs` 23)

- **Type and policy of the live object**: an RSA key of another size than the spec's, a secret
  key of another length, a certificate of another type, each a conflict (13).
- **Public key objects**: none under the locator (11), several (12), one that exposes no key
  material (13).
- **A write-protected token** asked to write (15), **two tokens with one label** (12), **a PIN
  from an environment variable that is not set** (16).
- **`create` on what it does not create**: a certificate, a `publicOnly` pair, named
  explicitly.

### TPM (`tpm2-pkcs11/src/attest/`: `esys.rs` 92, `mod.rs` 53, `store.rs` 28)

Each test now has its own swtpm, so state can be arranged freely:

- no TCTI configured and none in the environment (16);
- a key at the AK handle that is not cakeys' template (13);
- a store row whose blobs are not the object the module shows (13);
- a transient-parent store, which `tpm-certify` does not support (15);
- the module's `CKA_LOCAL`/`CKA_EXTRACTABLE` contradicting what the TPM certified (13), by
  editing the store row.

## Tier 3: SoftHSM posing as a YubiKey

Nothing in CI loads the YubiKey provider (`ykcs11/src/lib.rs`, 101 lines, 48%). An explicit
`provider = "ykcs11"` on a SoftHSM token does, and the committed fixture certificates
(`crates/ykcs11/tests/fixtures/`) can be planted under the labels and `CKA_ID`s ykcs11 uses.

Reaches: the attestation certificate lookup by `CKA_ID` and label, the device certificate
lookup, each "none" and "several" refusal, and the refusal of a chain that does not end at an
embedded Yubico root (the fixtures are signed by a test root, so this is the case they give).

Does not reach: a successful attestation (needs a certificate Yubico signed), generation and
import in an SO session (SoftHSM's SO creates no private objects), and the probe's scratch
slot. Those are tier 5.

## Tier 4: a module that misbehaves on request

[PLAN.md](PLAN.md) A3. What is left after tier 3 is mostly `map_err` arms on a call that a
correct module never fails: `C_FindObjects` failing, an attribute read failing after the
object was found, a login failing after the session opened, a derived secret with no value, a
key that vanishes between creation and resolution, a certificate with no readable value. The
shim returns a chosen `CKR_*` on the n-th call of a function and can drop or alter an
attribute; each arm becomes one line of test table.

It also covers what tier 2 cannot construct: a module reporting `CKF_USER_PIN_FINAL_TRY` or
`CKF_USER_PIN_LOCKED` (`token/mod.rs:70`), which no reference can be put into without spending
real PIN tries.

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

Found while reading the report; each is a branch no input reaches:

- `caprobe/src/supports.rs:117`, "name what to ask": clap already requires a name, a class or
  `--oaep`.
- `core/src/plan.rs:43`, "unknown token": a spec's token entries are checked against the
  tokens at load, and a token the spec lacks is refused one line later.
- `core/src/plaintext.rs:58`: an Edwards curve under `CKK_EC` cannot come out of
  `Curve::from_cfg`.
- `camigrate/src/lib.rs`: the three `unreachable!` arms document invariants and stay; the
  "later phase" refusal in `migrate` is reachable only for methods the planner never returns
  ready today.

Each needs a second look before deleting: a branch that is unreachable today may be the guard
that keeps a later change honest.

## Not counted

- Test code inside `#[cfg(test)]` modules shows in the report (the `panic!` arms of
  `let … else` in tests). It is not a gap.
- The real-TPM suite (`CAKEYS_FTPM_ATTEST=1`) stays opt-in and by hand: it runs against the
  machine's own TPM, under the hardware rules.
