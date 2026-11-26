# Phase 2 and 3 design: oracles independent of the code, adversary by table, mutants as a gate

Status: design, not built. Repo at `f3b8e5e` (branch `review-2026-11-24`, Phase 0 merged). Every
`path:line` is at that commit. Inputs: REVIEW-2026-11-24.md (items 9–13), A.md–F.md,
[phase1-design.md](phase1-design.md) and its §9 decisions, DEVELOPMENT.md, REVIEWING.md,
FAULT_SHIM.md, CAPROBE.md, `crates/p11-fault`, `nix/package-crane.nix`, `.github/workflows/`.

## 0. Inputs and conventions

- **Built on Phase 1.** This design uses Phase 1's names as they are specified:
  - `Rule`, `Refusal`, `Deferred` (pkcs11 `ops/rules.rs`);
  - `Known<T>` (core `known.rs`);
  - the `Outcome` row with `rule` and `device` (cli-common, P1 step 7; camigrate rows, P2 step 13);
  - the probe row's `by` (P3, §2.3);
  - the provider contract suite and its `Spy<P>` (P3, §3.3).

  Where Phase 2 needs more than those, §1.3 says what and why.
- **"Before" tests** are tests that fail on the commit before the package, or with the decision
  they guard mutated, and pass after it. Each is seen red once, and the red run is recorded in
  `Ran:`, per REVIEWING.md.
- **Mutant counts** come from `cargo mutants --list -p <crate>`, cargo-mutants 27.1.0, at
  `f3b8e5e`. The tool is not in the dev shell: it was run as
  `nix develop -c nix shell --inputs-from . nixpkgs#cargo-mutants -c …`. Nothing was mutated or
  run.
- **Line counts** (+/−) are estimates.
- **Tiers** are DEVELOPMENT.md's:
  - T0 is `.#checks-no-vm`, the Linux crane build with its software-token suites.
  - T1 is the VM.
  - T2 is hardware.

  The fault shim is Linux-only (FAULT_SHIM.md "Risks"; `cdylib`, LP64). So every liar cell runs
  in the Linux crane check phase, and only the pure lints also run on the darwin dev gate.

## 1. Item 9: the liar matrix

### 1.1 Lie classes and what p11-fault can express

**What p11-fault has today.**

- **Actions** (`crates/p11-fault/src/plan.rs:31-67`):
  - `Rv` (before or after the real call);
  - `Flags`;
  - `Attribute`: `Drop`, `Value`, `FromLabel`, `Unavailable` or `Truncate`;
  - `AddLabel`, `UseLabel`, `HideLabel`, `Corrupt`, `HideMechanisms` and `Abort`.
- **Matchers:**
  - the function;
  - `call = n`, the n-th call *of that function in the process*, counted across every object and
    attribute (`plan.rs:200-214`);
  - `of_label`, which is allowed only with an attribute or `use_label` rule (`plan.rs:348-350`).
- **Tests use only part of it.** They inject `rv` about 43 times, 32 of them `CKR_DEVICE_ERROR`,
  and the rest of their rules sit in one table (B.md:496-501).

| Class | Variants the matrix needs | Today | To add (package L1) |
|---|---|---|---|
| **OK** OK without effect | `C_DestroyObject`, `C_Login`, `C_SetAttributeValue`, `C_Logout` answer `CKR_OK` and do nothing | `rv = "CKR_OK"` (before) works on any function. It cannot be aimed at one object: `of_label` is refused on `rv` rules (`plan.rs:348`). "Destroy of `k` lies, cleanup of `new` does not" needs a fragile `call = n` | `of_label` on `rv` rules for the functions that take an object handle (`C_DestroyObject`, `C_SetAttributeValue`, `C_GetAttributeValue`, `C_CopyObject`) |
| **OTHER** another object handed over | a search finds another object; the key used is not the one shown; `C_WrapKey` wraps another key; the public key is another's | `add_label` (a second match only), `use_label` (argument 3, `forward.rs:33-39`), attribute `from_label` | `replace_label` on `C_FindObjects`: X is returned as Y, and X is not found. **`wrap_label` on `C_WrapKey`: argument 4, the key wrapped, is replaced.** Today `use_label` there replaces argument 3, the *wrapping* key (`forward.rs:188`), so the host's unwrap fails (`token/host.rs:47`), not its identity check. D-5 needs `wrap_label` (C-13: "p11-fault cannot make a source hand over another key") |
| **FLAG** a flag hidden or flipped on read | `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_WRAP_WITH_TRUSTED`, `CKA_DERIVE` dropped or flipped; token flags, the SO PIN flags included | attribute `drop` / `value = "00"`/`"01"`; `set_flags`/`clear_flags` (the SO names exist, `p11-names/src/lib.rs:328-330`) | nothing |
| **CHANGE** a value that changes between two reads | the first read honest and the second a lie, or the reverse; lock under one answer, check under another | `call = n` counts all `C_GetAttributeValue` calls of the process, so "the 2nd read of `k`'s `CKA_EC_POINT`" cannot be said | **`nth = n` / `from = n`**: a per-rule counter of the calls that match the rule's other matchers. Two processes with two plans need nothing new |
| **FORGE** a forged vendor certify or attestation | a corrupt certify signature; the Name of another object; a stale nonce; a forged PIV slot certificate | `corrupt` (the last byte, `hooks.rs:222-247`); attribute `from_label` on `CKA_TPM2_PUB_BLOB` or a certificate's `CKA_VALUE`; `value` (hex) | `replay_output = k` on output functions: the output of the k-th earlier call of the same function in this process, which gives a genuine AK signature over a stale nonce. A forgery that needs a signer the shim does not hold (another `qualifiedSigner`, a slot certificate signed by another key under a Yubico-like chain) is a **unit** row on fixtures (§1.4) |
| **BLOB** a corrupted blob the module still accepts | a proprietary wrap encoding: the same module unwraps it, no one else can | **no.** `corrupt` is not offered on `C_WrapKey` (`plan.rs:327-330`), and a corrupted KWP blob fails the module's own unwrap, which tests nothing E-3 asks | `transcode = true` on `C_WrapKey`: the output is XORed with a fixed pad, and every `C_UnwrapKey` input under the same plan is XORed back. The module accepts its own blobs; no host and no other module can read them |
| **DEV** device error vs refusal | the same call answering `CKR_DEVICE_ERROR` (device-failed, P1 §2.5) and `CKR_KEY_FUNCTION_NOT_PERMITTED` (a module refusal) | `rv` | nothing: cells come in pairs |
| **LOSS** session or device loss mid-run | `CKR_SESSION_HANDLE_INVALID`, `CKR_DEVICE_REMOVED`, `CKR_TOKEN_NOT_PRESENT`, `CKR_USER_NOT_LOGGED_IN` from the n-th call on; the slot without `CKF_TOKEN_PRESENT` | one call's `rv`; the real session lives on, so the next call succeeds, which no device does | `fn = "*"` with `from_seq = n`: every function from the process's n-th call |

**Kept unmodelled** (each becomes an `na` row with its reason in the table, §1.4):

- A length that grows between the size query and the fetch.
- A hang: cakeys has no per-call timeout by design, so a hang is a hang.
- `C_GetMechanismInfo` lies: `max_key_bits` and `clear_mechanism_flags` are cheap and are added
  in L1, but no current check reads them as a security decision.

**For the personas (§2), not for the matrix.**

- Rules gain `mechanism`, `class` and `key_type` matchers. They are read from the arguments
  before the call, as `trace::Detail` reads them after it (`trace.rs:73-110`).
- An `rv` can then be answered per mechanism or per key type. This is about +60 lines in L1.

### 1.2 Verbs, entry paths and objects

| Tool | Verb | Entry paths a cell runs | Oracle source |
|---|---|---|---|
| cakeys | `create` | real; `--dry-run` (opens the token after P1 step 6); `validate` (static) | `--json` rows |
| cakeys | `lock` | real; `--dry-run` | `--json` rows |
| cakeys | `check` | `check --spec`; `check --token` | `--json` rows |
| cakeys | `delete` | real; `--dry-run` | `--json` rows |
| camigrate | `migrate` | real; `--dry-run` (the twin, P1 §1.4) | camigrate rows (P2 step 13) |
| camigrate | `export` | `--to <tok>`; `--to-transport-file`; `--to-key-file` | rows; the output file |
| camigrate | `import` | `--in <bundle>`; `--key-file` | rows |
| caprobe | `probe` | `--write-probes`; read-only | the profile rows (`answer`, `by`), `[untested]` |

**Objects.** Each fixture plants the same named set behind the shim, beside a decoy of each kind
under `<name>-other`, as `lying()` does today (`crates/cli/tests/fault.rs:152-201`):

- `ec-sign`, `ec-derive`, `rsa-decrypt`, `rsa-unwrap`, `rsa-always-auth`: the five
  private-key bindings of today's table;
- `aes` (cmac and kcv commitments), `hmac`;
- `cert`, `data` (`CKA_PRIVATE = true`), `data-public`, `pub`;
- for camigrate, a source and a target transport key.

C-6 counted 7 verbs × 4 classes, with lies in 3 × 1. The grid here is 10 tool-verbs × 6 classes
(private, secret, certificate, data, public, transport) × 8 lie classes.

### 1.3 Naming the checks

**What Phase 1 names, and what it does not.**

- Phase 1 names the plan's rules (`Rule::ALL`). `Outcome.rule` carries `Rule::name()` for a
  refusal the plan made, or one `execute` re-checks (`DeleteKept`).
- It does not name the decisions a liar mostly provokes. They are taken deep in token
  operations and verifiers, and come back as a bare `KmError`:
  - proof of possession (`token/possession.rs:207,247,324,377,466,881`, `core/src/pop.rs:89`);
  - identity (`token/identity.rs:106,136,161,182,194,243`);
  - type and policy (`token/policy.rs:22-323`);
  - the attestation verifiers (`ykcs11/src/attest.rs:68,76`;
    `tpm2-pkcs11/src/attest/vendor.rs:190-208`, `attest/mod.rs:316-340`);
  - extraction (`token/host.rs:47`);
  - camigrate's identity checks (`host.rs:77`, `sealed.rs:501,677`, `file_verbs.rs:387`).
- Without a name, a cell can assert only an exit code. Exit 13 is shared by about 100
  constructions, and a lint cannot tell which check a row fires.

**Design: `cakeys_core::Check`, carried by the error.**

```rust
// core/src/check.rs (new). One name per security decision; ALL and name() from a macro,
// as pkcs11_names! does (core/src/types.rs:43).
pub enum Check { PopSign, PopDecrypt, PopEcdh, PopUnwrap, PopSignature, IdentityMaterial,
                 PublicDisagrees, PublicHoldsAnother, LocatorAmbiguous, TypeMismatch,
                 PolicyAttribute, AttestPivChain, AttestPivSlotByDevice, AttestPivSlotKey,
                 AttestTpmKind, AttestTpmNonce, AttestTpmName, AttestTpmSignature,
                 AttestTpmSigner, AttestTpmMaterial, AttestTpmReports, AttestTpmSecretOnModule,
                 AttestTpmEkOnModule, TokenWriteProtected, LoginPinLocked, LoginFinalTry, LoginState,
                 LoginNotRetried, CreateVanished, ExtractUnwraps, ExtractIdentity,
                 BundleUnwraps, BundleIdentity, ImportIdentity, TransportBound, TransportSize,
                 PublicCertificate, ProbeSlotMark, ProbeHostBlob, ProbeHostCommit, /* … */ }
// name(): "pop.sign", "attest.tpm.nonce", "probe.slot-mark", …  (dotted, stable, pinned by a test)

// core/src/error.rs: Conflict, Ambiguous and PreconditionFailed take a Reason, not a Msg.
pub struct Reason { basis: Basis, msg: Msg }       // Deref<Target = Msg>: m.contains(..) still works
enum Basis { Check(Check), Malformed }              // private
impl Reason { pub fn check(c: Check, text: impl Into<String>) -> Reason;
              pub fn malformed(text: impl Into<String>) -> Reason; }   // no From<String>, no Default
impl Msg { pub fn with_check(self, c: Check) -> Msg }  // optional, for 11/15/16 refusals
impl KmError { pub fn check(&self) -> Option<Check> } // HashMismatch is IdentityMaterial by itself
```

- **The compiler names every site.**
  - `KmError::Conflict("…".into())` no longer compiles. Each of the
    `Conflict`/`Ambiguous`/`PreconditionFailed` constructions in non-test source must say which
    check refuses, or that the input is `malformed`.
  - That is about 160 sites (rg: 106 `Conflict`, 16 `Ambiguous`, 41 `PreconditionFailed`).
  - "Malformed" means a structure that does not parse: `chain.rs:61-111`, `vendor.rs:110`,
    esys's unmarshalling. Fuzz targets cover those (`checks.fuzz`), and the matrix does not.
  - This is REVIEWING.md's "prefer the change that removes the class" applied to naming: a new
    check cannot be added without a name.
- **Outcome rows.** P1 step 7's `Outcome.rule` becomes `refusal.rule.name()` for a plan refusal,
  else `err.check().map(Check::name)`. This is one line in cli-common.
- **One namespace.** A unit test asserts that `Rule::ALL` and `Check::ALL` names are disjoint, and
  the lint (§1.5) walks both.
  - `Rule` stays in pkcs11 as Phase 1 put it. `Check` must be in core, because `KmError` is.
  - Should P1 still be open when this lands, moving `Rule` into core beside `Check` would
  remove the two-enum seam. That is optional.
- **Lock rules too.** `reconcile.rs`'s `PreconditionFailed` sites get `Check` names
  (`lock.downgrade`, `lock.locator-changed`, …). A-6's class fix then becomes one test: every
  lock-rule `Check` is a model rule in `lock.qnt`'s `decidedBy` or is listed in its `LEFT_OUT`.
  This replaces the `rule_of` text markers (`lock_mbt.rs`) that A-6 showed accept a suffix.

### 1.4 Table format

The table is TOML (the repo's data format). There is one file per tool:

- `crates/cli/tests/liars/cakeys.toml`;
- `crates/camigrate/tests/liars/camigrate.toml`;
- `crates/caprobe/tests/liars/caprobe.toml`;
- `crates/cli/tests/liars/tpm2.toml`, for the vendor route on swtpm.

A runner, `crates/cli/tests/common/liars.rs`, expands each file into cells. No cell is a
hand-written `#[test]`.

```toml
# The objects every cell may name, planted by the tool's fixture (common::liars).
[objects]
ec-sign  = { spec = "k", class = "private", binding = "pop-sign" }
aes      = { spec = "s", class = "secret",  commitment = "cmac" }
cert     = { spec = "c", class = "certificate" }
data     = { spec = "o", class = "data" }          # CKA_PRIVATE = true

# A lie: a fault plan with {label}, {other} (= "{label}-other") and {n} filled per cell.
[lies."ok.destroy"]
class = "OK"
plan  = '''
[[rule]]
fn = "C_DestroyObject"
of_label = "{label}"
rv = "CKR_OK"
'''

# A block: the cross product of lies × verbs × objects, one expectation for all of them.
[[block]]
lies    = ["ok.destroy"]
verbs   = ["delete", "delete --dry-run"]
objects = ["ec-sign", "rsa-decrypt", "aes", "hmac", "cert", "data"]
expect  = { exit = 16, rule = "delete-kept", unchanged = ["token", "lock"] }
# The dry run makes no destroy call: the lie never fires, and the dry run must say 0.
[[block.override]]
verbs  = ["delete --dry-run"]
expect = { exit = 0, fired = false, unchanged = ["token", "lock"] }

# Several steps under one plan: lock under the lie, then the verb.
[[block]]
lies    = ["flag.hide.CKA_PRIVATE"]
verbs   = ["migrate --dry-run", "export --to t2"]
objects = ["data"]
before  = [["lock", "--spec", "{spec}", "--token", "src"]]
side    = "source"                                   # camigrate: P11_FAULT_PLAN_SRC
expect  = { exit = [0, 15], method_not = "public", unchanged = ["target"] }

# Every (lie class, verb, object class) not covered above must be decided here, with why.
[[na]]
lies = ["ok.destroy"]
verbs = ["check", "lock", "create"]
objects = "*"
why = "makes no C_DestroyObject call; create's undo is covered by loss.create"

# A unit row: the lie is a fixture in the verifier's own test, which asserts the check.
[[unit]]
check = "attest.piv.slot-by-device"
test  = "a_slot_certificate_signed_by_another_key_is_refused"   # an fn; doc-references-style
why   = "a forged slot certificate needs a signer the shim does not hold"
```

- **Expansion.**
  - Each `block` yields one cell per (lie, verb, object). `override`s replace the expectation for
    a subset.
  - A cell's identity is `"<lie>/<verb>/<object>"`. Its `#[test]` is one per lie class per tool:
    `liars_ok`, `liars_other`, …, generated by a `liar_tests!` macro over the eight classes, so
    nextest runs them in parallel and a failure names its class.
- **Completeness (C-6's class fix).**
  - The runner computes the grid of lie *class* × verb × object *class*. Every grid point must be
    covered by a `block` or decided by an `na` with its `why`, else the lint fails.
  - That is 8 × 10 × 6 = 480 points. Most are decided by a dozen wildcard `na` rows (for
    example "`check` never destroys").
  - A missing cell is then visible the way a missing flag is in the surface test.
- **The honest run.**
  - Before its cells, each test runs the same verbs with no plan and asserts the honest outcome:
    0, 22, or the exit the object's honest row names.
  - After them, it re-checks that every object still verifies, as `a_lying_module_is_refused`
    does (`fault.rs:298-304`). This proves each refusal was the lie's.

### 1.5 The oracle per cell

Each cell asserts all of the following:

1. **Exit.** `exit` is an integer or a set (`[0, 15]` where Phase 1 §9.1 makes an unknown
   refuse, or an export may plan `sealed`).
2. **The rule**, from the JSON row, not from prose.
   - `rule = "<name>"`: the failing row's `rule` (P1 step 7) is exactly that name, a `Rule` or a
     `Check`.
   - `deferred = "<name>"`: for a dry run, the row lists that rule as deferred (P1 §1.4).
   - `device = true`: the row says `device`, and `rule` is absent. A device failure is never a
     verdict. These are the DEV and LOSS classes.
3. **Nothing changed** (C-9, C-4), where `unchanged` says so:
   `assert_unchanged(before, after, &["token", "lock", "out"])`.
   - The snapshot is the twin's `state()` generalised (§3.4): the lock's bytes, each named
     token's object listing (`pkcs11-tool --list-objects`, sorted, handles dropped;
     kryoptic's database hashed, `xref.rs:233-256`), and `--out` files.
   - A refusal without `unchanged` is a table error. A refusal leaves its state as it found it,
     or the row says why not (for example `left = ["new"]`, for a creation the module would not
     undo).
4. **The lie fired.**
   - The trace has a line whose `rule` is the cell's (`fired()`, `fault.rs:37-46`).
   - `fired = false` is the expectation for read-once properties: a CHANGE lie on the second
     read must find no second read (`a_resolve_reads_the_public_key_once`, `fault.rs:576`).
5. **Rows, for caprobe.**
   - `row = { cap = "…", absent = true }`, or `{ answer = "no", by = "module" }`, or
     `{ answer = "yes", by = "host" }`, compared with the written profile.
   - `untested = "<cap>"`: the `[untested]` line exists.
   - "Unchanged" for caprobe means the scratch token is as it was before the probe (CAPROBE.md:
     "Every run destroys what it made").
6. **The plan, for camigrate.** `method_not = "public"` (D-7), compared with the dry run's plan
   row.

### 1.6 The lint: no security check without a liar that fires it

`crates/cli/tests/liar_lint.rs` is a pure test with no token. It runs under plain `cargo test`,
on darwin too, and in T0.

1. **Coverage.** Every name in `Rule::ALL ∪ Check::ALL` is either:
   - the `rule`/`deferred` of at least one cell (any tool's table), or
   - the `check` of a `[[unit]]` row, or
   - listed under `[exempt]` in one tool's table with its `why`. Examples: `if-match` is the
     user's precondition, not a module's answer; `lock-writable` is the filesystem's. A check
     whose cells a later package adds is exempt in that tool's table with `why = "cells in L4b"`
     until then. Exemptions live per table so that packages editing different tools touch
     different files.
2. **No dangling names.** Every `rule`/`check` a table names is in `Rule::ALL ∪ Check::ALL`.
3. **Unit rows are real.**
   - The named `fn` exists in `crates/` (the doc-references index).
   - Its body contains `assert_fires(` with `Check::<Variant>`. `assert_fires(result, Check)`
     is a small helper in core's `testing` module: it asserts `err.check() == Some(c)`.
4. **Completeness.** Every grid point (§1.4) is covered or `na`.
5. **Exemptions only shrink.** Each `[exempt]` carries `max = N`, and the lint fails if there
   are more entries than that. Raising `N` is a visible diff.

How the lint finds the checks:

- **Statically, through the types.** `Check::ALL` and `Rule::ALL` are the registry, and the
  compiler forces every refusal site through `Reason::check` or `Reason::malformed`.
- **Not by grepping source.** The one source rule is P1's T-5 (rule calls only in the planner
  files), which stays as it is.

### 1.7 Today's findings as rows

"Red at" says what makes the row fail today. Everything Phase 1 fixes is green once Phase 1
lands. To see each row red once, as REVIEWING.md requires, run it at `f3b8e5e`.

| Finding | Lie (class) | Verb × object | Expect | Red at `f3b8e5e`; made green by |
|---|---|---|---|---|
| B-13 | `ok.destroy` (OK) | `delete` × every class | 16, `delete-kept`, token and lock unchanged | `ops/mod.rs:611-634` drops the lock entry; P1 step 5 |
| B-13 | none; the tpm2 swtpm profile's `delete.CKO_PRIVATE_KEY = no` | `delete` × `ec-sign` on swtpm | 15, `delete-refused` | P1 step 5 (K-6) |
| C-6 | `other.find` (`add_label` between identify and destroy, `nth = 2`) | `delete` × all | 12, `locator.ambiguous`, unchanged | nothing destroys today; likely green, now asserted |
| C-6 | `other.key` (`use_label` on `C_SignInit` of an HMAC key) | `check` × `hmac`, `aes` (cmac) | 10, `identity.material` | untested today; likely green |
| C-6 | `other.value` (`from_label` `CKA_VALUE`) | `check` × `cert`, `data-public` | 10 | untested |
| D-5 | `other.wrap` (`wrap_label`, new) | `export --to-key-file` × `ec-sign`, `aes`; `migrate` host path × `aes`, `hmac` | 10, `extract.identity`, no file written | `file_verbs.rs:42` extracts without `check_identity`, and secret keys are never checked; P2 step 12 |
| D-7 | `flag.hide.CKA_PRIVATE` (FLAG) under `lock`, then the verb | `migrate --dry-run`, `export --to` × `data` | method ≠ `public`; 0 sealed or 15 | `camigrate/src/plan.rs:121` `== Some(true)`; P2 step 11 with P1 §2.2 |
| D-7 | `flag.hide.CKA_WRAP_WITH_TRUSTED` | `migrate --dry-run` × `rsa-unwrap` | method ∉ {`host`, `sealed`} unless verified | `plan.rs:143`; P2 step 11 |
| E-3 | `blob.transcode` (new) | `probe --write-probes`, rows `export.sealed.*`, `unwrap.*` | `yes` only with `by = "host"`; else `by = "unverified"` (P3) and planned `Deferred` | `moves.rs:479-552` trusts the round trip. P3 makes it `unverified`. The instance fix (wrap toward the imported `rsa-2048` fixture, decode on the host) is **not** in Phase 1: package L4b |
| E-3 | `blob.transcode` | `migrate` × `aes` between two shimmed tokens | 13, `bundle.unwraps` at the target, target unchanged | likely green (the target refuses); now asserted |
| E-6 | none: a state fixture (the marker certificate beside a foreign key in scratch slot 17, ykcs11 named on SoftHSM) | `probe --write-probes` | 17, `probe.slot-mark`; slot unchanged | `probe.rs:258-289` passes; fix in L4b (the mark issued over the slot's key, the guard compares SPKIs) |
| E-2 (class) | DEV pairs at every probe family | `probe` | device: no row and `[untested]`; refusal: `no`, `by = "module"` | P3 (§2.3); the matrix gives the "error at each call" sweep P1 §2.3 asks for as rows |
| B-12 | `forge.certify.corrupt` (`corrupt` on `C_Sign`, `CKM_TPM2_CERTIFY`) | `lock` × `ec-sign`, vendor route | 13, `attest.tpm.signature` | untested (B-12); green when the call is there |
| B-12 | `forge.certify.blob` (`from_label` `CKA_TPM2_PUB_BLOB`) | same | 13, `attest.tpm.name` | untested |
| B-12 | `forge.certify.replay` (`replay_output = 1`, new; two certifies in one run) | same | 13, `attest.tpm.nonce` | untested |
| B-12 | none (options) | `lock` × `aes` on the vendor route; `ekCertificate` set with the vendor module | 15, `attest.tpm.secret-on-module`; 15, `attest.tpm.ek-on-module` | untested (`mod.rs:318-328`, `:133-145`) |
| B-12 | unit: `certify_statement` (`esys.rs:1170`) with another `qualifiedSigner` | `verify_certified` | `attest.tpm.signer` | untested |
| B-11 | unit: a `slot-other.pem` signed by a second key; and a 4-link chain | `ykcs11::attest::verify` | `attest.piv.slot-by-device`, `attest.piv.chain` | `attest.rs:67-71`: deleting the call fails nothing |
| B (list) 3 | `ok.login` (`C_Login` OK before, so the session stays public) | `delete`, `check` × `data`, `ec-sign` | `delete` never drops the realisation: 16 and the lock unchanged. `check` gives 16 `login.state`, not 11 | **Plausibly a new finding.** P1 step 4 decides "needs login" from the object, but here cakeys believes it logged in. The defence is a `C_GetSessionInfo` state check after `C_Login`; confirm with the cell first |
| B (list) 5 | `loss.device` (`fn = "*"`, `from_seq`) at each write step | `create`, `delete`, `migrate` | 16, `device`; lock unchanged; what is left is said | untested |
| B (list) 6 | `forge.mac` (`corrupt` on the unwrap proof's MAC `C_Sign`) | `check` × `rsa-unwrap` | 13, `pop.unwrap` | the host comparison was never reached (`fault.rs:253`) |

### 1.8 Runtime and tier

- **Cost per cell.**
  - A cakeys cell is one process on SoftHSM (fractions of a second), a lock read, and one
    `pkcs11-tool --list-objects` for the snapshot.
  - A camigrate cell is two tokens plus its dry-run twin: about 2–4 s.
  - A caprobe cell is a full `probe --write-probes --rsa-max-bits 4096` on SoftHSM: tens of
    seconds, which is today's `caprobe/tests/fault.rs` cost per case.
- **Estimated size.**
  - cakeys: about 150 cells, about 2 min serial.
  - camigrate: about 40 cells, about 2.5 min serial.
  - caprobe: about 15 cells, about 5 min serial.
  - tpm2: about 8 cells on swtpm, about 1 min.

  Split one test per (tool, lie class) and nextest runs them in parallel, each with its own token
  set (`nix/test-tokens.sh`). The added wall time in the crane check phase is about **2–3 min**
  on a 4-core runner. That fits T0.
- **To keep it in T0:**
  - caprobe cells share one honest probe per test.
  - A caprobe `--only <family>` flag would cut a cell to seconds. It is optional; add it if the
    budget is exceeded.
  - The cells run in the `liars` suite. `nix/test-tokens.sh:84-86` gains `liars` beside `fault`
    (the real module in `P11_FAULT_MODULE`), and `liars/*` joins the untraced list (`:61`).
    `CAKEYS_FAULT_REQUIRE` already fails a suite the routing misses (C-11's fix).
- **Where each part runs:**
  - The lint (§1.6) is pure: plain `cargo test`, darwin included.
  - The cells are Linux T0.
  - The tpm2 cells run where `tests/tpm2.rs` runs: Linux crane, swtpm.

## 2. Item 10: hardware personas by record and replay

### 2.1 Can p11-fault's trace capture a session well enough to replay it?

**No, not as built.** The trace is one JSON line per call:

- the function and the rv;
- the mechanism and its enumerated parameters;
- the attribute *types*;
- the classes, key types and certificate types named;
- the flags of the info structures (`trace.rs:35-62`).

By design it records no byte values: no attribute value, no signature, no blob, no PIN
(B.md:494). A replayer needs every output byte (handles, attribute values, signatures, wrapped
blobs, info structures) and every input it must match on.

**Recording all bytes is possible, but replaying them is mostly not honest.** Where the host
supplies fresh randomness, a recorded answer is an answer to another question:

| Exchange | Who chooses the input | Replayable byte for byte? |
|---|---|---|
| `pop-sign`, `pop-decrypt`, `pop-ecdh`, `pop-unwrap` (cakeys, camigrate) | the host: "a fresh 32-byte nonce from the OS" (`core/src/pop.rs:32`), an ephemeral ECDH key, a fresh KEK | **no.** The recorded signature is over another nonce, so the host's verification fails, as it must |
| TPM `tpm-certify` (vendor route and store path) | the host's nonce as qualifying data, checked at `vendor.rs:195-196` | **no**, for the same reason. Making it pass is exactly the replay attack B-12's nonce check exists to refuse |
| PIV attestation (slot certificate + f9 + Yubico chain) | the device: no host nonce. The chain is checked against pinned roots | **yes, at the verifier.** It carries no freshness, so a recorded chain is as valid as a new one. But it attests the device's slot key, which no software token holds, so a session replay cannot also pass that key's proof of possession |
| `C_WrapKey` / host extraction | a fresh session KEK per run (`token/host.rs:27-29`) | no |
| caprobe's write probes | fresh keys, random data | no |
| Reads: mechanism list, token info, attributes of existing objects, rvs of refusals | the device alone | yes |

**Could the randomness be made deterministic?** Only by a test-only seed in the security path:
the PoP nonce, the session KEK and the TPM nonce taken from `CAKEYS_TEST_SEED`. Then a byte
replay passes only while cakeys makes exactly the recorded calls with exactly the recorded
arguments. This would:

- put a nonce override into the code whose job is freshness. Even behind a feature flag it is
  a seam that can ship;
- stop answering the moment a change alters the conversation. That is exactly when a persona
  would be wanted. So "hardware is needed only to refresh a persona" would hold only for
  changes the persona cannot see anyway;
- still not cover attestation that the host verifies against fresh data.

**Decision: no byte-replay personas.** Item 10 as written ("replay them as personas in T0") is
cut.

### 2.2 What is possible instead

Three parts, all from one recording made during a T2 run that happens anyway
(`coverage-full`, `scripts/cloud/*.sh`, the YubiKey probe):

1. **Quirk personas, from the trace.**
   - A persona is a software token behind p11-fault with a *derived* plan, which reproduces the
     device's observable protocol behaviour:
     - the mechanism list (`hide_mechanisms`);
     - the rv per (function, mechanism, key type, class), with the §1.1 matchers;
     - attributes reported absent or with the wrong value: ykcs11's `CKA_DERIVE = false` on EC
       keys, CloudHSM's EC point form (an attribute `reshape`);
     - token and slot flags;
     - the login model (SO for writes).
   - The trace already holds every input of that derivation: function, mechanism, key type,
     class, rv. The derivation is a script, `nix/persona.py`, deterministic, run in the
     sandbox.
   - Cryptography stays the software token's, so the host's verifications run for real on fresh
     nonces. The persona says what the device *refuses and misreports*, not what it computes.
2. **Recorded public values become verifier fixtures.**
   - A recording option, `P11_FAULT_RECORD_VALUES=public`, writes the values of public
     attributes only:
     - `CKA_VALUE` of `CKO_CERTIFICATE`;
     - `CKA_EC_POINT`, `CKA_PUBLIC_KEY_INFO`, `CKA_MODULUS`, `CKA_TPM2_PUB_BLOB`;
     - the output of `C_Sign` under `CKM_TPM2_CERTIFY*`, *with the qualifying data cakeys sent*.
   - It never writes a PIN, a secret's or private key's `CKA_VALUE`, `C_WrapKey`/`C_Decrypt`
     output, or `C_UnwrapKey` input. The recorder refuses to run with any other value set,
     which keeps DEVELOPMENT.md's credential rules.
   - These values are the device's genuine attestation: the PIV chain, and TPM certify
     statements with the nonce that went in. Unit tests then run the verifiers on them, with
     the recorded nonce supplied as "this run's". This is honest: it tests that the verifier
     accepts a real device's output, and the forgery kit (B-11, B-12; §1.7) derives the forged
     variants from the same real material instead of from synthetic fixtures alone.
3. **The device's verdicts as the persona's oracle.**
   - The recording run executes a fixed scenario: a keys.toml of scratch-slot specs (YubiKey
     slots 90–95, `CKA_ID` 13–18 only, per DEVELOPMENT.md's hardware rules) through `create`,
     `check`, `lock`, `delete` (refused on ykcs11), and caprobe read-only plus write on slot 17.
   - It stores each verb's `--json` rows (exit, `rule`, `device`).
   - The T0 persona test runs the same scenario on the persona, with the provider named
     explicitly as the contract suite does (P1 §3.3). It asserts the same rows, except for an
     explicit `differs` list. That list holds, for example, the attestation verdict (the persona
     holds no slot key the f9 certificate attests) and PoP (the persona key is the software
     token's).

**Conversation drift (optional, later).** The persona test can also compare the call shapes of
its run (function, mechanism, attribute types, rv) with the recording's.

- A change that alters what cakeys *asks* the device shows up as a shape diff, even when every
  verdict holds.
- The diff is evidence for the ledger's `[artifact.acknowledged]` ("the device sees the same
  calls" or "it sees these new calls: T2 needed").
- It must not auto-acknowledge. A same-shaped conversation on a software token says nothing
  about the device's answers to value-dependent calls.

### 2.3 Where recordings live, and the ledger

- **Layout.** `profiles/personas/<module>/<version>+<device>/`:
  - `trace.jsonl.zst`, the shape trace: kilobytes, reviewable after decompression;
  - `values.jsonl`, public values only;
  - `scenario.toml`;
  - `outcomes.json`;
  - `plan.toml`, the derived persona plan.
- **`plan.toml` is generated.** `nix/persona.py` derives it from `trace.jsonl.zst`, and
  `checks.ledger` re-derives and byte-compares it (`verified-by` semantics), so it is never
  hand-edited.
- **The recording files are ledger artifacts** of the existing "came from a run no build
  repeats" kind, with no new semantics:
  - `[artifact.probed]` holds the commit, the date, `hash` and `code-hash`;
  - `code` names the scenario, caprobe's probe group, the provider crate and `crates/p11-fault`;
  - hand edits are `[[artifact.hand-edits]]` rows, and acknowledgements work as today
    (`nix/ledger.py:1-30`).
- **A persona never feeds a hardware profile.**
  - Probing a persona with caprobe yields the device's recorded rvs passed through today's
    classification. That is a good regression test for E-2's classifier on real ykcs11 rvs.
  - But its rows must never be written to `profiles/modules/ykcs11/…`. That would launder a
    software run as a device probe (E-7).
  - `caprobe probe` refuses `--out` into `profiles/modules/` when the module is a p11-fault copy
    with a persona plan. The shim announces itself in `C_GetInfo`'s `libraryDescription` suffix
    `+persona`.

### 2.4 What a persona can and cannot stand in for

| Stands in for (T0, per change) | Does not (stays T2) |
|---|---|
| Provider hooks against the device's refusals and misreports: placement and SO (B-1, B-2), `CKA_DERIVE` repair (UD-22), "keys are never deleted" (UD-21, B-13's ykcs11 half), the slot guard (E-6) | The device's cryptography, and whether it really destroys, wraps or imports |
| The planner on the device's real rvs, and caprobe's classifier on them (E-2: the ten `import.* = no, CKR_DEVICE_ERROR` rows are exactly a recorded rv) | Whether `CKR_DEVICE_ERROR` *means* "cannot import RSA" (E-2's plausible half) |
| The attestation verifiers on the device's genuine recorded chain and statements, and on forgeries derived from them | Freshness: the TPM's response to a new nonce, the EK chain of a new device, firmware changes |
| Error paths: what the device answered, replayed per call shape | Touch, PIN-retry counters, timing, concurrent clients (pcscd) |

**Priority.**

1. ykcs11 first. It has the most findings that touch it: B-1, B-2, B-7, B-10, B-13, D-2, E-2,
   E-6. Its quirks are few and its scenario is short.
2. The AMD fTPM next, as a delta over swtpm, which already runs in T0. The persona adds only the
   rvs where the two differ (`amd-ftpm.toml:84,91,107`).
3. **Not now:** CloudHSM and Cloud KMS.
   - Their vendor modules need the cloud even to record.
   - The profiles already drive their `Data`/code providers.
   - kmsp11's purpose-bound behaviour is already decided by `keys.json` (E-5), so a persona
     derived from it would test the table against itself.
   - Record their public values (certificates, points) at the next T2 run, for the verifier and
     `ec_point` unit tests only.

## 3. Item 11: independent oracles

### 3.1 Every probe "yes" is host-verified or says it is not

**P3 does this** (P1 §2.3):

- `by ∈ {module, host, unverified}`;
- `Draft::set` is split into `set_no(cap, ModuleRefusal)` and `set_yes(cap, Checked)`
  (`caprobe/src/probe.rs:341`);
- `unverified` turns into `Deferred` in the planner.

**Phase 2 adds three things:**

1. **A guard on the regenerated data.** `every_regenerated_yes_says_by_whom` is a test in
   `crates/profile/tests/answers.rs`.
   - For each profile `LEDGER.toml` marks `verified-by` (softhsm, kryoptic, swtpm), every `yes`
     row has `by = "host"` or `by = "unverified"`, and no `yes` is legacy.
   - Legacy rows are allowed only in the profiles the ledger records as hardware runs.
2. **`Checked` cannot be faked.**
   - Its constructors are the host-check functions themselves: `sig::verify`, `same_key` on the
     host, the host blob decode, `pop::verify`. `Checked::unverified(why)` is the only other way
     to make one.
   - A grep lint in the `ci-jobs` style keeps the constructor out of the probe families: the
     `Checked {` literal may appear only in `caprobe/src/probe/checked.rs`.
3. **E-3's instance fix.**
   - It is not in Phase 1: P3 only labels the row `unverified`.
   - `export.sealed.*` and `wraps` wrap toward the public key of the imported `rsa-2048` fixture
     and decode on the host (`aes-kw` is already a dev-dependency). Only a host decode makes
     `by = "host"`.
   - The liar cell `blob.transcode` (§1.7) is its before-test. This is package L4b.

### 3.2 The regeneration scripts diff before they overwrite

Today:

- `scripts/regen-profiles.sh:72-75` passes `--diff <name> --out <file>`, and "15 is drift … the
  file is written anyway".
- `scripts/cloud/{aws,gcp}.sh` do the same (E-7).
- `CAKEYS_UPDATE_OBJECTS` (`crates/cli/tests/object_matrix/mod.rs:817-833`),
  `CAKEYS_UPDATE_BASELINE` and `CAKEYS_UPDATE_COVERAGE` rewrite in place.

After P4 there is one `caprobe regenerate <profile>` verb (P1 §4.2, E-8). Phase 2 changes it,
and the three update variables, to the same shape:

1. Write `<file>.new`, never the file itself.
2. Print the row-level diff: added, removed and changed row keys, with old → new answers, read
   through the profile crate rather than as lines of text.
3. Write the diff's row keys into a `regenerated` stub for the ledger (§3.3), with each `why`
   left as `"TODO"`.
4. Replace the file only with `--accept` (`CAKEYS_ACCEPT=1` for the update variables). The
   ledger refuses a `"TODO"` why, so the diff cannot be accepted unread.

### 3.3 Logic and golden data changed together: the rows must be listed

**Which files.** The golden files are:

- `spec-coverage/objects/*.toml` (3);
- the three `verified-by` profiles;
- `spec-coverage/cakeys.toml`;
- `profiles/baselines/*.toml`.

The hardware profiles are already ledger artifacts. In 36 of the 47 commits that touched these
files, `crates/*/src` changed too (C-8).

**The sandbox part (T0, `checks.ledger`, no git).**

- Each golden file gets a ledger entry of a new kind, `[golden."<path>"]`, holding:
  - `hash`, the file now;
  - `generator`, the code globs that write it, for example the object matrix's test and
    `crates/pkcs11/src/**` for `objects/*`;
  - `code-hash`, as for artifacts: Rust read as tokens (`nix/ledger.py:22-29`).
- The check compares the file and the generator with the recorded hashes. Neither needs git:

  | File | Generator | Then |
  |---|---|---|
  | same | same or changed | pass. A generator change that does not move the output needs nothing |
  | changed | changed | the newest `[[golden."<path>".regenerated]]` must name the new `hash` and the generator's `code-hash`, with `rows = { "<row key>" = "<why it is right>", … }`. Every key must be present in the file, or be marked `removed`. Every `why` must be non-empty and not `"TODO"` |
  | changed | same | a hand edit: a `[[hand-edits]]` row, as for artifacts today. The object matrix's 244 hand-edited lines (fcaa6aa) would have needed one |

- `--write` folds the accepted record into `hash` and `code-hash`, as for artifacts.

**The CI part (git needed, so CI only).**

- On a pull request, a step in `checks.yml`'s `light` job runs
  `nix develop -c python3 -I nix/golden-rows.py --base "$(git merge-base origin/main HEAD)"`.
  It needs a checkout with `fetch-depth: 0`, and `checks.ci-jobs` holds the workflow to the step.
- For each golden file the diff touches, it parses both versions and computes the exact set of
  changed row keys. It fails when that set differs from the newest record's `rows`.
- It writes the row table, old → new, to `$GITHUB_STEP_SUMMARY`, so the review reads verdicts
  rather than TOML lines.

**Honest value: moderate.** This is a process control. It makes a person name each moved
verdict and say why. It does not make the expected value independent of the code. The class fix
C-8 asks for is hand-written assertions *in front of* each golden file, derived from the spec or
the vendor's documentation and not from the generator:

- `crates/cli/tests/object_matrix/properties.rs`: about 10 properties. For example, "an EC key
  with `CKA_ALLOWED_MECHANISMS = [CKM_ECDH1_DERIVE]` and `CKA_SIGN` is 17" (A-10), and "a
  `CKO_DATA` object is never `exit 13` for a type".
- `crates/profile/tests/properties.rs`: about 10 per software profile. For example, "SoftHSM's
  `wrap.rsa-oaep.SHA-256` is `yes, by = host`", "SoftHSM never wraps with
  `CKM_RSA_AES_KEY_WRAP`", "kryoptic's Edwards points are raw and DER".

Those are package L6. The record (§3.3) is the smaller half of it.

### 3.4 `assert_unchanged(token, lock)` in the harness

Today, "nothing changed" exists in two places only:

- the camigrate twin's private `state()` (`crates/cli/tests/common/xref.rs:185-200`, with
  `objects()`, `:233-256`);
- the lie table's lock-byte compare (`fault.rs:287-296`).

```rust
// crates/cli/tests/common/state.rs (new; xref.rs's objects() moves here, and the twin uses it)
pub struct Snapshot(Vec<(String, String)>);             // (what, content) — lock bytes, files, tokens
pub struct TokenView<'a> { pub module: &'a str, pub label: &'a str, pub env: &'a [(&'a str, &'a str)] }
pub fn snapshot(lock: &Path, files: &[&Path], tokens: &[TokenView]) -> Snapshot;
pub fn assert_unchanged(before: &Snapshot, after: &Snapshot, context: &str); // names the changed lines

impl Workdir {
    pub fn token_view(&self) -> TokenView<'_>;          // the "ref" token of reference_tokens()
    /// Run with --json: the exit is `exit`, the failing row's `rule` is `rule`, and the lock and
    /// the token are as they were. Returns the rows.
    pub fn refused(&self, args: &[&str], exit: i32, rule: &str) -> Vec<Row>;
}
pub fn rows(o: &Output) -> Vec<Row>;   // Row = cli-common's Outcome (P1 step 7), Deserialize
```

- **The helper does more than the old one.** `Workdir::refused` costs one argument more than
  `w.code(args)` plus `stderr(&o).contains(..)`, and it asserts three things. So the cheapest
  helper is now the strongest one, which is C-9's own diagnosis inverted.
- **Before-test.** `a_refusal_that_changes_the_lock_is_caught`: the test writes the lock inside
  `refused`'s window and expects a panic. It is red before the helper exists.

### 3.5 Structured rule IDs instead of prose: counts and migration order

**The count depends on the method.**

- C-9 counted 39 of 131 cli tests asserting "only exit codes and prose".
- Re-counting the same 131 by the asserts' first arguments, this design's script finds 12 to 22
  of them, depending on whether a lock read used only for setup counts as a state oracle.
- A count that moves this much with its definition is not a target. The ratchet below counts
  something mechanical instead: **prose assertion sites**, an `assert*!` whose subject is
  `stderr`/`stdout`/`said`… `.contains(…)`, and **exit-code assertion sites**.

At `f3b8e5e` (script over `crates/{cli,camigrate,caprobe}/tests/**/*.rs`):

| File | Tests | Prose asserts | Exit asserts |
|---|---:|---:|---:|
| `camigrate/tests/dry_run.rs` | 25 | 70 | 156 |
| `cli/tests/tpm2.rs` | 21 | 25 | 68 |
| `cli/tests/fault.rs` | 14 | 17 | 30 |
| `cli/tests/reference/lockfile.rs` | 8 | 17 | 55 |
| `cli/tests/reference/create.rs` | 7 | 16 | 32 |
| `cli/tests/validate.rs` | 4 | 13 | 5 |
| `cli/tests/reference/proofs.rs` | 8 | 12 | 34 |
| `cli/tests/reference/identity.rs` | 13 | 11 | 65 |
| `cli/tests/reference/check.rs` | 5 | 10 | 27 |
| `cli/tests/reference/drift.rs` | 12 | 10 | 44 |
| `camigrate/tests/fault.rs` | 6 | 10 | 11 |
| `caprobe/tests/fault.rs` | 7 | 9 | 10 |
| `cli/tests/reference/tokens.rs` | 7 | 8 | 15 |
| `camigrate/tests/from_files.rs` | 4 | 8 | 17 |
| `caprobe/tests/supports.rs` | 5 | 7 | 19 |
| `cli/tests/reference/delete.rs` | 3 | 6 | 38 |
| `cli/tests/reference/validate.rs` | 5 | 6 | 21 |
| `caprobe/tests/reference.rs`, `template_hook.rs` | 8 | 12 | 9 |
| the rest (adoption, ftpm, offline, p11kit, references, yubikey, cloud, `common/`, caprobe tpm2/yubikey; harness, surface and matrix have neither kind) | 45 | 17 | 82 |
| **Total** | **207** | **284** | **738** |

**The ratchet (T0, sandbox, seconds).**

- `nix/oracle-count.py` and `nix/oracle-count.toml` give each test file its maximum number of
  prose assertion sites. The check fails on more, and `--write` only lowers the numbers. It works
  the same way as `test-count`, with its own fixture tests (`nix/oracle-count-tests.py`) first.
- Exit-code assertions are not limited. For a refusal, the exit is half of the right oracle.
  What is limited is the prose standing in for the rule.

**Migration order.** Leverage first. Each step lowers the manifest in the same diff.

1. `cli/tests/fault.rs`: its lie table *becomes* the cakeys matrix (L4a). The 26 rows move in as
   cells, and the hand table goes.
   - The rows are one test, `a_lying_module_is_refused`. It goes, so `"cakeys::fault"` in
     `nix/test-count.toml` is lowered by one with the why "rows moved to liars".
2. The lock-rule refusals, asserted today as exit 17 or 14, which every lock rule returns
   (A root cause 6): `reference/lockfile.rs`, `drift.rs` and `identity.rs`. They move to
   `refused(args, 14, "lock.downgrade")` and the like, with the `Check` names of §1.3.
3. `reference/delete.rs`, `check.rs` and `create.rs`: refusal plus unchanged (C-4).
4. `camigrate/tests/dry_run.rs` (70 prose sites). Most of them go at once when the twin and its
   helpers read rows (P2 step 14).
5. `cli/tests/tpm2.rs`: the attestation refusals that C-9 names, for example
   `tpm2_attestation_refuses_a_store_that_disagrees`, become `attest.tpm.*` names.
6. `validate.rs` and `reference/validate.rs`: `deferred` rows (P1 step 3).
7. caprobe last: its rows are already data, and its prose is mostly notes.

## 4. Item 12: docs as tests

### 4.1 `doc-references` over Rust comments (A-2)

**Today.** `nix/doc-references.py` checks backticked names only in `docs/*.md`, `ISSUES.md` and
`README.md` (`:38-40`, `:61`), and only names of four or more words (`:53`).

**Extension.**

- **Where it reads.** For every `crates/**/*.rs` and `fuzz/**/*.rs`, it reads each line whose
  stripped form starts with `//` (`///` and `//!` included).
- **What it checks.** Each backticked name must exist. A name is:
  - a snake name with at least one `_`, of any length, or
  - a path `A::b(::c)*`, judged by its last segment.
- **What counts as existing.** An index of the tree's identifiers: `fn`, `struct`, `enum`,
  `trait`, `type`, `const`, `static`, `mod`, `macro_rules!`, fields and variants. That is a
  regex index like `:48-50`'s, not a parser.
- **Docs too.** The same rule applies to `Type::fn` forms in the docs, of any length.

**Measured at `f3b8e5e`.**

- 1,056 backticked names occur in Rust comments. **33 distinct names (56 occurrences) do not
  resolve.**
- Most are foreign. They go into `FOREIGN_NAMES` with what each one is:
  - `tpm2_ptool` (18), a tool;
  - methods of the standard library and dependencies: `to_der`, `into_vec`, `new_from_slice`,
    `sign_single`, `to_string_lossy`;
  - tpm2-pkcs11's C functions: `token_unseal_wrapping_key`, `db_init_new`, `set_esys_auth`;
  - kmsp11's `experimental_create_multiple_versions`.
- A handful look like stale names of our own, to be fixed rather than listed: `object_curve`,
  `mac_by`, `by_oid`, `private_key_type`, `pvtkey_objects`.
- A-2's own two instances (`scratch_occupant`, `spki_curve`) no longer occur.

So the allowlist is small, and the check is worth its cost.

**Before-test.** `nix/doc-references-test.py` (new) builds a fixture tree whose `///` comment
cites a `Type::gone`. It is red before the extension.

### 4.2 Universal claims: inventory and rule

**Counted at `f3b8e5e`.**

- Lines with *every*, *never*, *always*, *the one way*, *no other*, *only way* or
  *nothing can/may*:
  - DESIGN 113, CAMIGRATE 35, CAPROBE 58, CAKEYS 37: **243 lines**.
- Of those, the lines that also name a security subject (plaintext, PIN, secret, private,
  overwrite, delete, destroy, identity, attest, lock, refuse, in clear, leave, extract, bundle,
  transport, slot, scratch, write): DESIGN 42, CAMIGRATE 21, CAPROBE 21, CAKEYS 16. **100
  lines.** Those are the inventory.

**Rule.**

- **The register.** `docs/claims.toml` gives each such claim one entry:
  - `says`: a phrase unique in its document;
  - `kind = "enforced"`, with `tests` (fn names; existence checked against the doc-references
    index) and the `paths` the tests cover;
  - or `kind = "descriptive"`, with `why` it is not a guarantee. For example "Every verb takes
    the global options".
  - Softening is done in the document itself, so the line stops matching or becomes
    descriptive.
- **The lint.** `nix/claims.py` runs inside `checks.doc-references`. A matching line without a
  register entry counts as *unregistered*. The lint fails when that count exceeds the file's
  `max-unregistered`, which starts at 100 and only goes down.
- **DESIGN §8.1 "Enforced (with tests)"** (`DESIGN.md:636-660`) is held to its heading. Every
  bullet names at least one test in backticks, as the sidecar bullet already does
  (`update_lock_waits_for_the_sidecar_lock`).

**The claims findings named, and §8.1.**

| Claim (where) | Today | Decision |
|---|---|---|
| "On every `host` path the identity is checked on the host first" (CAMIGRATE.md:164-166); `hand_over` "the one way" (camigrate `host.rs`) | false: `export --to-key-file` and secret keys are unchecked (D-5) | enforced after P2 step 12 (`Extracted` → `Checked`). Tests: the `other.wrap` cells (§1.7) on every host path |
| a transport key "for the file's token" (D-1) | false | enforced after P2 step 8; tests: P2's D-1 before-test plus a `transport.bound` cell |
| a mechanism no row measures "reads *unknown*, never *yes*" (CAPROBE.md:135-136) | false (E-4) | enforced by P3 (`by`) and `every_regenerated_yes_says_by_whom` (§3.1) |
| the probe "never touches PIV data objects" (CAPROBE.md:205) | false: it writes the slot's certificate twice (E-6) | **soften:** "writes in the scratch slot only: the key it probes and its own mark certificate", plus the E-6 cell |
| "nothing reads `delete.*`" (CAPROBE.md:204) | true today, false after P1 step 5 | rewrite to name the consumer (`plan_delete`) and its test (K-6) |
| "A change to the lock rules changes the model in the same commit, or `lock_mbt.rs` fails" (DEVELOPMENT.md:254-255) | false (A-6) | **made true by L2:** `every_lock_rule_is_modelled_or_left_out` over the lock-rule `Check` names (§1.3) |
| YubiHSM detection "fixed" (ISSUES.md, B-10) | instance only | enforced by P3's registry rule; the entry cites K-4 |
| "Identity is the CA-ID. Every check recomputes it" (§8.1) | tested per scenario (`tests/references.rs`) | name the tests plus the matrix's `other.*` cells |
| "Locators never create over occupied slots, and never match more than one" (§8.1) | `never_create_over_an_occupied_locator`; `a_second_private_key_under_the_same_id_is_ambiguous` | add the `other.find` cells; cross-path once P1 step 6 / P2 step 9 put `LocatorFree` on every path |
| "Private keys prove possession … cannot weaken" (§8.1) | `binding_downgrade_is_refused` | plus the `other.key` cells for each binding |
| "Attestation … never a standalone identity" (§8.1) | `attestation_is_per_realisation_and_never_alone` | plus the B-11/B-12 rows |
| "Identity modes never weaken" (§8.1) | `downgrade_is_an_error` | name it |
| "Material is linked only through a shared scheme" (§8.1) | `material_links_only_through_a_shared_scheme`, `disjoint_schemes_never_link_material` | name them |
| "The lock never holds token outputs, only their hashes" (§8.1) | **no test found** | add `a_lock_holds_no_token_output`: after the honest runs of the matrix, no lock value equals a value the trace recorded (`P11_FAULT_RECORD_VALUES=public`, §2.2). Without it, soften |
| "Refused operations leave nothing behind" (§8.1) | `a_creation_that_cannot_be_identified_is_undone_or_reported`, `a_creation_that_fails_after_the_write_is_undone`, `a_move_the_module_fails_is_refused_and_undone`, `tpm2_identity_failure_after_create_leaves_nothing` | the class test is the matrix's `unchanged` on every refusal cell (§1.5); name it |
| "a run that wrote the lock exits 22, never 0" (CAKEYS.md:38; DESIGN.md:187) | tested per verb | the matrix runner asserts `exit == 22 ⟺ lock bytes changed` on every honest run and every cell: one invariant over every path |
| `check` "never writes: not the lock, not the token, not a TPM's persistent handles" (CAKEYS.md:49) | partly (the twin covers camigrate) | every `check` cell implies `unchanged = ["token", "lock"]` (runner rule). TPM handles stay T2 (`coverage-full` compares them) |
| `create` "is the one verb that writes keys to a token" (CAKEYS.md:22,47; DESIGN.md:182) | false across tools: camigrate imports, caprobe writes scratch | **soften:** "of cakeys' verbs" |
| "A run spends at most one failed PIN attempt, and never the last" (DESIGN.md:319) | `CKF_USER_PIN_FINAL_TRY` row (`fault.rs:226`) | add the SO flags (B's list 8) as cells |
| host plaintext "never on disk or the wire, zeroized after" (CAMIGRATE.md:84) | by construction (`Zeroizing`), untestable as stated | **descriptive**, citing the type. Not a test |

**The rest.** The remaining ~80 lines are triaged in package L7b against the same rule. The
ratchet keeps the count from growing meanwhile.

**Related: "Mutation-checked" claims.** DEVELOPMENT.md:145-146 says of named tests "disabling
the binding-downgrade rule fails it". Such a claim becomes a register entry of
`kind = "mutant"`, naming the mutant key (§5.4). The monthly mutants sweep verifies that it is
`caught`, which closes the A-6 shape for that claim.

## 5. Item 13 (Phase 3): cargo-mutants as a gate

### 5.1 Scope

**Today.**

- `packages.mutants` covers `cakeys-core` and `cakeys-profile` whole, plus camigrate's `plan`,
  `bundle`, `file` and `transport`. Each package's mutants meet that package's tests
  (`nix/package-crane.nix:308-328`).
- `mutantsOf` runs one scope with the token suites (`:329-334`).
- Mutants in the workspace (`--list`, `f3b8e5e`): core 986, profile 367, pkcs11 1,102,
  camigrate 945, caprobe 696, tpm2-pkcs11 386, p11-fault 118, kmsp11 78, cakeys 66,
  ykcs11 56, cli-common 32, aws-cloudhsm 26, p11-names 19. **4,877 in all.**

**Two tiers, by which tests can catch the mutant:**

| Tier | Crate: files (mutants) | Count |
|---|---|---:|
| **unit** (the package's own tests; seconds each; no tokens) | core: `reconcile` 139, `id` 133, `config/lock` 99, `plan` 96, `config/check` 77, `chain` 64, `config/object` 50, `pop` 43, `error` 33, `plaintext` 22, `sig` 18, `config/spec` 15, and the new `check.rs`, `known.rs` | ~790 |
| | profile: `capability` 138, `effective` 114 | 252 |
| | camigrate: `file` 92, `plan` 86, `bundle` 58, `side` 21, `transport` 13, and P2's `trust.rs` | ~310 |
| | tpm2-pkcs11 (Linux): `attest/esys` 134, `credential` 56, `vendor` 50, `mod` 41, `store` 29, `ek` 9 | 319 |
| | kmsp11 `lib` 78, aws-cloudhsm `lib` 26, ykcs11 `attest` 5 | 109 |
| **token** (every crate's tests under nextest with a token set per test) | pkcs11: `token/possession` 125, `ops/mod` 87, `token/identity` 67, `token/policy` 66, `provider` 60, `token/generate` 59, `ops/capabilities` 38, `templates` 38, `token/login` 38, `ops/planner` 33, `gate` 28, `token/rv` 25, `token/host` 21, `registry` 13, `token/public` 8, P1's `ops/rules.rs`; `resolution` and `token/mod` only by `--re` on `clear_hardware_rows`, `select_in`, `named_in`, `find`, `locate` (~55) | ~760 |
| | camigrate: `tokens` 115, `sealed` 101, `landing` 76, `file_verbs` 69, `public` 32, `host` 24 | 417 |
| | caprobe, the row-writing decisions: `probe/moves` 90, `secrets` 89, `asymmetric` 83, `extras` 62, `bound` 36, `wraps` 16, and `probe.rs` by `--re 'check_slot|mark_slot|Draft::|finish'` (~40) | ~416 |
| | cli-common (the `Outcome` mapping) | 32 |

That is about **1,780 unit and 1,625 token mutants: 3,400 of the 4,877.**

**Left out, each with its reason:**

- `camigrate/keyfile.rs` (177), the key-file parser, which fuzz target `key_file` covers.
- `pkcs11/token/uri.rs` (62), `measure.rs` (55), `library.rs` (44): printing, measurement,
  loading.
- caprobe `emit`, `diff`, `coverage`, `supports`: report code, held by golden checks.
- `cli/src/lib.rs` (65) and the three `main.rs`: glue, whose decisions moved into `plan` and
  `execute` in Phase 1.
- `ykcs11/src/lib.rs` (51): only the persona (§2) can catch these, so it joins once L9 lands.
- p11-fault and p11-names: test infrastructure.

### 5.2 Driving nextest with the token environment

The mechanism exists. `mutants { tokens = true; }` (`nix/package-crane.nix:108-197`):

- sets cargo's target runner to `nix/test-tokens.sh` (`:188-191`), the check phase's per-test
  token set;
- runs `common.args.preCheck` (`:193`), which builds the token templates;
- passes `--test-tool nextest --test-workspace=true` and selects the three tools
  (`:124-163`), so the integration suites spawn freshly built binaries.

What changes, as parameters of the same function:

| Parameter | cargo-mutants flag | Why |
|---|---|---|
| `inDiff ? null` (a store path) | `--in-diff <file>` | the PR gate |
| `shard ? null` (`"k/n"`) | `--shard k/n` | spread over a job matrix |
| `iterate ? null` (an earlier report) | its `mutants.out` copied into place, then `--iterate` | the token tier runs only on the unit tier's survivors |
| `testFilter ? null` | `--cargo-test-arg=-E --cargo-test-arg=<expr>` | e.g. `not (binary(kryoptic) | binary(p11kit) | binary(surface) | binary(harness))` |
| `timeout ? 600` | `--timeout` | a token run must not inherit a multiple of a slow baseline |

- **The kryoptic run is the same reference suite again** on another token. Leaving it out of
  the token tier roughly halves the time per mutant. A mutant only kryoptic would catch then
  shows up as a survivor and gets reviewed.
- **New outputs:**
  - `packages.mutants-unit` and `packages.mutants-tokens`: the §5.1 scopes;
  - `cakeys-crane.mutantsDiff { diff, tier, shard ? null, iterate ? null }`;
  - `packages.mutants-gate`, a `runCommand` over a report and `nix/mutants-baseline.toml`
    (§5.4).
- **It stays in the Nix sandbox.** The PR job reads the diff from outside and hands it in as a
  path (`--impure --expr`, the pattern `package-crane.nix:305-307` documents). So the gate's
  build is the check phase's build, patched cryptoki included. A run outside Nix
  (`scripts/local-tests.sh`) would need its own copy of that machinery.

### 5.3 CI mechanics

A new workflow, `.github/workflows/mutants.yml`. It replaces `reports.yml`'s `mutants` job;
the badge publish job moves with it, keeping the read-only build and write-only publish split.

**Pull request, unit tier: required, T0-CI.**

1. `actions/checkout` with `fetch-depth: 0`.
2. `git diff --merge-base origin/main HEAD -- 'crates/**/*.rs' > "$RUNNER_TEMP/pr.diff"`. An
   empty diff passes at once.
3. `nix build --impure --expr '(builtins.getFlake "git+file://'$PWD'").packages.x86_64-linux.cakeys-crane.mutantsDiff { diff = builtins.path { path = "'$RUNNER_TEMP'/pr.diff"; name = "pr.diff"; }; tier = "unit"; }'`
4. `nix build … mutants-gate`, on that report: a survivor not in the baseline fails the job.

It is required in branch protection beside `checks / light`. It is not part of
`.#checks-no-vm`, because a flake check cannot see a diff.

**Pull request, token tier: T1 rules** (before merge, or within a day and fixed forward, as for
`vm`).

- It runs on the unit tier's survivors in token-scope files (`iterate`), as a matrix of 4
  shards. The gate is the same.
- Over about 120 mutants after the unit pass, the job stops with "split the change, or run
  `scripts/mutants-diff.sh --tokens` on a Linux builder and record it in `Ran:`". It does not
  sample: a sampled gate passes or fails by chance.

**Scheduled runs.**

- **Weekly:** both tiers `--in-diff` against main as it was a week ago, which covers what
  changed. Then the gate, in "sweep" mode for the files touched.
- **Monthly** (first Monday): a full sweep of both tiers.
  - The unit tier in 4 shards; the token tier in 16–20 shards, all within the job limit.
  - It fails on new survivors *and* on stale baseline entries.
  - Its `missed.md` (§5.5) is uploaded as an artifact, and the badge (in-scope survivors over
    viable) is published.

**Locally.**

- `scripts/mutants-diff.sh [--tokens] [base]` builds the same `mutantsDiff` for
  `aarch64-linux` through the local builder (`--option builders ''`).
- On darwin, the unit tier also runs directly, through
  `nix develop -c cargo mutants -p <crate> --in-diff <(git diff …)`, for every crate but
  tpm2-pkcs11, which darwin does not compile.

### 5.4 The survivor baseline

```toml
# nix/mutants-baseline.toml — survivors that may stay, each with why (docs/REVIEWING.md).
# The PR gate fails on a survivor of the diff not listed here. The monthly sweep fails on a
# survivor not listed and on an entry that no longer survives. `--write` removes entries,
# never adds them, and never raises `max`.
max = 1180                       # entries; only goes down, and a raise is a visible diff
["crates/core/src/reconcile.rs"]
"compare: BinaryOperator ==→!=" = "a changed locator: lock.qnt leaves locators out (A-6); test in L11"
"record: FnValue →Ok(())" = { why = "seeded 2026-12-07", reviewed = false }
```

- **The key.** It is `<function>: <genre> <original→replacement>`, with `#k` for the k-th
  identical key in one function. It is built from `outcomes.json`'s `scenario.Mutant` fields
  (file, function name, genre, replacement, and the original text at the span). **It holds no
  line or column**, so an edit higher in the file does not churn the baseline.
- **Seeding.**
  - The first monthly sweep, once L8 lands, writes every survivor as
    `{ why = "seeded <date>", reviewed = false }`.
  - Those entries are the mechanical form of the ~120 unguarded decisions the reviewers found
    by hand. The next review starts from them (§5.5).
- **"May only shrink".** It has two parts:
  1. `max` is the entry count, and `--write` never raises it. Adding a survivor means raising
     `max` by hand, in the diff, with its `why`.
  2. The sweep fails while an entry no longer survives, so the file cannot keep dead entries.
- **Timeouts and unviable mutants** are reported, not gated. A timeout is a hang in a token
  run, and it is listed in the job summary.

### 5.5 Runtime budget, and how the survivors feed the review

**Unit tier.**

- Today's weekly `mutants` covers about 1,600 mutants (core, profile and four camigrate files)
  in one job under `timeout-minutes: 300` (`reports.yml:63-71`). That is about 5–6 mutants a
  minute on a standard runner.
- The new unit scope of about 1,780 is about 5–6 h on one runner, so **4 shards of about 1.5 h**,
  plus each shard's build of the dependencies (about 15 min: `cargoArtifacts = null`, `:177`).
- A pull request's `--in-diff` unit run is 10–60 mutants: **5–20 min**.

**Token tier.**

- **No measurement is on record.** `mutantsOf` says only "minutes for each mutant no test
  catches" (`:105-107`).
- Estimate: 2–4 min per mutant. That is a rebuild of the mutated crate, its dependents and
  about 40 test binaries, then a nextest run that stops at the first failure. So about
  1,625 mutants are **55–110 runner-hours**:
  - a monthly full sweep in 20 shards takes 3–5.5 h each, within GitHub's 6 h job limit;
  - **a weekly full sweep is not affordable**, hence the weekly in-diff (§5.3).
- **L8's first task is calibration:** one CI run of `mutantsOf` over
  `crates/pkcs11/src/token/policy.rs` (66 mutants), recording the time per mutant. It sets the
  shard counts and the 120-mutant cap. If a mutant costs more than 4 min, the token scope
  narrows to `--re` on the functions that construct a `Check` or a `Rule`.

**The survivors feed the review.**

- The monthly sweep writes `missed.md`: the survivors grouped by file and function, each with
  the `Check`/`Rule` names that function constructs (a grep of its span) and its baseline
  status.
- REVIEWING.md changes. Today it asks for a hand mutation pass ("Do a mutation pass",
  REVIEWING.md:58-60); it does not yet say reviews start from survivors. Its "Running a review"
  becomes:
  - **Start from the survivors.** Read the last sweep's `missed.md` and the baseline's
    `reviewed = false` entries for the files under review. Each becomes one of three things: a
    test seen failing on the mutant, a finding (an unguarded decision), or a `why` marked
    `reviewed = true`.
  - Do the hand mutation pass only for code outside §5.1's scope.
- **The plan's measure.** "The surviving-mutant count falls release over release" is read from
  `max` and the badge.

## 6. Packages

**Verification commands.** These are the commands available here: no KVM and no local x86_64,
so VM checks and `x86_64-linux` stay `Not run:` and CI.

- **darwin:** `nix develop -c cargo test -p <crate>`. tpm2-pkcs11 and p11-fault are Linux-only.
- **Linux crane build with every token suite** (`fault`, `liars`, `tpm2` on swtpm):
  `nix build --option builders '' -L .#checks.aarch64-linux.cakeys`.
- **Pure checks:** `nix build -L .#checks.aarch64-darwin.<name>`, for `doc-references`,
  `ledger`, `test-count` and `ci-jobs`.

**Two rules that hold for every package.**

- Every before-test is seen red. It is run either at the parent commit or with the guarded
  decision mutated, and the red run is recorded in `Ran:`.
- Where Phase 1 already makes a row green, red means the Phase 1 fix reverted in a scratch
  commit.

### 6.1 The packages

| Pkg | What | Files (owned; no other package in the same wave touches them) | Before-tests (red first) | Verify |
|---|---|---|---|---|
| **L1** | p11-fault lie kinds (§1.1): `of_label` on `rv`; `nth`/`from`; `fn="*"` + `from_seq`; `wrap_label`; `replace_label`; `corrupt` on `C_WrapKey`; `transcode`; `replay_output`; `mechanism`/`class`/`key_type` matchers; `P11_FAULT_RECORD_VALUES=public`. ~+700 | `crates/p11-fault/src/{plan,hooks,forward,trace,lib}.rs`, a new `record.rs`; `docs/FAULT_SHIM.md`; `crates/cli/tests/fault.rs` (new tests only, appended) | p11-fault unit: each new key parses and is refused where it cannot apply (red today: "unknown field", `plan.rs:441`); `nth_counts_only_matching_calls`; `transcode_round_trips`; `record_values_refuses_secrets`. `fault.rs`: `each_lie_kind_fires`, one row per new kind on SoftHSM, asserting the trace shows it and its effect | `checks.aarch64-linux.cakeys`; `doc-references` |
| **L7a** | doc-references over Rust comments (§4.1); `nix/claims.py` with `max-unregistered = 100`; `docs/claims.toml` seeded with §8.1's existing tests. The 5 stale names go in a `KNOWN_STALE` set that only shrinks. ~+350 | `nix/doc-references.py`, `nix/doc-references-test.py` (new), `nix/claims.py` (new), `docs/claims.toml` (new), `checks.nix` (the `doc-references` command only) | fixture trees: a `///` citing `Type::gone` fails; an unregistered universal line over `max` fails; a register entry naming a missing fn fails | `checks.aarch64-darwin.doc-references` |
| **L8a** | mutants infrastructure (§5.2–5.4): the new `mutants` parameters, `mutantsDiff`, `mutants-gate`, `mutants.yml`. `reports.yml` loses `mutants` and `publish-mutants`. The gate runs in report mode until the baseline is seeded. Calibration: one `mutantsOf` run on `token/policy.rs`. ~+500 | `nix/package-crane.nix` (the `mutants` function only, `:108-197`), `flake.nix:136`, `nix/mutants-baseline.{py,toml}`, `nix/mutants-baseline-tests.py`, `.github/workflows/{mutants,reports}.yml`, `scripts/mutants-diff.sh` | `mutants-baseline-tests.py` (all red before; the script is new): an unlisted survivor fails; a listed one passes; a stale entry fails in sweep mode; the key survives a line shift; `--write` never raises `max`; duplicates get `#k` | the tests in the dev shell; `nix eval` of the derivations. Not run: `scripts/mutants-diff.sh` on a one-function diff (Linux builder, about 20 min), and calibration (CI) |
| **L2** | `cakeys_core::Check`, `Reason`, `KmError::check()`, `assert_fires`, and the `Outcome.rule` fallback (§1.3). All ~160 `Conflict`/`Ambiguous`/`PreconditionFailed` sites are classified. A grep test allows `Reason::malformed` only in the parse modules (`chain.rs`, `vendor.rs` parse, `esys.rs` unmarshal, `config/io.rs`, `keyfile.rs`). `lock_mbt.rs` drops `rule_of` for lock `Check` names. ~+450/−250 | `crates/core/src/{check.rs (new),error.rs,lib.rs,testing.rs}`; every `src/` file with such a site (core, pkcs11, camigrate, caprobe, ykcs11, tpm2-pkcs11, kmsp11, aws-cloudhsm); `crates/cli-common/src/`; `crates/core/tests/lock_mbt.rs`; `nix/test-count.toml` | `check_names_are_stable_and_disjoint_from_rules`; `a_refusal_row_names_its_check` (cli-common: a `HashMismatch` row has `rule = "identity.material"`; red: `None` today); `every_lock_rule_is_modelled_or_left_out` (red with one lock `Check` added and left out, and on A-6's suffix case); `malformed_only_in_parsers` | darwin `cargo test` for each crate touched; `checks.aarch64-linux.cakeys` (tpm2-pkcs11); `clippy` |
| **L3** | `common/state.rs`: `Snapshot`, `assert_unchanged`, `Workdir::refused`, `rows()`. xref's `objects()` and `state()` move into it. The oracle-count ratchet (§3.5). ~+350/−60 | `crates/cli/tests/common/{state.rs (new),mod.rs,xref.rs}`; `nix/oracle-count.{py,toml}`, `nix/oracle-count-tests.py`; `checks.nix` (one new check) | `a_refusal_that_changes_the_lock_is_caught`, `…_the_token_…` (harness, `should_panic`); the oracle-count fixtures: one more prose site fails, `--write` only lowers | `checks.aarch64-linux.cakeys` (harness, the twin unchanged); `checks.aarch64-darwin.oracle-count` |
| **L4a** | the liar runner, the lint (§1.4–1.6) and the cakeys table (~150 cells). The old lie table moves in. Also the invariants: `exit 22 ⟺ lock changed`, `check` changes nothing, and `a_lock_holds_no_token_output`. If the `ok.login` cells are red (§7), they get a session-state check after `C_Login`. ~+1,000/−150 | `crates/cli/tests/{liars.rs,liar_lint.rs}`, `crates/cli/tests/liars/cakeys.toml`, `crates/cli/tests/common/liars.rs` (new); `crates/cli/tests/fault.rs` (table removed); `nix/test-tokens.sh` (`liars` arm, untraced list); `nix/test-count.toml`; `crates/pkcs11/src/token/login.rs` (only if `ok.login` is red) | the lint, red with the `delete-kept` block removed; B-13 `ok.destroy` cells, red with P1 step 5's re-find reverted; `other.find`/`other.key`/`other.value` (C-6); `ok.login` (red is expected; see §7) | darwin `cargo test -p cakeys --test liar_lint`; `checks.aarch64-linux.cakeys`; `test-count` |
| **L6** | independent oracles (§3.1–3.3): the golden ledger kind; `golden-rows.py` plus its CI step; regeneration writes `.new` and needs `--accept`; property assertions for the object matrix and the software profiles; `every_regenerated_yes_says_by_whom`. ~+700 | `nix/ledger.py`, `nix/ledger-test.py`, `profiles/LEDGER.toml`, `checks.nix` (the ledger fileset gains `./spec-coverage`), `nix/golden-rows.py` and its tests, `.github/workflows/checks.yml` (`light`: `fetch-depth: 0` plus a step), `scripts/regen-profiles.sh`, `scripts/cloud/{aws,gcp}.sh`, the `CAKEYS_UPDATE_*` sites, the file holding P4's `caprobe regenerate`, `crates/cli/tests/object_matrix/{mod.rs,properties.rs}`, `crates/profile/tests/{answers.rs,properties.rs}` | the ledger fixtures: a golden change without a record fails, and so do a `"TODO"` why or a record naming an unchanged row; the golden-rows fixtures on two trees; `regenerate_never_overwrites_without_accept`; each property, red with its golden row flipped in a copy | `checks.aarch64-darwin.ledger`; `checks.aarch64-linux.cakeys`; `checks.aarch64-linux.profiles` |
| **L8b** | the mutants scope lists after Phase 1's renames (§5.1). The first full sweep seeds the baseline (CI). REVIEWING.md: "start from the survivors". DEVELOPMENT.md: the mutation section. `missed.md`. ~+150, plus the generated baseline | `nix/package-crane.nix` (the `mutants*` scopes, `:303-334`), `nix/mutants-baseline.toml`, `docs/REVIEWING.md`, `docs/DEVELOPMENT.md` (the mutation section only) | the gate's fixture test: a seeded baseline passes, and one new survivor fails | the sweep (CI, `workflow_dispatch`); `doc-references` |
| **L4b** | the camigrate and caprobe tables. **E-3's instance fix**: probe toward the imported `rsa-2048` fixture and decode on the host. **E-6's fix**: the mark is issued over the slot's key, and the guard compares SPKIs. The `Checked` constructor grep test. The software profiles are re-derived. ~+800 | `crates/camigrate/tests/{liars.rs,liars/}`, `crates/caprobe/tests/{liars.rs,liars/}`, `crates/caprobe/src/probe.rs` (`check_slot`, `mark_slot`), `crates/caprobe/src/probe/{moves,wraps}.rs`, the file holding P3's `Checked`; the verified-by profile files | D-5 `other.wrap` cells (red with P2 step 12 reverted); D-7 flag cells (red with P2 step 11 reverted); E-3 `blob.transcode` (red until the host decode); E-6 slot-mark (red until the SPKI compare); E-2 DEV pairs | `checks.aarch64-linux.cakeys`; `profiles`; `ledger` |
| **L5** | the attestation forgery kit (§1.7). Unit rows: B-11's two forgeries; B-12's other signer. Cells on swtpm: B-12's corrupt, blob, replay, secret-on-module and ek-on-module. The forged fixtures are generated by a committed script (openssl, dev shell). ~+500 | `crates/ykcs11/src/attest.rs` (test module only) and its fixtures directory; `crates/tpm2-pkcs11/src/attest/{vendor,esys}.rs` (`#[cfg(test)]` only); `crates/cli/tests/liars/tpm2.toml`; `crates/cli/tests/tpm2.rs` (one appended test that runs the table, so it is routed as `tpm2` already) | `a_slot_certificate_signed_by_another_key_is_refused`, `a_chain_longer_than_three_is_refused` (red with the call at `attest.rs:67-71` deleted: B-11's own experiment); each B-12 cell, red with its check at `vendor.rs:190-208` or `mod.rs:133-145,318-328` removed | darwin `cargo test -p cakeys-ykcs11`; `checks.aarch64-linux.cakeys` |
| **L7b** | doc edits per §4.2's table: §8.1 names its tests; the softenings; the 5 stale names fixed, so `KNOWN_STALE` is empty; the register fills; `max-unregistered` lowered. ~+300 docs | `docs/{DESIGN,CAMIGRATE,CAPROBE,CAKEYS}.md`, `docs/DEVELOPMENT.md:254-255`, `ISSUES.md`, `docs/claims.toml`, `nix/doc-references.py` (the set only); comment lines in `camigrate/src/{file,keyfile}.rs`, `ykcs11/src/lib.rs`, `pkcs11/src/{provider,token/generate,token/policy}.rs` | the claims rule "every §8.1 bullet names a test", red on today's §8.1 | `checks.aarch64-darwin.doc-references` |
| **L9** | the ykcs11 persona (§2.2–2.4): `nix/persona.py`, the recording and its ledger entries, `persona.rs` (T0), verifier tests on the recorded chain, and caprobe's refusal of `--out` into `profiles/modules/` for a persona. Needs a **T2 session by the user** (scratch slots 90–95, `CKA_ID` 13–18). ~+600, plus the recordings | `nix/persona.py` and its tests, `profiles/personas/ykcs11/**`, `profiles/LEDGER.toml` (new entries), `crates/cli/tests/persona.rs`, `nix/test-tokens.sh` (a `persona` arm), the ykcs11 verifier tests, caprobe's `--out` guard, `docs/PERSONAS.md` (new) | `a_persona_probe_cannot_write_a_hardware_profile`; the persona scenario's rows equal the recording's (red with the derived plan emptied) | `checks.aarch64-linux.cakeys`; `ledger`. Not run: the recording (T2) |

### 6.2 Order (at most 4 at once; the files are disjoint within a wave)

```text
A  now, beside Phase 1:      L1   L7a   L8a
B  after Phase 1 merges:     L2   L3            (L2 is the only package editing src/ in B)
C  after L2 and L3 (+L1):    L4a  L6    L8b
D  after L4a:                L4b  L5
E  after L4b, L5, L6:        L7b  L9            (L9 also needs the user's T2 session)
```

- **The critical path** is Phase 1 → L2 → L4a → {L4b, L5} → L7b.
- **Wave A rules.** Wave A touches no file Phase 1's design names (phase1-design.md §5 file
  columns), with two exceptions:
  - `crates/cli/tests/fault.rs`: L1 only appends to it.
  - **P2 step 12's before-test** ("p11-fault substitutes `C_WrapKey` output",
    phase1-design.md:213) **needs L1's `wrap_label`**. p11-fault cannot do it today
    (`forward.rs:188` substitutes the wrapping key). So L1 merges before P2 step 12, or P2
    takes `wrap_label` and L1 drops it.
- **Shared manifests.**
  - L2 and L4a both edit `nix/test-count.toml`, in different waves.
  - `checks.nix` is edited by L7a (A), L3 (B) and L6 (C): one per wave.

## 7. Risks and cost

1. **A plausible new finding, worth one run now (`ok.login`).**
   - `C_Login` can answer `CKR_OK` without logging in. `rv` before works today, so no L1
     change is needed.
   - The session stays public, and private objects become invisible to `C_FindObjects`.
   - `rg 'get_session_info|SessionState' crates/pkcs11/src` finds nothing, so cakeys never
     checks the session state.
   - If `delete` or P1's re-find reads "not found" as "gone", the lock entry is dropped: a
     B-13 sibling that P1 step 5's re-check would not catch, because the re-check also runs in
     the public session.
   - This is unverified. The first L4a cell settles it, or it can be run as a one-off test
     before wave A.
2. **L2 is the riskiest package.**
   - About 160 sites are classified by hand.
   - A security check wrongly marked `malformed` vanishes from the lint. The parser-only
     grep test bounds this but cannot judge.
   - Every in-flight branch that constructs `KmError` conflicts with it, so it must land
     right after Phase 1 merges and before anything else touches `src/`.
   - Cost: about 1–2 days of careful work, plus review of the classification list in the
     commit body.
3. **The table can be tautological (T-TAUTO).** If expectations are copied from today's
   behaviour, the matrix pins bugs.
   - Mitigation: every block's expectation is a `Rule`/`Check` name taken from the spec, never
     an observed exit.
   - Each block is added red-first.
   - The honest run before the cells proves a refusal is the lie's.
4. **`nth`-based lies are brittle.** A refactor that changes the call order makes the lie hit
   another call.
   - The `fired` and `rule` oracles make most such drift loud. The table prefers `of_label`.
   - `nth` stays only for CHANGE lies, which need it.
5. **The runtime is estimated, not measured.**
   - Matrix: 2–3 min of added wall time, dominated by caprobe cells (tens of seconds each). If
     that is exceeded, add caprobe `--only`.
   - Mutants token tier: 2–4 min per mutant is a guess. L8a's calibration decides the shards
     and the 120-mutant cap.
6. **The GitHub budget.**
   - Unit-tier PR gate: 5–20 min per PR.
   - Weekly in-diff: a few hours.
   - Monthly full sweep: about 6 runner-hours for the unit tier, plus 55–110 for the token tier.
   - **If the repository is private, the monthly token sweep exceeds the included minutes. Only
     the unit tier and the weekly in-diff fit.**
   - Twenty shards also fill the free plan's 20-concurrent-job limit, so the sweep is
     scheduled at night.
7. **A seeded baseline is weak at first.**
   - "May only shrink" from a large seed (size unknown until the first sweep) protects only
     new code.
   - Its value comes from REVIEWING.md's "start from the survivors" being followed. That is a
     process risk, not a code one.
8. **Personas could launder a software run into a hardware profile (E-7).** Mitigation: the
   `+persona` marker, and caprobe's refusal to write it into `profiles/modules/`.
9. **L7a fails Phase 1 branches** that add backticked comment names which do not resolve.
   This is intended, and cheap to fix on rebase, but it is friction while Phase 1 is open.

**Total cost estimate.**

- About 6,000 lines added, over 12 packages and about 3–4 weeks of serial agent work,
  waves A–E.
- About 3–6 runner-hours a week, plus a monthly sweep.
- One T2 session of the user's for L9.

## 8. What to cut or change

- **Cut item 10 as written.** Byte replay cannot pass PoP or TPM certify without a nonce seam
  in security code, and it would then go silent exactly when the conversation changes (§2.1).
  - Replace it with quirk personas plus recorded public attestation as verifier fixtures
    (§2.2).
  - Defer even that (L9) until after the matrix. Only ykcs11 is worth it now. CloudHSM and KMS
    personas are cut.
- **Cut the weekly full token-tier mutants sweep.** It cannot be afforded: make it monthly,
  with a weekly in-diff. Do not sample in the PR gate.
- **Downgrade the golden "rows listed" check** (§3.3). It is a process control with moderate
  value. If time is short, do the property assertions and the `.new`/`--accept` regeneration,
  and drop `golden-rows.py`.
- **Do not target C-9's "39 of 131".** The number moves with its definition (12–22 by this
  design's script). Ratchet prose assertion sites instead (284 at `f3b8e5e`).
- **Not honest to test, so soften instead:**
  - "plaintext zeroized after use";
  - "never touches PIV data objects";
  - "`create` is the one verb that writes keys", across tools.
- **Not modelled:** hangs (there is no per-call timeout to test).
- **Change Phase 1 if it is still open:**
  - Put `Rule` in core beside `Check`, so there is one namespace.
  - Make P2 step 12's before-test depend on L1's `wrap_label`, or move `wrap_label` into P2.
  - Add the `ok.login` case to P1 step 5's K-5 contract row, if the one-off run is red.
- **The 480-point completeness grid** is kept only because wildcard `na` rows make it cheap.
  The lint that every `Check` has a firing cell (§1.6) is the part that pays.

## Lead decisions (2026-11-25)

1. **The designer's cuts are accepted.**
   - Item 10 becomes quirk personas built from traces, with recorded public attestation as
     verifier fixtures and recorded verdicts as the oracle. ykcs11 only, and last (L9). The
     CloudHSM and Cloud KMS personas are cut. Byte replay is not attempted.
   - The token-tier mutation sweep runs monthly in shards, with `--in-diff` weekly and nothing
     sampled in the PR gate.
   - The golden-change listing check is optional; the property assertions are the fix for C-8.
   - Prose assertions are ratcheted, with no numeric target from C-9.
   - The three claims are softened: plaintext zeroization, PIV data objects, and the one writer
     across tools.
2. **The repository is public**, since the CI API answers without authentication. GitHub's
   standard runners cost no minutes, so the monthly sharded sweep fits.
3. **The `C_Login`-without-effect lie** (risk 1) goes to Phase 1 P1 step 5. There, cakeys
   checks the session state after each login, and the shim's lie is the before-test.
4. **Wave A (L1, L7a, L8a) starts beside Phase 1.**
   - L1's `wrap_label` is a prerequisite of P2 step 12.
   - L7a and L8a touch no Phase 1 file.
   - L8a calibrates on the unit tier locally. Its token-tier timing comes from CI.
5. **`Rule` stays in pkcs11 for Phase 1** (P1 is implementing it there). L2 decides whether to
   move it into core beside `Check`, as one mechanical step.
6. **L9 needs one T2 session with the user's YubiKey, on scratch slots 90–95 only.** It is
   scheduled with the user, never run unattended.
