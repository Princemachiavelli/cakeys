# Phase 1 design: put rules where they cannot be skipped

Status: design, not built. Repo at `bbf159b` (branch `review-2026-11-24`). Every `path:line` is
at that commit. Inputs: REVIEW-2026-11-24.md (Phase 1, items 5–8), A.md–F.md, the code.

Conventions:

- Exit codes are those of `cakeys_core::EXIT_CODES` (`core/src/error.rs:210`).
- "Before" tests are tests over the *rule* that fail on `bbf159b` and pass after the step.
- Line counts are estimates (+added / −removed, tests included unless said).

## 1. Item 5: one plan-then-execute path per operation

### 1.1 Inventory: operations that write, and every entry path

| Operation (what it writes) | Real run | Dry run / gate | Other entries |
|---|---|---|---|
| cakeys `create` (key objects; lock, 22) | `cli/src/lib.rs:610-679` → `planner::plan_create` → `create_selected` → `ops::create` (`ops/mod.rs:512-534`) → `create_absent` (`:393-461`) → `Provider::create` | `create --dry-run`: `plan_create` only, **static, no token opened** (`planner.rs:132-178`); `validate` (`cli/src/lib.rs:529-608`): `gate::stack` + `gate::check` | `--no-update-lock` (creates, no record); caprobe `Made::create` (scratch, own path) |
| cakeys `lock` (lock, 22) | `ops::lock` → `lock_as` (`check_capabilities(Verb::Lock)` + resolve + reconcile, `ops/mod.rs:367`) | `lock --dry-run`: compare only (18 on first use) | `ops::lock_import` (camigrate, after every import, `ops/mod.rs:347`) |
| cakeys `delete` (destroys objects; lock, 22) | `ops::delete` (`ops/mod.rs:571-637`) → `destroy_identified` → `Provider::destroy` → `Token::destroy_plain` (`token/generate.rs:244-260`) | `delete --dry-run`: `WouldDelete` after If-Match, **before the login guard** (`:618`) | camigrate `roll_back` (`destroy_handles`, `public.rs`); caprobe scratch cleanup |
| cakeys `gc` (lock) | stale entries removed | `gc --dry-run` prints | — |
| cakeys `check` (nothing, but its 11/16 is the delete guard's twin) | `resolve`/`verify` | — | — |
| camigrate `migrate` (target objects; lock) | `lib.rs:774-862`: per method `host::import_ptool`, `tokens::transport`+`sealed::export`+`sealed::import`, `host::import`, `public::import` (catch-all `:843`) | `--dry-run`: `specs_import` → `plan_moves` → `landing::block` (`lib.rs:362-367`) | — |
| camigrate `export --to <tok>` (bundle file) | `export` (`lib.rs:614-687`) | `plan_moves` with `partial` (`lib.rs:395-444`, `:598-605`) | — |
| camigrate `export --to-transport-file` (bundle file) | `export`, key from `tokens::pinned(lock, t, …)` using **the file's** `t.token` (`:665-670`) | `plan_moves`; `Dest::token()` is `None` (`tokens.rs:497-502`) | — |
| camigrate `export --to-key-file` (plaintext key file) | `file_verbs::export_file` (`:15-56`), **no identity check** | `plan_moves` | — |
| camigrate `import --in <bundle>` (target objects; lock) | `import` (`lib.rs:693-765`) → `sealed::import` (`sealed.rs:363`) / `public::create` | `sealed::preflight` + `landing::import_checks` | — |
| camigrate `import --key-file` (target objects; lock) | `file_verbs::import_file` (`:88-198`) → `host::create_and_record` | `already_there` + `free_locator` + `import_checks` | — |
| camigrate `import` (files, no `--in`) | `import_files` → `from_its_file` (`:333-433`) | `free_locator`/`preflight` + `import_checks` | — |
| camigrate `transport --out` (transport file, 0o644) | `tokens::transport` → `Transport::new` (size rule) | — | `Transport::parse` (size rule) |
| camigrate `transport --trusted` (CKA_TRUSTED copy) | `trust` (`lib.rs:999-1027`) → `create_trusted_copy`, **no size rule** | — | — |
| PIV import (method, not a verb) | `host::import` with `PlaintextVia::PivImport` | as migrate/import | — |
| caprobe `probe` (scratch objects; profile file) | every probe writes and destroys on scratch | — | the profile it writes is item 6 |

### 1.2 Rule × path table (today)

D.md's table (`D.md:277-290`) is kept as is; below it is extended to cakeys' verbs and to the
rules B-1, B-2, B-4 and B-13 name. Y = enforced before the write; **N** = skipped (finding);
`post` = only after the write; `—` = no such step.

| Rule (exit) | `create` | `create --dry-run` | `validate` | `lock` | `delete` | `delete --dry-run` | camigrate (see D.md) |
|---|---|---|---|---|---|---|---|
| placement (17) | ykcs11 only, through its `create` override (**B-2**) | only if the stack resolves statically (**B-1**) | same (**B-1**) | — | — | — | `migrate --dry-run` **N** (D-2) |
| attestation cover (15/14) | Y (`check_capabilities`) | Y if stack resolves | Y if stack resolves | Y | — | — | Y |
| imported attestation (15) | — | — | — | — | — | — | Y; transport file **N** (D-4) |
| own generation (15) | Y | Y if resolves | Y if resolves | — | — | — | — |
| templates / unprovable (15) | Y | Y if resolves | Y if resolves | — | — | — | Y; transport file **N** (D-4) |
| locator free (13) | Y (`find_any`, `:433`) | **N** (static) | — | — | — | — | `migrate --dry-run` **N** (D-3) |
| unpinned key exists (19) | Y (`:517`) | **N** (static) | — | — | — | — | — |
| needs login (16) | by class only (**B-4**, `:413`) | — | — | — | by class only (**B-4**, `:618`) | **N** (returns before the guard) | `file_verbs.rs:345` re-derives it (fail-open) |
| If-Match (14) | — | — | — | — | Y | Y | — |
| delete really removed (16) / `delete.<class>` row (15) | — | — | — | — | **N** (**B-13**) | **N** | `roll_back` same |
| transport key bound to target | — | — | — | — | — | — | file's token (D-1), any object (D-8), no size (D-10) |
| identity before plaintext leaves | — | — | — | — | — | — | `hand_over` only; key file and secret keys **N** (D-5) |
| unknown flag is restrictive | — | — | — | — | — | — | **N** (D-7) |
| empty / unnamed export (15) | — | — | — | — | — | — | 15 real, 0 dry (D-6) |

Count: 9 rules are asked at 2–4 places each by hand; 12 cells are **N**.

### 1.3 Type design

Principle, in the repo's idiom (the `Planned`/`Action` of `planner.rs`, the `Plan` row of
`camigrate/src/plan.rs`): one function builds the plan and calls every rule; the write takes
only a value that function made; `--dry-run` prints the plan. Plan rows stay `Serialize`.

**pkcs11: rules with names** (new `crates/pkcs11/src/ops/rules.rs`):

```rust
// One name per rule; ALL and name() from a macro, as pkcs11_names! does (core/types.rs).
pub enum Rule { Placement, AttestationCover, ImportedAttestation, OwnGeneration, Templates,
                Capability, LocatorFree, UnpinnedExists, PinnedLost, NeedsLogin, IfMatch,
                DeleteRefused, DeleteKept, LockWritable }
pub struct Refusal  { pub rule: Rule, pub error: KmError }   // the exit comes from error
pub struct Deferred { pub rule: Rule, pub why: String }      // only the write can decide
pub enum Seat<'a> { Resolved(&'a dyn Provider), Unresolved(String) } // provider not known yet

/// Placement, attestation cover, imported attestation, own generation, templates, profile
/// verdicts. An Unresolved seat turns each provider rule into a Deferred, never into silence.
pub fn static_rules(t: &Target, seat: Seat, eff: Option<&Effective>) -> (Vec<Refusal>, Vec<Deferred>);
/// Locator free, unpinned exists, pinned lost, needs login, mechanisms listed. Same fn at plan
/// time and as the write's race recheck.
pub fn token_rules(t: &Target, tok: &Token, lock: &Lock, verb: Verb) -> Result<Vec<Refusal>>;
```

Callers of `static_rules`: `gate::check` (`gate.rs:132`), `check_capabilities`
(`capabilities.rs:260`, today without placement), the static half of `check_import`
(`capabilities.rs:158`, D.md's D-2 split), camigrate's `landing::block`, and `Token::create`
before it dispatches to `Provider::create` (B-2). B-1's second half: `gate::stack` failing
(`gate.rs:36-83`) yields `Seat::Unresolved`, so `validate` prints
`deferred: placement (provider resolves when the token opens)`, not a free-text note.

**pkcs11: the cakeys plan** (`planner.rs`, extended, not replaced):

```rust
pub struct Planned<'a> { spec, token, object, pub action: Action,
                         pub refusals: Vec<Refusal>, pub deferred: Vec<Deferred>, pub notes: Vec<String> }
pub enum Action { Create, Verify, Skip, Delete { handles: Vec<ObjectHandle> }, Refuse }
pub struct Ready<'p, 'a>(&'p Planned<'a>);       // private field: only Planned::ready() makes one
impl Planned<'_> { pub fn ready(&self) -> Option<Ready<'_, '_>> /* no refusals */ }
pub fn plan_create(..) -> Result<Vec<Planned>>;  // static_rules + token_rules when a token opens
pub fn plan_delete(..) -> Result<Planned>;       // find, ids, If-Match, NeedsLogin, DeleteRefused
pub fn execute(tok: &Token, r: Ready, lock: &mut Lock) -> Result<Outcome>;
```

- `execute` reruns `token_rules` (same function, a race check), then writes.
- `execute` for `Delete` re-finds the locator after `Provider::destroy`. Anything left is
  `DeleteKept` (16) and the lock keeps the realisation (B-13).
- `plan_delete` refuses up front (15) when the resolved profile answers `delete.<class> = no`.
  That row's first consumer.
- `create --dry-run` opens the token read-only when it can, as `delete --dry-run` and
  `lock --dry-run` already do. `validate` stays the no-token path; its rows list token rules as
  `deferred`.
- `Target::needs_login()` (core `plan.rs`, B-4) is the one answer to "is this object visible
  only after login".
  - Order: the lock's observed `CKA_PRIVATE`, then the spec's, then the class.
  - Unknown on a data object counts as private (fail closed, §2.2).
  - Used by `create_absent`, `delete`, `resolve`/`check` and camigrate `file_verbs.rs:345`.

**camigrate: one planner** (`landing.rs` becomes it; `plan.rs`'s `Plan` row is unchanged on the wire):

```rust
pub(crate) struct Move<'a> {
    pub row: Plan,                         // object, method, exposure, ready, reasons, notes: what --dry-run prints today
    pub src: Option<Target<'a>>, pub dst: Option<Target<'a>>,   // dst None only for a key file
    pub transport: Option<BoundTransport>, // §2.1: bound via the lock to dst's token
    pub occupied: Option<Occupied>,        // free_locator, when the target is open
    pub identity: IdentityCheck,           // BeforeWrite (host paths) | AfterUnwrap (deferred) | Public
    pub deferred: Vec<Deferred>,
}
pub(crate) struct Moves<'a> { moves: Vec<Move<'a>>, verdict: Verdict }  // one verdict fn: D-6
pub(crate) fn plan(run: &Run, req: &Request, dest: &Dest) -> Result<Moves>;   // every rule
pub(crate) fn execute(run: &mut Run, ready: ReadyMoves) -> Tally;         // one loop driver: D-9
```

- Every verb is `plan`, then `execute` unless `--dry-run`. That covers migrate, the three
  exports, the three imports and `transport --trusted`.
- `plan` calls:
  - `plan::plan` (material rules)
  - `ops::rules::static_rules` (placement: D-2)
  - `tokens::template_refusal`
  - `free_locator` when the target is open (D-3)
  - `BoundTransport::from_lock`/`from_file` (D-1, D-8, D-10)
  - the identity requirement (D-5)
- `Dest::Transport` carries the target token the operator named, so landing rules run on its
  `Side` (D-4).
- Execution functions (`host::import`, `sealed::import`, `public::create_as`,
  `file_verbs::*`) take `&ReadyMove` and drop their own `check_import`/`free_locator` calls.
  - `ReadyMove::recheck(tok)` calls the same functions again (race check).
  - So no rule has a second copy.

**What is not a rule, and stays in execute:** the write itself, rollback, lock save. A test
enforces this (§1.4 T-5): grep that `check_import|free_locator|check_identity|placement(`
appear only in `rules.rs`, `landing.rs` and `trust.rs`.

### 1.4 The exact dry-run twin oracle

Today: `dry 0 → real ∈ {0,22,10,13}` plus a stderr match for 16 (`cli/tests/common/xref.rs:136-150`), camigrate only (`:176`).

New oracle, per object, on machine-readable rows (one serde `Outcome`, C-1):

```text
real_row.exit == dry_row.exit                       (22 normalised to 0)
  or real_row.rule ∈ dry_row.deferred               (the dry run said it could not decide this)
  or real_row.device == true                        (rv::device_failed, §2.5)
```

- The process exit then follows from the rows (0/22, the one refusal, or 20).
- The admitted set stops being a hand list. A dry run admits a difference only by naming the
  rule it deferred.
- Deferred rules today:
  - identity after unwrap (10)
  - blob unwraps (13, or 16 "damaged")
  - a capability whose profile answer is unknown or `by = unverified` (§2.3)
- `Outcome` gains `rule: Option<&'static str>` (`Rule::name`) and `device: bool`. The 16 that
  stderr matches today becomes a row field.

Tests:

- **T-1, the oracle itself** (unit test in `xref.rs`). Synthetic row pairs:
  - dry ready / real refused by a non-deferred rule → fail
  - real refused by a deferred rule → pass
  - device → pass
  - dry refused X / real refused Y → fail
- **T-2, it fails before.** Run the new oracle at `bbf159b`. `camigrate/tests/dry_run.rs:2138`
  (D-3: dry 0, real 13 `LocatorFree`) fails, and so do D-2 and D-6. A ykcs11 stand-in pair is
  needed for D-2; `tests/from_files.rs` has the pattern.
- **T-3, cakeys twin.** The twin also runs before cakeys `create`, `delete`, `lock` and `gc`.
  The same "nothing changed" check applies (lock bytes + `pkcs11-tool --list-objects`), which
  closes C-4.
- **T-4, rule × path matrix.** New `cli/tests/rules.rs` and `camigrate/tests/rules.rs`.
  - Each walks `Rule::ALL` with a `match` that has no wildcard, so a new rule without a case
    fails to compile.
  - Each case runs every entry path of §1.1 that can meet the rule and asserts the same exit
    and `rule` name: dry, real, `validate` (or `deferred` there).
- **T-5** (source check in `checks.nix`'s `ci-jobs` style, ripgrep): the rule calls appear only
  in the planner files.

### 1.5 Migration order (each step green; smallest first)

| # | Step | Files | +/− | Before-test (fails at `bbf159b`) |
|---|---|---|---|---|
| 1 | `Rule`, `Refusal`, `Deferred`; `static_rules` extracted from `gate::check`; `check_capabilities`, `check_import` call it | pkcs11 `ops/rules.rs` (new), `gate.rs`, `ops/capabilities.rs` | +140/−70 | `cli/tests/rules.rs`: a placement-only test provider (no `create` override) refuses on `create` (B-2) |
| 2 | `Token::create` runs static facts and `managing` before `Provider::create`; ykcs11 drops its own `placement` call | `token/generate.rs`, `provider.rs`, `ykcs11/src/lib.rs` | +30/−20 | same, `manages_as_so` half |
| 3 | `Seat::Unresolved` → `deferred` rows in `validate` / `create --dry-run` | `gate.rs`, `planner.rs`, `cli/src/lib.rs` | +50/−25 | `validate` on a ykcs11 stand-in without `provider` lists `placement` (B-1) |
| 4 | `core::known` (§2.2) + `Target::needs_login`; delete / create / check use it | core `known.rs` (new), `plan.rs`, `config/mod.rs`; `ops/mod.rs` | +110/−30 | private data object without PIN: `delete` 16, lock kept; `identity.rs:732` oracle flips to 16 (B-4) |
| 5 | `plan_delete` / `execute` with re-find and `delete.<class>` | `ops/mod.rs`, `cli/src/lib.rs` | +90/−40 | p11-fault `C_DestroyObject` → `CKR_OK` without forwarding: `delete` 16, lock kept; swtpm profile → 15 (B-13) |
| 6 | `create --dry-run` opens the token; `token_rules`; `Ready` | `planner.rs`, `ops/mod.rs`, `cli/src/lib.rs`, docs/CAKEYS.md | +120/−50 | twin on `create` with an occupied locator: dry 0 vs real 13 |
| 7 | `Outcome` row (`rule`, `device`), cakeys side | cli-common, `cli/src/lib.rs` | +70/−45 | T-1 |
| 8 | camigrate `trust.rs`: `Claimed`, `BoundTransport` (§2.1) | camigrate `trust.rs` (new), `transport.rs`, `tokens.rs`, `lib.rs`, `landing.rs` | +170/−90 | swapped genuine transport file (D-1); bundle naming another realised object (D-8); `trust` on a 1024-bit key (D-10) |
| 9 | `landing::block` → `static_rules` + `free_locator`; `Dest::Transport` gets its token | `landing.rs`, `tokens.rs` | +60/−30 | D-2, D-3, D-4 twins (T-2) |
| 10 | one verdict over `Moves` (`partial`, `ready`, "nothing can go") | `tokens.rs`, `lib.rs` | +40/−45 | unnamed export, all kept home: dry 15 (D-6) |
| 11 | `Known` in `Material` / `Side` (§2.2) | `plan.rs`, `side.rs`, `tokens.rs`, `file_verbs.rs` | +100/−60 | lock without `CKA_PRIVATE` on a data object: never `public` (D-7) |
| 12 | `Extracted` → `check_identity` → `Checked` (private and secret) | pkcs11 `token/host.rs`; camigrate `host.rs`, `file_verbs.rs` | +80/−35 | p11-fault substitutes `C_WrapKey` output: key-file export 10 (D-5) |
| 13 | one `execute` loop; rows survive 21 and key-file refusals | `lib.rs`, `file_verbs.rs`, `host.rs` | +90/−130 | 21 path keeps the per-object JSON (D-9) |
| 14 | exact twin oracle; twin on cakeys verbs | `cli/tests/common/xref.rs` | +90/−25 | T-1, T-2, T-3 |

Steps 1–7 are cakeys (package P1); 8–14 are camigrate (P2, after P1). Step 14 last: each rule
enters the plan first, then the oracle stops admitting its exit.

## 2. Item 6: types for trust and knowledge

### 2.1 `Claimed<T>` → `Verified<T>` (D-1, D-8, D-10)

Generic `Verified<T>` in core would be forgeable: core cannot keep the constructor from
camigrate. So the types are crate-local, with their checks in one file:

- **`camigrate/src/trust.rs`** (new):
  - **`Claimed<T>(T)`**, from `Transport::parse` and `Bundle::parse`. Its only accessor is
    `unverified(&self) -> &T`, for messages.
  - **`BoundTransport`**, with private fields:
    - `spki`, `object`, `token`, `rfc7093m4`.
    - Constructors: `from_lock(cfg, lock, token)` and
      `from_file(Claimed<Transport>, cfg, lock, to: &str)`.
    - Both run one `check`: RSA, `check_transport_size`, `CKA_UNWRAP`, non-extractable read
      as `Known` (fail closed; today `transport_fault`'s `is_true` passes an absent
      `CKA_EXTRACTABLE`, `tokens.rs:745`).
    - `from_file` requires the operator's `--to` (D-1's instance fix). The file's
      `rfc7093m4` must be the lock's realisation of the transport spec on `to`, and
      `t.token == to`.
- **Users:**
  - `export --to-transport-file`: `from_file`, D-1.
  - `import`: `from_lock(to)`, and the bundle's `transport` must equal it, D-8.
  - `trust`: `from_lock`, D-10.
  - `transport --out`: `from_lock`.
  - `pinned` and `locked_transport` disappear into it.
- **Bundle `target`** (D-1's "name the target"): the bundle gains `target = "<token>"`,
  checked by `import` against `--to`. This is a **format change** (`Bundle` is
  `deny_unknown_fields`). Bump the bundle version, and read version 1 without `target` as
  `Claimed` with a warning.
- **D-5 (pkcs11):**
  - `Token::extract` (`token/host.rs:26`) returns `Extracted` (private field). Today it
    returns `Zeroizing<Vec<u8>>`.
  - `check_identity` moves from camigrate `host.rs:70` to pkcs11 `ops`, as
    `check_identity(t, lock, Extracted) -> Result<Checked>`, covering secret keys too.
  - `hand_over`, `export_file` and `create` take `Checked`.

### 2.2 `Known` (tri-state) for restrictions (D-7)

Name: camigrate already has `tokens::Known` (`tokens.rs:528`: where a side's capabilities came
from). Rename that one to `tokens::KnownFrom` (14 mentions, all in `tokens.rs`) and use `Known`
for the tri-state, in core (`core/src/known.rs`, new):

```rust
#[must_use] pub enum Known<T> { Is(T), Unknown(Why) }       // no Default, no From<Option<T>>, no unwrap_or
pub enum Restriction { Private, Sensitive, WrapWithTrusted, NeverExtractable, AlwaysSensitive }
pub enum Permission  { Extractable, Unwrap, Decrypt, Derive, Trusted }
impl Known<bool> { pub fn restricts(&self) -> bool /* Is(false) only → false */;
                   pub fn permits(&self)   -> bool /* Is(true) only → true  */; }
// Spec, Material, Immutables: fn restricted(Restriction) -> bool; fn permitted(Permission) -> bool;
// fn flag(name) -> Known<bool> kept for display only.
```

Sites on bbf159b (non-test source, `rg`):

- **Raw counts:**
  - `Option<bool>`: 28.
  - `== Some(true)`: 15. `!= Some(true)`: 7. `== Some(false)`: 7. `!= Some(false)`: 3.
  - `unwrap_or(true|false)`: 0.
  - `== Some(&AttrValue::Bool(true))`: 2.
- **On a security attribute: 22.**
  - **Fail-open, the bugs (6):**
    - `camigrate/src/plan.rs:121`: `CKA_PRIVATE`, data planned public.
    - `camigrate/src/plan.rs:143`: `CKA_WRAP_WITH_TRUSTED`.
    - `camigrate/src/file_verbs.rs:345`: `CKA_PRIVATE`.
    - `core/src/config/mod.rs:340`: `secret_material`, undeclared private data = not secret.
    - `camigrate/src/tokens.rs:745`: transport `CKA_EXTRACTABLE` absent passes.
    - `camigrate/src/tokens.rs:787`: `CKA_DECRYPT` unknown gives no warning (a warning only).
  - **Fail-closed already (9):** keep the behaviour, change the type.
    - `camigrate/src/plan.rs:137` (×2).
    - `core/src/plan.rs:187,199,207,215`.
    - `core/src/config/check.rs:138` (×2).
    - `core/src/config/lock.rs:467`.
  - **Declarations, where unknown means "not declared" (7):** leave as `Spec::flag`, each
    with a comment saying so.
    - `core/src/plan.rs:106,179,334,378`.
    - `core/src/config/check.rs:248`.
    - `kmsp11/src/lib.rs:268` (×2).
- **Capability optimism (the D-7 sibling):**
  - `Side::pkcs11` (`side.rs:146-167`) sets every capability to yes for a module with no
    profile.
  - `derive_sealed: Option<bool>`.
  - `ecdh_seals` (`capabilities.rs:38`).
  - `pkcs11/src/token/possession.rs:416`: `unwraps != Some(false)`, unknown = yes.
  - These become `Known<bool>`. The planner turns an Unknown into a `Deferred` rule (§1.4),
    never a yes.

Before-tests:

- A `Material` with an empty policy is planned `sealed` or refused, never `public`
  (`plan.rs` unit test).
- `secret_material` of an undeclared data object is true.
- A transport key without `CKA_EXTRACTABLE` is refused.

Guard: a `ci-jobs`-style ripgrep check.

- `flag\("CKA_(PRIVATE|SENSITIVE|EXTRACTABLE|WRAP_WITH_TRUSTED|NEVER_EXTRACTABLE|ALWAYS_SENSITIVE)"\)`
  must appear only in `known.rs`.
- `== Some\((true|false)\)` must not appear on a line naming `CKA_`.

### 2.3 Provenance on probe rows (E-2, E-4, E-5)

Row today: `{ answer, evidence, via }` (`profile/src/capability.rs:542`). New optional field `by`:

| `by` | Meaning | Allowed with |
|---|---|---|
| `module` | the module returned a `CK_RV` that is not device-failed (§2.5) and not `CKR_OPERATION_ACTIVE` | `no` only |
| `host` | cakeys decoded/verified the result itself (signature verified, unwrapped key compared) | `yes` |
| `unverified` | the module said `CKR_OK`; nothing outside it checked (E-3/E-4: one-module round trip) | `yes` |
| *(absent)* | legacy, provenance unknown (§2.4) | either |

- **Not written as rows.** Cakeys-refused (provider or host refused before the module was
  asked; E-2's "no Ed448 signature verifier") and device-failed refusals write no row. They
  become an `[untested]` line naming why.
- **One classifier.** caprobe gets
  `enum Refusal { Module(Rv), Busy, Device(Rv), Host(String) }`, built once by
  `Refusal::of(&KmError)` (E-2's class fix).
- **The writers are typed.** `Draft::set` (`caprobe/src/probe.rs:341`) splits into
  `set_no(cap, ModuleRefusal)` and `set_yes(cap, Checked)`, so the compiler names all 49
  writing sites: 27 `Answer::No`, 16 `Answer::Yes`, 6 `Answer::of`.
- **E-5.** A `ModuleRefusal` carries the `Capability` whose input was refused. `set_no`
  refuses (debug assert plus a test) a refusal produced for another input: "a refusal of X may
  not answer for Y".
- **Consumers:**
  - `Effective` reports `Yes{by: unverified}` in its note.
  - camigrate's `Side` turns `unverified` `export.sealed.*` / `unwrap.*` into a `Deferred`
    (§1.4), E-3.
- **A-9.** `Effective::commit` (`effective.rs:248-256`) answers Unknown for a length never
  tried. One `decide_size(rows, n)` decides that.

Before-tests:

- `caprobe/tests/fault.rs:211-220` flips: `CKR_DEVICE_ERROR` on every `C_UnwrapKey` gives no
  `wrap.rsa-oaep.*` row, and an `[untested]` line instead.
- `template_hook.rs` refuses `Import`, `PublicHalf` and `Object` too, and asserts no `no` rows
  (today only `Generate`, `:87-96`).
- A p11-fault sweep: error at every call, each in turn. It asserts that no row's `by=module`
  comes from a device-failed rv (F R4).

### 2.4 Profile schema change, and the committed profiles

- **Loading.**
  - `by` is optional, so every committed file loads.
  - A row without `by` loads as `Provenance::Legacy`. `caprobe supports` and gate notes show
    it as "legacy, provenance unknown".
  - Legacy rows decide as today, with one load rule: a legacy `no` whose `evidence` names a
    device-failed `CKR_*` (the §2.5 list, from the item-8 table) loads as **no row**
    (unknown), and the load notes it.
  - This is deterministic and testable, and no hardware file is edited by hand (E-7).
- **Writing.** New probes always write `by`.

| Profile | Re-derived by | Effect |
|---|---|---|
| softhsm/2.7 | re-probed per build, byte-compared (`caprobe/tests/reference.rs:13`) | regenerate on Linux in the same change (`scripts/regen-profiles.sh`); gains `by` on every row; `:134` Ed448 `prove.pop-sign` `no` (cakeys' own limitation) disappears into `[untested]` |
| kryoptic/1.5 | same | regenerate; `:123-125` `CKR_GENERAL_ERROR` rows become `[untested]` |
| tpm2-pkcs11/1.10+swtpm | Linux tpm suite | regenerate on Linux; `:109` `CKR_HOST_MEMORY` row becomes `[untested]` |
| ykcs11/2.7 | nothing (hardware) | stays legacy; `:91-102` ten `import.* = no (CKR_DEVICE_ERROR)` load as unknown, so `[migration] plaintext-accepts` decides again (E-2's high case) |
| tpm2-pkcs11/1.10+amd-ftpm | nothing | legacy; `:84,91,107` `CKR_GENERAL_ERROR` rows load as unknown |
| aws-cloudhsm ×2, kmsp11 ×2 | nothing | legacy; behaviour unchanged unless a `no` row cites a device-failed rv (a test lists which: expected none) |
| layers (p11-kit, cryptoki, swtpm) | hand-written `delta` | `subtract` is unaffected; rows legacy |

Format risk: `Row` is `deny_unknown_fields`, so an *older* cakeys cannot read a regenerated
profile. Profiles ship with the binary, so only `--profiles` directories are affected; say it in
the changelog.

### 2.5 `rv::device_failed`

- `pkcs11/src/token/rv.rs:101` `pub(super) fn device_failed(&CkError)` becomes `pub`, plus
  `pub fn device_failed_rv(Rv) -> bool`. caprobe's errors are `KmError` with an rv: `e.rv()`.
- Re-export from `token/mod.rs:55`, next to `rv_is`.
- Its 11-variant list moves to the item-8 table as names (`DEVICE_FAILED_RV`).
  - `device_failed` matches by name, so the profile loader (§2.4) and the token crate agree.
  - A test pins the two.

## 3. Item 7: the provider seam contract

### 3.1 Hook table

Overrides are from `rg` over the provider crates. "Silent" means what goes wrong without an
error.

| Hook | Default (`provider.rs`) | Overridden by | Contract | Silent failure today |
|---|---|---|---|---|
| `name`, `matches` | required | all 5 + `P11Kit` | detect the module | B-10: data detection by manufacturer alone takes a YubiHSM as ykcs11 |
| `hint` | `None` | kmsp11, tpm2, p11-kit | advice text | none (cosmetic) |
| `check_options` | refuses any option (17) | tpm2 | refuse unknown options | none: default is closed |
| `manages_as_so` | `false` | ykcs11 | writes need SO | B-2: honoured only via `managing`, which a `create` override may skip; B-7: `Data("ykcs11")` says false |
| `ec_point` | identity | aws-cloudhsm, tpm2 | repair a misreported point | B-7: `Data("tpm2-pkcs11")` on darwin repairs nothing (fails closed as 10/13) |
| `key_type` | identity | aws-cloudhsm | repair | as above |
| `policy_flag` | identity | ykcs11 (`CKA_DERIVE` false→true on EC/Montgomery) | repair only declared (attr, key type) pairs | B-3 class: may widen any permission, unchecked |
| `stand_in` | `None` | aws-cloudhsm | an equivalent mechanism | unchecked equivalence |
| `template` | no-op | none in tree (kmsp11's `Row::template`, `lib.rs:76`, is a helper); 5 test providers | adjust non-security attributes | B-3: may rewrite `CKA_EXTRACTABLE`, `CKA_TOKEN`, …; B-8: session templates unpinned |
| `generation` | `Ok(None)` | kmsp11 | own generation rules | none |
| `placement` | `Ok(())` | ykcs11 | where a key may go | B-1, B-2; B-7: `Data` drops it |
| `create` | `create_declared` | ykcs11 | perform creation | B-2: core does not ask static facts first |
| `destroy` | `destroy_plain` | ykcs11 (refuses keys) | perform deletion | B-13: `CKR_OK` trusted; tpm2's measured `delete.* = no` unread |
| `plaintext_import` | `CreateObject` | ykcs11 (`PivImport`), tpm2 (ptool) | how plaintext enters | B-7: `Data("tpm2-pkcs11")` says `CreateObject` |
| `attestation` | `None` | ykcs11, tpm2 | attestation capability | fails closed (14 on `check`, B-7) |
| `bound_keys` | empty | kmsp11 | probe only | — |
| `scratch_companion` | `false` | ykcs11 | probe scratch guard | B-7: `Data("ykcs11")` skips caprobe's guard (`probe.rs:199`) |

### 3.2 Typed decisions

The trait is public (`cli/examples/custom-provider.rs`), so the signatures change little. What
changes is who calls what, and what is checked on return:

1. **Order is core's.** `Token::create`/`destroy` (pkcs11) run `static_rules` and enter
   `managing` (SO) themselves. Then they call the override with `&Checked<Create>`, a type
   other crates cannot build. An override can no longer skip placement or SO (B-2).
2. **Repairs and adjustments are checked on return.**
   - `impl dyn Provider::adjusted` (`provider.rs:301-326`) compares before and after. A
     change to a security attribute is refused (17): `CKA_TOKEN`, `CKA_PRIVATE`,
     `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_WRAP_WITH_TRUSTED`, `CKA_TRUSTED`, `CKA_ID`,
     `CKA_LABEL`, `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`. The exception is a
     tightening (`restricts` gets stricter) (B-3).
   - `policy_flag` gets `fn repairs(&self) -> &'static [(AttributeType, KeyType)]`, default
     empty. Core applies the hook only to listed pairs.
3. **Deletion is verified.** `destroy` keeps `-> Result<usize>`, but the count is a claim.
   Core re-finds, and the profile's `delete.<class>` row is read (§1.3, B-13).
4. **A code family never resolves to data.**
   - `named_in`/`select_in` (`registry.rs:52-94`) refuse (17) a family in
     `CODE_FAMILIES = ["ykcs11", "tpm2-pkcs11", "kmsp11", "aws-cloudhsm"]` (pkcs11 const,
     feature-independent) when the registry lacks its provider (B-7).
   - They never fall back to that family's `Data` after its registered provider declined
     the module (B-10).
   - Module profiles follow the provider family (`resolution.rs:201`), so a YubiHSM then
     gets `Generic` and no ykcs11 profile.
   - This is one rule with no profile format change. It is preferred over B-7's
     `requires-code` and B-10's `[match] description`, which would edit hardware profiles
     by hand (E-7).
5. **Session templates are typed (B-8).** `SessionTemplate { token: false, sensitive,
   extractable, … }` is built only by `templates.rs::session`. The contract suite pins each
   `SessionKey`.

### 3.3 The contract suite

`crates/cli-common/tests/provider_contract.rs` (new). cli-common is the crate that links every
provider (`cli-common/src/lib.rs:23-29`).

- **Who runs:** `default_registry().names()` + `Generic` + `Data(f)` for every
  `Set::active().module_family_names()`.
- **How:** each provider is named explicitly on a SoftHSM token, so its overrides run without
  its hardware. p11-fault (Linux only, `cakeys` check) supplies module lies.
- **Cases:** each case is a function over `&dyn Provider`. A `Spy<P>` wrapper records the
  order of hook calls.

| Case | Asserts | Closes |
|---|---|---|
| K-1 | every entry path (gate, `check_capabilities`, `check_import`, `Token::create`) asks `placement` before `create` | B-1, B-2 |
| K-2 | every `Template` variant × every `SessionKey`: `adjusted` leaves the security set as built | B-3, B-8 |
| K-3 | `policy_flag(a, r, kt) == r` for every observed attr unless `(a, kt) ∈ repairs()`; repairs idempotent (`ec_point∘ec_point`) | B-3 |
| K-4 | `Registry::new()` (no code) refuses `named(f)` for every `f ∈ CODE_FAMILIES`; `select` with a Yubico manufacturer and a YubiHSM description gives `Generic` | B-7, B-10 |
| K-5 | p11-fault `C_DestroyObject` → `CKR_OK` without forwarding: `delete` is 16 and the lock is kept, for every provider that does not refuse first | B-13 |
| K-6 | a provider whose profile answers `delete.CKO_PRIVATE_KEY = no` (tpm2 swtpm) is refused 15 before any call | B-13 |
| K-7 | every `Provider` method is listed in the suite's hook table (a `match` over a `Hook` enum the trait doc names); a new hook fails until it has a case | class |

Before-tests: K-1 with a placement-only provider; K-2 with test provider `Stamp`
(`pkcs11/tests/templates.rs:48`) setting `CKA_EXTRACTABLE`; K-4 on `Registry::new()`; K-5 on
SoftHSM. All four fail on `bbf159b`.

## 4. Item 8: one source for restated tables

### 4.1 Inventory

| Table | Copies today | Finding |
|---|---|---|
| ECDSA hash per curve | `core/src/sig.rs:67-74` `HashAlg::for_curve` (token signs); `sig.rs:139-145` `ecdsa_over` literals (host verifies) | A-8 |
| Curves | `core/src/id.rs` `Curve::ALL` (8); `profile/src/baseline.rs:18` `CURVES` (10, with Montgomery); pinned by `gate.rs:298` test | — |
| Proof names | `core/src/config/lock.rs:587` `Binding::proof_name`; `profile/src/names.rs` `Proof` (5); pinned by test | — |
| Key types | `core/src/types.rs` `KeyType`; `profile/src/names.rs` `KeyKind` (17) | — |
| Commitment kind → mechanism | `core/src/id.rs:347-360` `Commit::mechanism`; `profile/src/capability.rs:316-328` `commit_mechanism`; `pkcs11/token/identity.rs` `commit_mechanism` ("pinned against this") | — |
| RSA modulus bits | `camigrate/src/sealed.rs:787` `bit_len` (right); `pkcs11/src/token/policy.rs:62` (bytes × 8); `caprobe/src/probe/asymmetric.rs:402` (len × 8) | B-5 |
| Exit codes | `core::EXIT_CODES` (rendered in every `--help`); `nix/demo.sh:32-37`; `scripts/xversion.sh`; docs | C-13 |
| Device-failed rv list | `pkcs11/src/token/rv.rs:101-119` only (needed by profile, §2.4) | E-2 |
| Capability kinds cleared on other hardware | `resolution.rs:409-427` `clear_hardware_rows` (12 of 20) | B-9 |
| Regeneration flags | profile header, test helper, `regen-profiles.sh` (`--rsa-max-bits 4096`); cloud scripts (default) | E-8 |

### 4.2 Where they live

Options:

- **p11-names.** Depends on `cryptoki-sys`; profile would inherit it. No.
- **Generation.** A build step for ~6 small tables is more machinery than the tables.
- **New leaf crate `cakeys-names`** (no dependencies, or serde only): chosen.

`cakeys-names` holds:

- `Curve` (with the Montgomery curves, and `in_core: bool`)
- `HashAlg::for_curve`
- `Proof`
- `CommitKind` with `mechanism(key_type)`
- `modulus_bits(&[u8]) -> u32`
- `DEVICE_FAILED_RV: &[&str]`

Which crate uses what:

- **core** re-exports `Curve`, `HashAlg` and `modulus_bits`. `ecdsa_over` takes its hash from
  `for_curve`, keeping only the `RustCrypto` type per curve.
- **profile** uses `Curve`, `Proof`, `CommitKind` and `DEVICE_FAILED_RV`. It still does not
  depend on core, so ARCHITECTURE's rule holds. The rule's point is that profile is not tied to
  core's config model; a shared names crate respects that.
- **pkcs11** `token::commit_mechanism` and `policy.rs:62`, caprobe `asymmetric.rs:402`, and
  camigrate `bit_len` all call it.
- **`KeyKind` stays in profile.** It keeps unknown names (`Other`) by design, and the existing
  pin test is enough.

Not tables:

- **B-9:** an exhaustive `match` in `clear_hardware_rows`, no wildcard.
- **E-8:** one `caprobe regenerate <profile>` verb holding the flags, called by every script.
- **C-13:** `demo.sh` reads `cakeys --help`'s exit table, and `doc-references` checks it.

Before-tests:

- `modulus_bits` of a 2047-bit modulus is 2047. Today `policy.rs` says 2048, and the B-5 drift
  test uses another byte length.
- A per-curve property test signs with `for_curve` and verifies through `ecdsa_over` for every
  `Curve`.
- `clear_hardware_rows` walks `Capability` kinds and fails on one not classified.
- `demo` check: exit 21 inside a Nix build is named.

## 5. Findings → step

| Finding | Step / section | Package |
|---|---|---|
| B-1 | 1, 3 (`Seat::Unresolved`), 9 for camigrate | P1, P2 |
| B-2 | 1, 2; §3.2.1 | P1 |
| B-3 | §3.2.2, K-2/K-3 | P1 |
| B-4 | 4 | P1 |
| B-5 | §4.2 | P4 |
| B-7, B-10 | §3.2.4, K-4 | P3 |
| B-8 | §3.2.5, K-2 | P1 |
| B-9 | §4.2 | P4 |
| B-13 | 5; K-5, K-6 | P1 (K-5/K-6 in P3's suite) |
| A-7 | `chain.rs`: `verify_signed_by` private; one `link()` with the chain rules, used by `ykcs11/src/attest.rs:67` | P1 |
| A-8 | §4.2 | P4 |
| A-9 | §2.3 (`decide_size`; unknown, not no) | P3 |
| C-1 (row shape), C-4 | 7, 14 | P1, P2 |
| C-13, E-8 | §4.2 | P4 |
| D-1, D-8, D-10 | 8 | P2 |
| D-2, D-3, D-4 | 9 | P2 |
| D-5 | 12 | P2 |
| D-6 | 10 | P2 |
| D-7 | 4 (core), 11 (camigrate) | P1, P2 |
| D-9 | 13 | P2 |
| E-2, E-5 | §2.3, §2.4, §2.5 | P3 |
| E-3, E-4 | §2.3 (`by = unverified` → `Deferred`) | P3 (rows), P2 (consumer, step 11) |
| E-7 | out of scope (Phase 0 ledger); §2.4 avoids hand edits | — |

## 6. Packages

Order: **P1 → (P2 ∥ P3) → P4.**

- P2 needs P1's `Rule`/`static_rules`/`Known`/`Outcome`.
- P3 needs P1's `Checked<Create>` and destroy re-find for K-1/K-5.
- P4 edits files P1–P3 also edit (`capability.rs`, `policy.rs`, `sealed.rs`, `asymmetric.rs`),
  so it goes last. It is mechanical.

| Package | Files (owned) | Checks |
|---|---|---|
| **P1 cakeys plan + seam core** (steps 1–7; §3.2.1–3, 5; A-7) | core: `known.rs` (new), `plan.rs`, `config/mod.rs`, `chain.rs`, `lib.rs`; pkcs11: `ops/rules.rs` (new), `ops/mod.rs`, `ops/capabilities.rs`, `ops/planner.rs`, `gate.rs`, `provider.rs`, `templates.rs`, `token/generate.rs`, `lib.rs`; `ykcs11/src/{lib,attest}.rs`; `cli/src/lib.rs`; cli-common `lib.rs` (Outcome); `cli/tests/rules.rs` (new), `cli/tests/reference/{identity,delete}.rs`, `cli/tests/validate.rs`; `pkcs11/tests/templates.rs`; `cli/examples/custom-provider.rs`; docs/CAKEYS.md, docs/DESIGN.md | `nix develop -c cargo test -p cakeys-core -p cakeys-pkcs11 -p cakeys-ykcs11 -p cakeys`; `nix build --option builders '' .#checks.aarch64-linux.{cakeys,clippy,examples,demo,doc-references}` |
| **P2 camigrate plan + trust** (steps 8–14) | `camigrate/src/*` (rename `tokens::Known` → `KnownFrom`), new `trust.rs`; `camigrate/tests/*`, new `camigrate/tests/rules.rs`; `pkcs11/src/token/host.rs` (`Extracted`), `pkcs11/src/ops/identity_check.rs` (new); `cli/tests/common/xref.rs`; docs/CAMIGRATE.md | `cargo test -p camigrate`; `.#checks.aarch64-linux.{cakeys,clippy,doc-references}` (fault suite runs there) |
| **P3 provenance + registry + contract suite** (§2.3–2.5, §3.2.4, §3.3, A-9) | profile: `capability.rs`, `profile.rs`, `effective.rs`; caprobe: `probe.rs`, `probe/*.rs` (not `asymmetric.rs:402`), `emit.rs`, `tests/{fault,template_hook}.rs`; pkcs11: `token/rv.rs`, `token/mod.rs`, `registry.rs`; `cli-common/tests/provider_contract.rs` (new); `profiles/modules/{softhsm/2.7,kryoptic/1.5,tpm2-pkcs11/1.10+swtpm}.toml` (regenerated on Linux); docs/CAPROBE.md | `cargo test -p cakeys-profile -p caprobe -p cakeys-pkcs11 -p cakeys-cli-common`; `.#checks.aarch64-linux.{cakeys,profiles,clippy}`; tpm suite for swtpm regen |
| **P4 tables** (§4) | new `crates/names/` (+ workspace `Cargo.toml`, `git add`); core `sig.rs`, `id.rs`; profile `baseline.rs`, `names.rs`, `capability.rs:316-328`; pkcs11 `token/policy.rs`, `token/identity.rs`, `resolution.rs`; caprobe `probe/asymmetric.rs`, `main`/cli (regenerate verb); camigrate `sealed.rs`; `nix/demo.sh`, `scripts/*.sh`, `nix/doc-references.py` | `cargo test --workspace`; `.#checks.aarch64-linux.{cakeys,clippy,msrv,deny,demo,profiles,doc-references}` |

## 7. Risks

User-visible behaviour and exit codes:

| Change | Before | After |
|---|---|---|
| `delete`/`check` on an object visible only after login, no PIN | 0/11 | 16 (B-4, intended). Undeclared data objects count as private, so **public data objects on PIN-less tokens also go from 0/11 to 16** unless the lock recorded `CKA_PRIVATE = false` |
| `delete` where the object stays | 0 | 16, lock kept; tpm2 private keys 15 up front |
| `create --dry-run` | static | opens the token (PIN file read, slower; fails 16 when the token is absent) |
| `validate` without `provider` | notes | lists `deferred` rules |
| migrate/export dry runs | 0 for D-2/D-3/D-6 cases | 17/13/15 |
| `export --to-transport-file` | — | requires `--to` (usage change) |
| ykcs11 `import.*` | 15 by device-error rows | planned by `[migration]` again. Real imports may now be *attempted* on a YubiKey (plausible-only evidence that RSA import works). Mitigate with a T2 run before release |
| Repairs | `policy_flag` applied to any attr | applied only to declared pairs. Any third-party provider repairing an undeclared pair silently stops repairing (its own tests will show 13/14) |

Format changes:

- **Bundle `target`:** version bump. Old bundles read as `Claimed` with a warning.
- **Profile rows gain `by`.** An older binary rejects regenerated profiles.
- **JSON outcome rows gain `rule` and `device`:** additive.

API break: `Provider::create`/`destroy` take `&Checked<…>`, and `policy_flag` needs `repairs()`.
Third-party providers must change. The example and changelog say how.

Size: about 1.6k added and 0.9k removed. P2 is the largest (steps 8–14, ~630/−460) and the
riskiest. Its fault and twin coverage is Linux-only, while work happens on darwin (C-12).

## 8. What in the plan is wrong or should be cut

1. **"The twin's oracle becomes exact: same exit unless the device fails."** Not achievable as
   written.
   - A sealed import's identity (10) and a tampered blob (13) are decidable only by
     unwrapping.
   - The honest version is §1.4: same exit unless the device fails *or the dry run named the
     rule it deferred*.
   - Unwrapping into a session object at dry-run time would make it exact. But it costs a
     second unwrap, and some modules refuse session objects. Defer.
2. **Item 5's claim "closes the 11-18 class".** This holds only for rules that run before the
   write. Post-write identity stays `post`, by design.
3. **Generic `Claimed<T>`/`Verified<T>` in core** gives no guarantee: anyone can construct
   it. Use crate-local types with private constructors (§2.1).
4. **B-7's `requires-code` and B-10's `[match] description`** both edit hardware profiles by
   hand, which E-7 forbids. One registry rule over `CODE_FAMILIES` closes both (§3.2.4). Cut
   the profile fields.
5. **Item 8's "mechanisms" in the leaf crate.** Mechanism names already have one source,
   `p11-names`. Moving them buys nothing. The restated tables are the six of §4.2, plus three
   non-table fixes (B-9, E-8, C-13).
6. **"`rv::device_failed` becomes public for caprobe"** is not enough. The profile loader
   needs the same list without pkcs11, hence `DEVICE_FAILED_RV` in the leaf crate (§2.5).
7. **Item 6 lists D-7 under `Option<bool>`.** Of 22 security-attribute sites, only 6 are
   fail-open; 7 are declarations where "absent" means "not declared". A blanket rewrite of all
   28 `Option<bool>` would churn `resolution.rs` and the probe for nothing. Scope it to §2.2's
   list plus `Side`.
8. **"1–2 weeks".** P1 + P2 alone are ~14 green steps with Linux-only verification for the
   fault and twin parts. 2–3 weeks is realistic.

## 9. Lead decisions (2026-11-25)

Taken so implementation can proceed. Each is reversible and listed in the job report for the
user. The rule behind all of them: unknown is never a verdict, and refusing is the default.

1. **Unknown capability refuses; it is never planned as yes.**
   - A row that loads as device-failed or legacy is unknown. The planner then refuses with the
     exit an unsupported capability gets today (15), and the message names the T2 re-probe.
   - This replaces §7's "planned by `[migration]` again" for ykcs11 `import.*`. No import is
     attempted on a YubiKey on the strength of an unverified claim.
   - The user-visible result for those ten rows is unchanged (15). Only the reason changes.
2. **Undeclared data objects count as private** (§7 row 1). The escape is the lock's recorded
   `CKA_PRIVATE = false`. The 16 for a public data object on a PIN-less token is accepted, and
   is documented in CAKEYS.md with the fix: lock it once, with a login.
3. **The twin oracle is §1.4's honest version:** same exit unless the device fails, or the dry
   run named the rule it defers. Plan item 5 and the summary are corrected to match (§8.1, §8.2).
4. **§8.3–§8.7 are accepted as written.** Crate-local verified types with private constructors.
   `CODE_FAMILIES` in the registry, and no hand edits to hardware profiles. The leaf crate holds
   only the six restated tables plus `DEVICE_FAILED_RV`. D-7 is scoped to §2.2's sites.
5. **Accepted:** `create --dry-run` opens the token; `export --to-transport-file` requires
   `--to`; the bundle `target` field with a version bump; profile rows gain `by`; the provider
   API break, with the example and the changelog updated.
6. **The software-token profiles are regenerated on the local aarch64-linux VM**
   (`--option builders ''`) in the same change as the `by` field.
   - Hardware profiles are not regenerated. Their rows load as legacy, and therefore unknown,
     where §2.4 says so.
   - The p0-ledger check records this as an acknowledged change.
