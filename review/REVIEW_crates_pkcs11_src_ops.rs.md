# Review: crates/pkcs11/src/ops.rs (1140 lines)

Reviewed 2026-11-18 [read]. Summary: the verbs (`resolve`, `verify`, `lock`, `lock_import`,
`create`, `create_selected`, `delete`, `check`, `check_token`), their shared capability check
(`needs`, `check_capabilities`, `check_templates`, `plan_templates`) and `create`'s plan
(`plan_create`). The verbs are thin over `Token` and `core::reconcile`, the "one source of
truth" for needs and templates is real (the gate and camigrate call the same functions), and the
2026-11-17 "create flags" change is implemented as ISSUES.md describes. Findings: one wrong
error for an unlogged session, rollback gaps around `create`, and the file's breadth.

## Findings

### F1. `create` on a pinned pair in a session without login reports "the token lost it" (14) — bug

**Verification:** confirmed. A `Write` session opens without a PIN and only logs in when one is configured (token/mod.rs:939-961, `logged_in = pin.is_some()` :421); `find_key` searches the private class only (:714-721), so a hidden pinned key is `None` at ops.rs:668, `check_capabilities` has no login test (ops.rs:300-318), and `create_absent`'s D1 (:575-583) returns 14 before its login test (:587). `delete` orders these correctly (:962). No caller requires a PIN first: `Opener::open`/`open_quiet` go straight to `Token::open` (cli-common lib.rs:105-133), and keys.toml needs a PIN only beside an SO credential (config.rs:1578). [read]
`crates/pkcs11/src/ops.rs:668`, `:681-682`, `:575-596`. Since "create flags", `create` runs
over pinned pairs and verifies them. Without a PIN the session cannot see private or secret
objects, so `find_key` at `:668` returns `None` for a key that is there; the run goes on to
`check_capabilities` and `create_absent`, whose D1 test (`:575`) fires before its own login test
(`:587`): `PreconditionFailed` (14), "the lock already pins object ...; creating it would
generate different material", which tells the user the key is gone. `delete` gets this right
(`:962-971`: no login and a private/secret class is `Unavailable`). Failure scenario: a token
configured without `pinFile`/`pinEnv`, holding a pinned private key -> `cakeys create` exits 14
with a message saying the key would be regenerated, instead of "configure pinFile or pinEnv". Fix: in `create`, before `find_key`, refuse
`!tok.logged_in` for private and secret classes as `delete` does (or move `create_absent`'s
login test before D1). [read]

### F2. Errors after the module created something skip `create_absent`'s cleanup — risk

**Verification:** confirmed. `tok.create(..)?` (ops.rs:610) returns before the cleanup, which only follows a failed `resolve_with` (:615-631). The one reachable path today is `as_so`'s logout/re-login failure after a successful ykcs11 generation (token/mod.rs:799-819, the same root cause as REVIEW_crates_pkcs11_src_token_mod.rs.md F2); no provider overrides `create` with a post-check (only ykcs11 lib.rs:116, which checks before generating), and ykcs11's `destroy` refuses keys, so the fix there yields an honest "still on the token" note rather than a removal. [read]
`crates/pkcs11/src/ops.rs:610`. `tok.create(...)?` returns early on any error, and the cleanup
at `:623-631` runs only when `resolve_with` fails. An error that comes after the module already
made the key escapes both cleanup and record: the SO logout or user re-login failing in
`Token::as_so` after a successful ykcs11 generation (see `REVIEW_crates_pkcs11_src_token_mod.rs.md`
F2), or a provider's `create` override that generates and then fails a post-check. The key
stays, unrecorded; the next run reports 19. Fix: since the locator was verified empty just
before (`:599-609`), treat any `Err` from `tok.create` as "maybe created": try `tok.destroy`
under the same notes as `:623-631`, then return the error. [read]

**Fixed (2026-11-18):** `undo_created` runs on a failed `create` as on a failed identity: what is
under the (empty before) locator is removed, or reported. Test:
`a_creation_that_fails_after_the_write_is_undone`.

### F3. The file holds four concerns in 1140 lines — complexity

`crates/pkcs11/src/ops.rs`. The verbs proper (`resolve_with`, `lock_as`, `create`,
`delete`, `check_open`), the capability and template checks shared with the gate and camigrate
(`needs`, `session_templates`, `check_templates`, `plan_templates`, `check_import`), the
`create` planner (`Action`, `Planned`, `plan_create`, `create_pairs`, `create_selected`) and the
`check` reference parsing live in one module whose doc is one line ("Idempotent verbs with
HTTP-like semantics"). `ecdh_seals` and `session_templates` are read by `gate.rs` and
`token/possession.rs` as much as by the verbs. Fix: split the capability/template checks
(`needs.rs`) and the create planner (`create.rs`) out; the verbs then read top to bottom.
[read]

### F4. `check_open` validates the requested scheme twice with two messages — nit

`crates/pkcs11/src/ops.rs:1045-1061`, `:1067-1075`. The first test (before opening) accepts any
attestation scheme when `attestation = true`, the second (after) narrows to `schemes_on`. Both
produce `Unsupported` with differently worded messages for what a user sees as one mistake. Fine
behaviour; the duplication could be one function taking `Option<&Token>`. [read]

**Fixed (2026-11-18):** one `requested_scheme` check runs before and after the open, with one
message. Test: `a_requested_scheme_is_refused_alike_before_and_after_the_open`.

## Design

- `resolve_with` (`:349-386`) computes the key's SPKI up to four times (identities, public
  objects, attestation, transport public key): see `REVIEW_crates_pkcs11_src_token_identity.rs.md`
  F2. One `Computed.spki` would remove three calls and make "the SPKI the attestation must
  name comes from the same source rfc7093m4 hashed" (`:409-410`) true by construction rather
  than by recomputation.
- `create`'s verification of pinned pairs runs on a token opened with `ChainTime::Unchecked`
  (only `cakeys check` sets a time), so "verified as `check` verifies it" differs in one respect:
  attestation chain dates. B8 says `create` stays clock-free on purpose; the `Made::Verified` doc
  (`:640-642`) and docs/CAKEYS.md should say so.
- `answers` (`:456-469`) records a generation without the `via = "by-name"` the run needed:
  see `REVIEW_crates_pkcs11_src_token_generate.rs.md` F2.

## Checked, no issue

- "create flags" (done 2026-11-17): an unpinned key under the locator is `Exists` (19) before
  any capability is asked (`:668-676`); a pinned one is `verify`d and `Made::Verified`
  (`:677-679`); `plan_create` marks it `Action::Verify` (printed `verify` by `--dry-run`) and
  still gates it with `creates = false`; `Action::runs` opens tokens for verified pairs;
  `create_selected` lists only `Made::Created`.
- B2: `create` never adopts a key; D1 refuses re-generating a pinned object.
- `create_absent`: login required to see the locator, any class under it refuses, the cleanup
  runs only on a locator that was empty before.
- `create_selected`: one token open at a time (the previous one dropped before `open`); the
  lock's `changed` is returned beside the failure so it is saved.
- `delete`: If-Match by the primary scheme or the first locked one, proof of possession on the
  way, only the identified object and public halves holding its key are destroyed; absent is
  success, but not in a session that cannot see the class.
- `attest`: a lock-pinned attestation that cannot be computed now is a downgrade (14);
  conflicts and ambiguity keep their codes.
- `check_capabilities`: commitments, wrap-rebind mechanisms, the generation, the proof and every
  session template are asked before anything is created.
