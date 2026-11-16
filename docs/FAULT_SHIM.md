# p11-fault: a PKCS#11 module that forwards, and misbehaves on request

Design for [PLAN.md](PLAN.md) A3 and tier 4 of [COVERAGE_PLAN.md](COVERAGE_PLAN.md), written
2026-11-14. Steps 1 and 2 of the order below are built (`crates/p11-fault`,
`packages.p11-fault`): the forwarders, every rule kind, the trace, the parity run, the
`pkcs11-tool` check and the first table of lies.

`libp11_fault.so` is a PKCS#11 module that loads a real one (SoftHSM, kryoptic, a vendor
module) and forwards every call to it, changing exactly what a fault plan says: a return
value on the n-th call of a function, an attribute dropped or taken from another object, a
token flag set, a handle swapped between find and use. Everything else is the real module's
own behaviour, so nothing in it implements cryptography, objects or sessions.

## Any client, for free

A PKCS#11 module is already the one interface every client loads, so a forwarding module
works under any of them unchanged: `cakeys`, `pkcs11-tool`, OpenSSL's `pkcs11-provider`, NSS
`modutil`, `p11-kit` (as a module in its configuration, or in front of `p11-kit-client.so`).
Being general costs three choices, none of which changes the implementation:

- **Configured from the environment**, which every client passes to the modules it loads:
  `P11_FAULT_MODULE` (the real module), `P11_FAULT_PLAN` (the plan file; unset, the shim is a
  pure forwarder), `P11_FAULT_TRACE` (a call log). No `CAKEYS_` names, no keys.toml. A copy
  of the library named `libp11_fault-<tag>.so` reads `P11_FAULT_MODULE_<TAG>`,
  `P11_FAULT_PLAN_<TAG>` and `P11_FAULT_TRACE_<TAG>` (upper-cased, `-` as `_`) and never the
  untagged names, so one process can hold several shims: one in front of each of several
  modules (camigrate between two tokens), or one in front of another (a tracing shim around a
  faulting one). A shim whose module is its own file fails with that reason instead of waiting
  on its own initialisation.
- **Plans name PKCS#11 things only**: function names, `CKR_*`, `CKA_*`, `CKF_*`, objects by
  `CKA_LABEL`. Any other value as a number (`rv = 0x30`).
- **Packaged on its own** (`packages.p11-fault`), outside the cakeys packages, so it is usable
  without cakeys.

The one general concern that does touch the code is the 3.x interface (below): v1 exports
only the 2.40 entry point, and a client that needs a 3.x-only function (`C_LoginUser`,
message-based encryption, KEM) gets `CKR_FUNCTION_NOT_SUPPORTED` from it. cakeys calls none.

## Shape

```text
crates/p11-fault/
  Cargo.toml       cdylib + rlib (the rlib for unit tests), publish = false
  src/lib.rs       C_GetFunctionList, loading, the guard around every entry
  src/forward.rs   the 68 forwarders, generated from one signature list
  src/plan.rs      the plan: parsing, matching, call counting
  src/hooks.rs     what rules do to the outputs of the few functions that need it
  src/names.rs     CKR_/CKA_/CKF_ names <-> values (the set the plans use; numbers otherwise)
  src/trace.rs     one JSON line per call
```

Dependencies: `cryptoki-sys` (the C types), `libloading`, `serde` and `toml`, all already in
the tree. About 1–1.5k lines.

### Loading

The first `C_GetFunctionList` loads the real module (`dlopen`, kept for the life of the
process), asks it for its `CK_FUNCTION_LIST`, reads the plan, and builds the shim's own table:
the real table's `version`, and the shim's forwarder in every slot the real module fills (a
slot the real module leaves `NULL` stays `NULL`). Both live in `OnceLock`s. A plan that does not
parse fails that first call with `CKR_GENERAL_ERROR` and a message on stderr: a typo in a fault
plan must never turn into a test of nothing.

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(out: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    guard(|| {
        // Loaded once: the real module, the plan and our table, or why not (kept, so every
        // later call fails the same way).
        let shim = SHIM.get_or_init(Shim::load).as_ref().map_err(Fatal::clone)?;
        unsafe { *out = (&raw const shim.table).cast_mut() };
        Ok(CKR_OK)
    })
}

/// Every entry: a panic never crosses the C boundary.
fn guard(f: impl FnOnce() -> Result<CK_RV, Fatal>) -> CK_RV {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(rv)) => rv,
        Ok(Err(fatal)) => fatal.report(), // stderr once; CKR_GENERAL_ERROR
        Err(_) => CKR_GENERAL_ERROR,
    }
}
```

### The forwarders

One macro invocation lists the 68 2.40 functions with their parameters; each expands to an
`extern "C"` function that counts the call, asks the plan, forwards, and lets the function's
hook (if any) change the outputs:

```rust
forward! {
    C_Initialize(init_args: *mut c_void);
    C_GetTokenInfo(slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) => hooks::token_info;
    C_FindObjects(s: CK_SESSION_HANDLE, out: *mut CK_OBJECT_HANDLE, max: CK_ULONG, n: *mut CK_ULONG)
        => hooks::find_objects;
    C_GetAttributeValue(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE, t: *mut CK_ATTRIBUTE, n: CK_ULONG)
        => hooks::attribute_value;
    C_SignInit(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE) key => key;
    // ... the other 63, most with no hook
}

// What each line expands to (C_FindObjects shown):
unsafe extern "C" fn C_FindObjects(s: CK_SESSION_HANDLE, out: *mut CK_OBJECT_HANDLE,
                                   max: CK_ULONG, n: *mut CK_ULONG) -> CK_RV {
    guard(|| {
        let call = Call::count(Fn::C_FindObjects); // per-process counter: the n-th call
        let plan = plan();
        if let Some(rv) = plan.before(&call) {     // `rv` rules with when = "before"
            return Ok(rv);
        }
        let rv = unsafe { real().C_FindObjects.unwrap()(s, out, max, n) };
        let rv = hooks::find_objects(plan, &call, rv, s, out, max, n);
        trace::call(&call, rv);
        Ok(plan.after(&call, rv))                  // `rv` rules with when = "after"
    })
}
```

The `key => key` form marks the functions that take a key (`C_SignInit`, `C_DecryptInit`,
`C_DeriveKey`, `C_UnwrapKey`, `C_WrapKey`, ...): a `use_label` rule substitutes the handle
before forwarding.

### The plan

TOML, read once per process. cakeys runs one process per verb, so one plan is one run's
behaviour. Rules apply in file order. A rule matches a function, optionally only its n-th call
(`call`), or one object (`of_label`). It then does one thing:

```toml
# A return value, without forwarding (default), or after forwarding (the real effect happened).
[[rule]]
fn = "C_FindObjects"
call = 2
rv = "CKR_DEVICE_ERROR"

[[rule]]
fn = "C_Login"
when = "after"
rv = "CKR_PIN_INCORRECT"

# Token and slot flags: the PIN counters, write protection, a removed token.
[[rule]]
fn = "C_GetTokenInfo"
set_flags = ["CKF_USER_PIN_FINAL_TRY"]

# An attribute: dropped (CKR_ATTRIBUTE_TYPE_INVALID for it), replaced, read from another
# object, or malformed.
[[rule]]
fn = "C_GetAttributeValue"
of_label = "victim"
attribute = "CKA_EC_POINT"
from_label = "other" # or: drop = true | value = "0441…" | length = "unavailable" | truncate = 3

# Handles: a second object under the locator (added where the real search finds something:
# a client reads until a call returns nothing), or another key used than the one shown (of
# the same class).
[[rule]]
fn = "C_FindObjects"
call = 2
add_label = "decoy"

[[rule]]
fn = "C_DecryptInit"
of_label = "shown"
use_label = "used"

# Found objects hidden; a byte of what a call returns changed (C_Sign, C_SignFinal, C_Encrypt,
# C_Decrypt); mechanisms no longer listed.
[[rule]]
fn = "C_FindObjects"
hide_label = "gone"

[[rule]]
fn = "C_Sign"
call = 2
corrupt = true

[[rule]]
fn = "C_GetMechanismList"
hide_mechanisms = ["CKM_ECDH1_DERIVE"]
```

**Failing half of an operation.** `C_Sign` and its like end the operation `C_SignInit` began,
also when they fail. A rule that answers instead of the module (`when = "before"`), or on the
call that only asks the output length, leaves the real operation open, and the module then
refuses what the client does next. To model a module that fails the operation, fail the call
that does the work, after it: `call = 2`, `when = "after"` for a client that asks the length
first.

**Labels to handles.** `of_label`, `from_label`, `add_label` and `use_label` are resolved
through a session of the shim's own (`C_OpenSession` on the caller's slot, read from
`C_GetSessionInfo`), so resolving never interrupts a find the caller has open. Object handles
are valid across an application's sessions, which is what makes this work.

### The trace

With `P11_FAULT_TRACE`, one JSON line per call, appended (`O_APPEND`, so the per-process
writers of a test run interleave whole lines):

```json
{"pid":4711,"seq":17,"fn":"C_SignInit","n":2,"mechanism":"CKM_ECDSA_SHA256","rv":"CKR_OK","rule":null}
```

This is PLAN.md A1's trace if `pkcs11-spy` proves too lossy: which functions, mechanisms,
attribute types and return values cakeys really meets, per reference token.

## Testing the shim itself

1. **Unit tests** (the rlib): plans parse, refuse unknown names and fields, and match the n-th
   call; an attribute served into a caller's entry.
2. **Parity**: the reference suite runs a third time, through the shim with no plan, in front of
   SoftHSM (a `tests/fault.rs` like `tests/softhsm.rs`, its `Reference` naming
   `libp11_fault.so`). It must pass exactly as directly. That proves the forwarder transparent
   before any test trusts it to lie.
3. **Another client**: in the Nix check, `pkcs11-tool --module libp11_fault.so` lists the
   slots, then, under a plan failing `C_GetSlotList`, fails with that return value. This is
   the "any client" claim tested.

## What cakeys tests with it

One table in `tests/fault.rs` (`a_lying_module_is_refused`): a rule, a verb, the exit code and
the message, on a token holding a signing, a deriving, a decrypting and an unwrapping key, each
beside another key of its kind. Every row asserts in the trace that its rule fired, and the
lock is unchanged at the end. As run on SoftHSM [run]:

| The lie | `verify` gives |
|---|---|
| `CKF_WRITE_PROTECTED` (on a `create`) | 15 |
| `CKF_USER_PIN_LOCKED`, `CKF_USER_PIN_FINAL_TRY` | 16, before any login |
| the public key's `CKA_EC_POINT` dropped, or its length unavailable | 11, no key material |
| the point cut short | 13, no P-256 point |
| the point of another key | 13, the proof of possession fails |
| `CKA_SIGN` reported false | 13 |
| a second object found under the locator | 12 |
| another key used by `C_SignInit`, `C_DeriveKey` | 13, the proof fails |
| another key used by `C_DecryptInit` | 13 (was 16: see below) |
| another key used by `C_UnwrapKey` | 16: SoftHSM answers `CKR_GENERAL_ERROR` |
| `C_Sign` or `C_GetAttributeValue` failing | 16, the call named |
| another key's `CKA_PUBLIC_KEY_INFO` on the private key | 13, it disagrees with the material |
| the per-use login of a `CKA_ALWAYS_AUTHENTICATE` key refused | 16, not retried |
| the MAC with the derived or unwrapped secret failing | 16, the call named |

**Found with it.** A swapped RSA key under `pop-decrypt` was reported as unavailable (16): the
token answers `CKR_ENCRYPTED_DATA_INVALID`, since OAEP under the wrong key fails outright and
never yields a wrong plaintext to compare. The challenge was encrypted to the public key the
identity names, so that answer means another key: `CKR_ENCRYPTED_DATA_INVALID`/`_LEN_RANGE`
and `CKR_WRAPPED_KEY_INVALID`/`_LEN_RANGE` are now a conflict (13). A module that answers a
general error instead (SoftHSM's `C_UnwrapKey`) stays unavailable: nothing in it says which.

A second test, `a_creation_that_cannot_be_identified_is_undone_or_reported`, takes §8.1's
"refused operations leave nothing behind": a key created whose proof then fails is removed
again, and where `C_DestroyObject` fails too, cakeys says the key is still on the token.

Later rows use three more rule kinds: a signature or a plaintext with one byte changed (13;
for `pop-decrypt` this is the wrong plaintext OAEP never yields by itself), the proof's
mechanism no longer listed (15), and the key hidden from every search once created (11,
"vanished after creation").

**camigrate** (`crates/camigrate/tests/fault.rs`): SoftHSM behind the shim as the source or
the target of a move, kryoptic the other side. The source's key-encryption key, its copy of the
transport key and each wrap failing (15); the target's unwrap of the KEK or the key (13), the
proof after the import (16), the host path's creation and commitment (15), a certificate the
target then reports as another type (13). Each leaves the target without the object and the
lock as it was; where the target will not delete either, what was imported is said to be still
there.

**caprobe** (`crates/caprobe/tests/fault.rs`): the write probes against the shim. Usage
attributes refused at generation, or a public key without its point, are said undetermined;
another key signing or deriving, a sealed derived secret refused, no derivation at all, a key
deriving while reporting `CKA_DERIVE` false and a wrap that does not unwrap become the row
and the note of what was seen, and drift from the committed profile (15).

Still to add: a derived secret with no value, and a certificate with no readable value. Two
rule kinds that native-pkcs11 shows real modules need (PLAN.md A0b): an attribute answered
with `CKR_ATTRIBUTE_TYPE_INVALID` but its entry left untouched (`untouched = true`, beside
`drop`, which sets the length unavailable as the spec asks; OPEN.md, "rust-cryptoki"), and a
search that returns only its first match (`first_only = true` on `C_FindObjects`), against
which the locator's 12 cannot fire. Its other search fault, one key under two handles, the shim
cannot make (`add_label` skips a handle already found), but a decoy under `add_label` gives
cakeys the same two handles to refuse.

## Nix

- A default member of the workspace, so the build makes `libp11_fault.so` beside the binaries
  and the tests find it there (`common::fault_shim`). `cargo test` alone does not build a
  `cdylib`: `scripts/local-tests.sh` builds it first.
- One more output of the same build, `p11fault` (as `caprobe` and `camigrate` are), holding
  `lib/libp11_fault.so`: `packages.p11-fault`. The `cakeys` output's closure does not carry it.
- The per-test runner (`nix/test-tokens.sh`) points `P11_FAULT_MODULE` at the test's own SoftHSM
  token for `tests/fault.rs`.

## The 3.x interface, later

A client that finds `C_GetInterface` uses it; one that does not falls back to
`C_GetFunctionList` (cryptoki, OpenSC and p11-kit all do). v1 therefore exports only the 2.40
entry point. When a 3.x function is needed, the same macro lists the 24 functions of
`CK_FUNCTION_LIST_3_0`, and the shim exports `C_GetInterfaceList` and `C_GetInterface`
returning its 3.0 table. `pkcs11-abi` (PLAN.md A0b) has the table layouts, should 3.2's be
needed too.

## Order

1. Done: the forwarder, `rv` rules, the trace, the parity test and the `pkcs11-tool` check.
2. Done: the hooks (attributes, flags, handles, malformed lengths) and the first cakeys table.
   The rows listed above remain.
3. The 3.x interface, when a client needs it.

## Risks

- **ABI.** Linux LP64 only, as cryptoki-sys's bindings are; Windows packing is out of scope.
- **Modules that keep per-process state** (tpm2-pkcs11 reads its store at `C_Initialize`) see
  the same calls through the shim as without it; the parity test runs on SoftHSM, and a
  kryoptic and a tpm2-pkcs11 leg can follow if a row needs them.
- **A plan that matches nothing** makes a test pass for the wrong reason. Each test asserts in
  the trace that its rule fired (`"rule"` is set on the line it changed).
