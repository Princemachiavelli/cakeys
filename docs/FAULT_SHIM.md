# p11-fault: a PKCS#11 module that forwards calls and injects faults on request

This is the design for [PLAN.md](PLAN.md) A3 and for tier 4 of
[archive/COVERAGE_PLAN.md](archive/COVERAGE_PLAN.md), written on 2026-11-14. Steps 1 and 2 of
the order below are built (`crates/p11-fault`, `packages.p11-fault`): the forwarders, every rule
kind, the trace, the parity run, the `pkcs11-tool` check and the first table of lies.

`libp11_fault.so` is a PKCS#11 module that loads a real module (SoftHSM, kryoptic, a vendor
module) and forwards every call to it. It changes exactly what a fault plan says, for example a
return value on the n-th call of a function, an attribute that is dropped or taken from another
object, a token flag that is set, or a handle that is swapped between the search and the use.
Everything else is the real module's own behavior, so the shim implements no cryptography, no
objects and no sessions.

## Any client can load it, unchanged

Every PKCS#11 client already loads modules through the same interface, so a forwarding module
works under any client without changes: `cakeys`, `pkcs11-tool`, OpenSSL's `pkcs11-provider`,
NSS `modutil`, and `p11-kit` (as a module in its configuration, or in front of
`p11-kit-client.so`). To stay general, the shim makes three choices, and none of them changes
the implementation:

- **The environment configures it**, because every client passes its environment to the modules
  that it loads. `P11_FAULT_MODULE` names the real module, `P11_FAULT_PLAN` names the plan file
  (when it is unset, the shim only forwards), and `P11_FAULT_TRACE` names a call log. The shim
  reads no `CAKEYS_` variables and no keys.toml. A copy of the library named
  `libp11_fault-<tag>.so` reads `P11_FAULT_MODULE_<TAG>`, `P11_FAULT_PLAN_<TAG>` and
  `P11_FAULT_TRACE_<TAG>` (the tag in upper case, with `-` written as `_`), and it never reads
  the untagged names. So one process can load several shims: one in front of each of several
  modules (camigrate between two tokens), or one in front of another (a tracing shim around a
  faulting one). If a shim's module is the shim's own file, the shim fails and names that
  reason, instead of waiting for its own initialization.
- **Plans name only PKCS#11 things**: function names, `CKR_*`, `CKA_*`, `CKF_*`, and objects by
  their `CKA_LABEL`. Any other value is written as a number (`rv = 0x30`).
- **It is packaged on its own** (`packages.p11-fault`), outside the cakeys packages, so it can
  be used without cakeys.

The one general concern that does affect the code is the 3.x interface (described below). v1
exports only the 2.40 entry point, so a client that needs a function that only 3.x has
(`C_LoginUser`, message-based encryption, KEM) gets `CKR_FUNCTION_NOT_SUPPORTED` for it. cakeys
calls none of these functions.

## Files

```text
crates/p11-fault/
  Cargo.toml       cdylib + rlib (the rlib for unit tests), publish = false
  src/lib.rs       C_GetFunctionList, loading, the guard around every entry
  src/forward.rs   the 67 forwarders (every 2.40 function but C_GetFunctionList), generated from one signature list
  src/plan.rs      the plan: parsing, matching, call counting
  src/hooks.rs     what rules do to the outputs of the few functions that need it
  src/trace.rs     one JSON line per call
  src/record.rs    the public values a trace line records (P11_FAULT_RECORD_VALUES=public)
crates/p11-names/
  src/lib.rs       CKR_/CKA_/CKF_/CKM_ names <-> values (the set the plans use; numbers
                   otherwise), re-exported as p11_fault::names; cakeys_pkcs11 names return
                   values with it too
```

The dependencies are `cryptoki-sys` (the C types), `libloading`, `libc`, `serde`, `serde_json`
and `toml`, which the tree already has, and `p11-names`, which depends on `cryptoki-sys` alone.
On 2026-11-26, the shim's sources held about 3,200 lines (unit tests included), and `p11-names`
held about 1,000, most of them in the name tables.

### Loading

The first `C_GetFunctionList` call loads the real module (with `dlopen`, and the module stays
loaded for the life of the process). It asks the module for its `CK_FUNCTION_LIST`, reads the
plan, and builds the shim's own table. The table takes the real table's `version`, capped at
2.40, because the table has the 2.40 layout: a 3.x version would tell a client that chooses the
layout by the version to read past the table's end. The table holds the shim's forwarder in every
slot that the real module fills, and a slot that the real module leaves `NULL` stays `NULL`. Both
are kept in `OnceLock`s. If the plan does not parse, that first call fails with
`CKR_GENERAL_ERROR` and a message on stderr, so that a typo in a fault plan never makes a test
silently test nothing.

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
        Ok(Err(fatal)) => fatal.report(), // each message once on stderr; CKR_GENERAL_ERROR
        Err(_) => CKR_GENERAL_ERROR,
    }
}
```

### The forwarders

One macro invocation lists the 2.40 functions with their parameters. Each entry expands to an
`extern "C"` function that counts the call, asks the plan, forwards the call, and lets the
function's hook (if it has one) change the outputs. The sketch below shows the idea; the real
macro is in `src/forward.rs`.

```rust
forward! {
    C_Initialize(init_args: *mut c_void);
    C_GetTokenInfo(slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) => hooks::token_info;
    C_FindObjects(s: CK_SESSION_HANDLE, out: *mut CK_OBJECT_HANDLE, max: CK_ULONG, n: *mut CK_ULONG)
        => hooks::find_objects;
    C_GetAttributeValue(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE, t: *mut CK_ATTRIBUTE, n: CK_ULONG)
        => hooks::attribute_value;
    C_SignInit(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE) => substitute_key;
    // ... the other 62, most with no hook
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

The `=> substitute_key` mark is on the functions that take a key (`C_SignInit`,
`C_DecryptInit`, `C_DeriveKey`, ...). Before such a function forwards the call, a `use_label`
rule replaces the key handle. `C_WrapKey`'s `=> wrap_key` mark does the same, and it also
replaces the key to be wrapped under a `wrap_label` rule and changes the blob in the way that
`corrupt_output` does. `C_UnwrapKey`'s `=> unwrap_key` mark undoes a `transcode`. The
`=> corrupt_output` mark is on the functions whose output a rule may change (`corrupt`,
`replay_output`). The plan's lists of which functions take which rules are generated from these
marks.

### The plan

The plan is a TOML file, and each process reads it once. cakeys runs one process per verb, so
one plan describes the behavior of one run. The rules apply in the order of the file. A rule
matches a function (`fn = "*"` matches every function), and it may narrow the match further:

- `call`: only the function's n-th call in the process (counted from 1).
- `of_label`: only calls on an object with this label. This is the key used for a `use_label`
  rule, the key wrapped for a `wrap_label` rule, and otherwise any object that the call names
  (for `C_WrapKey`, either key). It applies to the functions that name an object
  (`C_GetAttributeValue`, `C_DestroyObject`, `C_SignInit`, ...).
- `mechanism`: only calls with this mechanism (the `*Init` functions, `C_GenerateKey`,
  `C_WrapKey`, `C_GetMechanismInfo`, ...).
- `class`, `key_type`: only calls whose input template states this class or key type
  (`C_FindObjectsInit`, `C_CreateObject`, `C_GenerateKey`, `C_UnwrapKey`, ...).
- `nth`: only the n-th call that meets the rule's other matchers. `from`: that call and every
  call after it. A rule can give only one of `call`, `nth` and `from`.
- `from_seq`: the process's n-th call of any function (the trace's `seq`) and every call after
  it. With `fn = "*"`, this makes the module fail from one point of a run onward.

The shim reads a matcher from the call's arguments before the call reaches the module (the
`[kind(args)]` lists in forward.rs). The parser refuses a matcher on a function that has no such
argument, because the matcher would never match. A rule with `fn = "*"` takes no `call` and no
matcher on the arguments, and it can give only `rv` or `abort`. Each rule then does one thing:

```toml
# A return value, without forwarding the call (the default), or after forwarding it (the real
# effect happened).
[[rule]]
fn = "C_FindObjects"
call = 2
rv = "CKR_DEVICE_ERROR"

[[rule]]
fn = "C_Login"
when = "after"
rv = "CKR_PIN_INCORRECT"

# Token and slot flags (set_flags, or clear_flags): the PIN counters, write protection, a
# removed token. Each function takes the flag names of its own structure (C_GetSlotInfo takes
# the three slot flags), because the two flag words share bit values.
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

# Handles: a second object under the locator, or a key used other than the one shown. The
# second object is added only where the real search finds something, because a client reads
# until a call returns nothing. The key used has the same class as the one shown; when no
# object has the label, the call fails, as it does for `from_label`.
[[rule]]
fn = "C_FindObjects"
call = 2
add_label = "decoy"

[[rule]]
fn = "C_DecryptInit"
of_label = "shown"
use_label = "used"

# A key wrapped other than the one named, of the same class (when no object has the label, the
# call fails): the blob holds the other key's material. `of_label` names the key that the
# caller asked to wrap.
[[rule]]
fn = "C_WrapKey"
of_label = "shown"
wrap_label = "other"

# Found objects hidden, or other objects found in their place: each object labelled
# `of_label` is replaced by the object of its class labelled `replace_label` (when there is
# none, the call fails). The last byte of a call's output changed (C_Sign, C_SignFinal,
# C_Encrypt, C_Decrypt, C_WrapKey), or the output of the call n calls earlier returned again
# (when there was one and it fits the caller's buffer). Mechanisms no longer listed.
[[rule]]
fn = "C_FindObjects"
hide_label = "gone"

[[rule]]
fn = "C_FindObjects"
of_label = "shown"
replace_label = "other"

[[rule]]
fn = "C_Sign"
call = 2
corrupt = true

[[rule]]
fn = "C_Sign"
replay_output = 1

# A wrapped blob that passes through the module and back but is not what the module made: the
# shim pads every byte that C_WrapKey returns, and it removes the padding from a copy of every
# blob given to C_UnwrapKey before the blob reaches the module. The rule takes no matcher,
# because the unwrap that undoes the padding cannot tell which wraps were padded.
[[rule]]
fn = "C_WrapKey"
transcode = true

[[rule]]
fn = "C_GetMechanismList"
hide_mechanisms = ["CKM_ECDH1_DERIVE"]

# Matchers: the second ECDSA signing fails; a delete of `k` succeeds and does nothing; every
# call of every function fails from the process's 40th call on (the trace's `seq`).
[[rule]]
fn = "C_SignInit"
mechanism = "CKM_ECDSA"
nth = 2
rv = "CKR_DEVICE_ERROR"

[[rule]]
fn = "C_DestroyObject"
of_label = "k"
rv = "CKR_OK"

[[rule]]
fn = "*"
from_seq = 40
rv = "CKR_DEVICE_REMOVED"

# The process ends at the call, before the call reaches the module (std::process::abort). This
# models a crash, a kill or an out-of-memory error between two of a run's writes.
[[rule]]
fn = "C_UnwrapKey"
call = 4
abort = true
```

**Failing one half of an operation.** `C_Sign` and the functions like it end the operation that
`C_SignInit` began, also when they fail. A rule that answers in place of the module
(`when = "before"`), or a rule on the call that only asks for the output length, leaves the
real operation open, and the module then refuses what the client does next. To model a module
that fails the operation, fail the call that does the work, after it runs: `call = 2` and
`when = "after"` for a client that asks for the length first.

**Labels to handles.** The shim resolves `of_label`, `from_label`, `add_label`, `use_label`,
`wrap_label` and `replace_label` through a session of its own (`C_OpenSession` on the caller's
slot, which it reads from `C_GetSessionInfo`), so that a resolution never interrupts a search
that the caller has open. The session is read-only. It is read-write only where the module
refuses a read-only session because the caller holds an SO session
(`CKR_SESSION_READ_WRITE_SO_EXISTS`). This works because object handles are valid across all of
an application's sessions.

### The trace

With `P11_FAULT_TRACE`, the shim appends one JSON line per call to the file. It opens the file
with `O_APPEND`, so that the lines of the separate processes of a test run interleave as whole
lines:

```json
{"exe":"cakeys","fn":"C_SignInit","mechanism":4164,"n":2,"pid":4711,"rule":null,"rv":"CKR_OK","seq":17}
```

`n` is the call's number among the calls of its function in the process, and `seq` is its
number among the calls of every function (both are counted from 1). These are the numbers that
`call`, `nth` and `from`, and `from_seq` count.

**Public values.** With `P11_FAULT_RECORD_VALUES=public` (beside `P11_FAULT_TRACE`, which it
requires), a line also records the values that a test compares with what the token holds, and
only public ones (`record.rs`). `"values": [[type, "hex"], ...]` holds what
`C_GetAttributeValue` returned of `CKA_EC_POINT`, `CKA_EC_PARAMS`, `CKA_PUBLIC_KEY_INFO`,
`CKA_MODULUS`, `CKA_PUBLIC_EXPONENT` and tpm2-pkcs11's `CKA_TPM2_PUB_BLOB`, and `CKA_VALUE` only
of a certificate. `"signed": {"data": "hex", "signature": "hex"}` holds the nonce and the
attestation's signature of a `C_Sign` that ends a TPM2 certification (`CKM_TPM2_CERTIFY`,
`CKM_TPM2_CERTIFY_OBJECT`). The shim records no template that a caller sends (it may carry key
material) and no other signature. Any other value of the variable, or `public` without a trace,
is refused and never ignored, so a test that asks for values never reads a trace without them.

The function and the return value are written as names. What the call was about (the
`mechanism`, here `CKM_ECDSA_SHA256`, the attribute types, the classes, ...) is written as
numbers, which the reader maps to names (`trace.rs`). This is the trace of PLAN.md A1: with
`CAKEYS_TRACE_DIR`, `nix/test-tokens.sh` puts every module of a test behind a tagged copy of the
shim, and the trace shows which functions, mechanisms, attribute types and return values cakeys
really meets on each reference token.

The shim reads what a call returns through its arguments (the flags of an info structure, the
classes and key types of a `C_GetAttributeValue` template) only when the real call ran and
returned `CKR_OK`, because a rule that answered in place of the module filled nothing. A call
that the shim fails itself (for example, when a label that a rule names resolves to no object)
also has its line, with the `CKR_GENERAL_ERROR` that the caller received and the reason under
`"fatal"`.

## Testing the shim itself

1. **Unit tests** (the rlib) check that plans parse, refuse unknown names and fields, and match
   the n-th call, and that an attribute is written into the caller's entry. Against a fake
   module made of the test's own functions, they check the hooks (`add_label` adds once per
   search, and `corrupt` stays inside the caller's buffer), the trace of a failed call, and the
   table's version.
2. **Parity**: the reference suite runs a third time, through the shim with no plan, in front of
   SoftHSM (`tests/fault.rs`, like `tests/softhsm.rs`, with a `Reference` that names
   `libp11_fault.so`). It must pass exactly as it passes without the shim. This proves that the
   forwarder changes nothing before any test relies on it to inject faults.
3. **Another client**: in the Nix check, `pkcs11-tool --module libp11_fault.so` lists the slots,
   and then, under a plan that fails `C_GetSlotList`, fails with that return value. This tests
   the claim that any client can load the shim.

## What cakeys tests with it

The liar matrix (`tests/liars.rs`, with its table `tests/liars/cakeys.toml` and its runner
`tests/common/liars.rs`) tells each lie, as a plan, to each verb of cakeys about each kind of
object. The objects are five private keys, one for each proof of possession (`pop-sign`,
`pop-sign-pin`, `pop-ecdh`, `pop-decrypt`, `pop-unwrap`), four secret keys with different
commitments (`cmac` and `kcv-ecb`, an HMAC, `kw`, and wrap-rebind), a certificate, two data
objects and a public key. Each object sits beside another object of its kind. There is one test per class of lie. Every cell asserts its exit
code, the rule and the device bit of its output row, that the lock and the token are as the run
found them (or how they changed, and why), and that its rule fired in the trace. `liar_lint.rs`
checks that every rule of the plan is covered by a cell, a unit test or an exemption, and that
every (lie class, verb, object class) has a cell or an `na` row that gives the reason. The
matrix took over the table of lies in `tests/fault.rs`, whose rows were, on SoftHSM [run]:

| The lie | `check` gives |
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

**Found with it.** A swapped RSA key under `pop-decrypt` was reported as unavailable (16). The
token answers `CKR_ENCRYPTED_DATA_INVALID`, because OAEP decryption under the wrong key fails
outright and never yields a wrong plaintext to compare. The challenge was encrypted to the
public key that the identity names, so that answer means that the token used another key.
`CKR_ENCRYPTED_DATA_INVALID`/`_LEN_RANGE` and `CKR_WRAPPED_KEY_INVALID`/`_LEN_RANGE` are
therefore now a conflict (13). A module that answers with a general error instead (SoftHSM's
`C_UnwrapKey`) stays unavailable, because nothing in that answer says which case it is.

`each_lie_kind_fires` covers each rule kind added since then, with one row each on a token of
its own (`told`). Each row gives the rule, the run, the exit code and the message, and the
functions on which the trace shows the rule fired. Another key wrapped (`wrap_label`) under a
secret key's wrap-rebind gives 10, because the session copy that the commitment is computed on is
another key's. Each matcher has a row where it fires and, where the point is what the matcher
leaves alone, a row where it must not fire. `of_label` fails the attribute reads of `k` (16) and
not those of `k2`. `nth` and `from` fire on the call that they count to (the trace's `n`).
`fn = "*"` with `from_seq` fails every call from a run's first signing on (16) and none before
it. `mechanism`, `class` and `key_type` each fail one call (15, 16, 16) and not another. Another
key pair found (`replace_label`), a corrupted wrap commitment, and a transcoded wrap commitment
each give 10. A transcoded wrap-rebind still verifies (the unwrap undoes the padding), and a
replayed signature fails the second key's proof (13). Under `P11_FAULT_RECORD_VALUES=public`, a
`check` records `k`'s EC point as the token holds it and nothing outside the public attributes,
and `=all` is refused.

A second test, `a_creation_that_cannot_be_identified_is_undone_or_reported`, covers §8.1's
"refused operations leave nothing behind". A created key whose proof then fails is removed
again, and where `C_DestroyObject` fails too, cakeys says that the key is still on the token.

Later rows use three more rule kinds: a signature or a plaintext with one byte changed (13; for
`pop-decrypt`, this is the wrong plaintext that OAEP never yields by itself), the proof's
mechanism no longer listed (15), and the key hidden from every search after its creation (11,
"vanished after creation").

**camigrate** (`crates/camigrate/tests/fault.rs`) puts SoftHSM behind the shim as the source or
the target of a move, with kryoptic on the other side. The rows are: the source's
key-encryption key, its copy of the transport key, and each wrap failing (15); the target's
unwrap of the KEK or of the key (13); the proof after the import (16); the creation and the
commitment on the host path (15); and a certificate that the target then reports as another type
(13). Each row leaves the target without the object and the lock as it was. Where the target
also refuses to delete, camigrate says that what it imported is still there.

**caprobe** (`crates/caprobe/tests/fault.rs`) runs the write probes against the shim. Usage
attributes refused at generation, or a public key without its point, are reported as
undetermined. Another key signing or deriving, a sealed derived secret refused, no derivation at
all, a key that derives while it reports `CKA_DERIVE` false, and a wrap that does not unwrap
each become the row and the note of what the probe saw, and a drift from the committed profile
(15).

Still to add: a derived secret with no value, and a certificate with no readable value. Two rule
kinds that native-pkcs11 shows real modules need (PLAN.md A0b) are also still to add. The first
is an attribute answered with `CKR_ATTRIBUTE_TYPE_INVALID` whose entry is left untouched
(`untouched = true`, beside `drop`, which sets the length to unavailable as the spec requires;
OPEN.md, "rust-cryptoki"). The second is a search that returns only its first match
(`first_only = true` on `C_FindObjects`), against which the locator's exit 12 cannot fire. The
shim cannot make the other search fault, one key under two handles, because `add_label` skips a
handle that the search already returned. A decoy under `add_label` gives cakeys the same two
handles to refuse, though.

## Nix

- p11-fault is a default member of the workspace, so the build makes `libp11_fault.so` beside the
  binaries. The tests of cakeys, caprobe, camigrate and cakeys-cli-common have a dev-dependency
  on p11-fault, so every build of those tests also makes the library. The tests find it beside
  the binaries or among the tests' dependencies in `deps/` (`common::fault_shim`).
- `p11fault` is one more output of the same build (as `caprobe` and `camigrate` are), and it
  holds `lib/libp11_fault.so`: `packages.p11-fault`. The closure of the `cakeys` output does not
  contain it.
- The per-test runner (`nix/test-tokens.sh`) points `P11_FAULT_MODULE` at the test's own SoftHSM
  token for the `fault` and `liars` test binaries, and for cli-common's
  `tests/provider_contract.rs` together with a plan file in the test's directory.

## The 3.x interface, later

A client that finds `C_GetInterface` uses it, and a client that does not find it falls back to
`C_GetFunctionList` (cryptoki, OpenSC and p11-kit all do). v1 therefore exports only the 2.40
entry point. When a 3.x function is needed, the same macro will list the 24 functions of
`CK_FUNCTION_LIST_3_0`, and the shim will export `C_GetInterfaceList` and `C_GetInterface`,
which return its 3.0 table. `pkcs11-abi` (PLAN.md A0b) has the table layouts, in case 3.2's
table is needed too.

## Order

1. Done: the forwarder, the `rv` rules, the trace, the parity test and the `pkcs11-tool` check.
2. Done: the hooks (attributes, flags, handles, malformed lengths) and the first cakeys table.
   The rows listed above under "Still to add" remain.
3. The 3.x interface, when a client needs it.

## Risks

- **ABI.** The shim supports only Linux LP64, as cryptoki-sys's bindings do. Windows packing is
  out of scope.
- **Modules that keep per-process state** (tpm2-pkcs11 reads its store at `C_Initialize`) see
  the same calls through the shim as without it. The parity test runs on SoftHSM, and a kryoptic
  leg and a tpm2-pkcs11 leg can follow if a row needs them.
- **A plan that matches nothing** makes a test pass for the wrong reason. Each test therefore
  asserts in the trace that its rule fired (`"rule"` is set on the line that the rule changed).
