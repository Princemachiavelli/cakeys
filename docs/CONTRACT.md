# The contract with programs that use keys

Status: proposal (2026-11-13), from [`USE_CASE.md`](USE_CASE.md) open item 2. Nothing here is
implemented beyond what the CLI already does; the decisions it needs are listed at the end.

## The idea

A program in any language should use a key the way it uses a file or an HTTP endpoint: a
**declared resource whose use can fail, in a known set of ways.**

- *Declared:* the key is named in `keys.toml` (an object, and a spec saying how a token holds
  it) and pinned in `keys.lock` (the hash of its material). The pair is to a key what a URL plus
  its [Subresource Integrity](https://www.w3.org/TR/SRI/) hash is to a script: where to find it,
  and what it must be.
- *Fallible:* asking for the key either yields it, verified, or fails with one of a few typed
  errors the program handles like `ENOENT` or a `404`, instead of trusting a PKCS#11 URI it has no
  way to check.

What the program gets on success is the verified **URI** (and the IDs it was verified by),
never key material: it then signs, decrypts or derives through its own PKCS#11 library with that
URI, as it would today.

## What a caller asks, and gets

| Ask | Today's form | Success | Never |
|---|---|---|---|
| "The key `signing`, verified" | `cakeys check signing` | the URI on stdout, exit 0 | writes the lock |
| "…by this scheme" | `cakeys check signing.id.rfc7093m4` | as above, only if that scheme is pinned | passes on another scheme |
| "What is on the token?" | `cakeys resolve <spec> --token <t>` | JSON: `uri`, `ids`, `mode`, `binding`, `policy`, `immutables`, `specDigest`, … | compares with the lock |
| "Make it, then pin it" | `cakeys create`/`realise` | JSON, and the lock recorded | regenerates a pinned key |

`check` is the one a program calls before each use: it finds the object by its locator, checks
its type and policy, proves possession for a private key, and compares the IDs with the lock.

Messages a caller does not need to act on (notes, warnings, `created …`) go to stderr; stdout
carries only the result.

## The error model

Every failure has one exit code, the same for every verb (`KmError::exit_code`). Each maps onto
an error programs already handle:

| Exit | Meaning | Like | Retry? | Typical cause |
|---|---|---|---|---|
| 0 | ok | 200 | — | |
| 10 | hash mismatch: the token holds other material than the lock pins | a failed checksum / SRI mismatch | never blindly | a swapped or regenerated key; `expected: <none>` is first use (nothing pinned yet) |
| 11 | not found under the locator | `ENOENT`, 404 | after provisioning | key deleted, wrong token, autoCreate off |
| 12 | ambiguous: several objects match | 300 | no | duplicate labels or `CKA_ID`s |
| 13 | conflict: the object is not what the spec says | 409 | no | wrong type or policy, failed proof of possession, a foreign public key under the locator |
| 14 | precondition failed: the realisation moved | 412 | after review | spec or policy changed since recorded, a downgrade, a replaced object |
| 15 | unsupported: this token cannot do what the spec needs | 501, `ENOTSUP` | no | a mechanism or key type the module lacks |
| 16 | unavailable: the token cannot be used now | 503, `EIO` | sometimes | token absent, PIN locked or on its last try, module not loadable |
| 17 | invalid config, lock or spec | 400, `EINVAL` | no | a schema error, a malformed reference, an unknown token |
| 1 | other (I/O) | 500 | sometimes | the lock unreadable |
| 2 | usage (CLI only) | — | no | bad arguments |

Two distinctions a binding should keep rather than flatten into "failed":

- **10 vs 11:** "the key is there but is not the pinned one" is a security event; "the key is
  not there" is an operational one.
- **First use** (10 with `expected: <none>`) is "nothing pinned yet", the state before
  `realise`; a binding should surface it as its own case, like a missing lock entry.

## Options for the binding

**(a) The CLI is the binding.** Any language runs `cakeys check` (or `resolve`) per use and
reads the exit code and stdout. It works today, in every language, with no new code. The cost:
the CLI's output becomes a contract — the JSON fields, stdout carrying only the result, the exit
codes — so it needs a version and a stability promise, and each use costs a process and a token
open.

**(b) A library with a C ABI**, over `cakeys-pkcs11`, wrapped per language (Python, Go, Node,
Java). One token open can serve many checks, and errors are typed values rather than exit codes.
[`SCOPE.md`](SCOPE.md) ("Library or crate use") keeps a stable Rust or C API out of scope until
a real consumer needs it; this would be that consumer.

**(c) Native packages per language** that reimplement the checks. Rejected unless (a) and (b)
both fail a real need: the identity rules, proofs and lock rules would have to stay identical in
every implementation.

## The gap between check and use

A program that runs `check` and then opens the URI with its own PKCS#11 library uses the key a
moment after it was verified. A key swapped in that moment passes. The Nix pre-use check has the
same gap, bounded by the build.

- With (a), the gap stays; it is narrow, and a swap still fails the next check. This is
  accepted (2026-11-13) as the contract: the same one a program has with a file it checks and
  then opens, or an HTTP resource it validates and then fetches. What cakeys promises is
  *verified at check time*.
- An option under (a): `check` also returns the time it verified, so a caller can refuse a
  result older than it tolerates. That bounds how stale a verification may be; it does not
  close the gap (a swap one second after the check passes any age limit), and a cached Nix
  build has no check to age.
- With (b), the library could close it by handing the program the session and object handle it
  verified, so the program signs with exactly that object. That ties the program to the
  library's PKCS#11 session rather than its own.

## To decide

1. Which option is the contract: (a) alone, or (a) now and (b) when a consumer asks.
2. For (a): the JSON schema's version and stability promise, and whether `check` grows a
   `--json` form returning the URI with the IDs it was verified by and the time it verified.
3. Whether closing the check-then-use gap is worth binding programs to the library's session.
4. How a binding surfaces notes and warnings (provenance drift, a PIN counter running low): a
   side channel, a log, or dropped.
