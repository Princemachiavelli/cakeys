# cakeys: pinning and verifying keys

`cakeys` checks that a token still holds the key material its lock pins, before each use. It
keeps the verbs below, the Nix library, the NixOS module and the sandbox hook. Measuring modules
is [caprobe](CAPROBE.md)'s job and moving keys [camigrate](CAMIGRATE.md)'s; all three take
`--config` and `--module`, and share the exit codes. What the identities and the lock rules are:
[DESIGN.md](DESIGN.md).

```console
$ cakeys --config keys.toml [--lock keys.lock] [--module <token>=<path> ...] <verb> ...
```

`--config` and `--lock` also come from `CAKEYS_CONFIG` and `CAKEYS_LOCK`; the lock defaults to
the config path with a `.lock` extension. Notes and warnings go to stderr; stdout carries only
the result.

## Verbs

HTTP-like: `resolve`, `verify` and `check` are GETs and never write; `realise` and `create` are
PUTs with If-None-Match; `delete` is a DELETE with If-Match.

| Verb | Semantics |
|---|---|
| `validate` | Static check of modes, opt-ins, types and provider names; touches no token. Then the capability-profile gate ([CAPROBE.md](CAPROBE.md)): each spec's needs — its commitments' mechanisms, generating its type, curve and size when `autoCreate`, an attestation — against its token's profiles, resolved from the lock's recorded module and token or keys.toml's `provider`; a profile's *no* is refused (15) naming the profile, *unknown* is a note. |
| `resolve <spec> --token` | GET: find (exactly one), check type and policy, compute IDs, print JSON. Never writes. For a private key, every public key object under the locator must hold its own public key — a consumer may select the public half by the locator alone — else a conflict (13, `a_foreign_public_key_conflicts_and_is_never_deleted`); `verify`, `realise` and `check` resolve the same way. |
| `verify <spec> --token` | GET with If-Match against the lock; prints the URI. |
| `realise <spec> --token [--no-update-lock]` | PUT, recording what the lock lacks (DESIGN §3.5), and prints the resolved JSON. If absent and `autoCreate`: refused (14) when the lock already pins the object's material — generated material could never match (`autocreate_never_fights_a_locked_identity`). **If-None-Match** — never create when anything sits under the locator (`never_create_over_an_occupied_locator`), nor from a session without login, which cannot see private objects there (16). Then create, compute and compare. If the identity of a just-created object cannot be established, it is destroyed (`tpm2_identity_failure_after_create_leaves_nothing`); on a module that cannot delete keys (ykcs11) the key stays and the message says so. Re-running never duplicates (`ec_lifecycle`). |
| `create [<spec>] [--token T] [--no-update-lock]` | PUT, asked for explicitly: every selected (spec, token) pair whose object the lock does not pin yet is created and recorded as `realise` would with `autoCreate`, which only opts the first-use flows (`realise`, `check`) into creating; pinned, adopted-only (certificates, public keys, data) and `publicOnly` pairs are skipped with a note. Naming both the spec and `--token` creates that pair or says why not (a pinned object its token lost: 14). A name that selects nothing is refused (an unknown spec 11, an unknown token 17, a spec without that token 11), never an empty success. One token is open at a time, so tokens of one module follow each other. Prints the realised objects as a JSON array; what was created before a failure — opening the next token included — is still recorded (`create_makes_keys_without_autocreate`, `create_records_what_it_made_before_a_failure`). |
| `delete <spec> --token [--if-match ID] [--no-update-lock]` | DELETE with If-Match. Absent is success, even without a lock — but a session without login cannot see a private object, so it never reports one absent (16); a present object with no expected ID is never deleted (`ec_lifecycle`), and only what was identified is removed: a private key's public half only when it holds the same key, never another key's public object under the locator (`delete_removes_only_what_it_identified`); a key on a module whose delete leaves it in place (ykcs11) is refused (15), never claimed. Unless `--no-update-lock`, it removes the realisation but keeps `objects.<name>.ids`, since the material may live on other tokens. |
| `check <obj>[.id.<scheme>] [--token] [--spec]` | The pseudo-FOD pre-use check: realise without writing the lock, print the URI. Schemes the spec or token can never compute are refused before anything is created (`scheme_the_token_lacks_is_refused_before_create`). |
| `gc [--apply]` | Print lock entries `keys.toml` no longer names, as table names; `--apply` removes exactly what it printed, holding the update lock . Live objects keep their `ids` (`gc_prints_then_removes_stale_entries`). |

## Exit codes

One code per failure, the same for every verb and all three tools (`KmError::exit_code`), each
mapped onto an error programs already handle. The codes are frozen (DESIGN §10).

| Exit | Meaning | Like | Retry? | Typical cause |
|---|---|---|---|---|
| 0 | ok | 200 | — | |
| 10 | hash mismatch: the token holds other material than the lock pins; prints `got: sha256-…` | an SRI mismatch | never blindly | a swapped or regenerated key; with nothing pinned yet, first use |
| 11 | not found under the locator | `ENOENT`, 404 | after provisioning | key deleted, wrong token, `autoCreate` off |
| 12 | ambiguous: several objects match | 300 | no | duplicate labels or `CKA_ID`s |
| 13 | conflict: the object is not what the spec says | 409 | no | wrong type or policy, a failed proof of possession, a foreign public key under the locator |
| 14 | precondition failed: the realisation moved | 412 | after review | the spec or policy changed since recorded, a downgrade, a replaced object |
| 15 | unsupported: the token cannot do what the spec needs | 501, `ENOTSUP` | no | a mechanism or key type the module lacks |
| 16 | unavailable: the token cannot be used now | 503, `EIO` | sometimes | token absent, PIN locked or on its last try, module not loadable |
| 17 | invalid config, lock, spec or token options | 400, `EINVAL` | no | a schema error, a malformed reference, an unknown token |
| 1 | I/O or other | 500 | sometimes | the lock unreadable |
| 2 | command-line usage | — | no | bad arguments |

Two distinctions a caller should keep rather than flatten into "failed": 10 against 11 ("the
key is there but is not the pinned one" is a security event; "the key is not there" an
operational one), and first use (10 with nothing pinned), the state before `realise`.

## The contract with programs that use keys

A program in any language uses a key the way it uses a file or an HTTP endpoint: a declared
resource whose use can fail in a known set of ways. keys.toml and keys.lock are to a key what a
URL and its Subresource Integrity hash are to a script. On success the program gets the verified
URI, never key material, and signs or decrypts through its own PKCS#11 library as before.

| Ask | Form | Success | Never |
|---|---|---|---|
| "The key `signing`, verified" | `cakeys check signing` | the URI on stdout, exit 0 | writes the lock |
| "…by this scheme" | `cakeys check signing.id.rfc7093m4` | as above, only if that scheme is pinned | passes on another scheme |
| "What is on the token?" | `cakeys resolve <spec> --token <t>` | JSON: `uri`, `ids`, `mode`, `binding`, `policy`, `immutables`, `specDigest`, … | compares with the lock |
| "Make it, then pin it" | `cakeys create` / `realise` | JSON, and the lock recorded | regenerates a pinned key |

Today the CLI is the binding. **The check is not the use** (accepted 2026-11-13): a program that
runs `check` and then opens the URI uses the key a moment after it was verified, as with a file
it checks and then opens. What cakeys promises is *verified at check time*; a swap still fails
the next check. A library binding, a JSON form of `check` and the output's stability promise
are open ([OPEN.md](OPEN.md)).

## Nix integration

### Library (`lib.mkKeys`, builtins only)

One calling convention: **every object is a function**. The call resolves the object's one
(spec, token) pair — the arguments are optional when there is exactly one — and returns plain
data, so consumers destructure once and reuse:

```nix
signing = keys.signing { token = "softhsm"; };      # { } when the object has one pair
shared  = keys.shared { token = "softhsm"; spec = "shared-sign"; };  # several specs on one token
```

- The result carries `type`, `id.<scheme>` (`pubkeyhash` is an input alias), the resolved
  `spec`/`token`, and the pair's realisation: `uri`, `mode`, `specDigest`, `module`, `tokenInfo`,
  `functions` (mechanism → `true`), `requiredSystemFeatures` (`<featurePrefix><token>` unless keys.toml
  names one) and `check`.
- **`check`** is the shell command for the pre-use check (prints the URI); `scheme = "certhash"`
  requires that identity, and the resolved pair is passed explicitly. Interpolating config, lock
  and module makes them build inputs. Like `id`, `type` and `requiredSystemFeatures`, it is usable
  before anything is recorded in the lock — the first-use pseudo-FOD flow; only the realisation's
  own fields throw on a missing record.
- A call that does not name exactly one pair throws, listing the choices — so does a missing
  realisation, naming the `realise` command to run.
- Tested by `checks.lib` (synthetic fixture) and `checks.vm` (consumer built in the guest sandbox).

### Pseudo-FOD check

A consumer derivation requires the token's feature and runs `check` before using the URI.

1. **First use** creates the key (with `autoCreate`) and fails with `got:` — `check` never
   writes, and in the sandbox it could not.
2. Record the ID out of band (`realise`, outside the sandbox; it writes the lock by default).
3. Every later build verifies first.

**Caveat:** a cached consumer is not rebuilt, so the token is not re-contacted; `nix build --check`
forces it. The VM test covers all of this.

### NixOS module (`nixosModules.default`, `services.cakeys`)

- **`tokens.<n>.{sandboxPaths, pcscd}`.** Each token advertises the system feature
  `<featurePrefix><n>` (`services.cakeys.featurePrefix`, default `token-`, the same default as
  `lib.mkKeys`'s `featurePrefix`); keys.toml's `tokens.<t>.systemFeature` names one of these when a
  config's token name differs from the host's. Paths are **not** global `extra-sandbox-paths`: a pre-build-hook
  (`nix/sandbox-hook.sh`, bash + jq over `nix derivation show`) grants them only to builds whose
  `requiredSystemFeatures` name the token's feature.
  - It reads plain, structured-attrs (JSON v4) and `env.__json` derivations.
  - It emits only existing paths from the module's map.
  - It always exits 0 and grants nothing on error.
  - Test: `checks.module`, *the hook grants token paths only to builds requiring the token's feature*.
- **`sandbox.pcscd.enable`:** pcscd, plus a polkit rule for nixbld or the auto-allocated UID range,
  plus `PrivateUsers=false` with auto UIDs.
- **`sandbox.tpm2.enable`:** a udev ACL on `/dev/tpmrm*` for every build GID: the nixbld GID, or,
  with `auto-allocate-uids`, each 65 536-ID slot's first UID, which is also its GID. Test:
  `checks.tpm`, with auto UIDs, uid-range, nixbld, and a stripped-ACL control.
- **`sandbox.uidRange.enable`:** `auto-allocate-uids` and the `uid-range` feature.
- **`checks.<n>`:** a oneshot `cakeys-check-<n>` unit running `check`, required by the
  units that use the key — `checks.module`.

### What real builds may reach

- **Allowed:** a **p11-kit forwarding socket** (`p11-kit server` outside the sandbox) or a **real
  TPM** (`/dev/tpmrm0`).
- **Never** a token database: SoftHSM files allow offline PIN guessing and key extraction.
- **SoftHSM paths in tests are for testing only.**
- **PINs:** p11-kit login is per client (`p11kit_login_is_per_client`). A build that uses private
  objects needs the PIN, through a granted file; `publicOnly` needs none.
