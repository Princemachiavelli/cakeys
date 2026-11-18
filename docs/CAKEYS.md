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

HTTP-like, over two stores, the token and the lock. `resolve`, `verify` and `check` are GETs and
never write either. `create` is the one verb that writes keys to a token, a PUT with
If-None-Match; `delete` is a DELETE with If-Match. `lock` writes only the lock: it records
what is there now, as a lock file does.

Every verb but `validate` and `gc` takes one address, the object first:
`<object> [--spec S] [--token T]`. The object may be left out when `--spec` names it; `--spec`
and `--token` narrow it where keys.toml realises the object more than once (else 12). Only
`check` also takes `<object>.id.<scheme>`. A name keys.toml lacks, or an address no pair
matches, is 17 (`every_verb_names_the_object_first`). `create`'s address selects: what it
leaves out selects every one, so `create` alone selects every pair. `check --token T` alone
checks every object on the token.

| Verb | Semantics |
|---|---|
| `validate` | Static check of modes, opt-ins, types and provider names; touches no token. Then the capability-profile gate ([CAPROBE.md](CAPROBE.md)): each spec's needs — its commitments' mechanisms, an attestation — against its token's profiles, resolved from the lock's recorded module and token or keys.toml's `provider`; a profile's *no* is refused (15) naming the profile, *unknown* is a note. Generating the type, curve and size is asked only of the pairs `create` makes (`origin = "create"`, not yet pinned). |
| `resolve <address>` | GET: find (exactly one), check type and policy, compute IDs, print JSON. Never writes. For a private key, every public key object under the locator must hold its own public key — a consumer may select the public half by the locator alone — else a conflict (13, `a_foreign_public_key_conflicts_and_is_never_deleted`); `verify`, `lock` and `check` resolve the same way. |
| `verify <address>` | `check`, by another name. |
| `lock <address> [--no-update-lock]` | The lock verb: find the object, compare it with the lock and record what the lock lacks or what changed around it (DESIGN §3.5), and print the resolved JSON. It never creates the object: absent is not found (11), naming `cakeys create`. It does provision a TPM Attestation Key a realisation needs (DESIGN §3.7). |
| `create [<address>] [--dry-run] [--skip-unsupported] [--no-update-lock]` | PUT with **If-None-Match**, the one verb that makes keys: every selected (spec, token) pair with `origin = "create"` whose object the lock does not pin yet is created, then recorded as `lock` records it. One whose object the lock pins is never made again: the key under its locator is verified as `check` verifies it and left alone with a note, one that does not match fails with `check`'s code (10 for other material, 14 for a realisation the lock does not record), and one its token lost is 14. The pairs of other origins are skipped with a note. A key the lock does not pin, already under its locator, ends the run with 19, whatever it holds and before anything is asked of the token (`lock` is the verb for a key that is there). Before any token is opened, each is checked against the capability profiles (the `validate` gate): a pair they say cannot be made refuses the whole run (15) and nothing is created, unless `--skip-unsupported`, which creates the rest and warns; `--dry-run` prints what each pair would get (`create`, `verify`, `skip`, `refuse`) and why, as JSON, opening no token and writing nothing (`create_checks_the_profiles_before_it_makes_anything`). Refused (14) when the lock already pins the object's material — generated material could never match (`create_never_fights_a_locked_identity`); never over anything under the locator (`never_create_over_an_occupied_locator`), nor from a session without login, which cannot see private objects there (16). If the identity of a just-created object cannot be established, it is destroyed (`tpm2_identity_failure_after_create_leaves_nothing`); on a module that cannot delete keys (ykcs11) the key stays and the message says so. Re-running never duplicates: the second run verifies what the first made, and exits 0 when it all matches (`create_makes_keys_and_nothing_else_does`). An address naming one pair (an object or `--spec`, and `--token`) creates or verifies it, or says why not (an `import`, `file` or `adopt` pair: 17; a key already there the lock does not pin: 19; a pinned object its token lost: 14). A name that selects nothing is refused (17), never an empty success. One token is open at a time, so tokens of one module follow each other. Prints the realised objects as a JSON array; what was created before a failure — opening the next token included — is still recorded (`create_makes_keys_and_nothing_else_does`, `create_records_what_it_made_before_a_failure`). |
| `delete <address> [--if-match ID] [--no-update-lock]` | DELETE with If-Match. Absent is success, even without a lock — but a session without login cannot see a private object, so it never reports one absent (16); a present object with no expected ID is never deleted (`ec_lifecycle`), and only what was identified is removed: a private key's public half only when it holds the same key, never another key's public object under the locator (`delete_removes_only_what_it_identified`); a key on a module whose delete leaves it in place (ykcs11) is refused (15), never claimed. Unless `--no-update-lock`, it removes the realisation but keeps `objects.<name>.ids`, since the material may live on other tokens. |
| `check <address>` | The pseudo-FOD pre-use check: verify the pair the address names against the lock (If-Match), in a read-only session, and print the URI. It never writes: not the lock, not the token, not a TPM's persistent handles. An object that is not there is not found (11, naming `cakeys create`); one that is there but not pinned fails with its `got:` (18). Schemes the spec or token can never compute are refused before the object is looked for (`scheme_the_token_lacks_is_refused_before_create`). A key's PIV attestation chain is held to its certificates' validity periods by the system clock (never `SOURCE_DATE_EPOCH`, which Nix sets to 1980): `--at <YYYY-MM-DDTHH:MM:SSZ>` judges it at another time, `--ignore-validity` skips the dates with a note; a certificate outside its period is a conflict (13). `lock`, `create` and camigrate read no clock (`check_judges_attestation_dates_at_the_time_asked`). |
| `check --token T` | `check` of every (spec, token) pair keys.toml places on `T`, in one read-only session; a failing pair does not stop the others. All pass: prints the module file the check loaded (what `--uri-module` names), for a consumer that is handed the token rather than one key. Any fails: nothing on stdout, one stderr line per failure led by its own code (`exit 11: '<object>' (spec '<spec>'): …`), and 20. The token itself unopenable is its own code (16), never 20; a token nothing is placed on, and `--format`, `--uri-module` or `--uri-pin`, which shape a URI, are 17 (`check_token_checks_every_object_on_it`). |
| `gc [--apply]` | Print lock entries `keys.toml` no longer names, as table names; `--apply` removes exactly what it printed, holding the update lock . Live objects keep their `ids` (`gc_prints_then_removes_stale_entries`). |

## Exit codes

One code per failure, the same for every verb and all three tools (`KmError::exit_code`), each
mapped onto an error programs already handle. The codes are frozen (DESIGN §10).

| Exit | Meaning | Like | Retry? | Typical cause |
|---|---|---|---|---|
| 0 | ok | 200 | — | |
| 10 | hash mismatch: the token holds other material than the lock pins; prints `got: sha256-…` | an SRI mismatch | never blindly | a swapped or regenerated key |
| 11 | not found under the locator | `ENOENT`, 404 | after provisioning | key deleted, wrong token, not created yet (`cakeys create`) |
| 12 | ambiguous: several objects match | 300 | no | duplicate labels or `CKA_ID`s |
| 13 | conflict: the object is not what the spec says | 409 | no | wrong type or policy, a failed proof of possession, a foreign public key under the locator |
| 14 | precondition failed: the realisation moved | 412 | after review | the spec or policy changed since recorded, a downgrade, a replaced object |
| 15 | unsupported: the token cannot do what the spec needs | 501, `ENOTSUP` | no | a mechanism or key type the module lacks |
| 16 | unavailable: the token cannot be used now | 503, `EIO` | sometimes | token absent, PIN locked or on its last try, module not loadable |
| 17 | invalid config, lock, spec or token options | 400, `EINVAL` | no | a schema error, a malformed reference, an unknown token |
| 18 | first use: the lock pins nothing to compare with yet; prints `got: sha256-…` | 428 | after `lock` records it | a key just created or adopted; a scheme the lock does not pin, asked for by name |
| 19 | already exists: `create` found a key the lock does not pin under the locator and made nothing | `EEXIST`, 412 | no | `create --no-update-lock` run twice; a key something else put there (`lock` records it) |
| 20 | objects failed: `check --token` found objects on the token that fail their check; each is listed on stderr with its own code | 207 | per object | any of 10–18 for one of the token's objects |
| 1 | I/O or other | 500 | sometimes | the lock unreadable |
| 2 | command-line usage | — | no | bad arguments |

Two distinctions a caller should keep rather than flatten into "failed", each with its own
code: 10 against 11 ("the key is there but is not the pinned one" is a security event; "the key
is not there" an operational one), and 10 against 18 (a mismatch against a pinned ID, against
first use with nothing pinned: the state before `lock`, reviewed through the `got:` line).

## The contract with programs that use keys

A program in any language uses a key the way it uses a file or an HTTP endpoint: a declared
resource whose use can fail in a known set of ways. keys.toml and keys.lock are to a key what a
URL and its Subresource Integrity hash are to a script. On success the program gets the verified
URI, never key material, and signs or decrypts through its own PKCS#11 library as before.

| Ask | Form | Success | Never |
|---|---|---|---|
| "The key `signing`, verified" | `cakeys check signing` | the URI on stdout, exit 0 | writes the lock |
| "…by this scheme" | `cakeys check signing.id.rfc7093m4` | as above, only if that scheme is pinned | passes on another scheme |
| "…as a key file" | `cakeys check signing --format pkcs11-provider-pem` | pkcs11-provider's key file (`PKCS#11 PROVIDER URI`, as its `uri2pem.py` writes) wrapping the URI; a warning when the key has no `CKA_ID` | wraps anything but a private key (15) |
| "…with the module and PIN" | `--uri-module`, `--uri-pin source` or `value` | the URI with `?module-path=` (the module file the check loaded) and the PIN as `pin-source=file:`/`env:` (`pinFile`/`pinEnv`) or `pin-value=` | adds either unasked; puts a PIN for a token without one (17) |
| "What is on the token?" | `cakeys resolve <object> [--spec s] [--token t]` | JSON: `uri`, `ids`, `mode`, `binding`, `policy`, `immutables`, `specDigest`, … | compares with the lock |
| "Make it, then pin it" | `cakeys create` / `lock` | JSON, and the lock recorded | regenerates a pinned key |

A program names a cakeys object, never a URI: a bare URI only locates, so by itself it is
underdescribed. What `check` hands back is shaped for the program, while the lock's URI stays
the bare locator; the module and the PIN are added only on request, at the check.
pkcs11-provider reads `pin-source` (`file:`, and its own `env:`) and `pin-value`, but not
`module-path`: it takes the module from its configuration or `PKCS11_PROVIDER_MODULE`. p11-kit
and libp11 read `module-path`. A `pin-value` is in whatever the output reaches.
pkcs11-provider finds a private key's public half by `CKA_ID` alone: on a module whose private
key carries no public point (SoftHSM: no `CKA_EC_POINT`, an empty `CKA_PUBLIC_KEY_INFO`), a key
file for a key without `CKA_ID` signs but cannot give OpenSSL the public key (to match a
certificate, say), so `check` warns when the key it verified has none. Activate
OpenSSL's `default` provider before `pkcs11`: SoftHSM 2.7.0 deadlocks otherwise (OPEN.md).

A program that takes its key as a file and cannot be changed to call `check` can still be given
one the check just verified: [`examples/inject/unotify-inject`](../examples/inject/unotify-inject)
runs it under a seccomp filter and answers its open of a path with what a command prints, say
`cakeys check signing --format pkcs11-provider-pem` (or the bare URI, for a program that reads
that). The command runs at each open, a failed check fails the open and the run with its exit
code, and the number of opens can be asserted. It is an example, not a sandbox
([`examples/README.md`](../examples/README.md)).

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

- The result carries only what evaluation knows without the token (review N1, N2): `type` (the
  lock's canonical one once it pins the object, keys.toml's as written before),
  `id.<scheme>` (`pubkeyhash` is an input alias), the resolved `spec`/`token`,
  `requiredSystemFeatures` (`<featurePrefix><token>` unless keys.toml names one) and `check`. No
  URI: the one a consumer uses is the one `check` prints once it has verified the key, never the
  lock's, which nothing has checked at evaluation. Nothing is re-derived from the lock either
  (assurance, mode): `cakeys resolve` says those.
- **`check`** is the shell command for the pre-use check (prints the URI); `scheme = "certhash"`
  requires that identity, and the resolved pair is passed explicitly. The call's `checkArgs` are
  `cakeys check`'s own flags, appended as given and validated by cakeys, as in `keys.signing {
  checkArgs = [ "--format" "pkcs11-provider-pem" "--uri-pin" "source" ]; }`; a `--uri-pin value`
  PIN is in the build log or store path the output reaches. Interpolating config, lock and module
  makes them build inputs. Everything is usable before anything is recorded in the lock — the
  first-use pseudo-FOD flow; `id` is then empty.
- A call that does not name exactly one pair throws, listing the choices; so does a lock whose
  `version` is not 1.
- Tested by `checks.lib` (synthetic fixture) and `checks.vm` (consumer built in the guest sandbox).

### Pseudo-FOD check

A consumer derivation requires the token's feature and runs `check` before using the URI.

1. **Create** the key out of band (`cakeys create`). `check` never creates one: in the sandbox
   it fails as not found (11), naming `cakeys create`.
2. **First use** fails with `got:` (18) — `check` never writes, and in the sandbox it could not.
   Record the ID out of band (`lock`, or `create` itself, which writes the lock by default).
3. Every later build verifies first.

**Caveat:** a cached consumer is not rebuilt, so the token is not re-contacted; `nix build --check`
forces it. The VM test covers all of this.

### NixOS module (`nixosModules.default`, `services.cakeys`)

- **`tokens.<n>.{sandboxPaths, pcscd}`.** Each token advertises the system feature
  `<featurePrefix><n>` (`services.cakeys.featurePrefix`, default `token-`, the same default as
  `lib.mkKeys`'s `featurePrefix`); keys.toml's `tokens.<t>.nix.systemFeature` names one of these when a
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
  units that use the key — `checks.module`. `args` are `check`'s own flags, appended as given
  (`[ "--format" "pkcs11-provider-pem" "--uri-pin" "source" ]`). `outputFile` (with
  `outputGroup`) writes what it prints to a file instead of the journal: removed before each
  check, written (0600, or 0640 for the group) only when it passes; `--uri-pin value` requires
  it. In `checks.module` the check writes a key file and the
  service it gates signs with it through OpenSSL and pkcs11-provider.

### What real builds may reach

- **Allowed:** a **p11-kit forwarding socket** (`p11-kit server` outside the sandbox) or a **real
  TPM** (`/dev/tpmrm0`).
- **Never** a token database: SoftHSM files allow offline PIN guessing and key extraction.
- **SoftHSM paths in tests are for testing only.**
- **PINs:** p11-kit login is per client (`p11kit_login_is_per_client`). A build that uses private
  objects needs the PIN, through a granted file; `publicOnly` needs none.
