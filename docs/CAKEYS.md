# cakeys: pinning and verifying keys

`cakeys` checks, before each use, that a token still holds the key material that its lock pins.
This tool provides the verbs below, the Nix library, the NixOS module and the sandbox hook.
[caprobe](CAPROBE.md) measures modules, and [camigrate](CAMIGRATE.md) moves keys. All three
tools take `--config` and `--module`, and they share the exit codes. [DESIGN.md](DESIGN.md)
describes the identities and the rules of the lock.

```console
$ cakeys --config keys.toml [--lock keys.lock] [--module <token>=<path> ...] <verb> ...
```

`--config` and `--lock` can also come from `CAKEYS_CONFIG` and `CAKEYS_LOCK`. The lock defaults
to the config path with a `.lock` extension. Notes and warnings go to stderr, and stdout carries
only the result. `--module <token>=<path>` replaces that token's module for the run. An override
that lacks either half, that names a token that `keys.toml` does not name, or that names a token
twice is invalid (17), and cakeys refuses it before any token opens
(`an_override_that_cannot_apply_is_invalid`).

## Verbs

The verbs follow HTTP semantics over two stores, the token and the lock. `resolve` and `check`
are GETs, and they never write either. Of cakeys' verbs, `create` is the one that makes the keys
that keys.toml declares, and it is a PUT with If-None-Match. `delete` is a DELETE with If-Match.
`lock` writes the lock: it records what is there now. (On the token, `lock` makes only a TPM
Attestation Key that a realisation needs, DESIGN §3.7.)

Every verb except `validate` and `gc` takes one address, with the object first:
`<object> [--spec S] [--token T]`. The object may be left out when `--spec` names it. `--spec`
and `--token` narrow the address where keys.toml realises the object more than once (otherwise
the result is 12). Only `check` also takes `<object>.id.<scheme>`. A name that keys.toml does
not contain, or an address that matches no pair, gives 17 (`every_verb_names_the_object_first`).
`create`'s address selects pairs: each part that the address
leaves out selects every value of that part, so `create` alone selects every pair.
`check --token T` alone checks every object on the token.

The options that every verb takes, before or after the verb, are `-c`/`--config` (keys.toml),
`-l`/`--lock` (by default, keys.toml's path with `.lock`), `--module <token>=<path>`,
`--new-lock` and `--json`. A lock that does not exist is refused
(17) unless `--new-lock` is given, so a mistyped `--lock` never becomes a second lock. `--json`
applies to the reports (`validate`, `gc`). `lock`, `create` and `delete` print JSON arrays
whatever `--json` says. An array has one row per (spec, token) pair that the run reached, and
all rows have one shape, whether the pair passed or failed (review 2026-11-24 C-1;
`every_pair_has_a_row_of_one_shape`). A row has these fields: `object`, `spec`, `token`,
`outcome` (`locked`, `compared`, `created`, `verified`, `deleted`, `would-delete` or `absent`;
for a `create --dry-run` row, `create`, `verify`, `skip` or `refuse`; or `failed`), `exit` (0,
or the failure's code), `rule` (the rule that refused the pair, where one did), `device`
(whether the PKCS#11 return value says that the device, the token or the session failed),
`error`, a dry run's `deferred`, and the verb's own fields beside them (the realisation that
`lock` recorded or that `create` made, as `resolve` prints it). The exit code of a run follows
from its rows. It is 22 if the run wrote the lock, even if a pair failed after the write. The
failed pair's row then shows the failure's code, and a note on stderr says why the run exits
22. Otherwise, the exit code is 0, the code of the one failure, or 20 for several refusals of a
plan (`validate`, `create`), and stderr lists each refusal, led by its code. A run that wrote the lock
exits 22, never 0 and never a failure's code (see "Exit codes"). `--dry-run` (`lock`, `delete`,
`gc`, `create`) writes nothing, and `create --no-update-lock` creates keys without recording
them.

| Verb | Semantics |
|---|---|
| `validate` | A static check of the modes, the opt-ins, the types and the provider names, which opens no token. Then the capability-profile gate ([CAPROBE.md](CAPROBE.md)) checks each spec's needs (its commitments' mechanisms, an attestation) against its token's profiles. The profiles are resolved from the module and the token that the lock recorded, or from keys.toml's `provider`. A profile's *no* is refused (15), and the message names the profile. The provider's own rules come from the same function that the write asks (`ops::static_rules`): where a key may go (`placement`, 17) for a pair that a write puts on the token (because `create` makes it, or because it is imported), and the attestation that the token can give (15; for an imported key, `imported-attestation`). What only the open token or its provider decides is deferred: a profile's *unknown*, or every provider rule when the provider is not in this build or the token's stack does not resolve (there is no `provider`, and nothing is recorded in the lock). Each deferral prints one note per pair and reason, ending with `(deferred: <rule>, …)`, and it is never a pass (`a_provider_known_only_at_open_defers_its_rules_by_name`). Only the pairs that `create` makes (`origin = "create"`, not yet pinned) are asked whether the token can generate their type, curve and size. When the check passes, it prints `<spec> on <token>: mode <mode>` for each pair on stdout. When it is refused, it prints nothing on stdout. One refusal is the run's error, with its own code. Several refusals are each listed on stderr, led by their codes, and the run exits 20 (`validate_prints_the_modes_only_when_it_passes`; review 2026-11-24 §1.4: it exited 15 whatever the codes were). |
| `resolve <address>` | GET: it finds the object (exactly one), checks the type and the policy, computes the IDs, and prints JSON. It never writes. For a private key, every public key object under the locator must hold the private key's own public key, because a consumer may select the public half by the locator alone. Otherwise, the result is a conflict (13, `a_foreign_public_key_conflicts_and_is_never_deleted`). `lock` and `check` resolve in the same way. |
| `lock <address> [--dry-run]` | The verb that writes the lock: it finds the object, compares it with the lock, records what the lock lacks or what changed around the object (DESIGN §3.5), and prints the resolved JSON. `--dry-run` only compares, so a first use gives 18 with its `got:`. It never creates the object: an absent object is not found (11), and the message names `cakeys create`. It does provision a TPM Attestation Key that a realisation needs (DESIGN §3.7). |
| `create [<address>] [--dry-run] [--skip-unsupported] [--no-update-lock]` | PUT with **If-None-Match**. `create` is the one verb that makes the keys that keys.toml declares. It creates every selected (spec, token) pair with `origin = "create"` whose object the lock does not pin yet, and it then records the pair as `lock` records it. A pair whose object the lock pins is never made again: cakeys verifies the key under its locator as `check` verifies it, and it leaves the key alone with a note. A key that does not match fails with `check`'s code (10 for other material, 14 for a realisation that the lock does not record), and a pinned key that its token lost gives 14. The pairs of other origins are skipped with a note. A key that the lock does not pin, but that is already under its locator, ends the run with 19, whatever the key holds, before anything is asked of the token (`lock` is the verb for a key that is already there). Before any token is opened, each pair is checked against the capability profiles (the `validate` gate). A pair that the profiles say cannot be made refuses the whole run (with its refusal's code, mostly 15, or with 20 for several refusals, each listed), and nothing is created. The exception is `--skip-unsupported`, which creates the rest and warns. `--dry-run` prints, as JSON, what each pair would get (`create`, `verify`, `skip`, `refuse`) and why: `reasons` in words, `refusals` as `{rule, exit, error}`, and `deferred` as `{rule, why}`, which are the rules that only the run decides (a token whose provider is known only when it opens defers placement, own-generation, templates and capability). The dry run then opens, read-only, each token that the run would use, and it refuses a write-protected token (`CKF_WRITE_PROTECTED`, 15) as the run does. It reads the token's PIN file. A token that fails there, at its open, at a login or at a search ends the dry run at that pair, as it ends the run (16), and that pair's row is `failed` with the failure's `exit` and `device`, as the run's row is. The dry run asks each pair the token's rules that the run asks just before it writes: another class under the locator (13, `locator-free`), a key there that the lock does not pin (19, `unpinned-exists`), a pinned key that the token lost (14, `pinned-lost`), a session without login (16, `needs-login`), and what the token lists. A refused pair's row is `refuse`, `--skip-unsupported` does not skip it, and the dry run exits with the first refusal's code, as the run would (`a_dry_run_refuses_what_the_run_refuses_on_the_token`; review 2026-11-24 C-4: it once passed with 0). A run that the profiles refuse opens no token and writes nothing (`create_checks_the_profiles_before_it_makes_anything`). `create` is refused (14) when the lock already pins the object's material, because generated material could never match (`create_never_fights_a_locked_identity`). It never creates over anything under the locator (`never_create_over_an_occupied_locator`), and it never creates from a session without login, which cannot see private objects there (16). If the identity of a just-created object cannot be established, cakeys destroys the object (`tpm2_identity_failure_after_create_leaves_nothing`). On a module that cannot delete keys (ykcs11), the key stays, and the message says so. A second run of `create` never duplicates a key: it verifies what the first run made, and it exits 0 when everything matches (`create_makes_keys_and_nothing_else_does`). An address that names one pair (an object or `--spec`, and `--token`) creates or verifies that pair, or says why it does not (an `import`, `file` or `adopt` pair: 17; a key that is already there and that the lock does not pin: 19; a pinned object that its token lost: 14). A name that selects nothing is refused (17), and it is never an empty success. One token is open at a time, so the tokens of one module are handled one after another. `create` prints a row for each pair that it reached (`created`, `verified`, or `failed` with its code, as described above). What was created before a failure, including a failure to open the next token, is still recorded, and the run exits 22 (`create_makes_keys_and_nothing_else_does`, `create_records_what_it_made_before_a_failure`). |
| `delete <address> [--if-match ID] [--dry-run]` | DELETE with If-Match. An absent object counts as success, even without a lock. However, a session without login cannot see a private object, so it never reports one absent (16, `needs-login` above, which includes a data object that no spec declares public), and it keeps the lock. A present object with no expected ID is never deleted (`ec_lifecycle`), and only what was identified is removed. A private key's public half is removed only when it holds the same key, and another key's public object under the locator is never removed (`a_foreign_public_key_conflicts_and_is_never_deleted`). A write-protected token (`CKF_WRITE_PROTECTED`) is refused (15) before any session is opened, also by `--dry-run`, which opens the token read-only. An object that the module does not remove when asked is refused (15, `delete-refused`) before anything is destroyed, also by `--dry-run`. This refusal applies to a key on ykcs11 (the provider says so, before any SO session), and to a class whose module profile row says `delete.<class> = no` (caprobe measured that `C_DestroyObject` leaves the object behind, as with tpm2-pkcs11's private keys on swtpm; `tpm2_delete_is_refused_where_the_module_keeps_keys`). cakeys looks again under the locator for what it destroyed. An object that is still there gives `delete-kept` (16), and the lock keeps the realisation, whatever the module said (`a_delete_the_module_does_not_do_keeps_the_lock`). Every destroy that cakeys makes, including an undo or a rollback, looks again in the same way. `delete` removes the realisation but keeps `objects.<name>.ids`, since the material may live on other tokens, and it prints what happened to each object as a JSON array. `--dry-run` identifies and checks each object as a delete would, and it destroys and writes nothing. |
| `check <address>` | The pseudo-FOD pre-use check: it verifies the pair that the address names against the lock (If-Match), in a read-only session, and prints the URI. It never writes: not the lock, not the token, and not a TPM's persistent handles. An object that is not there is not found (11), and the message names `cakeys create`. An object that is there but is not pinned fails with its `got:` (18). Schemes that the spec or the token can never compute are refused before the object is looked for (`scheme_the_token_lacks_is_refused_before_create`). A key's PIV attestation chain is held to its certificates' validity periods by the system clock (not by `SOURCE_DATE_EPOCH`, which Nix sets to 1980). `--at <YYYY-MM-DDTHH:MM:SSZ>` judges the chain at another time, and `--ignore-validity` skips the dates with a note. A certificate outside its period is a conflict (13). A system clock that reads a time before 1970 is unavailable (16), and the message names the clock (`a_clock_before_the_epoch_is_named`). Every other verb (`lock`, `create`, `resolve`, camigrate) judges the same dates but only warns, so `check` is the verb that enforces them (`check_judges_attestation_dates_at_the_time_asked`). |
| `check --token T` | `check` of every (spec, token) pair that keys.toml places on `T`, in one read-only session. A failing pair does not stop the others. When all pairs pass, it prints the module file that the check loaded (what `--uri-module` names), for a consumer that is given the token rather than one key. When any pair fails, it prints nothing on stdout, one stderr line per failure led by the failure's own code (`exit 11: '<object>' (spec '<spec>'): …`), and it exits 20. A token that cannot be opened gives its own code (16), never 20. A token on which nothing is placed gives 17, and so do `--format`, `--uri-module` and `--uri-pin`, which shape a URI (`check_token_checks_every_object_on_it`). |
| `gc [--dry-run]` | It removes the lock entries that `keys.toml` no longer names, prints each entry as its table name, holds the update lock, and says `updated <lock>` as every writing verb does (22). `--dry-run` prints the entries and removes nothing, and `--json` prints the report as JSON. Live objects keep their `ids` (`gc_prints_then_removes_stale_entries`, `gc_says_what_it_did_through_the_notes`). |

## Exit codes

Each failure has one code, which is the same for every verb and for all three tools
(`KmError::exit_code`), and each code maps onto an error that programs already handle. The
codes are frozen (DESIGN §10). Each tool's `--help` ends with this table's codes and meanings
(`EXIT_CODES`, which `the_exit_code_table_lists_every_code` holds to the rows below). Scripts
read the codes there rather than copy them (`nix/demo.sh`).

| Exit | Meaning | Like | Retry? | Typical cause |
|---|---|---|---|---|
| 0 | ok | 200 | — | |
| 10 | hash mismatch: the token holds other material than the material that the lock pins; prints `got: sha256-…` | an SRI mismatch | never without review | a swapped or regenerated key |
| 11 | not found under the locator | `ENOENT`, 404 | after provisioning | the key was deleted, the token is the wrong one, or the key is not created yet (`cakeys create`) |
| 12 | ambiguous: several objects match | 300 | no | duplicate labels or `CKA_ID`s |
| 13 | conflict: the object is not what the spec says | 409 | no | a wrong type or policy, a failed proof of possession, or a foreign public key under the locator |
| 14 | precondition failed: the realisation changed | 412 | after review | the spec or the policy changed since it was recorded, a downgrade, or a replaced object; camigrate's admin operations inside a Nix build |
| 15 | unsupported: the token cannot do what the spec needs | 501, `ENOTSUP` | no | a mechanism or key type that the module lacks; a delete of an object that the module does not remove (`delete-refused`) |
| 16 | unavailable: the token cannot be used now | 503, `EIO` | sometimes | the token is absent, the PIN is locked or on its last try, or the module cannot be loaded; an object that only a login shows, looked for without a login (`needs-login`, below); a login that the module accepted but that the session does not show (`C_GetSessionInfo`); an object that is still there after the module said that it destroyed it (`delete-kept`) |
| 17 | invalid config, lock, spec or options | 400, `EINVAL` | no | a schema error, a malformed reference, or an unknown token; no lock at `--lock` (or beside keys.toml) without `--new-lock` |
| 18 | first use: the lock pins nothing to compare with yet; prints `got: sha256-…` | 428 | after `lock` records it | a key that was just created or adopted; a scheme that the lock does not pin, asked for by name |
| 19 | already exists: `create` found a key under the locator that the lock does not pin, and it made nothing | `EEXIST`, 412 | no | `create --no-update-lock` run twice; a key that something else put there (`lock` records it) |
| 20 | objects failed: `check --token` found objects on the token that fail their check, or a plan (`validate`, `create`) was refused more than once; stderr lists each failure with its own code | 207 | per object | any of 10–18 for one of the token's objects, or for one pair of the plan |
| 21 | the lock cannot be written (read-only, or inside a Nix build) | 507, `EROFS` | after fixing the path | a writing run whose lock or lock directory is read-only, or that runs inside a Nix build sandbox (refused before any token is opened; `--dry-run` compares instead); a save that failed part-way, after which the token may hold what the lock does not record (`lock` records it) |
| 22 | the lock was written: review and commit it, and retry any failed row | 201 | only its failed rows | a writing run (`lock`, `create`, `delete`, `gc`, camigrate's `import` and `migrate`) that recorded or removed something; the run exits 0 when it changed nothing. A run that fails after it wrote the lock also exits 22: the failed pair's row shows the failure's code, and a note on stderr says why the run exits 22, so a script never misses a written lock (`a_run_that_wrote_the_lock_exits_22_whatever_failed_after`) |
| 1 | I/O or other failure | 500 | sometimes | the lock is unreadable |
| 2 | command-line usage | — | no | bad arguments |

**Seen only after a login** (`needs-login`, review 2026-11-24 B-4). A session without login
cannot see a private object. No verb therefore reports such an object absent (11), reports its
locator free, or deletes it as absent: `check`, `resolve`, `lock`, `create` and `delete`
(`--dry-run` too) end with 16 and keep the lock. cakeys decides which objects are private from
the lock's record of what the token reported (the `CKA_PRIVATE` of that realisation), otherwise
from what the spec declares, and otherwise from the class: a public key or a certificate is
public, and anything else is private. A data object whose spec does not declare `CKA_PRIVATE`
counts as private. A public data object that is not there, on a token without a PIN, therefore
gives 16, not 11 (and a `delete` of it gives 16, not 0). The fix is to lock the object once
where it shows, which records `CKA_PRIVATE = false`
(`private_data_objects_are_identified_when_declared`). The same rule makes the `migrate.file` of
an undeclared data object secret at rest.

A caller should keep two distinctions, each with its own code, rather than reduce them to
"failed". The first is 10 against 11: "the key is there but is not the pinned key" is a security
event, and "the key is not there" is an operational event. The second is 10 against 18: a
mismatch against a pinned ID, against a first use with nothing pinned. A first use is the state
before `lock`, and it is reviewed through the `got:` line.

## Rules and checks

A refusal names the rule or the check that refused it. A JSON row prints the name in its `rule`
field: the rule's name where a rule refused, and otherwise the check's name. Code reads them as
`KmError::rule` and `KmError::check`. A rule is a question that a plan asks before a write; a
check is a comparison that a run makes of what a token, the lock, an attestation or a file
says. A first use (18) names no check, because nothing was compared. A refusal whose input does
not parse as the structure it should be (a certificate that is not DER, a TPM structure that
does not unmarshal, a damaged store row) names neither, and its row has no `rule`.
Every other refusal of 10, 12, 13 or 14 names a rule or a check (`malformed_only_in_parsers`).
Scripts may match on these names: they are stable, and
`check_names_are_stable_and_disjoint_from_rules` holds the two tables below to the code, in
order. The exit code is the refusing error's own; the tables give the usual one.

| Rule | Exit | What the plan asks before a write |
|---|---|---|
| `placement` | 17 | The module may place the key where the spec puts it (the provider's rule). |
| `attestation-cover` | 15 | The provider computes the attestation that the spec opts into, for the object's class. |
| `imported-attestation` | 15 | The provider attests a key that is imported (PIV attests only a key the device generated). |
| `own-generation` | 15, 17 | A module that generates a key only from its own template makes the key as the spec declares it. |
| `templates` | 15, 17 | The provider accepts the templates that the write sends. |
| `capability` | 15 | The token can do what the spec needs: the mechanisms, the generation, the proof and the commitments, by its capability profiles or the open token. |
| `locator-free` | 13 | Nothing of another class is under the locator that a creation or an import is made under. |
| `unpinned-exists` | 19 | No key that the lock does not pin is under the locator that `create` makes the key under. |
| `pinned-lost` | 14 | The token still holds the material that the lock pins, so `create` does not generate other material for it. |
| `needs-login` | 16 | The session is logged in when an object is one that only a login shows. |
| `if-match` | 14 | The object that `delete` would destroy holds the identity that the delete expects. |
| `delete-refused` | 15 | The module removes objects of the class (its profile's `delete.<class>` row, or the provider). |
| `delete-kept` | 16 | What a delete destroyed is no longer under the locator. |
| `lock-writable` | 21 | The lock can be written. |

| Check | Exit | What it verifies |
|---|---|---|
| `identity.material` | 10 | The token's material hashes to the IDs that the lock pins for the object. |
| `pop.sign` | 13 | The private key signed a fresh challenge, and the signature verifies under the public key that the identity is computed from (`pop-sign`). |
| `pop.ecdh` | 13 | The private key derived the secret that the host derived with the public key (`pop-ecdh`). |
| `pop.decrypt` | 13 | The private key decrypted a fresh challenge that the host encrypted to the public key (`pop-decrypt`). |
| `pop.unwrap` | 13 | The private key unwrapped a fresh secret that the host wrapped to the public key (`pop-unwrap`). |
| `public.key-type` | 13 | The public key that a token reports, or that a certificate or a file holds, decodes as a key of the object's declared type and curve. |
| `public.same-key` | 13 | A public key object under the locator holds the private key's public key, and exposes it. |
| `public.key-info` | 13 | The `CKA_PUBLIC_KEY_INFO` that the token reports for a key is the key's own material. |
| `certificate.decodes` | 13 | A certificate object's `CKA_VALUE` is a DER X.509 certificate. |
| `locator.unique` | 12 | One object of the class matches the locator. |
| `cka-id.unique` | 12 | One private key on the token carries the key's `CKA_ID`. |
| `token.unique` | 12 | One token of the module carries the token label. |
| `address.unique` | 12 | The address on the command line selects one (spec, token) pair. |
| `object.type` | 13 | The object's class, key type, curve, size and certificate type are the ones that the spec declares. |
| `policy.attribute` | 13 | Each attribute that the spec declares has the declared value on the token. |
| `lock.type` | 14 | The object's type in keys.toml is the type that the lock recorded. |
| `lock.spec` | 14 | The spec (its object, locator, `publicOnly` and digest) is the one that was realised. |
| `lock.mode` | 14 | The identity mode is at least the mode that the lock recorded. |
| `lock.binding` | 14 | The proof of possession is at least the binding that the lock recorded. |
| `lock.attestation-anchor` | 14 | The attestation has the kind and the root that the lock recorded. |
| `lock.attestation-id` | 10 | The attestation ID is the one that the lock recorded under the same root. |
| `lock.attestation-kept` | 14 | The attestation that the lock recorded is still computed. |
| `lock.schemes-kept` | 14 | The schemes that the lock recorded for the realisation are still computed. |
| `lock.immutables` | 14 | The immutables fixed when the object was made (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`) are not weaker than the lock recorded. |
| `lock.attributes` | 14 | The policy attributes and immutables that the token reports are the ones that the lock recorded. |
| `lock.shared-scheme` | 14 | The IDs computed now share a scheme with the IDs that the lock pins, so they can be compared. |
| `lock.realised` | 14 | The lock records a realisation of the spec on the token. |
| `lock.one-name` | 14 | The lock records the material under one object name of the class. |
| `lock.import-ids` | 14 | The lock pins IDs for an object that is imported, so the imported material can be checked. |
| `lock.same-object` | 14 | A second spec of the same token object does not realise it weaker than the first spec did. |
| `chain.validity` | 13 | Each certificate of an attestation chain is valid at the time that it is judged at. |
| `chain.ca` | 13 | Each issuer is a CA that may sign certificates (`basicConstraints`, its `pathLen`, and `keyCertSign` when it has a `keyUsage`). |
| `chain.critical-extension` | 13 | No certificate of the chain has a critical extension that cakeys does not process. |
| `chain.length` | 13 | The chain has no more links than its attestation allows. |
| `chain.anchor` | 13 | The chain ends at a pinned root. |
| `chain.signature` | 13 | Each certificate's signature verifies under its issuer's key, with the algorithm that the signed part of the certificate names. |
| `attest.scheme` | 13 | The provider attests with the scheme that it advertises. |
| `attest.piv.slot-by-device` | 13 | The PIV slot's attestation certificate was issued by the device's attestation certificate. |
| `attest.piv.slot-key` | 13 | The PIV slot's attestation certificate names the object's public key. |
| `attest.piv.unique` | 12 | One certificate on the PIV token is the slot's, or the device's, attestation certificate. |
| `attest.tpm.ak` | 13 | The TPM's Attestation Key is a cakeys Attestation Key: one key of its label, a restricted P-256 ECDSA-SHA256 signing key fixed to the TPM and its parent, with a public key. |
| `attest.tpm.statement` | 13 | The TPM's statement is a certify statement. |
| `attest.tpm.nonce` | 13 | The certify statement names this run's nonce as its qualifying data. |
| `attest.tpm.name` | 13 | The Name that the statement attests is the Name of the object's public area, as the module or the store reports it and as the TPM loaded it. |
| `attest.tpm.signature` | 13 | The statement's signature verifies against the Attestation Key. |
| `attest.tpm.signer` | 13 | The statement's qualified signer is the Attestation Key. |
| `attest.tpm.material` | 13 | The key in the attested public area is the object's key, of the same kind, and a certified secret key computes the object's commitment. |
| `attest.tpm.immutables` | 13 | What the module reports as `CKA_LOCAL` and `CKA_EXTRACTABLE` is what the TPM certified. |
| `attest.tpm.ek-certificate` | 13 | The EK certificate names the purpose `tcg-kp-EKCertificate` and this TPM's endorsement key. |
| `attest.tpm.credential` | 13 | The TPM activates a credential made for the Attestation Key and the endorsement key to its secret, so the two keys are in one TPM. |
| `host.unwraps` | 13 | The key that the source wrapped for the host unwraps under the host's key. |
| `host.key-type` | 13 | The plaintext key that the host holds is a key of the object's declared type. |
| `import.unwraps` | 13, 16 | A sealed bundle's wrapped key unwraps on the target, so the bundle is intact and was wrapped to the target's transport key (16 where the module says only that the unwrap failed). A dry run defers it. |
| `import.identity` | 10, 13 | What a move hands over or unwraps is the key that the lock pins: its IDs (10) and its proof of possession (13). A dry run defers it. |
| `import.transport` | 10, 14 | The transport key that a sealed move wraps to is the one that the lock pins on the target, under a spec that keys.toml names, and a bundle is made for that target and sealed to that key (10 where the key's hash differs). |
| `import.locked` | 14 | The lock pins what a move checks the moved object by: its IDs, its type, the scheme that pairs a key with its certificate, and a locked key for a key file's identity. |
| `import.binding` | 14 | An EC or Edwards key that a bundle file carries is bound by a proof of possession, because a `token-asserted` binding would rest on the public key that the bundle itself names. |
| `probe.same-key` | 13 | The key that a probe's move brings back is the key that it moved: the host's check value of an AES key, or the commitment that the module computes. |

## The contract with programs that use keys

A program in any language treats a key as a declared resource whose use can fail in a known set
of ways. keys.toml says where the key is, and keys.lock records the hash that the key must
match. On success, the program gets the verified URI, never key material, and it signs or
decrypts through its own PKCS#11 library as before.

| Ask | Form | Success | Never |
|---|---|---|---|
| "The key `signing`, verified" | `cakeys check signing` | the URI on stdout, and exit 0 | writes the lock |
| "…by this scheme" | `cakeys check signing.id.rfc7093m4` | as above, but only if that scheme is pinned | passes on another scheme |
| "…as a key file" | `cakeys check signing --format pkcs11-provider-pem` | pkcs11-provider's key file (`PKCS#11 PROVIDER URI`, as its `uri2pem.py` writes it), which wraps the URI; a warning when the key has no `CKA_ID` | wraps anything but a private key (15) |
| "…with the module and PIN" | `--uri-module`, `--uri-pin source` or `value` | the URI with `?module-path=` (the module file that the check loaded) and the PIN as `pin-source=file:`/`env:` (`pinFile`/`pinEnv`) or as `pin-value=` | adds either one unasked; adds a PIN for a token that has none (17) |
| "What is on the token?" | `cakeys resolve <object> [--spec s] [--token t]` | JSON: `uri`, `ids`, `mode`, `binding`, `policy`, `immutables`, `specDigest`, … | compares with the lock |
| "Make it, then pin it" | `cakeys create` / `lock` | JSON, and the record in the lock | regenerates a pinned key |

A program names a cakeys object, never a URI: a bare URI only locates an object, so by itself it
does not describe enough. What `check` returns is shaped for the program, while the lock's URI
stays the bare locator. The module and the PIN are added only on request, at the check.
pkcs11-provider reads `pin-source` (`file:`, and its own `env:`) and `pin-value`, but not
`module-path`: it takes the module from its configuration or from `PKCS11_PROVIDER_MODULE`.
p11-kit and libp11 read `module-path`. A `pin-value` is exposed wherever the output goes.
pkcs11-provider finds a private key's public half by `CKA_ID` alone. On a module whose private
key carries no public point (SoftHSM: no `CKA_EC_POINT`, and an empty `CKA_PUBLIC_KEY_INFO`), a
key file for a key without `CKA_ID` can sign but cannot give OpenSSL the public key (for example,
to match a certificate). `check` therefore warns when the key that it verified has no `CKA_ID`.
Activate OpenSSL's `default` provider before `pkcs11`, because SoftHSM 2.7.0 deadlocks otherwise
(OPEN.md).

A program that takes its key as a file and cannot be changed to call `check` can still be given
a file that the check has just verified.
[`examples/inject/unotify-inject`](../examples/inject/unotify-inject) runs the program under a
seccomp filter, and it answers the program's open of a path with what a command prints, for
example `cakeys check signing --format pkcs11-provider-pem` (or the bare URI, for a program that
reads a URI). The command runs at each open. A failed check fails the open, and the run fails
with the check's exit code. The number of opens can be asserted per path (for several paths,
from a rules file). It is an example, not a sandbox
([`examples/README.md`](../examples/README.md)).

Today, the CLI is the binding that programs use. **The check is not the use** (accepted
2026-11-13): a program that runs `check` and then opens the URI uses the key a moment after
cakeys verified it. cakeys promises a result that is *verified at check time*, and a swapped key
still fails the next check. A library binding, a JSON form of `check` and a stability promise
for the output are open ([OPEN.md](OPEN.md)).

## Nix integration

### Library (`lib.mkKeys`, builtins only)

There is one calling convention: **every object is a function**. The call resolves the object's
one (spec, token) pair, and the arguments are optional when there is exactly one pair. The call
returns plain data, so consumers destructure the result once and reuse it:

```nix
signing = keys.signing { token = "softhsm"; };      # { } when the object has one pair
shared  = keys.shared { token = "softhsm"; spec = "shared-sign"; };  # several specs on one token
```

- The result carries only what evaluation knows without the token (review N1, N2): `type` (the
  lock's canonical type once the lock pins the object, and keys.toml's type as written before
  that), `id.<scheme>` (`pubkeyhash` is an input alias), the resolved `spec`/`token`,
  `requiredSystemFeatures` (`<featurePrefix><token>` unless keys.toml names a feature) and
  `check`. The result has no URI. The URI that a consumer uses is the one that `check` prints
  after it has verified the key, never the
  lock's URI, which nothing has checked at evaluation. Nothing is derived again from the lock
  either (the assurance, the mode): `cakeys resolve` reports those.
- **`check`** is the shell command for the pre-use check, and it prints the URI.
  `scheme = "certhash"` requires that identity, and the resolved pair is passed explicitly. The
  call's `checkArgs` are `cakeys check`'s own flags, which are appended as given and validated by
  cakeys, as in
  `keys.signing { checkArgs = [ "--format" "pkcs11-provider-pem" "--uri-pin" "source" ]; }`. A
  `--uri-pin value` PIN appears in the build log or the store path that the output reaches.
  Interpolating the config, the lock and the module makes them
  build inputs. Everything is usable before anything is recorded in the lock, which is the
  first-use pseudo-FOD flow; `id` is then empty.
- A call that does not name exactly one pair throws an error that lists the choices. So does a
  lock whose `version` is not 1, and a `lock` path that does not exist (a mistyped path, or a
  path that a git flake cannot see until it is `git add`ed). `lock = null` says that nothing is
  recorded yet.
- `checks.lib` (with a synthetic fixture) and `checks.vm` (with a consumer that is built in the
  guest sandbox) test the library.

### Pseudo-FOD check

A consumer derivation requires the token's feature and runs `check` before it uses the URI.

1. **Create** the key out of band (`cakeys create`). `check` never creates a key: in the
   sandbox, it fails as not found (11), and the message names `cakeys create`.
2. **First use** fails with `got:` (18), because `check` never writes, and in the sandbox it
   could not write. Record the ID out of band (`lock`, or `create` itself, which writes the lock
   by default).
3. Every later build verifies the key first.

**Caveat:** a cached consumer is not rebuilt, so the token is not contacted again;
`nix build --check` forces the check. The VM test covers all of this.

### NixOS module (`nixosModules.default`, `services.cakeys`)

- **`tokens.<n>.{sandboxPaths, pcscd}`.** Each token advertises the system feature
  `<featurePrefix><n>` (`services.cakeys.featurePrefix`, by default `token-`, which is the same
  default as the `featurePrefix` of `lib.mkKeys`). keys.toml's `tokens.<t>.nix.systemFeature`
  names one of these features when a config's token name differs from the host's token name.
  The paths are **not** global `extra-sandbox-paths`. A pre-build-hook (`nix/sandbox-hook.sh`,
  bash and jq over `nix derivation show`) grants them only to builds whose
  `requiredSystemFeatures` name the token's feature.
  - It reads plain, structured-attrs (JSON v4) and `env.__json` derivations.
  - It emits only the existing paths from the module's map.
  - It always exits 0, and it grants nothing on an error.
  - Test: `checks.module`, *the hook grants token paths only to builds requiring the token's feature*.
- **`sandbox.pcscd.enable`:** enables pcscd, a polkit rule for nixbld or for the auto-allocated
  UID range, and `PrivateUsers=false` with auto UIDs. The grant applies to the whole host:
  pcscd serves every reader, so a build that is granted the pcscd socket reaches every card that
  is plugged in, not only its own token's card. Several tokens with `pcscd = true` give a
  warning.
- **`sandbox.tpm2.enable`:** a udev ACL on `/dev/tpmrm*` for every build GID: the nixbld GID,
  or, with `auto-allocate-uids`, the first UID of each 65 536-ID slot, which is also its GID. The
  device is the whole TPM: a build that is granted it reaches every object that its
  authorization allows. Test: `checks.tpm`, with auto UIDs, uid-range, nixbld, and a
  stripped-ACL control.
- **`sandbox.uidRange.enable`:** enables `auto-allocate-uids` and the `uid-range` feature.
- **`checks.<n>`:** a oneshot `cakeys-check-<n>` unit that runs `check`, and that the units that
  use the key require (`checks.module`). It runs again on every start of one of those units
  (including a restart), and it is ordered after `time-sync.target` without pulling that target
  in. A PIV chain's dates are judged by the clock, and that target means a synchronized clock
  only with a service that waits for it (`systemd-time-wait-sync`). `args` are `check`'s own
  flags, appended as given (`[ "--format" "pkcs11-provider-pem" "--uri-pin" "source" ]`).
  `outputFile` (with `outputGroup`) writes what the check prints to a file instead of the
  journal. The file is removed before each check, and it is written (0600, or 0640 for the
  group) only when the check passes. `--uri-pin value` requires `outputFile`. In
  `checks.module`, the check writes a key file, and the service that it gates signs with that
  file through OpenSSL and pkcs11-provider.

### What real builds may reach

- **Allowed:** a **p11-kit forwarding socket** (`p11-kit server`, outside the sandbox) or a
  **real TPM** (`/dev/tpmrm0`).
- **Never** allowed: a token database, because SoftHSM files allow offline PIN guessing and key extraction.
- **SoftHSM paths in tests are for testing only.**
- **PINs:** p11-kit login is per client (`p11kit_login_is_per_client`). A build that uses private
  objects needs the PIN, through a granted file, and `publicOnly` needs none.
