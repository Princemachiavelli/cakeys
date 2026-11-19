# Open and parked items

Everything not built or not decided, in one list. Each item names where its context lives;
"archive" is `docs/archive/`, and git history holds the earlier plans (PLAN.md, NEXT.md,
MIGRATE.md, docs/PROVIDERS.md, WORKPLAN.md).

## Identity coverage: what objects cakeys can take

- **A matrix of what can be created, and at what assurance** (2026-11-14). Generate PKCS#11
  objects over every sane combination of class, key type and attributes (usage bits,
  `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_ALLOWED_MECHANISMS`, …) by property test or fuzzing,
  on every reference token, and record which identity mode, schemes, binding and assurance each
  gets, or why none. Goal: keys.toml can declare any sane object, even when its assurance is
  low, and the matrix says what that assurance is. Clean fixtures cakeys made itself are not
  evidence of what deployments need. **Built for SoftHSM and kryoptic** (2026-11-15,
  PLAN.md A4): `spec-coverage/objects/<token>.toml`, 1544 objects each, adopted as a
  legacy key arrives (crates/cli/tests/object_matrix/): generated keys and imported secret
  keys; imported private keys by where their public half is; certificates; data objects. Also
  on tpm2-pkcs11 over swtpm (`tpm2-pkcs11+swtpm.toml`), where most of the grid is the module's
  refusal to hold it: it generates EC keys only with `CKA_SIGN`, RSA keys only with both
  `CKA_SIGN` and `CKA_DECRYPT`, no secret key at all; takes no private key by `C_CreateObject`;
  stores an imported secret key as a software blob without `CKA_VALUE_LEN` (now refused as
  unverifiable, 15, rather than a conflict); holds data objects only private and certificates
  only public. Its findings are fixed:
  - proofs choose within the key's `CKA_ALLOWED_MECHANISMS` (raw `CKM_ECDSA`, raw `CKM_RSA_PKCS`
    over a `DigestInfo`, PKCS #1 v1.5 decryption), and every binding names what the list lacks
    (15) rather than failing inside the token; a declared list narrows the commitments computed
    (DESIGN §3.4, §3.6);
  - an unnamed mechanism in the list reads (patch `cryptoki-allowed-mechanisms-unnamed`);
  - an HMAC-typed key generates with `CKM_SHA*_KEY_GEN` (kryoptic; SoftHSM 2.7 refuses at
    validation);
  - an imported EC or Edwards private key whose importer wrote only the certificate beside it
    takes its public half from the certificate (DESIGN §3.2), and any stand-in must be a key of
    the private key's own type and curve (13 otherwise).
- **An imported EC private key with nothing beside it has no identity** (11, object matrix:
  `public=none`). `pkcs11-tool --write-object --type privkey` of an EC key writes just that, and
  PKCS#11 private EC keys carry no `CKA_EC_POINT` (kryoptic computes the Edwards one; SoftHSM
  does not). Today the fix is to write the public key object or certificate beside it. For a
  non-sensitive key the point could be computed from `CKA_VALUE` on the host, which reads the
  private key out; not done.
- **Upstream cryptoki: keep an unnamed `CKA_ALLOWED_MECHANISMS` entry.** 0.12.1's
  `MechanismType::try_from` refuses any value it has no name for — vendor mechanisms (CloudHSM's
  EdDSA is `0x80001057`, CLOUD_HSM.md) and some 385 standard ones (`CKM_DES3_CBC_PAD`), so the
  whole read fails. Upstream main accepts vendor values but not unnamed standard ones. Our patch
  keeps the raw value; a PR candidate, not filed.
- **Weaker identity modes for keys cakeys did not create** (DESIGN §3.4). Non-extractable keys
  with no usage bit a commitment can use (derive-only, unwrap-only, random-IV-only allowed
  mechanisms) are common, especially existing and legacy keys, and are refused today (17).
  Candidates: `commit-at-creation`, `host-at-import`, `token-specific` (e.g. a TPM Name). Each
  must rank below `wrap-rebind` and report that the token is not re-checked. The matrix above
  says which cases need them.
- **X25519 / Montgomery keys**: no key type in `id.rs` (SPKI, host X25519); ykcs11 cannot
  generate them anyway.
- **More Triple DES** (2026-11-15). `CKK_DES3` keys are identified by the two check values
  (`kcv-ecb`, `kcv-ecb-dec`, `CKM_DES3_ECB`); what payment and banking HSMs also hold is
  refused:
  - *Sign-only DES3 keys* (MAC keys: ISO 9797-1 retail MAC, CMAC), non-extractable: 17, no
    commitment. SoftHSM 2.7 offers `CKM_DES3_CMAC` (`pkcs11-tool -M` [run]), but cryptoki
    0.12 has no constant or `Mechanism` for it, so it is also missing from SoftHSM's profile.
    A cryptoki patch beside the KWP one (and its upstream PR), a `cmac` over DES3, and the
    profile regenerated. kryoptic 1.5 and tpm2-pkcs11 have no DES at all (15).
  - *Two-key Triple DES* (`CKK_DES2`, 16 bytes: the "double-length" keys of payment
    schemes, which many HSMs store this way): unknown key type (17). Same mechanisms
    (`CKM_DES3_ECB`), its own key type in the label; `des::TdesEde2` as the oracle.
  - *Single DES* (`CKK_DES`): not planned.
- **Moving private data objects** (2026-11-15). `cakeys` identifies a private data object
  (`valuehash`) when its spec declares `CKA_PRIVATE = true`; camigrate moves none (15,
  `private_data_objects_never_move`): the `public` method would put the value in a bundle and
  recreate it under the target's default `CKA_PRIVATE`. It would serve application secrets
  and tpm2-pkcs11's data objects, which are all private. PKCS#11 wraps keys, not data objects,
  so the candidate is the `host` path behind `--allow-host-plaintext`, with `CKA_PRIVATE = true`
  in the target's template and the value zeroized after; never a bundle.
- **brainpoolP512r1** (2026-11-15): refused (15, `CURVES_WITHOUT_CRATE`). It would serve keys
  under BSI TR-03111 (German government and eID PKI) and HSMs that offer the curve beside
  P256r1/P384r1. RustCrypto has no `bp512` release: "Add Brainpool P-512"
  (RustCrypto/elliptic-curves#1914) is open, unmerged since 2026-08-18, and an earlier draft
  (#1186) was closed. The one crate on crates.io, `bp512-nestler` 0.2.1, is
  PolyForm-Noncommercial-1.0.0 (outside `deny.toml`'s allowlist, and not usable in a
  BSD-3-Clause workspace) and builds on a fork of `primeorder` (`nestler-primeorder`, an rc).
  Take it up when a RustCrypto `bp512` on the elliptic-curve 0.14 line is released: the SPKI
  re-encoding, ECDSA with SHA-512 and ECDH like the other Brainpool curves. Not hand-rolled:
  curve arithmetic is not this repository's to write.
- **Post-quantum key types** (ML-DSA, ML-KEM, SLH-DSA through kryoptic): `rfc7093m4` over the
  SPKI, a `parameterSet` in keys.toml (out of the spec digest when unset), OpenSSL 3.5 oracles,
  and first a test of whether p11-kit forwards PKCS#11 3.2. No token here has PQ hardware.
- **`pop-ecdh` and `pop-decrypt` for `CKA_ALWAYS_AUTHENTICATE` keys**: only the sign path logs
  in per use, so derive- or decrypt-only always-authenticate keys are refused (17 declared, 16
  reported).
- **`binding = "attested"`** as an opt-in replacement for `pop-*` on PIV keys (a proof without
  touch).
- **PIV touch policy**: invisible in PKCS#11; readable only from the attestation's
  `1.3.6.1.4.1.41482.3.8` extension. A working version fetches the attestation before the proof
  and refuses (16) or warns for every `pop-*` on a touch slot.

## To decide

- **The contract with programs** (CAKEYS.md): the CLI alone as the binding, or a C-ABI library
  when a consumer asks; a versioned JSON form of `check` (the URI, the IDs, the time verified);
  how notes and warnings reach a binding; whether closing the check-then-use gap is worth tying
  programs to the library's session.
- **Asserting how keys relate**: "A and B are the same key" or "must differ", across locks.
  Options: declarative assertions in keys.toml checked by `validate` and `verify`, or a
  documented Nix pattern over `lib.mkKeys` results (`assert a.id.rfc7093m4 != b.id.rfc7093m4`,
  which works today but compares only what the locks pin).
- **Changing an existing object's policy**: a verb that applies the spec's attribute changes with
  `C_SetAttributeValue` when the material still matches, then re-records. PKCS#11 allows only
  one-way changes on modifiable objects; to decide whether it fits cakeys at all, and whether a
  loosened key is a downgrade.
- **Signing the lock**: every lock write signs the canonical lock into `keys.lock.sig`, and
  `check` refuses one that does not verify. The hard part is an anchor the lock's editor cannot
  change. Until then keys.toml and keys.lock live in signed, reviewed version control. Reuse a
  format (SSH signatures, minisign, DSSE) rather than design one.
- **A merge rule for lock fragments** (review S16): updates are serialized and `gc` collects
  stale entries, but two hand-edited fragments still need a manual merge.
- **A published JSON Schema** for keys.toml and keys.lock (`schemars`), for other-language
  readers and editor validation (taplo); cross-field invariants stay in code.
- **Remote keystores beyond p11-kit forwarding** (KMIP, cloud KMS), as a backend crate if ever.
- **Dropping `--no-update-lock`**: deferred; `create --no-update-lock` is how a first use is
  seen before it is recorded.
- **Keystores with an `idPrefix`**: an opt-in grouping whose prefix marks managed objects on the
  token (labels only on PIV?), probably outside the spec digest.
- **One token through two modules** (TODO.md): objects created through a vendor's SO module
  and then used through p11-kit (as in the Nix sandbox). Can the planner and profiles express
  "created via A, used via B", and should `--module` also switch the token's profile?

## Moving keys (CAMIGRATE.md)

- **Phase 6, `tpm-duplicate`**: a duplication blob built on the host to the target parent's
  public key, `TPM2_Import` through tss-esapi.
- **Phase 7, vendor methods** (D10) for Luna, CloudHSM, nShield, with hardware.
- **`CKA_UNWRAP_TEMPLATE` on transport keys**: warn when a `migrate.transportWith` key has none (a
  template forcing `CKA_SENSITIVE`/non-extractable keeps even the target's PIN holder from
  reading the KEK). Needs a cryptoki patch first (0.12 cannot read or set array attributes), and
  a strict template breaks the direct-OAEP path.
- **Delete and replace a key in a PIV slot** (PIV DELETE/MOVE KEY, firmware 5.7+): ykcs11 cannot
  erase a key, so `cakeys delete` refuses and an import refuses an occupied slot.
- **`tpm2_ptool` takes the user PIN on its command line** (allowed for now): other local users
  can read it while the import runs.
- **A secret key into tpm2-pkcs11 is refused only after it is written** (2026-11-17,
  `examples/every-object` [run]): `camigrate import <hmac key> --token tpm` from its file runs
  `tpm2_ptool import`, then finds no `CKA_VALUE_LEN` on the result, removes it and exits 15 (the
  module's defect under "Upstream"). The plan could refuse it first, from a profile row saying
  the module drops the length of what it imports, as `move.secret-unwrap` does for SoftHSM.

## Capability profiles (CAPROBE.md)

- **D12, FIPS mode as a match field**: `[match.fields]`, the standard 3.2 fields, the observing
  provider hook (ykcs11 FIPS mode, a TPM's `TPM_PT_MODES`), `tokens.<t>.require` (14).
  ykcs11/2.7 was probed in approved mode, so it may refuse on a non-FIPS device what that device
  can do.
- **D4, `CKO_PROFILE` claims**: read and record them, never trust them. Case in point:
  native-pkcs11 serves a `CKP_BASELINE_PROVIDER` profile object while it accepts any PIN and
  reports constant key policy (PLAN.md A0b).
- **native-pkcs11 as a Darwin reference token** (PLAN.md A0b), parked: the only module here over
  a platform keystore (macOS Keychain, Secure Enclave keys), and keys cakeys did not create,
  which the object matrix still lacks (its keys are made on software tokens). Against it: read-only (caprobe's write probes and `create`
  have nothing to do), policy reported as constants (DESIGN §8.2), an EC private key with no
  `CKA_EC_POINT` or `CKA_PUBLIC_KEY_INFO`, so its identity needs a stored public key item under
  the same locator, which Secure Enclave keys usually lack [todo]; macOS only, not in nixpkgs,
  and the keychain is out of reach of the Nix sandbox [todo]. `pop-sign` should pass through the
  raw `CKM_ECDSA` fallback [src]. Take it up if cakeys is to pin keychain keys.
- **The probe tests everything it can, the rest of it** (2026-11-15). RSA sizes 512–16384,
  unlisted curve families and operation mechanisms, and proofs at every size and curve are
  done (CAPROBE.md, write probes). Still only what the module advertises: the secret-key
  generation (`probe_secrets`) and the key wraps (`probe_key_wraps`). Cryptoki is the limit: it
  drops what it cannot name from `C_GetMechanismList`, and what it has no type for cannot be
  asked.
- **tpm2-pkcs11 over swtpm: P-521 signs with `CKR_HOST_MEMORY`** (2026-11-15, the proofs at
  every curve): `pop-sign` on secp521r1 fails at `C_SignInit`, deterministically, while
  `pop-ecdh` on the same key proves. A module defect or a P-521 limit of swtpm's TPM; the
  profile records the "no". To read in tpm2-pkcs11's sign path and report upstream.
- **More probes**: PQ parameter sets, AES-KW/KWP round trips, the HMAC key types,
  `C_GetMechanismInfo` beyond RSA, attribute defaults, existing-object encodings, ECDH with
  Montgomery keys, SHA-224 RSA-PSS (no binding variant), delete in a scratch slot.
- **haskoki as a reference token** (PLAN.md A0b), parked: it implements everything cakeys uses,
  but beside kryoptic it is one more OpenSSL-backed software token, and it is packaged for
  Docker, not nixpkgs (Haskell, pinned OpenSSL 4). Take it up with PQ key types, where a second
  implementation beside kryoptic counts.
- **caprobe profiles as pkcs11-check's run scoping**: its roadmap asks for a way to say which
  curves, key sizes and mechanisms a module implements, so the vector suites skip what it
  never offered. A caprobe profile is that statement. A conversation with upstream, not code.
- **Ed25519 into AWS CloudHSM**: the module holds Ed25519 as `CKK_EC` and refuses a
  `CKK_EC_EDWARDS` public half (`C_CreateObject`, `CKR_ATTRIBUTE_VALUE_INVALID` [run]), so the
  non-FIPS profile's `migration.refuses` blocks the move in; it moves out. A provider hook that
  writes the module's key type into import templates (the reverse of `key_type`), with the
  point in whatever `CKA_EC_POINT` form it takes, would let it in; untried.
- **Vendor mechanisms are invisible to the probe**: cryptoki 0.12 drops IDs it cannot name from
  `C_GetMechanismList`, so CloudHSM's vendor list (EdDSA `0x80001057`, ML-DSA, AES-GCM, its
  RFC 3394/5649 wraps) is in no profile; a provider reaches one only as a stand-in for a
  standard mechanism.
- **CloudHSM's `--aes-key-wrap-mapping`** (`configure-pkcs11`) maps `CKM_AES_KEY_WRAP` to a vendor
  padding [doc]; untried, so the profiles describe the default client configuration only.
- **Cloud KMS AES keys**: GCM (Google's vendor mechanism), CBC and CTR only. cakeys commits an AES
  key by CMAC, an ECB check value or key wrap, so it refuses them. A commitment by AES-CBC
  encryption of the label would cover them.
- **Probing bound keys more narrowly**: a binding lists `CKM_RSA_PKCS` for signing, and
  `rsa_ops` also tries it for decryption on that key. The SHA-512 keys get the probe's SHA-256
  inputs. Both end as notes, not rows (each mechanism works on some key), but the notes are
  noise. A per-binding operation list (sign, decrypt) and digest would remove them.
- **Forwarders are invisible**: pkcs11-proxy and pkcs11-proxy-ng report the backend's
  `C_GetInfo`, so their layer must be named in keys.toml (`profiles = [...]`). Worth stating in
  CAKEYS.md once A6 settles whether pkcs11-proxy-ng needs a layer at all.

## TPM and attestation

- **Chain the Attestation Key to the EK certificate** (MakeCredential/ActivateCredential), so
  `tpm-certify` proves "a genuine TPM", not only "the same TPM as at first use".
- **`tpm-certify` reads tpm2-pkcs11's private sqlite store**, hence its 1.10.x-only version
  guard: odd and fragile. Better: tpm2-pkcs11 exposes what attestation needs as vendor-defined
  attributes or a vendor mechanism (a `TPM2_Certify`-backed `C_Sign`, or `CKA_TPM2_*` attributes
  for the blobs), so cakeys never opens the database. Worth an upstream proposal.
- **A native TPM backend** beside tpm2-pkcs11, for PCR- and policy-bound keys.
- **Vendor HSM attestation formats** (Luna PKC, Google Cloud HSM, nShield): a scheme each, not
  researched.
- **Maybe, a challenge bank**: host-held, single-use challenges narrow replay of secret-key
  fingerprints after `lock`; it needs mutable host state the sandboxed `check` lacks.

## Upstream

- **SoftHSM, to reproduce**: the probe's process died in SoftHSM's `C_Sign` after the shim
  (FAULT_SHIM.md) gave every `C_SignInit` a P-256 private key, whatever the mechanism: one of
  those inits accepted a key of another type than its mechanism's, and the signature crashed.
  Seen once (2026-11-14) through `use_label` without `call`; which mechanism is not isolated
  yet. A direct reproduction (`C_SignInit` with `CKM_EDDSA` or an RSA mechanism and an EC key)
  would make it an upstream report.
- **SoftHSM**: `C_UnwrapKey` stores an unwrapped secret key's `CKA_VALUE` but never its
  `CKA_VALUE_LEN` (reads 0), and refuses `CKA_VALUE_LEN` in the template
  (`CKR_ATTRIBUTE_READ_ONLY`; SoftHSMv2 #628). Filed as SoftHSMv2 #925 with tests
  (`upstream/softhsm/PR.md`; the older #650 has the same core change), and
  `checks.softhsm-unwrap-value-len` tests it on a patched SoftHSM. A fixed release gets its own
  profile without `move.secret-unwrap` no.
- **SoftHSM under pkcs11-provider** (what reads `check --format pkcs11-provider-pem`): SoftHSM
  2.7.0 does its own crypto in the application's default OpenSSL library context, so with pkcs11-provider
  activated before `default` its `C_Login` calls back into itself and deadlocks on the token
  mutex (SoftHSMv2 #834, open; pkcs11-provider #723 calls it SoftHSM's). A fix is drafted in
  `upstream/softhsm/` (0004, `PR-834.md`; not filed: ask on #834 whether the maintainers want the
  minimal change or every default-context call converted). 2.7.0 also refuses multi-part
  `CKM_ECDSA_SHA*` (`C_SignUpdate`, so `openssl dgst -sign` fails) and crashes at exit under
  OpenSSL's cleanup (#780); main fixed both after 2.7.0 (#857, #897), backported as 0002 and
  0003. The check phase and `scripts/local-tests.sh` test on SoftHSM with all four patches;
  `checks.softhsm-pkcs11-provider` runs the reproduction. A deployment on stock 2.7.0 must list
  `default` before `pkcs11` and cannot stream-sign through the provider.
- **rust-cryptoki**: the HMAC key-type fix, `CKM_AES_KEY_WRAP_KWP` and `CKM_RSA_AES_KEY_WRAP`
  and the single-part sign after `C_SignInit` (`upstream/rust-cryptoki/`); later, array
  attributes and `CKM_DES3_CMAC` (a DES3 `cmac`, above).
- **rust-cryptoki, untouched attributes read as zero** [src]: 0.12's `get_attributes` hands a
  fixed-size attribute a zeroed buffer of its size, and a module that answers
  `CKR_ATTRIBUTE_TYPE_INVALID` without setting that entry's length to
  `CK_UNAVAILABLE_INFORMATION` (native-pkcs11 for every type it does not know, and for the
  entries after it) leaves the zeros, which are returned as a value. Through cakeys that records
  `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE` and `CKA_WRAP_WITH_TRUSTED` false in the
  observed policy and `CKA_KEY_GEN_MECHANISM` as `CKM_RSA_PKCS_KEY_PAIR_GEN` (0) in the
  immutables, on an EC key too. A length-only first pass for every attribute makes the
  untouched entry a zero-length value that fails to convert instead of a false one. Reproduce
  under the shim first (FAULT_SHIM.md, "untouched"), then report.
- **tpm2-pkcs11**: the P-521 `CKA_EC_POINT` fix (`upstream/tpm2-pkcs11/`). Not filed yet: a
  secret key made by `C_CreateObject` is stored without `CKA_VALUE_LEN`, which PKCS#11
  requires of AES and generic secret keys (the object matrix; the same class as SoftHSM's
  unwrap above), so cakeys cannot check its length (15).

## Engineering

- **The token suites under a plain parallel `cargo test`** no longer crash (since 2026-11-17 the
  test helpers share one reference-counted context per module, `tests/common`'s `Module`, so no
  test finalizes the module under another), but they do not pass there: every test of a binary
  shares one token set, so the tests that change the token (a second `kmtest` token, burnt PIN
  tries) break the others, and some find no object a CLI run just made, by a cause not
  established. Unsupported: `scripts/local-tests.sh` (nextest, a token set per test) is the
  local runner, as the crane check phase, the regular build and the coverage report are; the
  mutation report runs on one thread against shared tokens.
- **Closing what the reports show** (`packages.coverage`, `packages.mutants`, DEVELOPMENT.md):
  the lock's load-time invariants and the transport-key rules are pinned by
  `crates/core/tests/refusals.rs`, which a plain `cargo test` runs; the sealed path with OAEP SHA-256
  and the host path's occupied-locator and rollback branches run in no test; the YubiKey
  provider and the probe's scratch-slot guard only in the opt-in hardware tests.
- **Unit tests in `cakeys-pkcs11`** (4.5k lines, 16 unit tests): it is tested almost only
  through the reference suite (`crates/cli/tests/reference/`, which every reference binary
  includes whole).
- **Design models** (DEVELOPMENT.md, "Verification beyond tests"): Quint for the lock rules is
  begun (2026-11-18: `crates/core/spec/lock.qnt`, `checks.quint`, `crates/core/tests/lock_mbt.rs`).
  Left for the model: imports and provenance, certificates and public-key objects (pairs, the
  certificate exception of the second-name rule), transport keys (`publicKey`), locators and
  `publicOnly`, recorded commitment labels, deprecated schemes; and an inductive invariant, so
  that Apalache proves the properties for every reachable lock, not only within two steps.
  Then Alloy for the lock's structure and S16, Tamarin for proof of possession and attestation.
- **Kani and fuzzing**: a property written once as a function that panics when it fails
  (`cakeys_core::fuzzing`, `cakeys_tpm2_pkcs11::fuzzing`, `camigrate::fuzzing`), then checked at random by a
  proptest, under libFuzzer by a cargo-fuzz target, and for every input up to a bound by a Kani
  proof where one fits. It fits only code without FFI or deep parser stacks. The properties
  (2026-11-18, DEVELOPMENT.md "Testing"): hex round-trips and `decode` takes exactly hex (fuzz
  target `hex`); the attestation IDs' length-prefixed encoding reads back to its fields
  (`attest_encoding`); `tpm2_pkcs11::fix_ec_point` repairs exactly the malformed short form
  (`p521_point`); the lock and the bundle read back from their own writing (`lock`, `bundle`);
  a key file yields a private key only where the shape scan sees one (`key_file`). Kani is packaged (`nix/kani.nix`, 0.68.0 from source) and `checks.kani` (in
  `nix flake check`, not `checks-crane-only`) proves three: the hex round trip for every input
  of up to two bytes (52 s, 2.5 GB), `decode` for every text of up to four (13 s, 0.5 GB), and
  `fix_ec_point` for every input of up to 258 bytes, so every shape it repairs or leaves alone
  (1m42s, 5.7 GB). Under Kani a heap value of symbolic length becomes array constraints, so a
  proof takes a fixed array and a length, never a `Vec` or `String`, and code that copies
  symbolic lengths onto the heap is what costs: `fix_ec_point`'s one copy is most of its 5.7 GB,
  and `attest_encoding`, which copies every field, has no proof — fields of up to one byte ran
  out of 8 GB, both encodings or `tpm-certify`'s two fields alone. The three engines were first
  bolero's (one harness, `--engine kani`); dropped 2026-11-18: its `Vec` and `String`
  generators are such values (no fix as of 2026-11; bolero #231 fixed only its byte-slice
  input), its engine took the hex round trip past 8 GB where the plain proof takes 2.5 and
  `fix_ec_point` past 8 GB where the plain proof takes 5.7, and the libFuzzer side was never
  wired while cargo-fuzz is. `Commit::label`'s
  injectivity stays a proptest: Kani handles `format!` badly, and a proof would need a label
  parser written only for it. The other fuzz targets stay cargo-fuzz: tss-esapi's
  unmarshalling is C, and the DER, X.509 and TOML parsers are too deep for a bounded proof.
- **More reference tokens**: an OP-TEE PKCS#11 TA in QEMU; a Nitrokey.
- **Examples on hardware and in the cloud** (2026-11-17): `examples/` runs on software tokens
  and swtpm only. The YubiKey pairs (`every-object`'s imports, `secure-boot`'s attested PK and
  KEK) are validated against the ykcs11 profile, never run; Cloud KMS and CloudHSM have no
  example. `examples/tls/configuration.nix` and `examples/secure-boot/sign.nix` are evaluated, not
  deployed: no VM test boots the TLS unit pair or builds the signing derivation on a TPM host.
