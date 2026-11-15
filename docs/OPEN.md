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
  PLAN.md A4): `profiles/coverage/objects/<token>.toml`, 1544 objects each, adopted as a
  legacy key arrives (crates/cli/tests/reference/matrix.rs): generated keys and imported secret
  keys; imported private keys by where their public half is; certificates; data objects. Still
  open: tpm2-pkcs11. Its findings so far are fixed:
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

- **`autoCreate` on `check`** (review A7, archive): whether first use may create.
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
- **Dropping `--no-update-lock`**: deferred; it changes how `autoCreate` behaves.
- **Keystores with an `idPrefix`**: an opt-in grouping whose prefix marks managed objects on the
  token (labels only on PIV?), probably outside the spec digest.
- **One token through two modules** (TODO.md): objects created through a vendor's SO module
  and then used through p11-kit (as in the Nix sandbox). Can the planner and profiles express
  "created via A, used via B", and should `--module` also switch the token's profile?

## Moving keys (CAMIGRATE.md)

- **Phase 6, `tpm-duplicate`**: a duplication blob built on the host to the target parent's
  public key, `TPM2_Import` through tss-esapi.
- **Phase 7, vendor methods** (D10) for Luna, CloudHSM, nShield, with hardware.
- **`CKA_UNWRAP_TEMPLATE` on transport keys**: warn when a `transportWith` key has none (a
  template forcing `CKA_SENSITIVE`/non-extractable keeps even the target's PIN holder from
  reading the KEK). Needs a cryptoki patch first (0.12 cannot read or set array attributes), and
  a strict template breaks the direct-OAEP path.
- **Delete and replace a key in a PIV slot** (PIV DELETE/MOVE KEY, firmware 5.7+): ykcs11 cannot
  erase a key, so `cakeys delete` refuses and an import refuses an occupied slot.
- **`tpm2_ptool` takes the user PIN on its command line** (allowed for now): other local users
  can read it while the import runs.

## Capability profiles (CAPROBE.md)

- **D12, FIPS mode as a match field**: `[match.fields]`, the standard 3.2 fields, the observing
  provider hook (ykcs11 FIPS mode, a TPM's `TPM_PT_MODES`), `tokens.<t>.require` (14).
  ykcs11/2.7 was probed in approved mode, so it may refuse on a non-FIPS device what that device
  can do.
- **D4, `CKO_PROFILE` claims**: read and record them, never trust them.
- **More probes**: PQ parameter sets, AES-KW/KWP round trips, the HMAC key types,
  `C_GetMechanismInfo` beyond RSA, attribute defaults, existing-object encodings, ECDH with
  Montgomery keys, SHA-224 RSA-PSS (no binding variant), delete in a scratch slot.
- **`Provider::mechanisms` and `Provider::migration`** are overridden by no in-tree provider
  (review A4): revisit with the first real HSM provider.
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
- **The OAEP proofs use SHA-1 only**: `pop-decrypt` and `pop-unwrap` decrypt and unwrap with
  RSA-OAEP over SHA-1 (`possession.rs`). Cloud KMS refuses it, offering SHA-256 or SHA-512 only,
  so decrypt-only Cloud KMS keys need `token-asserted`. A SHA-256 proof, chosen from the key's
  `CKA_ALLOWED_MECHANISMS` or the profile's `decrypt.oaep`, would prove them.
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
  fingerprints after `realise`; it needs mutable host state the sandboxed `check` lacks.

## Upstream

- **SoftHSM, to reproduce**: the probe's process died in SoftHSM's `C_Sign` after the shim
  (FAULT_SHIM.md) gave every `C_SignInit` a P-256 private key, whatever the mechanism: one of
  those inits accepted a key of another type than its mechanism's, and the signature crashed.
  Seen once (2026-11-14) through `use_label` without `call`; which mechanism is not isolated
  yet. A direct reproduction (`C_SignInit` with `CKM_EDDSA` or an RSA mechanism and an EC key)
  would make it an upstream report.
- **SoftHSM**: `C_UnwrapKey` stores an unwrapped secret key's `CKA_VALUE` but never its
  `CKA_VALUE_LEN` (reads 0), and refuses `CKA_VALUE_LEN` in the template
  (`CKR_ATTRIBUTE_READ_ONLY`; SoftHSMv2 #628). A fix is drafted in `upstream/softhsm/` (not
  filed: PR #650 covers the same change, so comment there or file with a link), and
  `checks.softhsm-unwrap-value-len` tests it on a patched SoftHSM. A fixed release gets its own
  profile without `secret-unwraps = false`.
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
- **tpm2-pkcs11**: the P-521 `CKA_EC_POINT` fix (`upstream/tpm2-pkcs11/`).

## Engineering

- **The token suites under a plain parallel `cargo test`** still crash (one test finalizes the
  module under the others in one process): the crane check phase runs them under
  `cargo-nextest` with a token set per test (DEVELOPMENT.md), as the regular build and the
  coverage report do; the mutation report runs on one thread against shared tokens. One session per module in
  `tests/common` would fix the plain run.
- **Closing what the reports show** (`packages.coverage`, `packages.mutants`, DEVELOPMENT.md):
  no unit test in `core` pins the lock's load-time invariants or the transport-key rules (the
  token suites reach them, a plain `cargo test` does not); the sealed path with OAEP SHA-256
  and the host path's occupied-locator and rollback branches run in no test; the YubiKey
  provider and the probe's scratch-slot guard only in the opt-in hardware tests.
- **Split the reference suite** (`crates/cli/tests/reference/mod.rs`, 3,085 lines, 62 functions
  in one module): submodules by theme, e.g. identity and oracles (curves, AES, HMAC, schemes),
  the lock (invariants, provenance, `gc`, the sidecar lock), conflicts and drift (H1, S3–S8,
  downgrades), proof of possession, and certificates and adoption, with the shared helpers in
  their own module. Each binary (`tests/softhsm.rs`, `tests/kryoptic.rs`) still includes the
  whole suite. `cakeys-pkcs11` (4.5k lines, 16 unit tests) is tested almost only through it.
- **Fuzz the remaining parsers**: the PIV chain, the P-521 fix-up, profile emit and parse.
- **Design models** (DEVELOPMENT.md): Quint or TLA+ for the lock rules, Alloy for the lock's
  structure and S16, Tamarin for proof of possession and attestation, Kani for small pure
  functions.
- **More reference tokens**: an OP-TEE PKCS#11 TA in QEMU; a Nitrokey.
