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
  evidence of what deployments need.
- **Weaker identity modes for keys cakeys did not create** (DESIGN §3.4). Non-extractable keys
  with no usage bit a commitment can use (derive-only, unwrap-only, random-IV-only allowed
  mechanisms) are common, especially existing and legacy keys, and are refused today (17).
  Candidates: `commit-at-creation`, `host-at-import`, `token-specific` (e.g. a TPM Name). Each
  must rank below `wrap-rebind` and report that the token is not re-checked. The matrix above
  says which cases need them.
- **X25519 / Montgomery keys**: no key type in `id.rs` (SPKI, host X25519); ykcs11 cannot
  generate them anyway.
- **Post-quantum key types** (ML-DSA, ML-KEM, SLH-DSA through kryoptic): `rfc7093m4` over the
  SPKI, a `parameterSet` in keys.toml (out of the spec digest when unset), OpenSSL 3.5 oracles,
  and first a test of whether p11-kit forwards PKCS#11 3.2. No token here has PQ hardware.
- **`pop-ecdh` and `pop-decrypt` for `CKA_ALWAYS_AUTHENTICATE` keys**: only the sign path logs
  in per use today, so derive- or decrypt-only always-authenticate keys are refused (16).
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

- **SoftHSM**: `C_UnwrapKey` stores an unwrapped secret key's `CKA_VALUE` but never its
  `CKA_VALUE_LEN` (reads 0), and refuses `CKA_VALUE_LEN` in the template
  (`CKR_ATTRIBUTE_READ_ONLY`; SoftHSMv2 #628). A fix is drafted in `upstream/softhsm/` (not
  filed: PR #650 covers the same change, so comment there or file with a link), and
  `checks.softhsm-unwrap-value-len` tests it on a patched SoftHSM. A fixed release gets its own
  profile without `secret-unwraps = false`.
- **rust-cryptoki**: the HMAC key-type fix, `CKM_AES_KEY_WRAP_KWP` and `CKM_RSA_AES_KEY_WRAP`
  (`upstream/rust-cryptoki/`); later, array attributes and single-part sign after a
  context-specific login.
- **tpm2-pkcs11**: the P-521 `CKA_EC_POINT` fix (`upstream/tpm2-pkcs11/`).

## Engineering

- **The token suites under parallel `cargo test`** crash (one test finalizes the module under
  the others); the Nix build runs them on one thread. One session per module in `tests/common`
  would fix it, and would let `cargo-nextest` take about 40 s off the check phase, once each
  suite has its own token.
- **Profiles are parsed on every token open**: parse once per process (`OnceLock`).
- **Coverage and mutation testing** (`cargo-llvm-cov`, `cargo-mutants`) in Nix, so new tests go
  where the gaps are.
- **Fuzz the remaining parsers**: the PIV chain, the P-521 fix-up, profile emit and parse.
- **Design models** (DEVELOPMENT.md): Quint or TLA+ for the lock rules, Alloy for the lock's
  structure and S16, Tamarin for proof of possession and attestation, Kani for small pure
  functions.
- **More reference tokens**: an OP-TEE PKCS#11 TA in QEMU; a Nitrokey.
