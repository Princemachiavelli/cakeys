# Scope

cakeys pins what key material a token holds, and checks it before every use. It records and
verifies; it does not decide how keys should be managed. This page draws the boundaries: what
belongs in the core crates, what only in a provider crate, what is still open, and what stays
out.

The core crates are `cakeys-core` (no token access), `cakeys-pkcs11` (the generic PKCS#11
layer) and the `cakeys` CLI. Provider crates (`cakeys-ykcs11`, `cakeys-tpm2-pkcs11`, and any
vendor's) plug in through the `Provider` trait.

## In scope (core)

- **The lock file for keys.** Content-addressed identities, realisations, the compare and
  record rules (a write fills gaps, never overrides), `gc`, the lock's own invariants, and its
  versioning ([`LOCK.md`](LOCK.md)).
- **Provenance and creation metadata.** Module, token, provider and cakeys version; the
  immutables a token sets at creation; the closed-world policy vector; attestation records; the
  `origin` of a migrated key. Recorded, compared or reported, never trusted on its own.
- **Use as a CLI and as a Nix build tool.** The verbs and their exit codes, the Nix library
  (`lib.mkKeys`), and the NixOS module (the sandbox hook, check units).
- **Verify before use.** The pseudo-fixed-output `check`, proof of possession, type and policy
  checks.
- **Keystore import and export** ([`MIGRATE.md`](../MIGRATE.md)). The planner and `--dry-run`,
  standard PKCS#11 wrapping and unwrapping, transport keys, bundles, and the standard file
  formats (PKCS#8, PKCS#12), with every path's exposure named.
- **Testing against reference tokens.** SoftHSM, kryoptic, tpm2-pkcs11 and p11-kit: the shared
  suite, cross-reference tests, property tests, fuzzing, and design models
  ([`VERIFICATION.md`](VERIFICATION.md)).
- **Integrating RustCrypto and other standard crates.** These do the parsing, canonical
  encoding, hashing and signature verification on the host, so identities are portable.
- **Standards-based identity schemes.** RFC 7093, certificate and value hashes, and commitments
  computed through standard mechanisms (HMAC, CMAC, AES key wrap).

## In scope, only in provider crates

The rule: anything true of one module or vendor lives in its provider crate, behind the
`Provider` trait. The core stays vendor-neutral, and a fix-up must return exactly what a
spec-compliant module would.

- **Vendor PKCS#11 quirks and fix-ups.** Point-encoding repairs, mechanism filtering, slot
  mapping, keys a module cannot delete, SO-only key management.
- **Vendor attestation.** The formats, the pinned trust anchors (the Yubico roots, the TPM
  Attestation Key) and their verification.
- **Vendor export and import methods** (MIGRATE.md D10), each under its declared exposure; the
  identity after import is still decided by the core's realise.
- **Keystore-specific metadata.** FIPS mode, firmware policy, PIV PIN and touch policy: reported
  through hooks as observed facts or provenance. It never changes the core's identity rules.
- **Vendor binaries, tools and libraries.** `tpm2_ptool`, tss-esapi, sqlite, `ykman`, Luna
  `cmu`: dependencies of that crate only, behind a cargo feature, so `checks.minimal` builds
  the CLI without any of them.
- **Native backends that are not PKCS#11**, such as a native TPM path: their own crate.

## Possible scope (decide when needed)

- **Library or crate use.** Today the CLI is a library only so a binary can link more providers
  (`cakeys::main(registry)`). A stable Rust API beyond that waits for a real consumer, and would
  expose the same operations as the CLI, not new ones.
- **Post-quantum key types** (ML-DSA, ML-KEM through kryoptic), once tokens offer them (PLAN).
- **Keystore grouping with an `idPrefix`** (PLAN to-do).
- **A merge rule for lock fragments** (review finding S16).
- **Remote keystores beyond p11-kit forwarding** (KMIP, cloud KMS), as a backend crate if ever.
- **Build systems other than Nix.** The CLI works anywhere; only the Nix integration is
  maintained.
- **Changing an existing object's policy** (question, 2026-11-13). Today a live object whose
  policy differs from its spec is a conflict (13), and drift from the recorded policy fails
  `verify` (14) until `realise`; cakeys never writes attributes. The open question is a verb
  that, when the *material* still matches the lock, accepts the spec's policy differences,
  applies them with `C_SetAttributeValue`, reports per attribute whether the token took it,
  then re-reads the object and records the new policy and `specDigest` (the object's IDs do not
  change). PKCS#11 bounds what it could do: nothing on a `CKA_MODIFIABLE = false` object;
  one-way changes only (`CKA_SENSITIVE` and `CKA_WRAP_WITH_TRUSTED` false → true,
  `CKA_EXTRACTABLE` true → false); `CKA_TRUSTED` needs the SO; immutables never change; and
  modules may refuse more (ykcs11, tpm2-pkcs11). To decide: whether it fits "records and
  verifies, does not decide how keys are managed"; tightening only, or loosening too where a
  token allows it; and whether a loosened key stays the same realisation or must be treated as
  a downgrade.
- **Signing the lock file** (idea, 2026-11-13). The lock is the trust root of every check:
  whoever can edit `keys.lock` can re-pin an object to their own key, and `check` then passes.
  Today its integrity is the repository's (review, signed commits, the flake's `narHash`):
  until the lock is signed, the stated requirement is that `keys.lock` and `keys.toml` live in
  version control whose history is signed and reviewed (decided 2026-11-13). The
  idea: every lock write (`realise`, `create`, `delete`, `gc --apply`) signs the canonical lock
  bytes — with a token key cakeys itself manages, e.g. a PIV signature slot (`pop-sign-pin`) —
  into a detached `keys.lock.sig`, and `check`/`verify` refuse a lock that does not verify.
  The hard part is the anchor: the verifying public key must live where the lock's editor
  cannot also change it (the NixOS module, the builder, another repository), or an attacker
  re-signs with their own key and swaps the pin. To decide: what this adds over signed commits
  and review; where the anchor lives and how the Nix `check` (sandboxed) gets it; the cost of a
  token signature (PIN, touch) on every lock write; key rotation and several signers (approval
  by two people); lock fragments and merges (S16), which invalidate a signature; and whether
  `keys.toml` must be covered too (the lock carries each spec's `specDigest` and locator, but
  not the token entries).

## Minimize (some, but keep it small)

- **Key and object parsing and manipulation.** Only what identity and migration need (the
  canonical SPKI, a certificate's subject key, attestation fields, PKCS#8 for import and
  export), always through standard crates. No general-purpose ASN.1 or certificate tooling.
- **Secret material on the host.** Only on the explicit `host` and `file` paths, in memory,
  zeroized, never written in plaintext.
- **State cakeys creates on tokens.** Transport keys, the TPM Attestation Key: explicit, and
  declared in keys.toml wherever possible.
- **Unsafe code and FFI.** Only where a library forces it (the loader lookup of the module file), each
  site allowed explicitly with its reason.

## Out of scope

- **Cryptographic implementations.** No primitives, no key generation on the host, no
  home-made formats where a standard exists.
- **Opinionated key management practices.** No rotation schedules, expiry rules or approval
  workflows: cakeys records and verifies what keys.toml declares.
- **Storing secrets.** No vault, no PIN management, no key escrow: PINs come from files or the
  environment, and backups are the standard export formats.
- **Being a PKCS#11 module or key server.** cakeys uses tokens; forwarding is p11-kit's job.
- **Certificate authority work.** Issuing, CSRs, revocation.
- **Access control** beyond the token's own and the Nix sandbox gating.
- **Proving exclusivity.** That a key exists nowhere else is unobservable (DESIGN §8.2).
- **Reimplementing vendor tools,** or vendor-proprietary formats in the core.
