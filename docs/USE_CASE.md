# Use cases

What cakeys is for, in one line each. How it works: [`DESIGN.md`](DESIGN.md); the files:
[`CONFIG.md`](CONFIG.md), [`LOCK.md`](LOCK.md).

## Problems it solves

General:

1. **We cloned HSM A onto HSM B with the vendor's backup/restore: are the keys really the same?**
   Realise each spec on A, then on B into the same lock: B's copy must hash to A's locked IDs
   (a different key fails with 10), and B never generates its own (`autoCreate` is refused once
   the material is locked). cakeys verifies the copy; the HSM's tools make it.
2. **We created new keys on our HSM: are they set up correctly for our software?** The spec
   declares type (curve, size) and policy (sign-only, non-extractable, …); a key of another type
   is refused (13) and any policy difference is reported (14).
3. **We are moving keys from vendor A's HSM to vendor B's: did the export and import carry the
   same material?** After the import, realise the object on B into A's lock: identities are
   deterministic functions of the material (a hash of the public key, or a MAC over a fixed label
   for a secret key), so the copy matches under any scheme both compute; only the per-device
   attestation differs, by design.
4. **Our backup HSM was last used three years ago: the IDs and labels look right, but is the
   material what we expect?** `verify` recomputes every identity from the token and compares it
   with the committed lock; labels only locate, they prove nothing.
5. **We updated our signing server and now cannot sign: what changed?** The lock records which
   PKCS#11 module and token produced each entry, so running `verify` with the new module before
   deploying shows the module change and whether every key still resolves and proves possession.
6. **Does this token still behave the way our tooling was tested against?** A vendor update, a
   new firmware or another model can change what a token lists, generates or wraps.
   `cakeys probe --token <t> --diff <profile>` compares the token with its committed capability
   profile (docs/PROVIDERS.md); read-only, it is safe on a production token, and on a scratch
   token `--write` also tests generation, wrapping and unwrapping. Every drifted row is named
   (15). The profiles cakeys ships are checked this way against their reference tokens on every
   build.
7. **A key may only be used on a token running in FIPS-approved mode.** *Planned*
   (docs/PROVIDERS.md D12): keys.toml requires the mode per token, and cakeys checks it from the
   live token before any use — the PKCS#11 3.2 validation objects and flags where the module has
   them, the vendor's own query where it does not (a YubiKey FIPS's approved mode, a TPM's
   `TPM_PT_MODES`) — refusing (14) a token that is not in it, or that reports a failed
   self-test.

Nix:

8. **A derivation signs a release with an HSM key, but a PKCS#11 URI in it proves nothing about
   which key signs.** The build runs `cakeys check` first, like a fixed-output derivation: it fails
   unless the token holds exactly the locked material.
9. **The build sandbox should not see every token on the builder.** The NixOS module's pre-build
   hook grants a token's device or socket only to builds whose `requiredSystemFeatures` name that
   token.
10. **Builds reach tokens through p11-kit forwarding, never the token's database: is the forwarded
    token the one we recorded?** Realise through p11-kit and directly into one lock; the IDs must
    match.
11. **A service must not start with the wrong key, or with none.** `services.cakeys.checks.<name>`
    adds a oneshot unit running `check`, required by the units that use the key.
12. **Key identities should be pinned in the repository like any other input.** `keys.lock` is
    committed next to `flake.lock`, every change is a reviewable diff, and `lib.mkKeys` exposes the
    IDs, URIs and check commands to Nix code.

## Questions it answers

General:

1. **Does my software use an insecure key or certificate type?** A URI does not say; the spec and
   lock record class, key type, curve and size, and a token object of another type is refused.
2. **Is this private key really the one behind the public key or certificate I published?** The
   token proves possession on every use: it signs (or derives, or decrypts) a fresh challenge the
   host checks against the public key the identity hashes.
3. **Was this key generated on the device, or imported?** The lock records `CKA_LOCAL` and the
   other creation-time flags, and with `attestation = true` a YubiKey or TPM signs the answer.
4. **Has anyone changed a key's policy since we set it up, say made it extractable?** The lock
   records every policy attribute the token shows, and `verify` reports any change.
5. **On which tokens did we record this key?** The lock's realisations of the object list every
   (spec, token) where that material was found.

Nix:

6. **Which key does this derivation actually use?** `keys.<object> { … }.id` is the content hash
   of the material, not a label, and the build's `check` fails if the token disagrees.
7. **Can this builder build it?** `requiredSystemFeatures = key.requiredSystemFeatures` limits it to builders that
   advertise the token's feature.
8. **Can Nix code tell what a token can do with a key?** `key.functions` (for example
   `functions.CKM_ECDSA`) lists the mechanisms the token offered, at evaluation time.
9. **Did a nixpkgs bump change the PKCS#11 module our tokens are read through?** The lock records
   the module's build and path; the next `verify` notes a rebuild and warns on a new version.
10. **Did an edit to keys.toml change what a deployed key is?** A type change is refused outright,
    and a policy change fails every check until it is reviewed and re-recorded with `realise`.
