# Draft PR for tpm2-software/tpm2-pkcs11: the attestation key as an object of the token

Status: **draft, not filed. Depends on PR-CERTIFY.md** (`CKM_TPM2_CERTIFY`, the header, the
mechanism table entry): the patch is `0003-key-add-the-attestation-key-as-an-object-of-the-token.patch`,
on top of 0002. Signed off in ~/srcs/tpm2-pkcs11.certify, branch `upstream-pr/2-attestation-key` (one
commit, on `upstream-pr/1-certify`). Before opening it:

- File PR-CERTIFY first and rebase this on what upstream merges.
- Upstream requires the PR to pass their CI. The checks below ran through nixpkgs' build
  environment with `--enable-unit --enable-integration` (swtpm), not their Docker image.
- The FAPI backend is untested: every test ran on the esysdb backend. `token_load_object` is used
  as for any key, and the second HMAC session is the module's own, so nothing here depends on the
  backend, but it has not been run.
- The PR body below carries no AI attribution lines (the commit has the Co-Authored-By line).

Why cakeys wants it: with `CKM_TPM2_CERTIFY` cakeys needs the TPM tools, a TCTI and tss-esapi
only to create and read the attestation key. With this the whole provider path is PKCS#11: create
the key with `C_GenerateKeyPair`, read its public key, call `CKM_TPM2_CERTIFY_OBJECT`. It changes
the lock's `attestation.root` (the pinned public key is the token's attestation key, not a
persistent handle's): re-lock after the switch. The attested qualified signer is not checked on
this path: a client cannot compute it, and the pinned public key identifies the signer.

Follow-up (not in this PR): `CKM_TPM2_ACTIVATE_CREDENTIAL` on this key, for chaining it to the EK
certificate.

---

**Title:** key: add the attestation key as an object of the token

**Body:**

`CKM_TPM2_CERTIFY` (#NNN) names its signer by a persistent TPM handle: a key the caller made with
the TPM tools, which needs access to the TPM. This makes the attestation key an ordinary key pair
of the token, so a PKCS#11 client needs nothing else.

- `CKM_TPM2_AK_PAIR_GEN`, for `C_GenerateKeyPair`, takes no parameter and the EC key pair's
  templates. The TPM key is restricted, a signing key with ECDSA over the hash of its curve (P-256,
  P-384, P-521), `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`. The private key has `CKA_SIGN`
  false and an empty `CKA_ALLOWED_MECHANISMS`, so `C_SignInit` refuses it in the module instead of
  failing in the TPM, which asks a restricted key for a hashcheck ticket. A template asking for
  `CKA_SIGN`/`VERIFY`/`ENCRYPT`/`DECRYPT` true, or an extractable key, is
  `CKR_TEMPLATE_INCONSISTENT`.
- `CKM_TPM2_CERTIFY_OBJECT` is `CKM_TPM2_CERTIFY` with the signer named by object handle
  (`CK_TPM2_CERTIFY_OBJECT_PARAMS`). Only a key made by `CKM_TPM2_AK_PAIR_GEN` is accepted
  (`CKA_KEY_GEN_MECHANISM`): an ordinary key of the token does not sign statements about the TPM.
  The key's auth value is the module's, proved in an HMAC session of its own: the TPM takes no
  session twice in a command (`TPM_RC_HANDLE` for session 2), and a password session would put the
  auth value on the wire.

That the key is restricted is in the `TPMA_OBJECT` of its `CKA_TPM2_PUB_BLOB`, where a client that
trusts the key only if it is restricted checks it.

Tests: `pkcs-attest-key.int` generates attestation keys on P-256 and P-384, checks the attributes and
the TPM public area, certifies private (EC, RSA) and secret keys and verifies each statement with
OpenSSL (signature, nonce, Name), checks the refusals (a usage attribute, an extractable key, an
unsupported curve, a parameter; as signer an ordinary key, a public key, no object, the key itself;
a missing or short parameter, a verify operation, too long a nonce, no login), and that the key
survives `C_Finalize`/`C_Initialize` with its empty `CKA_ALLOWED_MECHANISMS`. docs/VENDOR.md
describes the interface.

Testing, through nixpkgs' tpm2-pkcs11 build environment (`--enable-unit --enable-integration`,
swtpm): the six unit tests and the twelve `pkcs-*.int` tests I ran, all pass.
