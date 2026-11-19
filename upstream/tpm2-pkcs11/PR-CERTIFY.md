# Draft PR for tpm2-software/tpm2-pkcs11: CKM_TPM2_CERTIFY

Status: **draft, not filed.** The patch is `0002-sign-add-the-vendor-mechanism-CKM_TPM2_CERTIFY.patch`
(on master `a5156c5`, independent of the P-521 patch). Signed off in ~/srcs/tpm2-pkcs11.certify, branch
`upstream-pr/1-certify` (one commit on master, pushed to Princemachiavelli/tpm2-pkcs11). Before opening it:

- Upstream requires the PR to pass their CI. The checks below ran through nixpkgs' build
  environment with `--enable-unit --enable-integration` (swtpm), not their Docker image.
- The PR body below carries no AI attribution lines (the commit has the Co-Authored-By line).

Why cakeys wants it: `tpm-certify` reads the module's private sqlite store (schema, YAML attributes,
the sealed wrapping key) to run `TPM2_Certify` itself (docs/OPEN.md, "TPM and attestation"). With this
mechanism cakeys reads `CKA_TPM2_PUB_BLOB` and calls the mechanism, and never opens the store.
`CKA_TPM2_PUB_BLOB`, `_PRIV_BLOB` and `_OBJAUTH_ENC` were already returned by `C_GetAttributeValue`
(verified on 1.10.1 / swtpm, 2026-11-19: the public blob without a login, the other two after the
user login); only the public blob is made a stable interface here.

Follow-up PRs (not in this one):

1. **The attestation key as a token object.** Today the signer is a persistent handle the caller
   created. A vendor key-generation (a `CKA_TPM2_*` template attribute for a restricted signing key)
   would make it an ordinary tobject, so a client needs no TCTI and no TPM access of its own. It
   changes the signer parameter (an object handle, not a TPM handle), so it is its own design.
2. **`CKM_TPM2_ACTIVATE_CREDENTIAL`** on that key, for chaining it to the EK certificate. The EK
   is a primary of the endorsement hierarchy, not a child of the token's primary, so it is not a token
   object: it is created or read inside the operation, and its public key and certificate are
   returned (behind the user login: the EK is a stable hardware identifier).

---

**Title:** sign: add the vendor mechanism CKM_TPM2_CERTIFY

**Body:**

A PKCS#11 client has no way to tell that an object of a tpm2-pkcs11 token is a key that sits in
this TPM, as opposed to whatever the module says it is. `TPM2_Certify` answers that with a
statement the TPM signs, which the client verifies without trusting the module. This adds it as a
vendor mechanism.

`CKM_TPM2_CERTIFY` is used with `C_SignInit` / `C_Sign` on the key object to certify. Its parameter
names the signing key by its persistent TPM handle (an attestation key the caller created, with an
empty auth value; one with an auth value is `CKR_MECHANISM_PARAM_INVALID`); the data is the qualifying data (a nonce of up to 64 bytes); the output is the
marshaled `TPM2B_ATTEST` followed by the `TPMT_SIGNATURE`. The client checks the signature under the
signer's public key, the nonce, and that the attested Name is the Name of the object's
`CKA_TPM2_PUB_BLOB`.

Design:

- **Inside the module.** The logged-in session already has the object loaded and its auth unwrapped,
  so no secret leaves the module and the client needs no access to the store or the TPM.
- **No `CKA_SIGN` or `CKA_ALLOWED_MECHANISMS` check.** The mechanism signs nothing the key holder
  chose, and it certifies keys that can sign nothing (decrypt-only RSA, AES, HMAC). Tokens made by
  earlier versions list no such mechanism, so a check would make it useless on them.
- **A fixed output bound.** `C_Sign` with a `NULL` output returns `CK_TPM2_CERTIFY_MAX_LEN` (1024)
  without using the TPM, and a smaller buffer is `CKR_BUFFER_TOO_SMALL`.
- **A stable header.** `src/tpm2-pkcs11-vendor.h` is installed and fixes `CKA_TPM2_PUB_BLOB`, the new
  mechanism and its parameter. `attrs.h` said the `CKA_TPM2_*` values are not stable; the other four
  stay that way, undocumented.

Tests: `pkcs-certify.int` certifies EC, RSA, AES and HMAC keys (and one that needs a context login),
verifies each statement with OpenSSL (signature, nonce, Name), and checks the refusals (no login, a
verify operation, bad parameters, a signer that is no persistent signing key or has an auth value, too long a nonce, a
public key object), and an empty nonce. `create_pkcs_store.sh` makes the signers. docs/VENDOR.md describes the interface.

Testing, through nixpkgs' tpm2-pkcs11 build environment (`--enable-unit --enable-integration`,
swtpm): the six unit tests and the eleven `pkcs-*.int` tests I ran, including the existing
mechanism-list and sign/verify tests, all pass.
