# Draft PR for tpm2-software/tpm2-pkcs11: CKM_TPM2_ACTIVATE_CREDENTIAL

Status: **draft, not filed. Depends on PR-AK.md** (and through it PR-CERTIFY.md): the patch is
`0004-key-add-CKM_TPM2_ACTIVATE_CREDENTIAL-to-chain-an-attestation-key-to-the-EK.patch`, on top of
0003. Signed off in ~/srcs/tpm2-pkcs11.certify, branch `tpm2-activate-credential` (on
`tpm2-ak-object`). Before opening it:

- File the other two first and rebase this on what upstream merges.
- Upstream requires the PR to pass their CI. The checks below ran through nixpkgs' build
  environment with `--enable-unit --enable-integration` (swtpm), not their Docker image.
- Only swtpm ran this. The endorsement hierarchy of a real TPM may have an auth value (the
  operation is then `CKR_GENERAL_ERROR`, the attribute absent), and the EK public area is what its
  certificate is for only on a TPM that provisioned the default RSA 2048 EK; both are untested on
  hardware (docs/DEVELOPMENT.md "Hardware rules": ask before touching one).
- `CKA_TPM2_EK_PUB_BLOB` is a stable hardware identifier: it is on the private object, readable after
  the user login, as the PR says. Say if upstream wants it elsewhere.
- The PR body below carries no AI attribution lines (the commit has the Co-Authored-By line).

Why cakeys wants it: `DESIGN.md` plans to chain the attestation key to the EK certificate
(EK → AK via MakeCredential/ActivateCredential) so `tpm-certify` proves "a genuine TPM", not only "the
same TPM as at first use". With this the whole chain is PKCS#11: read `CKA_TPM2_EK_PUB_BLOB` and the
attestation key's `CKA_TPM2_PUB_BLOB`, make the credential on the host (no TPM needed), have the module
activate it, and compare. The EK certificate (NV or the vendor's service) and its chain to the
manufacturer CA stay the client's business.

---

**Title:** key: add CKM_TPM2_ACTIVATE_CREDENTIAL, to chain an attestation key to the EK

**Body:**

Builds on the attestation key as an object of the token (#NNN). To show that such a key sits in the
TPM whose Endorsement Key certificate the client trusts, the client makes a credential with
`TPM2_MakeCredential` for the EK's public key and the key's Name; only a TPM that holds both can
recover it with `TPM2_ActivateCredential`. This adds the two things a PKCS#11 client lacks:

- `CKA_TPM2_EK_PUB_BLOB` on the attestation key's private object: the public area (a
  `TPM2B_PUBLIC`) of the default RSA 2048 EK of the TCG EK Credential Profile. It is what
  `tpm2_createek` makes, byte for byte (a test compares them), so the manufacturer's EK
  certificate is for it. It is read after the user login: the EK identifies the TPM for good. It is
  absent if the endorsement hierarchy has an auth value when the key is made.
- `CKM_TPM2_ACTIVATE_CREDENTIAL`, for `C_DecryptInit` / `C_Decrypt` on that key: the input is the
  marshaled `TPM2B_ID_OBJECT` followed by the `TPM2B_ENCRYPTED_SECRET`, the output the credential. The
  module makes the EK for the command (it is a primary of the endorsement hierarchy, not a child of the
  token's primary, so it is not an object of the token), authorizes it with
  `PolicySecret(TPM_RH_ENDORSEMENT)`, and flushes it. Any key but an attestation key is
  `CKR_KEY_TYPE_INCONSISTENT`; a credential that does not parse, is damaged, or was made for another
  key or Name is `CKR_ENCRYPTED_DATA_INVALID`. As with any decryption a buffer too small keeps the
  operation; any other error ends it (the module otherwise leaves a decrypt operation active after an
  error, so this is only for this mechanism).

Tests: `pkcs-activate-credential.int` checks the EK against `tpm2_createek`'s, makes credentials of
three lengths with `TPM2_MakeCredential` and recovers them, and checks the size query and a buffer
too small, a credential for another attestation key (which that key activates), a damaged one, one
truncated, with a trailing byte, empty and too long, an ordinary key and a public key object, a
parameter, the encrypting side, and no login. docs/VENDOR.md describes the interface.

Testing, through nixpkgs' tpm2-pkcs11 build environment (`--enable-unit --enable-integration`,
swtpm): the six unit tests and the thirteen `pkcs-*.int` tests I ran, all pass.
