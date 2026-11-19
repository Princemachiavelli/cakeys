# tpm2-pkcs11 master (a5156c5, after 1.10.1) with upstream/tpm2-pkcs11/'s vendor-mechanism patches
# 0002 to 0004 (CKM_TPM2_CERTIFY, the attestation key as a token object, CKM_TPM2_ACTIVATE_CREDENTIAL):
# the module the provider's vendor path is tested with (crates/cli/tests/tpm2.rs, CAKEYS_TPM_VENDOR_MODULE),
# beside nixpkgs' own, which the store path is tested with. The patches are written against master,
# not the 1.10.1 tag nixpkgs builds (sign.c changed in between). Drop this when a release carries them.
{
  fetchFromGitHub,
  tpm2-pkcs11,
}:
tpm2-pkcs11.overrideAttrs (old: {
  pname = "tpm2-pkcs11-vendor";
  src = fetchFromGitHub {
    owner = "tpm2-software";
    repo = "tpm2-pkcs11";
    rev = "a5156c50ed22dfb63f2052a39cd72f65a7267739";
    hash = "sha256-r68wTPtwnEJ2SbobGa7bdXMMjnlQM0knuZyLrZ4uQb4=";
  };
  patches = (old.patches or [ ]) ++ [
    ../upstream/tpm2-pkcs11/0002-sign-add-the-vendor-mechanism-CKM_TPM2_CERTIFY.patch
    ../upstream/tpm2-pkcs11/0003-key-add-the-attestation-key-as-an-object-of-the-token.patch
    ../upstream/tpm2-pkcs11/0004-key-add-CKM_TPM2_ACTIVATE_CREDENTIAL-to-chain-an-attestation-key-to-the-EK.patch
  ];
  # The module's own suites ran for each patch (upstream/tpm2-pkcs11/PR-*.md), not here.
  doCheck = false;
})
