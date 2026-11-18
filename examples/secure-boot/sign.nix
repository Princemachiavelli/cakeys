# A Nix build that signs a unified kernel image with db (keys.toml), on the host whose TPM holds
# it. The build requires that token's system feature, so it is scheduled only there; it reaches
# the TPM, tpm2-pkcs11's store and the PIN file through what the host grants that feature; and
# it checks db against keys.lock before it signs, with the URI the check printed. run.sh runs
# the same two commands, in the same environment, on a software TPM; checks.examples evaluates
# this file.
#
#   signed = pkgs.callPackage ./sign.nix { inherit cakeys; uki = ...; dbCert = ./db.crt; };
#
# The host (cakeys' NixOS module):
#
#   services.cakeys = {
#     sandbox.tpm2.enable = true;
#     tokens.tpm.sandboxPaths = [ "/dev/tpmrm0" "/var/lib/tpm2-pkcs11" "/etc/secure-boot/tpm-pin" ];
#   };
{
  pkgs,
  # The cakeys flake.
  cakeys,
  # The image to sign, and db's certificate (issued once from the TPM key; run.sh shows how).
  uki,
  dbCert,
}:
let
  module = "${pkgs.tpm2-pkcs11}/lib/libtpm2_pkcs11.so";
  keys = cakeys.lib.mkKeys {
    config = ./keys.toml;
    # Recorded by `cakeys create db --token tpm` on the host, and committed.
    lock = ./keys.lock;
    cakeys = cakeys.packages.${pkgs.stdenv.hostPlatform.system}.cakeys;
    modules.tpm = module;
  };
  # The pre-use check: prints the URI it verified, the PIN by reference.
  db = keys.db {
    checkArgs = [
      "--uri-pin"
      "source"
    ];
  };
in
pkgs.runCommand "${uki.name}-signed"
  {
    # token-tpm: only the host advertising the token builds this.
    inherit (db) requiredSystemFeatures;
    TPM2_PKCS11_TCTI = "device:/dev/tpmrm0";
    TPM2_PKCS11_STORE = "/var/lib/tpm2-pkcs11";
    SB_TPM_PIN_FILE = "/etc/secure-boot/tpm-pin";
    # systemd-sbsign loads pkcs11-provider by name; the provider opens the module.
    OPENSSL_MODULES = "${pkgs.pkcs11-provider}/lib/ossl-modules";
    PKCS11_PROVIDER_MODULE = module;
  }
  ''
    uri=$(${db.check})
    ${pkgs.systemd}/lib/systemd/systemd-sbsign sign --private-key-source=provider:pkcs11 \
      --private-key="$uri" --certificate=${dbCert} --output=$out ${uki}
  ''
