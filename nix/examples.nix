# checks.examples: every example under examples/ played on throwaway tokens (its run.sh, each
# step's exit code required), the YubiKey adoption validated, and the Nix files evaluated
# (examples/tls/configuration.nix's two units, examples/secure-boot/sign.nix's derivation), so
# no example drifts from cakeys.
{
  pkgs,
  lib,
  self,
  cakeys,
}:
let
  tpm2Module = "${pkgs.tpm2-pkcs11}/lib/libtpm2_pkcs11.so";
  # The TLS example's units, as a NixOS system with cakeys' module would have them. Its lock is
  # the deployment's own (./keys.lock beside keys.toml): a path stands in.
  tls = pkgs.nixos {
    imports = [
      self.nixosModules.default
      ../examples/tls/configuration.nix
    ];
    services.cakeys.package = cakeys;
    services.cakeys.checks.web-tls.lock = lib.mkForce "/var/lib/cakeys/keys.lock";
  };
  # The secure-boot build, evaluated only: building it needs the host's TPM.
  signed = import ../examples/secure-boot/sign.nix {
    inherit pkgs;
    cakeys = self;
    uki =
      pkgs.runCommand "uki.efi" { }
        "cp ${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub $out";
    dbCert = pkgs.writeText "db.crt" "";
  };
in
pkgs.runCommand "cakeys-examples"
  {
    nativeBuildInputs = with pkgs; [
      cakeys
      cakeys.camigrate
      softhsm
      opensc
      openssl
      gawk
      swtpm
      dbus
      tpm2-abrmd
      tpm2-tools
      tpm2-pkcs11
      sbsigntool
      (python3.withPackages (p: [ p.python-pkcs11 ]))
    ];
    SOFTHSM_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
    KRYOPTIC_MODULE = "${pkgs.kryoptic}/lib/libkryoptic_pkcs11${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}";
    TPM2_PKCS11_MODULE = tpm2Module;
    TPM2_TEST_ENV = ./tpm2-test-env.sh;
    PKCS11_PROVIDER_DIR = "${pkgs.pkcs11-provider}/lib/ossl-modules";
    SYSTEMD_SBSIGN = "${pkgs.systemd}/lib/systemd/systemd-sbsign";
    EFI_STUB = "${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub";
    # Throwaway keys made and used in a build: the sandbox's refusals (a lock write, camigrate's
    # admin operations) lifted, as docs/FILE.md describes.
    CAKEYS_ALLOW_NIX_STORE_KEYS = "1";
    tlsUnits = map (u: tls.config.systemd.units.${u}.unit) [
      "web.service"
      "cakeys-check-web-tls.service"
    ];
    signDrv = builtins.unsafeDiscardStringContext signed.drvPath;
  }
  ''
    set -o pipefail
    export HOME=$TMPDIR
    for e in every-object tls secure-boot programs; do
      echo "━━ examples/$e"
      bash ${../examples}/$e/run.sh
    done 2>&1 | tee $out
    echo "━━ examples/yubikey-secureboot.toml" | tee -a $out
    cakeys --config ${../examples/yubikey-secureboot.toml} validate 2>&1 | tee -a $out
    echo "evaluated: $signDrv $tlsUnits" | tee -a $out
  ''
