# examples/tls on NixOS: a check unit verifies the TPM holds the pinned key and writes the key
# file the server reads; the server does not start unless it passed. Import it beside cakeys'
# NixOS module (nixosModules.default, with services.cakeys.package set). checks.examples
# evaluates both units.
#
# One-time setup, by hand: a tpm2-pkcs11 token labelled "web" in the store below
# (`tpm2_ptool init` and `addtoken --label web`), its user PIN in /run/secrets/web-tpm-pin, then
# `cakeys --config keys.toml --module tpm=<path>/lib/libtpm2_pkcs11.so create web-tls` as root,
# which writes keys.lock (commit it), and a CSR from the key for the CA (run.sh shows one).
# The setup runs as root, so the store it makes is root's; the server opens the same store as
# `web`, and tpm2-pkcs11 opens its sqlite database for writing (with its journal beside it), so
# give the store to the `tss` group, which `web` is in: `chgrp -R tss /var/lib/tpm2-pkcs11` and
# `chmod -R g+rwX /var/lib/tpm2-pkcs11`. Left root's, the server fails at its first key load.
{ pkgs, ... }:
let
  module = "${pkgs.tpm2-pkcs11}/lib/libtpm2_pkcs11.so";
  # tpm2-pkcs11's object store and how it reaches the TPM, the same for both units.
  tpm2 = {
    TPM2_PKCS11_STORE = "/var/lib/tpm2-pkcs11";
    TPM2_PKCS11_TCTI = "device:/dev/tpmrm0";
  };
  # OpenSSL with pkcs11-provider, `default` activated first as pkcs11-provider's examples list it.
  opensslConf = pkgs.writeText "openssl-pkcs11.cnf" ''
    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect

    [provider_sect]
    default = default_sect
    pkcs11 = pkcs11_sect

    [default_sect]
    activate = 1

    [pkcs11_sect]
    module = ${pkgs.pkcs11-provider}/lib/ossl-modules/pkcs11.so
    pkcs11-module-path = ${module}
    activate = 1
  '';
in
{
  security.tpm2.enable = true;

  services.cakeys.checks.web-tls = {
    config = ./keys.toml;
    lock = ./keys.lock;
    token = "tpm";
    modules.tpm = module;
    environment = tpm2 // {
      WEB_TPM_PIN_FILE = "/run/secrets/web-tpm-pin";
    };
    # pkcs11-provider's key file: the URI the check verified, the PIN by reference (pin-source),
    # so the file holds no secret; written 0640 for the server's group, and only on success.
    args = [
      "--format"
      "pkcs11-provider-pem"
      "--uri-pin"
      "source"
    ];
    outputFile = "/run/cakeys/web-tls.pem";
    outputGroup = "web";
    requiredBy = [ "web.service" ];
  };

  users.groups.web = { };
  users.users.web = {
    isSystemUser = true;
    group = "web";
    # The TPM device (security.tpm2's udev rules), and the store once the setup above gives it
    # to the group. The PIN file the key file names (pin-source) must be readable by this user
    # too: OpenSSL logs in as the server.
    extraGroups = [ "tss" ];
  };

  # The server. `openssl s_server` stands in, as in run.sh: a server that reads its key through
  # OpenSSL 3 with pkcs11-provider loaded takes the same file, which pkcs11-provider's decoder
  # turns back into the TPM key. The certificate is the CA's, from a file, renewed as usual.
  systemd.services.web = {
    wantedBy = [ "multi-user.target" ];
    environment = tpm2 // {
      OPENSSL_CONF = "${opensslConf}";
    };
    serviceConfig = {
      User = "web";
      AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
      ExecStart = "${pkgs.openssl}/bin/openssl s_server -accept 443 -www -cert /var/lib/acme/example.org/cert.pem -key /run/cakeys/web-tls.pem";
    };
  };
}
