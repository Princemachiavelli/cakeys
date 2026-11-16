# VM test of the NixOS module (nix/module.nix): sandboxed pcscd access with auto-allocated
# build UIDs, uid-range builds, token system features, and the pre-use check unit writing the key
# file a real signer (OpenSSL through pkcs11-provider) uses.
{
  pkgs,
  module,
  cakeys,
  pcsc-probe,
  # SoftHSM with upstream/softhsm/'s patches (nix/softhsm-unwrap-value-len.nix): over stock 2.7.0,
  # OpenSSL through pkcs11-provider cannot stream-sign and crashes at exit.
  softhsm,
}:
let
  inherit (pkgs) lib;
  system = pkgs.stdenv.hostPlatform.system;
  stateDir = "/var/lib/softhsm";

  keysToml = pkgs.writeText "keys.toml" ''
    [tokens.softhsm]
    module = "${softhsm}/lib/softhsm/libsofthsm2.so"
    tokenLabel = "kmtest"
    pinFile = "${stateDir}/pin"

    [objects.signing]
    class = "CKO_PRIVATE_KEY"
    keyType = "CKK_EC"
    curve = "secp256r1"

    [specs.signing-soft]
    object = "signing"
    attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
    tokens.softhsm = { locator = { CKA_LABEL = "signing", CKA_ID = "01" } }
  '';

  # What a build's sandbox sees: pcscd reachability and the SoftHSM state directory.
  sandboxProbe = pkgs.writeText "sandbox-probe.sh" ''
    # Structured-attrs builds get their outputs from the attrs file, not the environment.
    if [ -n "''${NIX_ATTRS_SH_FILE:-}" ]; then . "$NIX_ATTRS_SH_FILE"; out=''${outputs[out]}; fi
    {
      ${pcsc-probe}/bin/pcsc-probe
      if [ -d ${stateDir} ]; then echo softhsm-dir=yes; else echo softhsm-dir=no; fi
    } > "$out" 2>&1
  '';

  # Built inside the guest (store paths re-attached with builtins.storePath).
  guestBuilds = pkgs.writeText "builds.nix" ''
    { nonce }:
    let
      sp = builtins.storePath;
      bash = sp "${pkgs.bash}" + "/bin/bash";
      # What the sandbox of a build with these features sees.
      probe = name: features: extra: derivation ({
        name = "''${name}-''${nonce}";
        system = "${system}";
        builder = bash;
        requiredSystemFeatures = features;
        args = [ (sp "${sandboxProbe}") ];
      } // extra);
    in
    {
      # pcscd only for the pcsc token's feature (no reader in the VM, so "connected" is the goal).
      pcsc = probe "pcsc" [ "token-pcsc" ] { };
      softhsm = probe "softhsm" [ "token-softhsm" ] { };
      plain = probe "plain" [ ] { };
      structured = probe "structured" [ "token-pcsc" ] { __structuredAttrs = true; };
      # uid-range: root inside the build with a full 65536-UID range.
      uidRange = derivation {
        name = "uid-range-''${nonce}";
        system = "${system}";
        builder = bash;
        requiredSystemFeatures = [ "uid-range" ];
        args = [ "-c" "read -r _ _ n < /proc/self/uid_map; echo \"uid=$UID range=$n\" > $out" ];
      };
    }
  '';
in
pkgs.testers.runNixOSTest {
  name = "cakeys-module";

  nodes.machine = {
    imports = [ module ];
    services.cakeys = {
      package = cakeys;
      sandbox.pcscd.enable = true;
      sandbox.uidRange.enable = true;
      tokens.softhsm.sandboxPaths = [ stateDir ];
      tokens.pcsc.pcscd = true;
      checks.signing = {
        config = keysToml;
        lock = "/var/lib/km/keys.lock";
        token = "softhsm";
        environment.SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
        requiredBy = [ "signer.service" ];
        # The key as a file: pkcs11-provider's key file, the PIN by reference.
        format = "pkcs11-provider-pem";
        uriPin = "source";
        outputFile = "/run/cakeys/signing.pem";
        outputGroup = "signer";
      };
    };
    users.groups.signer = { };
    security.polkit.enable = true;
    # A service that signs with the key, knowing only the file the check wrote.
    systemd.services.signer = {
      environment = {
        SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
        PKCS11_PROVIDER_MODULE = "${softhsm}/lib/softhsm/libsofthsm2.so";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = lib.concatStringsSep " " [
          (lib.getExe pkgs.openssl)
          "dgst"
          "-sha256"
          "-provider-path"
          "${pkgs.pkcs11-provider}/lib/ossl-modules"
          # `default` first, as pkcs11-provider's own test configuration lists them (docs/OPEN.md,
          # SoftHSM under pkcs11-provider).
          "-provider"
          "default"
          "-provider"
          "pkcs11"
          "-sign"
          "/run/cakeys/signing.pem"
          "-out"
          "/run/signer.sig"
          "/etc/km/keys.toml"
        ];
      };
    };
    environment.systemPackages = [
      cakeys
      softhsm
      pkgs.openssl
    ];
    environment.etc."km/keys.toml".source = keysToml;
    environment.etc."km/builds.nix".source = guestBuilds;
    environment.variables.SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
    systemd.tmpfiles.rules = [
      "d ${stateDir}/tokens 0700 root root -"
      "d /var/lib/km 0700 root root -"
    ];
    nix.settings.substituters = lib.mkForce [ ];
    virtualisation.additionalPaths = [ guestBuilds ];
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import re

    km = "cakeys --config /etc/km/keys.toml --lock /var/lib/km/keys.lock"

    def guest_build(attr):
        out = machine.succeed(
            f"nix-build /etc/km/builds.nix -A {attr} --argstr nonce {attr} --no-out-link 2>&1"
        ).strip().splitlines()[-1]
        return machine.succeed(f"cat {out}")

    start_all()
    machine.wait_for_unit("multi-user.target")

    with subtest("nix settings: features are added, defaults kept"):
        conf = machine.succeed("cat /etc/nix/nix.conf")
        m = re.search(r"^system-features = (.*)$", conf, re.M)
        assert m, conf
        features = m.group(1).split()
        for f in ["uid-range", "token-softhsm", "token-pcsc", "nixos-test", "kvm"]:
            assert f in features, f"{f} missing from {features}"
        assert re.search(r"^auto-allocate-uids = true$", conf, re.M), conf
        # Token paths are granted per build by the hook, never globally.
        assert re.search(r"^pre-build-hook = /nix/store/\S+/bin/cakeys-sandbox-hook$", conf, re.M), conf
        assert "/run/pcscd" not in conf and "${stateDir}" not in conf, conf
        assert "PrivateUsers=no" in machine.succeed("systemctl show pcscd.service -p PrivateUsers")

    with subtest("pcscd is reachable from the sandbox with auto-allocated build UIDs"):
        for attr in ["pcsc", "structured"]:
            out = guest_build(attr)
            print(attr, out)
            assert "SCardEstablishContext: 0x00000000" in out, out
            assert "0x8010002e" in out, out  # connected; the VM simply has no reader
            assert "softhsm-dir=no" in out, out

    with subtest("the hook grants token paths only to builds requiring the token's feature"):
        out = guest_build("softhsm")
        print(out)
        assert "softhsm-dir=yes" in out and "SCardEstablishContext: 0x00000000" not in out, out
        out = guest_build("plain")
        print(out)
        assert "softhsm-dir=no" in out and "SCardEstablishContext: 0x00000000" not in out, out

    with subtest("uid-range builds run"):
        out = guest_build("uidRange")
        print(out)
        assert "uid=0 range=65536" in out, out

    with subtest("check unit gates the signer"):
        machine.succeed(
            "printf 'directories.tokendir = ${stateDir}/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\n'"
            " > ${stateDir}/softhsm2.conf",
            "echo 1234 > ${stateDir}/pin",
            "softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678",
        )
        # No key yet: the check fails (it never creates one), so does signer.
        machine.fail("systemctl start signer.service")
        assert "`cakeys create` makes it" in machine.succeed(
            "journalctl -u cakeys-check-signing.service --no-pager"
        )
        machine.succeed(f"{km} create signing-soft --token softhsm --update-lock")
        machine.fail("test -e /run/cakeys/signing.pem")
        machine.succeed(f"{km} realise signing-soft --token softhsm --update-lock")
        machine.succeed("systemctl start signer.service")
        machine.succeed("systemctl is-active cakeys-check-signing.service")
        # The signer signed through the key file, with the locked key.
        assert machine.succeed("stat -c '%a %G' /run/cakeys/signing.pem").split() == ["640", "signer"]
        assert machine.succeed("head -n1 /run/cakeys/signing.pem").strip() == "-----BEGIN PKCS#11 PROVIDER URI-----"
        # The module, as the signer's environment names it: the key file does not.
        machine.succeed(
            "PKCS11_PROVIDER_MODULE=${softhsm}/lib/softhsm/libsofthsm2.so"
            " openssl pkey -provider-path ${pkgs.pkcs11-provider}/lib/ossl-modules -provider default"
            " -provider pkcs11 -in /run/cakeys/signing.pem -pubout -out /run/signing.pub",
            "openssl dgst -sha256 -verify /run/signing.pub -signature /run/signer.sig /etc/km/keys.toml",
        )
        # Key gone: a fresh check fails, and makes no new key.
        machine.succeed(f"{km} delete signing-soft --token softhsm --no-update-lock")
        machine.succeed("systemctl stop signer.service cakeys-check-signing.service")
        machine.fail("systemctl start signer.service")
        machine.fail(f"{km} resolve signing-soft --token softhsm")
        # No key file outlives the failed check.
        machine.fail("test -e /run/cakeys/signing.pem")
  '';
}
