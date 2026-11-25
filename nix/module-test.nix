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
  # The token, keys.toml and guest builds nix/test.nix and nix/tpm-test.nix use too.
  vm = import ./vm-common.nix;
  inherit (vm) stateDir;

  keysToml = pkgs.writeText "keys.toml" ''
    ${vm.keysToml "${softhsm}/lib/softhsm/libsofthsm2.so"}
    [specs.signing-soft]
    object = "signing"
    attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
    tokens.softhsm = { locator = { CKA_LABEL = "signing", CKA_ID = "01" }, origin = "create" }
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
    imports = [
      module
      vm.softhsm.config
    ];
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
        args = [
          "--format"
          "pkcs11-provider-pem"
          "--uri-pin"
          "source"
        ];
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
    systemd.tmpfiles.rules = [
      "d ${vm.softhsm.tokens} 0700 root root -"
      "d /var/lib/km 0700 root root -"
      # The deployment's lock, started empty: `cakeys --new-lock` would start the same.
      "f /var/lib/km/keys.lock 0600 root root - version = 1"
    ];
    nix.settings.substituters = lib.mkForce [ ];
    virtualisation.additionalPaths = [ guestBuilds ];
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import re

    km = "cakeys --config /etc/km/keys.toml --lock /var/lib/km/keys.lock"

    def expect(cmd, code):
        status, out = machine.execute(cmd + " 2>&1")
        assert status == code, f"{cmd}: exit {status}, wanted {code}\n{out}"
        return out

    ${vm.guestBuild}

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
            out = guest_build(machine, attr, attr)
            print(attr, out)
            assert "SCardEstablishContext: 0x00000000" in out, out
            assert "0x8010002e" in out, out  # connected; the VM simply has no reader
            assert "softhsm-dir=no" in out, out

    with subtest("the hook grants token paths only to builds requiring the token's feature"):
        out = guest_build(machine, "softhsm", "softhsm")
        print(out)
        assert "softhsm-dir=yes" in out and "SCardEstablishContext: 0x00000000" not in out, out
        out = guest_build(machine, "plain", "plain")
        print(out)
        assert "softhsm-dir=no" in out and "SCardEstablishContext: 0x00000000" not in out, out

    with subtest("uid-range builds run"):
        out = guest_build(machine, "uidRange", "uidRange")
        print(out)
        assert "uid=0 range=65536" in out, out

    with subtest("check unit gates the signer"):
        machine.succeed(
            ${vm.softhsm.init}
        )
        # No key yet: the check fails (it never creates one), so does signer.
        machine.fail("systemctl start signer.service")
        assert "`cakeys create` makes it" in machine.succeed(
            "journalctl -u cakeys-check-signing.service --no-pager"
        )
        # Created and recorded: 22, the lock was written.
        expect(f"{km} create --spec signing-soft --token softhsm", 22)
        machine.fail("test -e /run/cakeys/signing.pem")
        expect(f"{km} lock --spec signing-soft --token softhsm", 0)
        machine.succeed("systemctl start signer.service")
        # The check passed and finished: inactive, so the next start of signer runs it again.
        check = "systemctl show --value -p Result -p ActiveState cakeys-check-signing.service"
        assert sorted(machine.succeed(check).split()) == ["inactive", "success"], machine.succeed(check)
        # A finished oneshot is not a stopped dependency: signer keeps running.
        machine.succeed("systemctl is-active signer.service")
        # Ordered after the clock is set, without pulling the target in.
        unit = "cakeys-check-signing.service"
        assert "time-sync.target" in machine.succeed(f"systemctl show --value -p After {unit}")
        assert "time-sync.target" not in machine.succeed(f"systemctl show --value -p Wants -p Requires {unit}")
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
        # Key gone: restarting signer runs the check again, which fails and makes no new key.
        # No hand stop of the check unit: a restart alone must re-check (review D5).
        expect(f"{km} delete --spec signing-soft --token softhsm", 22)
        machine.fail("systemctl restart signer.service")
        # Refused by the check run again, not only by a signer that could not sign: a check
        # left active from the earlier pass would still say success.
        assert machine.succeed(f"systemctl show --value -p Result {unit}").strip() == "exit-code"
        machine.fail(f"{km} resolve --spec signing-soft --token softhsm")
        # No key file outlives the failed check.
        machine.fail("test -e /run/cakeys/signing.pem")
  '';
}
