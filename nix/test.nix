# NixOS integration test against SoftHSM.
#   kind = "vm":        QEMU VM (needs `kvm` + `nixos-test`); also runs the pseudo-FOD check
#                       inside the guest's Nix build sandbox.
#   kind = "container": systemd-nspawn (needs `uid-range`); CLI flow only.
{
  pkgs,
  cakeys,
  module,
  kind ? "vm",
}:
let
  inherit (pkgs) lib;
  isVM = kind == "vm";
  # The token, keys.toml and guest builds nix/module-test.nix and nix/tpm-test.nix use too.
  vm = import ./vm-common.nix;
  inherit (vm) stateDir;
  softhsmLib = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";

  keysToml = pkgs.writeText "keys.toml" ''
    ${vm.keysToml softhsmLib}
    [specs.signing-soft]
    object = "signing"
    attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
    tokens.softhsm = { locator = { CKA_LABEL = "signing" }, origin = "create" }

    [objects.kek]
    class = "CKO_SECRET_KEY"
    keyType = "CKK_AES"
    valueLen = 32

    [specs.kek-wrap]
    object = "kek"
    # No usage bit allows a commitment, but it is extractable: wrap-rebind.
    attributes = { CKA_SIGN = false, CKA_ENCRYPT = false, CKA_WRAP = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
    tokens.softhsm = { locator = { CKA_LABEL = "kek" }, origin = "create" }
  '';

  # A consumer derivation that uses the key: evaluated and built *inside* the guest.
  # Store paths are re-attached with builtins.storePath so they become sandbox inputs.
  consumer = pkgs.writeText "consumer.nix" ''
    { config, lock ? null }:
    let
      sp = builtins.storePath;
      km = import (sp "${./lib.nix}");
      keys = km.mkKeys {
        inherit config lock;
        cakeys = sp "${cakeys}";
        modules.softhsm = sp "${pkgs.softhsm}" + "/lib/softhsm/libsofthsm2.so";
      };
      signing = keys.signing { token = "softhsm"; };
    in
    derivation {
      name = "uses-signing-key";
      system = "${pkgs.stdenv.hostPlatform.system}";
      builder = sp "${pkgs.bash}" + "/bin/bash";
      PATH = sp "${pkgs.coreutils}" + "/bin";
      SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
      requiredSystemFeatures = signing.requiredSystemFeatures;
      args = [ "-c" "uri=$(${"$"}{signing.check}) && echo \"$uri\" > $out" ];
    }
  '';

  machine = {
    imports = [ vm.softhsm.config ] ++ lib.optional isVM module;
    environment.systemPackages = [
      cakeys
      pkgs.softhsm
      pkgs.opensc
      pkgs.openssl
    ];
    environment.etc."km/keys.toml".source = keysToml;
    environment.etc."km/consumer.nix".source = consumer;
    # World-writable for this test alone: root makes the token and its objects, and the
    # sandboxed nixbld builder must use the same files (the chmods in testScript too). A token
    # database inside the build sandbox is what docs/CAKEYS.md ("What real builds may reach")
    # says never to deploy; this tests the pre-build-hook's grant, not a configuration to copy.
    systemd.tmpfiles.rules = [ "d ${vm.softhsm.tokens} 0777 root root -" ];
  }
  // lib.optionalAttrs isVM {
    # The consumer gets the token through the module's pre-build-hook, because it requires the
    # token's feature ((keys.signing { token = "softhsm"; }).requiredSystemFeatures, i.e.
    # token-softhsm).
    services.cakeys = {
      package = cakeys;
      tokens.softhsm.sandboxPaths = [ stateDir ];
    };
    virtualisation.additionalPaths = [ consumer ];
    nix.settings.substituters = lib.mkForce [ ];
  };

  test = pkgs.testers.runNixOSTest {
    name = "cakeys-${kind}";
    ${if isVM then "nodes" else "containers"}.machine = machine;

    testScript = ''
      import re

      km = "cakeys --config /root/keys.toml"
      def build(extra="", ok=True):
          # Token objects created by root must stay usable by the sandboxed nixbld builder.
          machine.succeed("chmod -R a+rwX ${stateDir}")
          cmd = f"nix-build /etc/km/consumer.nix --no-out-link --arg config /root/keys.toml {extra} 2>&1"
          status, out = machine.execute(cmd)
          assert (status == 0) == ok, f"{cmd}: exit {status}\n{out}"
          return out

      def got(out):
          m = re.search(r"got:\s+(sha256-\S+)", out)
          assert m, f"no got: line in\n{out}"
          return m.group(1)

      def expect(cmd, code):
          status, out = machine.execute(cmd + " 2>&1")
          assert status == code, f"{cmd}: exit {status}, wanted {code}\n{out}"
          return out

      start_all()
      machine.wait_for_unit("multi-user.target")
      machine.succeed(
          ${vm.softhsm.init}
          "chmod -R a+rwX ${stateDir}",
          "cp /etc/km/keys.toml /root/keys.toml",
      )

      with subtest("no lock yet: refused (17) unless --new-lock starts one"):
          assert "--new-lock" in expect(f"{km} validate", 17)
          print(machine.succeed(f"{km} --new-lock validate"))
          machine.fail("test -e /root/keys.lock")

      ${
        if isVM then
          ''
            with subtest("pseudo-FOD: the check inside the Nix sandbox never creates; first use fails with got:"):
                out = build(ok=False)
                assert "`cakeys create` makes it" in out, out
                # The key is created out of band; the sandbox's check then fails like a FOD with
                # a fake hash, and never creates a second key (else: exit 12, ambiguous).
                first = got(expect(f"{km} --new-lock create --spec signing-soft --token softhsm --no-update-lock", 18))
                assert got(build(ok=False)) == first
                expect(f"{km} --new-lock resolve --spec signing-soft --token softhsm", 0)

            with subtest("record out of band (22: the lock was written), then the consumer builds"):
                expect(f"{km} --new-lock lock --spec signing-soft --token softhsm", 22)
                assert first in machine.succeed("cat /root/keys.lock")
                machine.succeed("cp /root/keys.lock /root/keys.lock.built")
                out = build("--arg lock /root/keys.lock.built")
                uri = machine.succeed(f"cat {out.strip().splitlines()[-1]}").strip()
                assert uri.startswith("pkcs11:token=kmtest;serial=") and uri.endswith(";object=signing;type=private"), uri
          ''
        else
          ''
            with subtest("only create creates; first use fails with got:"):
                expect(f"{km} --new-lock lock --spec signing-soft --token softhsm --dry-run", 11)
                first = got(expect(f"{km} --new-lock create --spec signing-soft --token softhsm --no-update-lock", 18))
                assert got(expect(f"{km} --new-lock lock --spec signing-soft --token softhsm --dry-run", 18)) == first
                expect(f"{km} --new-lock lock --spec signing-soft --token softhsm", 22)
                expect(f"{km} lock --spec signing-soft --token softhsm", 0)
          ''
      }

      with subtest("independent oracle: pkcs11-tool + openssl agree with rfc7093m4"):
          machine.succeed(
              "pkcs11-tool --module ${softhsmLib} --token-label kmtest --read-object --type pubkey"
              " --label signing -o /root/pub.der"
          )
          oracle = "sha256-" + machine.succeed(
              "openssl pkey -pubin -inform DER -in /root/pub.der -outform DER"
              " | openssl dgst -sha256 -binary | base64"
          ).strip()
          assert oracle == first, f"{oracle} != {first}"

      with subtest("check prints the URI, by pair and by identity"):
          assert expect(f"{km} check --spec signing-soft --token softhsm", 0).startswith("pkcs11:")
          assert expect(f"{km} check signing.id.rfc7093m4", 0).startswith("pkcs11:")

      with subtest("wrap-rebind identity for an extractable AES key"):
          got(expect(f"{km} create --spec kek-wrap --token softhsm --no-update-lock", 18))
          expect(f"{km} lock --spec kek-wrap --token softhsm", 22)
          lock = machine.succeed("cat /root/keys.lock")
          assert 'mode = "wrap-rebind"' in lock, lock
          # The AES session copy gets every AES commitment.
          for scheme in ["cmac", "kcv-ecb", "kw"]:
              assert re.search(rf'^"?{scheme}"? = "sha256-', lock, re.M), (scheme, lock)
          expect(f"{km} check --spec kek-wrap --token softhsm", 0)

      with subtest("DELETE + If-Match is idempotent and guarded"):
          delete = f"{km} delete --spec signing-soft --token softhsm"
          expect(f"{delete} --if-match sha256-AAAA", 14)
          expect(f"{km} check --spec signing-soft --token softhsm", 0)
          expect(f"{delete} --dry-run", 0)
          expect(f"{km} check --spec signing-soft --token softhsm", 0)
          expect(delete, 22)
          expect(delete, 0)
          expect(f"{km} check --spec signing-soft --token softhsm", 11)

      ${lib.optionalString isVM ''
        with subtest("caveat: a cached consumer does not re-contact the token; --check does"):
            # The key was deleted above, yet the consumer still "builds": it is cached.
            build("--arg lock /root/keys.lock.built")
            # Forcing a rebuild re-runs the pre-use check, which finds the key gone (11) and
            # never regenerates it: new material could never match what the lock pins.
            out = build("--arg lock /root/keys.lock.built --check", ok=False)
            assert "`cakeys create` makes it" in out, out
      ''}
    '';
  };
in
if isVM then
  test
else
  # Extra sandbox paths under /var (e.g. /var/cache/ccache) make Nix create /var owned by
  # the unmapped host root, so the driver cannot create /var/run inside a uid-range build.
  test.overrideTestDerivation (old: {
    buildCommand = ''
      if ! touch /var/.writable 2>/dev/null; then
        ${pkgs.util-linux}/bin/mount -t tmpfs none /var
      fi
    ''
    + old.buildCommand;
  })
