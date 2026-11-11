# NixOS integration test against SoftHSM.
#   kind = "vm":        QEMU VM (needs `kvm` + `nixos-test`); also runs the pseudo-FOD check
#                       inside the guest's Nix build sandbox.
#   kind = "container": systemd-nspawn (needs `uid-range`); CLI flow only.
{
  pkgs,
  key-mgmnt,
  kind ? "vm",
}:
let
  inherit (pkgs) lib;
  isVM = kind == "vm";
  stateDir = "/var/lib/softhsm";
  module = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";

  keysToml = pkgs.writeText "keys.toml" ''
    [tokens.softhsm]
    module = "${module}"
    tokenLabel = "kmtest"
    pinFile = "${stateDir}/pin"

    [objects.signing]
    class = "CKO_PRIVATE_KEY"
    keyType = "CKK_EC"
    curve = "secp256r1"

    [specs.signing-soft]
    object = "signing"
    attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
    tokens.softhsm = { locator = { CKA_LABEL = "signing" }, autoCreate = true }

    [objects.kek]
    class = "CKO_SECRET_KEY"
    keyType = "CKK_AES"
    valueLen = 32

    [specs.kek-wrap]
    object = "kek"
    # No usage bit allows a commitment, but it is extractable: wrap-rebind.
    attributes = { CKA_SIGN = false, CKA_ENCRYPT = false, CKA_WRAP = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
    tokens.softhsm = { locator = { CKA_LABEL = "kek" }, autoCreate = true }
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
        keyMgmnt = sp "${key-mgmnt}";
        modules.softhsm = sp "${pkgs.softhsm}" + "/lib/softhsm/libsofthsm2.so";
      };
    in
    derivation {
      name = "uses-signing-key";
      system = "${pkgs.stdenv.hostPlatform.system}";
      builder = sp "${pkgs.bash}" + "/bin/bash";
      PATH = sp "${pkgs.coreutils}" + "/bin";
      SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
      requiredSystemFeatures = keys.signing.rsf.softhsm;
      args = [ "-c" "uri=$(${"$"}{keys.signing.check { token = "softhsm"; }}) && echo \"$uri\" > $out" ];
    }
  '';

  machine = {
    environment.systemPackages = [
      key-mgmnt
      pkgs.softhsm
      pkgs.opensc
      pkgs.openssl
    ];
    environment.etc."km/keys.toml".source = keysToml;
    environment.etc."km/consumer.nix".source = consumer;
    environment.variables.SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
    systemd.tmpfiles.rules = [ "d ${stateDir}/tokens 0777 root root -" ];
  }
  // lib.optionalAttrs isVM {
    virtualisation.additionalPaths = [ consumer ];
    nix.settings = {
      substituters = lib.mkForce [ ];
      system-features = [ "token-softhsm" ];
      extra-sandbox-paths = [ stateDir ];
    };
  };

  test = pkgs.testers.runNixOSTest {
    name = "key-mgmnt-${kind}";
    ${if isVM then "nodes" else "containers"}.machine = machine;

    testScript = ''
      import re

      km = "key-mgmnt --config /root/keys.toml"
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
          "printf 'directories.tokendir = ${stateDir}/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\n'"
          " > ${stateDir}/softhsm2.conf",
          "echo 1234 > ${stateDir}/pin",
          "softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678",
          "chmod -R a+rwX ${stateDir}",
          "cp /etc/km/keys.toml /root/keys.toml",
      )

      with subtest("validate"):
          print(machine.succeed(f"{km} validate"))

      ${
        if isVM then
          ''
            with subtest("pseudo-FOD: first use inside the Nix sandbox creates the key, fails with got:"):
                first = got(build(ok=False))
                # Retrying never creates a second key (else: exit 12, ambiguous).
                assert got(build(ok=False)) == first
                expect(f"{km} resolve signing-soft --token softhsm", 0)

            with subtest("record out of band, then the consumer builds"):
                expect(f"{km} realise signing-soft --token softhsm --update-lock", 0)
                assert first in machine.succeed("cat /root/keys.lock")
                machine.succeed("cp /root/keys.lock /root/keys.lock.built")
                out = build("--arg lock /root/keys.lock.built")
                uri = machine.succeed(f"cat {out.strip().splitlines()[-1]}").strip()
                assert uri.startswith("pkcs11:token=kmtest;object=signing;type=private"), uri
          ''
        else
          ''
            with subtest("first use creates the key and fails with got:"):
                first = got(expect(f"{km} realise signing-soft --token softhsm", 10))
                assert got(expect(f"{km} realise signing-soft --token softhsm", 10)) == first
                expect(f"{km} realise signing-soft --token softhsm --update-lock", 0)
          ''
      }

      with subtest("independent oracle: pkcs11-tool + openssl agree with pubkeyhash"):
          machine.succeed(
              "pkcs11-tool --module ${module} --token-label kmtest --read-object --type pubkey"
              " --label signing -o /root/pub.der"
          )
          oracle = "sha256-" + machine.succeed(
              "openssl pkey -pubin -inform DER -in /root/pub.der -outform DER"
              " | openssl dgst -sha256 -binary | base64"
          ).strip()
          assert oracle == first, f"{oracle} != {first}"

      with subtest("verify and check print the URI"):
          assert expect(f"{km} verify signing-soft --token softhsm", 0).startswith("pkcs11:")
          assert expect(f"{km} check signing.id.pubkeyhash", 0).startswith("pkcs11:")

      with subtest("wrap-rebind identity for an extractable AES key"):
          got(expect(f"{km} realise kek-wrap --token softhsm", 10))
          expect(f"{km} realise kek-wrap --token softhsm --update-lock", 0)
          lock = machine.succeed("cat /root/keys.lock")
          assert 'mode = "wrap-rebind"' in lock, lock
          # The AES session copy gets every AES commitment.
          for scheme in ["cmac", "kcv-ecb", "kw"]:
              assert re.search(rf'^"?{scheme}"? = "sha256-', lock, re.M), (scheme, lock)
          expect(f"{km} verify kek-wrap --token softhsm", 0)

      with subtest("DELETE + If-Match is idempotent and guarded"):
          delete = f"{km} delete signing-soft --token softhsm --update-lock"
          expect(f"{delete} --if-match sha256-AAAA", 14)
          expect(f"{km} verify signing-soft --token softhsm", 0)
          expect(delete, 0)
          expect(delete, 0)
          expect(f"{km} verify signing-soft --token softhsm", 11)

      ${lib.optionalString isVM ''
        with subtest("caveat: a cached consumer does not re-contact the token; --check does"):
            # The key was deleted above, yet the consumer still "builds": it is cached.
            build("--arg lock /root/keys.lock.built")
            # Forcing a rebuild re-runs the pre-use check: autoCreate makes a new key, which does
            # not match the locked identity.
            out = build("--arg lock /root/keys.lock.built --check", ok=False)
            assert "hash mismatch" in out, out
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
