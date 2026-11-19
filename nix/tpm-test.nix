# VM test of TPM access from the Nix build sandbox (nix/module.nix, `sandbox.tpm2`): a udev ACL
# on /dev/tpmrm0 for every build GID, granted per build by the pre-build-hook. Two nodes:
# `auto` (auto-allocate-uids: one GID per UID slot) and `nixbld` (classic build users).
{
  pkgs,
  module,
  cakeys,
}:
let
  inherit (pkgs) lib;
  system = pkgs.stdenv.hostPlatform.system;

  # What a build's sandbox sees of the TPM.
  tpmProbe = pkgs.writeText "tpm-probe.sh" ''
    export TPM2TOOLS_TCTI=device:/dev/tpmrm0
    {
      read -r uid_map < /proc/self/uid_map; echo "uid_map: $uid_map"
      read -r gid_map < /proc/self/gid_map; echo "gid_map: $gid_map"
      if [ -e /dev/tpmrm0 ]; then echo device=present; else echo device=absent; fi
      if ${pkgs.tpm2-tools}/bin/tpm2_getrandom --hex 8; then echo; echo tpm=ok; else echo tpm=fail; fi
    } > "$out" 2>&1
  '';

  # Built inside the guest (store paths re-attached with builtins.storePath).
  guestBuilds = pkgs.writeText "builds.nix" ''
    { nonce }:
    let
      sp = builtins.storePath;
      probe = name: features: derivation {
        name = "''${name}-''${nonce}";
        system = "${system}";
        builder = sp "${pkgs.bash}" + "/bin/bash";
        requiredSystemFeatures = features;
        args = [ (sp "${tpmProbe}") ];
      };
    in
    {
      tpm = probe "tpm" [ "token-tpm" ];
      # Root inside the sandbox, with a 65536-ID range (the slot's first GID is the ACL entry).
      tpmUidRange = probe "tpm-uid-range" [ "token-tpm" "uid-range" ];
      plain = probe "plain" [ ];
    }
  '';

  node = auto: {
    imports = [ module ];
    services.cakeys = {
      package = cakeys;
      sandbox.tpm2.enable = true;
      sandbox.uidRange.enable = auto;
      tokens.tpm.sandboxPaths = [ "/dev/tpmrm0" ];
    };
    # The usual host setup: /dev/tpmrm0 is tss:tss 0660; the ACL extends it.
    security.tpm2.enable = true;
    virtualisation.tpm.enable = true;
    environment.systemPackages = [ pkgs.acl ];
    environment.etc."km/builds.nix".source = guestBuilds;
    virtualisation.additionalPaths = [ guestBuilds ];
    nix.settings.substituters = lib.mkForce [ ];
  };
in
pkgs.testers.runNixOSTest {
  name = "cakeys-tpm";

  nodes.auto = node true;
  nodes.nixbld = node false;

  # The build GIDs the ACL must list, from the `auto` node's own Nix settings (with Nix's
  # defaults, as nix/module.nix reads them): a change there moves the expectation with it.
  testScript =
    { nodes, ... }:
    let
      settings = nodes.auto.nix.settings;
      startId = settings.start-id or 872415232;
      idCount = settings.id-count or 8388608;
      # The UIDs Nix gives each auto-allocated build: fixed in Nix, not a setting.
      slotSize = 65536;
      slots = idCount / slotSize;
    in
    ''
      import re

      ${(import ./vm-common.nix).guestBuild}

      def build(m, attr, nonce):
          res = guest_build(m, attr, nonce)
          print(f"{m.name} {attr}: {res}")
          return res

      start_id, slot_size, n_slots = ${toString startId}, ${toString slotSize}, ${toString slots}
      nixbld_gid = ${toString nodes.nixbld.users.groups.nixbld.gid}

      start_all()
      for m in [auto, nixbld]:
          m.wait_for_unit("multi-user.target")
          m.wait_until_succeeds("test -e /dev/tpmrm0")
          m.succeed("udevadm settle")

      with subtest("udev puts the build GIDs on the device ACL"):
          acl = auto.succeed("getfacl -n /dev/tpmrm0")
          slots = re.findall(r"^group:(\d+):rw-$", acl, re.M)
          assert len(slots) == n_slots, acl
          assert slots[0] == str(start_id) and slots[-1] == str(start_id + (n_slots - 1) * slot_size), slots
          assert "mask::rw-" in acl, acl
          acl = nixbld.succeed("getfacl -n /dev/tpmrm0")
          assert re.search(rf"^group:{nixbld_gid}:rw-$", acl, re.M), acl
          assert "crw-rw----+" in auto.succeed("ls -l /dev/tpmrm0")

      with subtest("auto-allocated UIDs: a build requiring the TPM feature uses the TPM"):
          out = build(auto, "tpm", "a1")
          assert "device=present" in out and "tpm=ok" in out, out
          u = re.search(r"uid_map:\s+1000\s+(\d+)\s+1", out)
          g = re.search(r"gid_map:\s+100\s+(\d+)\s+1", out)
          assert u and g, out
          # Host gid == the slot's first uid: exactly what the ACL lists.
          assert u.group(1) == g.group(1) and (int(g.group(1)) - start_id) % slot_size == 0, out

      with subtest("auto-allocated UIDs: uid-range build (root in the sandbox)"):
          out = build(auto, "tpmUidRange", "a2")
          assert "device=present" in out and "tpm=ok" in out, out

      with subtest("a build without the feature does not even see the device"):
          out = build(auto, "plain", "a3")
          assert "device=absent" in out and "tpm=ok" not in out, out

      with subtest("the ACL is what grants access"):
          auto.succeed("setfacl -b /dev/tpmrm0")
          out = build(auto, "tpm", "a4")
          assert "device=present" in out and "tpm=fail" in out, out
          # A change event re-applies the rule.
          auto.succeed("udevadm trigger --action=change /sys/class/tpmrm/tpmrm0 && udevadm settle")
          out = build(auto, "tpm", "a5")
          assert "tpm=ok" in out, out

      with subtest("classic nixbld build users"):
          out = build(nixbld, "tpm", "n1")
          assert "device=present" in out and "tpm=ok" in out, out
          out = build(nixbld, "plain", "n2")
          assert "device=absent" in out, out
    '';
}
