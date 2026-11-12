# Host support for key-management: token access from the Nix build sandbox, uid-range builds,
# and pre-use identity checks for services (PLAN.md, "Nix integration").
#
# Token paths are not global `extra-sandbox-paths`: a pre-build-hook (nix/sandbox-hook.sh) grants
# them only to builds whose `requiredSystemFeatures` name the token's system feature.
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  inherit (lib)
    mkOption
    mkEnableOption
    mkIf
    mkMerge
    types
    ;
  cfg = config.services.key-management;
  autoUids = config.nix.settings.auto-allocate-uids or false;
  # Nix defaults; NixOS only sets these when nix-daemon runs unprivileged.
  startId = config.nix.settings.start-id or 872415232;
  idCount = config.nix.settings.id-count or 8388608;

  # Host GIDs builds run with: the nixbld group, or with auto-allocate-uids one GID per 65536-ID
  # slot (Nix's Linux sandbox always uses a user namespace there and sets gid = the slot's first
  # uid; supplementary groups are dropped). PLAN.md, "Build identities".
  slotSize = 65536;
  buildGids =
    if autoUids then
      lib.genList (i: startId + i * slotSize) (idCount / slotSize)
    else
      [ config.users.groups.nixbld.gid ];

  # feature -> sandbox paths, merged over tokens that share a feature.
  hookMap = lib.zipAttrsWith (_: lib.concatLists) (
    lib.mapAttrsToList (_: t: {
      ${t.systemFeature} = t.sandboxPaths ++ lib.optional t.pcscd "/run/pcscd";
    }) cfg.tokens
  );
  hook = pkgs.writeShellApplication {
    name = "key-mgmnt-sandbox-hook";
    runtimeInputs = [
      config.nix.package
      pkgs.jq
    ];
    runtimeEnv.KM_SANDBOX_MAP = pkgs.writeText "key-mgmnt-sandbox-map.json" (builtins.toJSON hookMap);
    text = builtins.readFile ./sandbox-hook.sh;
  };

  tokenModule =
    { name, ... }:
    {
      options = {
        systemFeature = mkOption {
          type = types.str;
          default = "token-${name}";
          description = "System feature advertised for this token; consumers put it in `requiredSystemFeatures`.";
        };
        sandboxPaths = mkOption {
          type = types.listOf (types.strMatching "/[^\n=]*(=/[^\n=]*)?");
          default = [ ];
          example = [
            "/var/lib/softhsm"
            "/etc/km/yubikey.pin"
          ];
          description = ''
            Paths builds requiring `systemFeature` get in their sandbox (token storage, sockets,
            PIN files), as `/path` or `/target=/source`. Granted per build by the pre-build-hook,
            and only if they exist.
          '';
        };
        pcscd = mkOption {
          type = types.bool;
          default = false;
          description = "Also grant pcscd's socket (`/run/pcscd`); needs `sandbox.pcscd.enable`.";
        };
      };
    };

  checkModule =
    { name, ... }:
    {
      options = {
        config = mkOption {
          type = types.either types.path types.str;
          description = "keys.toml.";
        };
        lock = mkOption {
          type = types.either types.path types.str;
          description = "keys.lock holding the expected identities.";
        };
        object = mkOption {
          type = types.str;
          default = name;
          description = "Object name in keys.toml.";
        };
        scheme = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Identity scheme (`pubkeyhash`, `certhash`, `commitment`); null for the object's primary one.";
        };
        token = mkOption {
          type = types.nullOr types.str;
          default = null;
        };
        spec = mkOption {
          type = types.nullOr types.str;
          default = null;
        };
        modules = mkOption {
          type = types.attrsOf types.str;
          default = { };
          example = lib.literalExpression ''{ yubikey = "''${pkgs.yubico-piv-tool}/lib/libykcs11.so"; }'';
          description = "PKCS#11 module path per token, overriding keys.toml.";
        };
        environment = mkOption {
          type = types.attrsOf types.str;
          default = { };
          example = {
            SOFTHSM2_CONF = "/var/lib/softhsm/softhsm2.conf";
          };
        };
        requiredBy = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "signer.service" ];
          description = "Units that must not start unless the identity check passes.";
        };
      };
    };
in
{
  options.services.key-management = {
    package = mkOption {
      type = types.package;
      description = "The key-mgmnt package.";
    };

    sandbox.pcscd.enable = mkEnableOption ''
      smart cards in the Nix build sandbox through pcscd: enables pcscd and lets build users
      past its polkit check (nixbld users, or the auto-allocated UID range when
      `nix.settings.auto-allocate-uids` is set). Tokens with `pcscd = true` get its socket
    '';

    sandbox.tpm2.enable = mkEnableOption ''
      the TPM resource manager (`/dev/tpmrm*`) for builds: a udev rule adds an ACL granting
      read/write to every build GID (the nixbld group, or each auto-allocated UID slot). Builds
      still only see the device if a token lists it in `sandboxPaths` and they require that
      token's feature. Builds select it with `TPM2TOOLS_TCTI`/`TPM2_PKCS11_TCTI=device:/dev/tpmrm0`
    '';

    sandbox.uidRange.enable = mkEnableOption ''
      builds that require the `uid-range` system feature (e.g. systemd-nspawn NixOS tests).
      Turns on `auto-allocate-uids`, so builds no longer run as nixbld users
    '';

    tokens = mkOption {
      type = types.attrsOf (types.submodule tokenModule);
      default = { };
      description = ''
        Tokens builds on this host may use. Each advertises its `systemFeature`, and builds that
        require that feature get its `sandboxPaths` from a pre-build-hook. Features are
        self-declared by derivations: this keeps tokens out of unrelated builds, it does not
        authenticate who asks (that is `nix.settings.allowed-users`).
      '';
    };

    checks = mkOption {
      type = types.attrsOf (types.submodule checkModule);
      default = { };
      description = ''
        Pre-use identity checks: one oneshot `key-management-check-<name>` unit each, which runs
        `key-mgmnt check` and blocks the units in `requiredBy` unless the token holds the
        locked identity.
      '';
    };
  };

  config = mkMerge [
    (mkIf cfg.sandbox.uidRange.enable {
      nix.settings = {
        auto-allocate-uids = true;
        experimental-features = [
          "auto-allocate-uids"
          "cgroups"
        ];
        # Adds to (does not replace) the NixOS default system-features.
        system-features = [ "uid-range" ];
      };
    })

    (mkIf cfg.sandbox.pcscd.enable {
      services.pcscd.enable = true;
      # Build users have no session, so pcscd's polkit check would refuse them.
      # Auto-allocated UIDs have no passwd entry: polkit reports them as the decimal UID.
      security.polkit.extraConfig = ''
        polkit.addRule(function(action, subject) {
          if (action.id != "org.debian.pcsc-lite.access_pcsc" &&
              action.id != "org.debian.pcsc-lite.access_card") {
            return polkit.Result.NOT_HANDLED;
          }
          if (subject.isInGroup("nixbld")) {
            return polkit.Result.YES;
          }
          var uid = parseInt(subject.user, 10);
          if (${lib.boolToString autoUids} && String(uid) === subject.user &&
              uid >= ${toString startId} && uid < ${toString (startId + idCount)}) {
            return polkit.Result.YES;
          }
          return polkit.Result.NOT_HANDLED;
        });
      '';
      # Upstream PrivateUsers=identity maps only UIDs 0-65535, so pcscd would see
      # auto-allocated build UIDs as 65534 and polkit would never match them.
      systemd.services.pcscd.serviceConfig.PrivateUsers = mkIf autoUids false;
    })

    (mkIf cfg.sandbox.tpm2.enable {
      assertions = [
        {
          assertion = autoUids -> lib.mod idCount slotSize == 0;
          message = "services.key-management.sandbox.tpm2: nix.settings.id-count must be a multiple of ${toString slotSize}";
        }
      ];
      # Runs after the node exists (and after NixOS's tss/0660 rule), on every add/change event.
      services.udev.extraRules = ''
        KERNEL=="tpmrm[0-9]*", RUN+="${pkgs.acl}/bin/setfacl -m ${
          lib.concatMapStringsSep "," (g: "g:${toString g}:rw") buildGids
        } /dev/%k"
      '';
    })

    (mkIf (cfg.tokens != { }) {
      assertions = lib.mapAttrsToList (n: t: {
        assertion = t.pcscd -> cfg.sandbox.pcscd.enable;
        message = "services.key-management.tokens.${n}.pcscd needs services.key-management.sandbox.pcscd.enable";
      }) cfg.tokens;
      nix.settings.system-features = lib.mapAttrsToList (_: t: t.systemFeature) cfg.tokens;
      # A plain definition: a second pre-build-hook elsewhere is a conflict, not a silent override.
      nix.settings.pre-build-hook = lib.getExe hook;
    })

    {
      systemd.services = lib.mapAttrs' (
        name: c:
        lib.nameValuePair "key-management-check-${name}" {
          description = "key-management identity check: ${c.object}";
          inherit (c) requiredBy environment;
          before = c.requiredBy;
          wants = lib.optional cfg.sandbox.pcscd.enable "pcscd.socket";
          after = lib.optional cfg.sandbox.pcscd.enable "pcscd.socket";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            # Global options, then `check <object>[.id.<scheme>]` and its options; nulls drop out.
            ExecStart = utils.escapeSystemdExecArgs (
              [ (lib.getExe cfg.package) ]
              ++ lib.cli.toCommandLineGNU { } {
                config = "${c.config}";
                lock = "${c.lock}";
                module = lib.mapAttrsToList (t: p: "${t}=${p}") c.modules;
              }
              ++ [
                "check"
                (c.object + lib.optionalString (c.scheme != null) ".id.${c.scheme}")
              ]
              ++ lib.cli.toCommandLineGNU { } { inherit (c) token spec; }
            );
          };
        }
      ) cfg.checks;
    }
  ];
}
