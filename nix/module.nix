# Host support for key-management: token access from the Nix build sandbox, uid-range builds,
# and pre-use identity checks for services (PLAN.md, "Nix integration").
{
  config,
  lib,
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
          type = types.listOf types.str;
          default = [ ];
          example = [
            "/var/lib/softhsm"
            "/etc/km/yubikey.pin?"
          ];
          description = "Paths builds need for this token (token storage, sockets, PIN files). A trailing `?` makes a path optional.";
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
      smart cards in the Nix build sandbox through pcscd: enables pcscd, exposes its socket to
      builds and lets build users past pcscd's polkit check (nixbld users, or the
      auto-allocated UID range when `nix.settings.auto-allocate-uids` is set)
    '';

    sandbox.uidRange.enable = mkEnableOption ''
      builds that require the `uid-range` system feature (e.g. systemd-nspawn NixOS tests).
      Turns on `auto-allocate-uids`, so builds no longer run as nixbld users
    '';

    tokens = mkOption {
      type = types.attrsOf (types.submodule tokenModule);
      default = { };
      description = "Tokens builds on this host may use.";
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
      nix.settings.extra-sandbox-paths = [ "/run/pcscd" ];
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

    (mkIf (cfg.tokens != { }) {
      nix.settings.system-features = lib.mapAttrsToList (_: t: t.systemFeature) cfg.tokens;
      nix.settings.extra-sandbox-paths = lib.concatMap (t: t.sandboxPaths) (lib.attrValues cfg.tokens);
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
            ExecStart = lib.escapeShellArgs (
              [
                (lib.getExe cfg.package)
                "--config"
                "${c.config}"
                "--lock"
                "${c.lock}"
              ]
              ++ lib.concatLists (
                lib.mapAttrsToList (t: p: [
                  "--module"
                  "${t}=${p}"
                ]) c.modules
              )
              ++ [
                "check"
                ("${c.object}" + lib.optionalString (c.scheme != null) ".id.${c.scheme}")
              ]
              ++ lib.optionals (c.token != null) [
                "--token"
                c.token
              ]
              ++ lib.optionals (c.spec != null) [
                "--spec"
                c.spec
              ]
            );
          };
        }
      ) cfg.checks;
    }
  ];
}
