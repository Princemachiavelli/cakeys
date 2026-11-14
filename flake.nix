{
  description = "Content-addressed identity for PKCS#11 (and later TPM) keys";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The RustSec advisory database for checks.deny, pinned like any other input: the Nix
    # sandbox has no network, so cargo-deny cannot clone it at build time.
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      advisory-db,
    }:
    let
      inherit (nixpkgs) lib;
      # aarch64-darwin builds the CLI without its tpm2 feature (nix/package.nix); the NixOS
      # tests, the PC/SC sandbox probe and the TPM tools are Linux only.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      # One evaluation per system, shared by every output: nixpkgs, treefmt, and cakeys and the
      # tools around it (pkgs.nix).
      perSystem = lib.genAttrs systems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          local = import ./pkgs.nix { inherit pkgs advisory-db; };
        in
        {
          inherit system pkgs local;
          inherit (pkgs.stdenv.hostPlatform) isLinux;
          treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
          mkTest =
            kind:
            import ./nix/test.nix {
              inherit pkgs kind;
              inherit (local) cakeys;
              module = self.nixosModules.default;
            };
        }
      );
      forAllSystems = f: lib.mapAttrs (_: f) perSystem;
    in
    {
      lib = import ./nix/lib.nix;

      nixosModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.cakeys.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.cakeys;
        };

      packages = forAllSystems (
        {
          local,
          isLinux,
          mkTest,
          ...
        }:
        {
          default = local.cakeys;
          inherit (local) cakeys;
        }
        // lib.optionalAttrs isLinux {
          inherit (local) pcsc-probe;
          # systemd-nspawn variant of the integration test. Needs the `uid-range` system feature
          # (nix.conf: `system-features = ... uid-range` and `auto-allocate-uids = true`).
          test-nspawn = mkTest "container";
        }
      );

      # Not cached: a fresh nonce makes a new derivation each time.
      # nix build --impure --expr '(builtins.getFlake "path:.").legacyPackages.x86_64-linux.pcscSandboxProbe { nonce = "1"; }'
      legacyPackages = forAllSystems (
        {
          system,
          pkgs,
          local,
          isLinux,
          ...
        }:
        lib.optionalAttrs isLinux {
          pcscSandboxProbe =
            { nonce }:
            import ./nix/pcsc-sandbox-probe.nix {
              inherit system nonce;
              inherit (local) pcsc-probe;
              inherit (pkgs) bash coreutils;
            };
        }
      );

      apps = forAllSystems (
        { pkgs, local, ... }:
        import ./apps.nix {
          inherit pkgs;
          inherit (local)
            demo
            deny
            fuzz
            pcsc-probe
            ;
        }
      );

      checks = forAllSystems (
        {
          pkgs,
          local,
          treefmt,
          mkTest,
          ...
        }:
        import ./checks.nix {
          inherit
            pkgs
            self
            treefmt
            mkTest
            ;
          inherit (local)
            cakeys
            pcsc-probe
            deny
            demo
            fuzz
            ;
        }
      );

      devShells = forAllSystems (
        {
          pkgs,
          local,
          isLinux,
          ...
        }:
        {
          default = pkgs.mkShell {
            inputsFrom = [ local.cakeys ];
            packages =
              with pkgs;
              [
                clippy
                rustfmt
                rust-analyzer
                softhsm
                kryoptic
                opensc
                openssl
                pcsc-tools
                pkg-config
                local.mezura
              ]
              # The TPM stack the tpm2 tests and probes run on (nix/tpm2-test-env.sh).
              ++ lib.optionals isLinux [
                tpm2-tss
                swtpm
                tpm2-abrmd
                tpm2-tools
                tpm2-pkcs11
                dbus
              ];
          };
        }
      );

      # treefmt over the whole tree (treefmt.nix): formatters and linters, one command.
      formatter = forAllSystems ({ treefmt, ... }: treefmt.config.build.wrapper);
    };
}
