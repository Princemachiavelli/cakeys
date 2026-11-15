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
    # Rust builds with their dependencies built once per Cargo.lock (nix/package-crane.nix).
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      advisory-db,
      crane,
    }:
    let
      inherit (nixpkgs) lib;
      # aarch64-darwin builds the tools without their tpm2 feature (nix/package-common.nix); the
      # NixOS tests, the PC/SC sandbox probe and the TPM tools are Linux only.
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
          # The AWS CloudHSM client (nix/cloudhsm.nix) is unfree: it alone is allowed, on an
          # instance of nixpkgs evaluated only when one of its packages is.
          pkgsCloudhsm = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = p: lib.hasPrefix "cloudhsm-" (lib.getName p);
          };
          local = import ./pkgs.nix {
            inherit pkgs pkgsCloudhsm advisory-db;
            craneLib = crane.mkLib pkgs;
          };
        in
        {
          inherit system pkgs local;
          inherit (pkgs.stdenv.hostPlatform) isLinux;
          treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
          # The integration tests run the crane build (nix/package-crane.nix), as every check does.
          mkTest =
            kind:
            import ./nix/test.nix {
              inherit pkgs kind;
              cakeys = local.cakeys-crane;
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
          system,
          pkgs,
          local,
          isLinux,
          mkTest,
          ...
        }:
        {
          default = local.cakeys;
          inherit (local)
            cakeys
            cakeys-crane
            caprobe
            camigrate
            p11-fault
            softhsm-unwrap-value-len
            cloud-tools
            ;
          # What the tests reach, and what they would not notice changing (nix/package-crane.nix):
          # reports, not checks.
          inherit (local.cakeys-crane) coverage mutants;
          # Every check but the fuzz smoke run, whose build cannot reuse crane's dependencies: the
          # gate while working (`nix build .#checks-crane-only`); `nix flake check` adds the fuzz run.
          checks-crane-only = pkgs.linkFarm "checks-crane-only" (
            builtins.removeAttrs self.checks.${system} [ "fuzz" ]
          );
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          inherit (local) kmsp11;
          inherit (local.cloudhsm)
            cloudhsm-pkcs11
            cloudhsm-cli
            cloudhsm-dyn
            cloudhsm-openssl-provider
            ;
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
            camigrate
            caprobe
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
            pcsc-probe
            deny
            fuzz
            softhsm-unwrap-value-len-tested
            ;
          # Every check runs the crane build (packages.cakeys-crane).
          cakeys = local.cakeys-crane;
          demo = local.demo-crane;
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
