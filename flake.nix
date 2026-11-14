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
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
      # cakeys and the tools around it (pkgs.nix).
      local = import ./pkgs.nix { inherit pkgs advisory-db; };
      inherit (local)
        cakeys
        caprobe
        pcsc-probe
        mezura
        ;
      mkTest =
        kind:
        import ./nix/test.nix {
          inherit pkgs cakeys kind;
          module = self.nixosModules.default;
        };
    in
    {
      lib = import ./nix/lib.nix;

      nixosModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.cakeys.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.cakeys;
        };

      packages.${system} = {
        default = cakeys;
        inherit cakeys caprobe pcsc-probe;
        # systemd-nspawn variant of the integration test. Needs the `uid-range` system feature
        # (nix.conf: `system-features = ... uid-range` and `auto-allocate-uids = true`).
        test-nspawn = mkTest "container";
      };

      # Not cached: a fresh nonce makes a new derivation each time.
      # nix build --impure --expr '(builtins.getFlake "path:.").legacyPackages.x86_64-linux.pcscSandboxProbe { nonce = "1"; }'
      legacyPackages.${system}.pcscSandboxProbe =
        { nonce }:
        import ./nix/pcsc-sandbox-probe.nix {
          inherit system pcsc-probe nonce;
          inherit (pkgs) bash coreutils;
        };

      apps.${system} = import ./apps.nix {
        inherit pkgs;
        inherit (local)
          caprobe
          demo
          deny
          fuzz
          pcsc-probe
          ;
      };

      checks.${system} = import ./checks.nix {
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
      };

      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ cakeys ];
        packages = with pkgs; [
          clippy
          rustfmt
          rust-analyzer
          softhsm
          kryoptic
          opensc
          openssl
          pcsc-tools
          tpm2-tss
          pkg-config
          swtpm
          tpm2-abrmd
          tpm2-tools
          tpm2-pkcs11
          dbus
          mezura
        ];
      };

      # treefmt over the whole tree (treefmt.nix): formatters and linters, one command.
      formatter.${system} = treefmt.config.build.wrapper;
    };
}
