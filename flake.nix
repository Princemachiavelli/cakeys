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
      cakeys = pkgs.callPackage ./nix/package.nix { };
      pcsc-probe = pkgs.callPackage ./nix/pcsc-probe.nix { };
      # cargo-deny (NEXT.md §1): the sandboxed checks.deny (advisories against the pinned
      # RustSec database, licenses, bans, sources) and the online apps.deny-online (yanked —
      # registry metadata the sandbox has no network for). Configuration: deny.toml.
      deny = pkgs.callPackage ./nix/deny.nix {
        inherit advisory-db;
        inherit (cakeys) cargoDeps;
      };
      # cargo-fuzz (fuzz/): a fixed-seed smoke run in checks.fuzz, and apps.fuzz for long runs.
      fuzz = pkgs.callPackage ./nix/fuzz.nix { };
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
        inherit cakeys pcsc-probe;
        # systemd-nspawn variant of the integration test. Needs the `uid-range` system feature
        # (nix.conf: `system-features = ... uid-range` and `auto-allocate-uids = true`).
        test-nspawn = mkTest "container";
      };

      # Not cached: a fresh nonce makes a new derivation each time.
      # nix build --impure --expr '(builtins.getFlake "path:.").legacyPackages.x86_64-linux.pcscSandboxProbe { nonce = "1"; }'
      legacyPackages.${system}.pcscSandboxProbe =
        { nonce }:
        pkgs.runCommand "pcsc-sandbox-probe-${nonce}" { } ''
          rc=0
          { id; ${pkgs.lib.getExe pcsc-probe} || rc=$?; echo "exit=$rc"; } > $out 2>&1
        '';

      apps.${system} = {
        # The one cargo-deny check the sandbox cannot make: yanked releases, against the live
        # crates.io index (see the `deny` binding above). Network, host-side, uncached.
        deny-online = {
          type = "app";
          program = pkgs.lib.getExe deny.online;
          meta.description = "cargo-deny with current yanked flags: fetch the live index, then the pinned-database check with --deny yanked";
        };
        # Fuzz one target for as long as you like: nix run .#fuzz -- lock -max_total_time=600
        fuzz = {
          type = "app";
          program = pkgs.lib.getExe fuzz.run;
          meta.description = "Run a cargo-fuzz target (public_key, certificate, lock, config) from the repository root";
        };
        # Host-side PC/SC check.
        pcsc-probe = {
          type = "app";
          program = pkgs.lib.getExe pcsc-probe;
          meta.description = "Print raw PC/SC context and reader-list return codes";
        };
        # Same probe from inside the Nix build sandbox (needs /run/pcscd in sandbox-paths).
        pcsc-sandbox-probe = {
          type = "app";
          meta.description = "Run pcsc-probe inside the Nix build sandbox (uncached)";
          program = pkgs.lib.getExe (
            pkgs.writeShellApplication {
              name = "pcsc-sandbox-probe";
              text = ''
                out=$(nix build --impure --no-link --print-out-paths --expr \
                  "(builtins.getFlake \"path:${self}\").legacyPackages.${system}.pcscSandboxProbe { nonce = \"$(date +%s%N)\"; }")
                cat "$out"
              '';
            }
          );
        };
      };

      checks.${system} = import ./checks.nix {
        inherit
          pkgs
          self
          cakeys
          pcsc-probe
          treefmt
          deny
          fuzz
          mkTest
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
        ];
      };

      # treefmt over the whole tree (treefmt.nix): formatters and linters, one command.
      formatter.${system} = treefmt.config.build.wrapper;
    };
}
