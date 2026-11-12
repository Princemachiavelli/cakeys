{
  description = "Content-addressed identity for PKCS#11 (and later TPM) keys";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst";
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      cakeys = pkgs.callPackage ./nix/package.nix { };
      pcsc-probe = pkgs.callPackage ./nix/pcsc-probe.nix { };
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

      checks.${system} = {
        inherit cakeys;
        vm = mkTest "vm";
        module = import ./nix/module-test.nix {
          inherit pkgs cakeys pcsc-probe;
          module = self.nixosModules.default;
        };
        tpm = import ./nix/tpm-test.nix {
          inherit pkgs cakeys;
          module = self.nixosModules.default;
        };
        lib =
          let
            keys = self.lib.mkKeys {
              config = ./crates/cli/tests/fixtures/keys.toml;
              lock = ./crates/cli/tests/fixtures/keys.lock;
              cakeys = cakeys;
              modules.softhsm = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
            };
            fails = e: !(builtins.tryEval e).success;
          in
          assert keys.signing.id.rfc7093m4 == "sha256-d3++Ph3T9bppuPnNz6blK4vDij+Swy9RMmKdfQnLmPk=";
          assert keys.signing.id.pubkeyhash == keys.signing.id.rfc7093m4; # input alias
          assert keys.signing.uri.softhsm == "pkcs11:token=kmtest;object=signing;type=private";
          assert keys.signing.mode.softhsm == "direct";
          assert keys.signing.rsf.softhsm == [ "token-softhsm" ];
          assert keys.signing.functions.softhsm.CKM_ECDSA;
          assert !(keys.signing.functions.softhsm ? CKM_SHA256_HMAC);
          # One object, two specs with different policy on the same token.
          assert keys.shared.specs.shared-sign.mode.softhsm == "commitment";
          assert keys.shared.specs.shared-nosign.mode.softhsm == "wrap-rebind";
          assert fails keys.shared.uri.softhsm; # ambiguous: several specs on one token
          assert keys.signing.module.softhsm.version == "2.7";
          assert keys.signing.tokenInfo.softhsm.model == "SoftHSM v2";
          assert keys.shared.specs.shared-sign.module.softhsm == null; # older lock entry
          # No scheme: the CLI verifies every ID the spec computes; a scheme also requires it.
          assert pkgs.lib.hasInfix "check signing-cert --token softhsm" (
            keys.signing-cert.check { token = "softhsm"; }
          );
          assert pkgs.lib.hasInfix "check signing-cert.id.certhash" (
            keys.signing-cert.check { scheme = "certhash"; }
          );
          pkgs.runCommand "cakeys-lib-check" { } ''
            echo ${pkgs.lib.escapeShellArg (keys.signing.check { })} > $out
          '';
      };

      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ cakeys ];
        packages = with pkgs; [
          clippy
          rustfmt
          rust-analyzer
          softhsm
          opensc
          openssl
          pcsc-tools
        ];
      };

      # nixfmt-tree formats the tree; bare nixfmt would wait on stdin.
      formatter.${system} = pkgs.nixfmt-tree;
    };
}
