# The flake's `apps` output (flake.nix): `nix run .#<name>`. Each runs on the host, outside
# the sandbox.
{
  pkgs,
  camigrate,
  caprobe,
  demo,
  deny,
  fuzz,
  pcsc-probe,
  pkcs11-check,
  softhsm-unwrap-value-len,
}:
let
  inherit (pkgs.stdenv.hostPlatform) system;
  probe = builtins.path {
    path = ./nix/pcsc-sandbox-probe.nix;
    name = "pcsc-sandbox-probe.nix";
  };
in
{
  # nix run .#camigrate -- --config keys.toml export <object> --token <t> --target <t2> --dry-run
  camigrate = {
    type = "app";
    program = "${camigrate}/bin/camigrate";
    meta.description = "Move keys between PKCS#11 tokens: plan exports and migrations (--dry-run), write transport files";
  };
  # nix run .#caprobe -- --config keys.toml probe --token <t> --diff <profile>
  caprobe = {
    type = "app";
    program = "${caprobe}/bin/caprobe";
    meta.description = "Measure PKCS#11 modules: probe a token into a capability profile, query the profiles, list what a token offers";
  };
  # nix run .#demo (-- --keep to leave the tokens and keys.toml for poking around)
  demo = {
    type = "app";
    program = pkgs.lib.getExe demo.demo;
    meta.description = "Walk through cakeys on two software tokens: pinned identity, the Nix view, drift, one identity across modules, export plans";
  };
  # The one cargo-deny check the sandbox cannot make: yanked releases, against the live
  # crates.io index (see `deny` in pkgs.nix). Network, host-side, uncached.
  deny-online = {
    type = "app";
    program = pkgs.lib.getExe deny.online;
    meta.description = "cargo-deny with current yanked flags: fetch the live index, then the pinned-database check with --deny yanked";
  };
  # Coverage of the whole test run with the hardware suites the sandbox cannot reach, into one
  # report (scripts/coverage-full.sh says which variables turn each suite on):
  # nix run .#coverage-full
  coverage-full = {
    type = "app";
    meta.description = "Line coverage of every suite on the host: the software tokens, and the opt-in YubiKey and real-TPM suites";
    program = pkgs.lib.getExe (
      pkgs.writeShellApplication {
        name = "cakeys-coverage-full";
        runtimeInputs = [
          pkgs.cargo-llvm-cov
          pkgs.yubikey-manager
        ];
        runtimeEnv = {
          # The llvm-tools of this rustc's own LLVM, as packages.coverage uses them.
          LLVM_COV = "${pkgs.rustc.llvmPackages.llvm}/bin/llvm-cov";
          LLVM_PROFDATA = "${pkgs.rustc.llvmPackages.llvm}/bin/llvm-profdata";
          CAKEYS_YKCS11_MODULE = "${pkgs.yubico-piv-tool}/lib/libykcs11.so";
        };
        text = ''
          [ -f scripts/coverage-full.sh ] || { echo "run from the repository root" >&2; exit 2; }
          exec bash scripts/coverage-full.sh "$@"
        '';
      }
    );
  };
  # Fuzz one target for as long as you like: nix run .#fuzz -- lock -max_total_time=600
  fuzz = {
    type = "app";
    program = pkgs.lib.getExe fuzz.run;
    meta.description = "Run a cargo-fuzz target (${pkgs.lib.concatStringsSep ", " fuzz.targets}) from the repository root";
  };
}
# The PC/SC probes check pcscd's socket from the host and from the Linux build sandbox.
// pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
  # pkcs11-check on a reference module's throwaway token, beside its caprobe profile
  # (scripts/pkcs11-check.sh): nix run .#pkcs11-check-compare -- kryoptic [main|destructive|vectors]
  pkcs11-check-compare = {
    type = "app";
    meta.description = "Run pkcs11-check on SoftHSM, kryoptic or tpm2-pkcs11 (swtpm) and summarise it against the caprobe profile";
    program = pkgs.lib.getExe (
      pkgs.writeShellApplication {
        name = "pkcs11-check-compare";
        runtimeInputs = with pkgs; [
          pkcs11-check
          softhsm-unwrap-value-len
          opensc
          python3
          swtpm
          dbus
          tpm2-abrmd
          tpm2-tools
          tpm2-pkcs11
          coreutils
        ];
        runtimeEnv = {
          # The builds the profiles were probed on (scripts/regen-profiles.sh).
          SOFTHSM_MODULE = "${softhsm-unwrap-value-len}/lib/softhsm/libsofthsm2.so";
          KRYOPTIC_MODULE = "${pkgs.kryoptic}/lib/libkryoptic_pkcs11.so";
          TPM2_PKCS11_MODULE = "${pkgs.tpm2-pkcs11}/lib/libtpm2_pkcs11.so";
          TPM2_TEST_ENV = ./nix/tpm2-test-env.sh;
          CAKEYS_TOKEN_ENV_SH = ./nix/token-env.sh;
          PROFILES = ./profiles/modules;
          TESTCASES = "${pkcs11-check}/${pkgs.python3.sitePackages}/pkcs11_check/testcases";
          COMPARE = ./scripts/pkcs11-check-compare.py;
        };
        text = ''exec bash ${./scripts/pkcs11-check.sh} "$@"'';
      }
    );
  };
  # Host-side PC/SC check.
  pcsc-probe = {
    type = "app";
    program = pkgs.lib.getExe pcsc-probe;
    meta.description = "Print raw PC/SC context and reader-list return codes";
  };
  # Same probe from inside the Nix build sandbox (needs /run/pcscd in sandbox-paths): builds
  # nix/pcsc-sandbox-probe.nix with a fresh nonce. builtins.path copies that one file, not the
  # source tree, and builtins.storePath gives each store path the context that puts it in the
  # sandbox.
  pcsc-sandbox-probe = {
    type = "app";
    meta.description = "Run pcsc-probe inside the Nix build sandbox (uncached)";
    program = pkgs.lib.getExe (
      pkgs.writeShellApplication {
        name = "pcsc-sandbox-probe";
        text = ''
          out=$(nix build --impure --no-link --print-out-paths --expr \
            "import ${probe} {
              system = \"${system}\";
              bash = builtins.storePath \"${pkgs.bash}\";
              coreutils = builtins.storePath \"${pkgs.coreutils}\";
              pcsc-probe = builtins.storePath \"${pcsc-probe}\";
              nonce = \"$(date +%s%N)\";
            }")
          cat "$out"
        '';
      }
    );
  };
}
