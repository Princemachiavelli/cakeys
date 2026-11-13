# The flake's `checks` output (flake.nix): build, lint, and test derivations for
# `nix flake check`. Everything here is sandboxed and cached except where noted.
{
  pkgs,
  self,
  cakeys,
  pcsc-probe,
  treefmt,
  deny,
  fuzz,
  mkTest,
}:
{
  inherit cakeys;
  # `nix fmt` would change nothing: every formatter and linter in treefmt.nix passes.
  formatting = treefmt.config.build.check self;
  # Every fuzz target, built with libFuzzer, for a fixed seed and input count.
  fuzz = fuzz.smoke;
  # Clippy with -D warnings (NEXT.md §2): plain clippy is clean, and the workspace
  # lints (Cargo.toml [workspace.lints]: unsafe_code deny, clippy::pedantic with one
  # blanket allow) travel with every build, editor and this check.
  clippy = cakeys.overrideAttrs (old: {
    pname = "cakeys-clippy";
    # The lint replaces the build and the tests, so the integration-test inputs are
    # not needed; the vendored deps and the cryptoki patch are inherited.
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.clippy ];
    nativeCheckInputs = [ ];
    buildPhase = ''
      runHook preBuild
      cargo clippy --workspace --all-targets -- -D warnings
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p $out
    '';
    doCheck = false;
  });
  # cargo-deny offline (see the `deny` binding in flake.nix): reproducible with the flake.lock.
  deny = deny.check;
  # The CLI without its `tpm2` and `ykcs11` features: builds without tpm2-tss and sqlite.
  minimal = cakeys.overrideAttrs {
    pname = "cakeys-minimal";
    cargoBuildNoDefaultFeatures = true;
    buildInputs = [ ];
    doCheck = false;
  };
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
        inherit cakeys;
        modules.softhsm = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
      };
      fails = e: !(builtins.tryEval e).success;
      # One calling convention: the object is a function naming its (spec, token) pair.
      signing = keys.signing { token = "softhsm"; };
      shared-sign = keys.shared {
        token = "softhsm";
        spec = "shared-sign";
      };
      shared-nosign = keys.shared {
        token = "softhsm";
        spec = "shared-nosign";
      };
      signing-cert = keys.signing-cert { token = "softhsm"; };
    in
    assert signing.id.rfc7093m4 == "sha256-d3++Ph3T9bppuPnNz6blK4vDij+Swy9RMmKdfQnLmPk=";
    assert signing.id.pubkeyhash == signing.id.rfc7093m4; # input alias
    assert signing.uri == "pkcs11:token=kmtest;object=signing;type=private";
    assert signing.mode == "direct";
    assert signing.spec == "signing-soft" && signing.token == "softhsm";
    assert signing.rsf == [ "token-softhsm" ];
    assert signing.functions.CKM_ECDSA;
    assert !(signing.functions ? CKM_SHA256_HMAC);
    # One object, two specs with different policy on the same token.
    assert shared-sign.mode == "commitment";
    assert shared-nosign.mode == "wrap-rebind";
    assert fails (keys.shared { token = "softhsm"; }); # ambiguous: several specs on one token
    assert fails (keys.signing { token = "elsewhere"; }); # no such pair
    assert signing.module.version == "2.7";
    assert signing.tokenInfo.model == "SoftHSM v2";
    assert shared-sign.module == null; # older lock entry
    # No scheme: the CLI verifies every ID the spec computes; a scheme also requires it.
    assert pkgs.lib.hasInfix "check signing-cert --token softhsm" signing-cert.check;
    assert pkgs.lib.hasInfix "check signing-cert.id.certhash"
      (keys.signing-cert { scheme = "certhash"; }).check;
    pkgs.runCommand "cakeys-lib-check" { } ''
      echo ${pkgs.lib.escapeShellArg (keys.signing { }).check} > $out
    '';
}
