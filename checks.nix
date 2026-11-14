# The flake's `checks` output (flake.nix): build, lint, and test derivations for
# `nix flake check`. Everything here is sandboxed and cached except where noted.
{
  pkgs,
  self,
  cakeys,
  pcsc-probe,
  treefmt,
  deny,
  demo,
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
  # nix/demo.sh straight through: every step's expected exit code still holds.
  demo = demo.check;
  # The CLI without its `tpm2` and `ykcs11` features: builds without tpm2-tss and sqlite.
  minimal = cakeys.overrideAttrs {
    pname = "cakeys-minimal";
    cargoBuildNoDefaultFeatures = true;
    buildInputs = [ ];
    doCheck = false;
  };
  vm = mkTest "vm";
  # The capability-profile query (docs/PROVIDERS.md): static answers from the profiles embedded
  # in the binary, no token needed. yes -> 0, no -> 15, unknown -> 16.
  profiles = pkgs.runCommand "cakeys-profiles" { } ''
    set -u
    # No keys.toml: `supports --profile` reads only the profiles.
    q() { "${cakeys}/bin/cakeys" supports "$@"; }
    expect() {
      want=$1
      shift
      # The builder runs with set -e: a wanted nonzero exit must be caught, not end the script.
      code=0
      got=$(q "$@" 2>&1) || code=$?
      printf '%s => exit %s (want %s)\n%s\n' "$*" "$code" "$want" "$got" >> $out
      [ "$code" = "$want" ] || { echo "FAIL: $* (exit $code, want $want)" >&2; exit 1; }
    }
    expect 15 --profile softhsm/2.7 --layer p11-kit/0.26 CKM_AES_KEY_WRAP
    # The cryptoki binding layer is always in the stack; this Nix build's cryptoki carries the
    # key-type fix, so it subtracts nothing: the probed module profile decides. It advertises
    # the SHA-512 HMAC mechanism; the key type has no generate row, so it answers unknown.
    expect 16 --profile softhsm/2.7 CKK_SHA512_HMAC
    expect 0 --profile softhsm/2.7 CKM_SHA512_HMAC
    expect 16 --profile softhsm/2.7 CKM_NOT_A_MECHANISM
    expect 0 --profile softhsm/2.7 secp256r1
    expect 0 --profile softhsm/2.7 --oaep
    expect 15 --profile kryoptic/1.5 secp256k1
    expect 15 --profile tpm2-pkcs11/1.10+swtpm --bits 4096 CKK_RSA
    # The same fact, factored out by hand into the swtpm layer.
    expect 15 --profile tpm2-pkcs11 --layer swtpm --bits 4096 CKK_RSA
    # A class listing on a probed module profile: SoftHSM advertises no PQ mechanism.
    expect 15 --class pq --profile softhsm/2.7
    # A binding without the fix, modelled through --profiles (D11): the layer subtracts.
    sim=$TMPDIR/unpatched-binding
    mkdir -p $sim
    printf 'profile = "cryptoki-sim"\nmode = "delta"\n[subtract]\nkey-types = ["CKK_SHA224_HMAC", "CKK_SHA384_HMAC", "CKK_SHA512_HMAC"]\nnote = "a binding without the key-type fix"\n' > $sim/layer.toml
    expect 15 --profile softhsm/2.7 --layer cryptoki-sim --profiles $sim CKK_SHA512_HMAC
    # The static gate (phase 4): `validate` against the profiles, no token opened. kryoptic
    # generating secp256k1 and a `kw` commitment through p11-kit are refused (15); the fixture
    # with a recorded SoftHSM lock passes.
    q() { "${cakeys}/bin/cakeys" --config "$@" validate; }
    expect 15 ${./crates/cli/tests/fixtures/gate.toml}
    cp ${./crates/cli/tests/fixtures/keys.toml} keys.toml
    cp ${./crates/cli/tests/fixtures/keys.lock} keys.lock
    expect 0 keys.toml
  '';
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
    assert signing.requiredSystemFeatures == [ "token-softhsm" ];
    assert signing.functions.CKM_ECDSA;
    assert !(signing.functions ? CKM_SHA256_HMAC);
    # One object, two specs with different policy on the same token.
    assert shared-sign.mode == "commitment";
    assert shared-nosign.mode == "wrap-rebind";
    # The replay labels: a proven private key, a secret key's fingerprint.
    assert signing.assurance == "proof";
    assert shared-sign.assurance == "fingerprint";
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
