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
  softhsm-unwrap-value-len-tested,
}:
{
  # The crane build (nix/package-crane.nix) with its tests; every check below runs it.
  # packages.cakeys is the same build without its check phase (`unchecked`), what users get.
  inherit cakeys;
  # `nix fmt` would change nothing: every formatter and linter in treefmt.nix passes.
  formatting = treefmt.config.build.check self;
  # Clippy with -D warnings over every target (nix/package-crane.nix).
  inherit (cakeys) clippy;
  # rustdoc, private items included, with -D warnings: no broken doc link (nix/package-crane.nix).
  inherit (cakeys) doc;
  # `cargo check --all-targets` with the toolchain at Cargo.toml's rust-version.
  inherit (cakeys) msrv;
  # cargo-deny offline (see `deny` in pkgs.nix): reproducible with the flake.lock.
  deny = deny.check;
  # Every test and function the docs name is a `fn`, and every docs/*.md cited exists
  # (nix/doc-references.py). Its own fileset, so a docs edit does not rebuild crane.
  doc-references =
    let
      src = pkgs.lib.fileset.toSource {
        root = ./.;
        fileset = pkgs.lib.fileset.unions [
          ./docs
          ./ISSUES.md
          ./README.md
          ./LICENSE
          ./Cargo.toml
          ./examples
          ./profiles
          ./crates
          ./fuzz
          ./nix
          ./scripts
          (pkgs.lib.fileset.fileFilter (f: f.hasExt "nix") ./.)
        ];
      };
    in
    pkgs.runCommand "cakeys-doc-references" { nativeBuildInputs = [ pkgs.python3 ]; } ''
      python3 -I ${src}/nix/doc-references.py ${src}
      touch $out
    '';
  # What was measured on hardware or a cloud and no build repeats (profiles/LEDGER.toml,
  # nix/ledger.py): a file changed, or the code on its path changed since its run, fails until
  # the ledger records it. Its fixture tests first. Its own fileset, like doc-references.
  ledger =
    let
      src = pkgs.lib.fileset.toSource {
        root = ./.;
        fileset = pkgs.lib.fileset.unions [
          ./profiles
          ./crates
          ./nix
          ./scripts
          ./examples
        ];
      };
    in
    pkgs.runCommand "cakeys-ledger" { nativeBuildInputs = [ pkgs.python3 ]; } ''
      set -o pipefail
      python3 -I ${src}/nix/ledger-test.py
      python3 -I ${src}/nix/ledger.py ${src} | tee $out
    '';
  # The software tokens are set up in one place, nix/token-env.sh (review D9): no other script
  # writes a SoftHSM configuration or initialises a token by hand, but those its header leaves
  # out (VM tests, old SoftHSM releases, upstream repros, a cloud host, p11-kit's own token).
  token-setup =
    let
      src = pkgs.lib.fileset.toSource {
        root = ./.;
        fileset = pkgs.lib.fileset.fileFilter (f: f.hasExt "sh" || f.hasExt "nix") ./.;
      };
    in
    pkgs.runCommand "cakeys-token-setup" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
      cd ${src}
      if rg -n -e 'directories\.tokendir' -e '--init-token' -g '!nix/token-env.sh' -g '!checks.nix' \
        -g '!nix/test.nix' -g '!nix/module-test.nix' -g '!scripts/xversion.sh' -g '!upstream/**' \
        -g '!scripts/cloud/aws.sh' -g '!nix/p11kit-test-env.sh' .; then
        echo "token-setup: set the tokens up through nix/token-env.sh, or name the script in its header and here" >&2
        exit 1
      fi
      touch $out
    '';
  # CI builds the three parts flake.nix splits the checks into, each once
  # (.github/workflows/checks.yml): a part the workflow stops naming is never built there.
  ci-jobs = pkgs.runCommand "cakeys-ci-jobs" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
    for part in '.#checks-no-vm' '.#checks-vm' '.#checks.x86_64-linux.kani'; do
      if [ "$(rg -c -F "build: $part" ${./.github/workflows/checks.yml})" != 1 ]; then
        echo "ci-jobs: .github/workflows/checks.yml should build $part once" >&2
        exit 1
      fi
    done
    if [ -e ${./.github/workflows}/flake-check.yml ]; then
      echo "ci-jobs: flake-check.yml would build the checks a second time" >&2
      exit 1
    fi
    touch $out
  '';
  # nix/demo.sh straight through: every step's expected exit code still holds.
  demo = demo.check;
  # cakeys, caprobe and camigrate without their `tpm2` and `ykcs11` features (nix/package-crane.nix).
  inherit (cakeys) minimal;
  # SoftHSM with upstream/softhsm/ (SoftHSMv2 #628): its own test suite, extended by the patch,
  # passes, and an unwrapped AES key reports CKA_VALUE_LEN 32 under every wrapping mechanism.
  softhsm-unwrap-value-len =
    pkgs.runCommand "softhsm-unwrap-value-len"
      {
        nativeBuildInputs = [
          softhsm-unwrap-value-len-tested
          (pkgs.python3.withPackages (p: [ p.python-pkcs11 ]))
        ];
      }
      ''
        bash ${./upstream/softhsm}/repro.sh ${softhsm-unwrap-value-len-tested}/lib/softhsm/libsofthsm2.so | tee $out
      '';
  # The same SoftHSM under OpenSSL through pkcs11-provider, activated before `default`: no
  # deadlock in C_Login (SoftHSMv2 #834), a streaming ECDSA signature that verifies (#857), and
  # no crash at exit (#780). Stock SoftHSM 2.7.0 hangs on the first step.
  softhsm-pkcs11-provider =
    pkgs.runCommand "softhsm-pkcs11-provider"
      {
        nativeBuildInputs = [
          softhsm-unwrap-value-len-tested
          pkgs.opensc
          (pkgs.lib.getBin pkgs.openssl)
        ];
      }
      ''
        bash ${./upstream/softhsm}/repro-834.sh ${softhsm-unwrap-value-len-tested}/lib/softhsm/libsofthsm2.so \
          ${pkgs.pkcs11-provider}/lib/ossl-modules | tee $out
      '';
  # The lock rules' Quint model, crates/core/spec/lock.qnt (docs/DEVELOPMENT.md, "Verification
  # beyond tests"): it typechecks; a fixed-seed simulation holds every invariant and reaches
  # every rule that decides a run (each `decidedBy` witness at least once); and Apalache proves
  # the invariants for every run of up to two steps. That the Rust agrees with the model is
  # crates/core/tests/lock_mbt.rs, among the crane build's tests.
  quint =
    let
      spec = ./crates/core/spec/lock.qnt;
      witnesses = [
        "Type"
        "Spec"
        "Mode"
        "Binding"
        "Anchor"
        "AttestationId"
        "AttestationLost"
        "SchemesLost"
        "Replaced"
        "Object"
        "Unlinked"
        "Mismatch"
        "FirstUse"
        "Unrealised"
        "SecondName"
        "Compared"
        "Recorded"
        "Unchanged"
      ];
    in
    pkgs.runCommand "cakeys-quint" { nativeBuildInputs = [ pkgs.quint ]; } ''
      export HOME=$TMPDIR
      quint typecheck ${spec}
      quint run ${spec} --seed 1 --max-samples 2000 --max-steps 12 --invariant invariants \
        --witnesses ${pkgs.lib.concatMapStringsSep " " (w: "decidedBy${w}") witnesses} | tee run.txt
      # A positive count per witness, not the absence of a zero: a reworded or missing line
      # fails the check instead of passing it.
      for w in ${pkgs.lib.concatStringsSep " " witnesses}; do
        if ! grep -Eq "^decidedBy$w was witnessed in [1-9][0-9]* trace" run.txt; then
          echo "quint: no simulated run reaches decidedBy$w (or quint no longer reports it)" >&2
          exit 1
        fi
      done
      quint verify ${spec} --max-steps 2 --invariant invariants | tee verify.txt
      mkdir $out
      cp run.txt verify.txt $out/
    '';
  # The capability-profile query (docs/CAPROBE.md, `caprobe supports`): static answers from the
  # profiles embedded in the binary, no token needed. yes -> 0, no -> 15, unknown -> 16.
  profiles = pkgs.runCommand "cakeys-profiles" { } ''
    set -u
    # No keys.toml: `supports --profile` reads only the profiles.
    q() { "${cakeys.caprobe}/bin/caprobe" supports "$@"; }
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
  # The configs and locks `mkKeys` reads here are fixture files, not `builtins.toFile` text:
  # CI's `nix flake check --no-build` ran on Determinate Nix and failed with "path
  # '/nix/store/...-keys.lock' is not valid" on a `toFile` path read back by `readFile`. We
  # suspect a parallel-evaluation issue in DetSys Nix (unconfirmed; upstream Nix passes), and
  # path literals do not hit it.
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
      # The library reads keys.toml with fromTOML, not through cakeys' loader (which refuses
      # these names, 17): `check` still quotes every word it builds.
      odd =
        (self.lib.mkKeys {
          config = ./crates/cli/tests/fixtures/odd-names.toml;
          inherit cakeys;
        })."a b; echo pwned #"
          { };
      # An object born in a file (docs/FILE.md): its `migrate` table is camigrate's, not its type.
      fromFile =
        (self.lib.mkKeys {
          config = ./crates/cli/tests/fixtures/from-file.toml;
          inherit cakeys;
        }).k
          { };
    in
    assert signing.id.rfc7093m4 == "sha256-d3++Ph3T9bppuPnNz6blK4vDij+Swy9RMmKdfQnLmPk=";
    assert signing.id.pubkeyhash == signing.id.rfc7093m4; # input alias
    # The type is the material alone: `origin` sits on the pair, beside the locator.
    assert
      signing.type == {
        class = "CKO_PRIVATE_KEY";
        keyType = "CKK_EC";
        curve = "secp256r1";
      };
    assert
      fromFile.type == {
        class = "CKO_PRIVATE_KEY";
        keyType = "CKK_EC";
        curve = "secp256r1";
      };
    # A curve's alias in keys.toml: the type is the lock's canonical one once the lock pins the
    # object, keys.toml's as written before (ISSUES.md N2).
    assert
      let
        aliased =
          lock:
          (self.lib.mkKeys {
            inherit lock cakeys;
            config = p256Alias;
          }).signing
            { };
        p256Alias = ./crates/cli/tests/fixtures/p256-alias.toml;
      in
      (aliased ./crates/cli/tests/fixtures/keys.lock).type.curve == "secp256r1"
      && (aliased null).type.curve == "P-256";
    assert signing.spec == "signing-soft" && signing.token == "softhsm";
    assert signing.requiredSystemFeatures == [ "token-softhsm" ];
    # Only what evaluation knows without the token: no URI or observation read from the lock
    # unchecked (`check` prints the verified URI).
    assert
      builtins.attrNames signing == [
        "check"
        "id"
        "requiredSystemFeatures"
        "spec"
        "token"
        "type"
      ];
    # One object, two specs with different policy on the same token: one identity.
    assert shared-sign.id == shared-nosign.id;
    assert fails (keys.shared { token = "softhsm"; }); # ambiguous: several specs on one token
    assert fails (keys.signing { token = "elsewhere"; }); # no such pair
    # A lock of another version is not read.
    assert fails
      (
        (self.lib.mkKeys {
          config = ./crates/cli/tests/fixtures/keys.toml;
          lock = ./crates/cli/tests/fixtures/version-99.lock;
        }).signing
          { }
      ).id;
    # A lock path that does not exist is an error, in `id` and in `check` alike, not a silent
    # first use; `null` is the lock not yet recorded.
    assert
      let
        missing =
          (self.lib.mkKeys {
            inherit cakeys;
            config = ./crates/cli/tests/fixtures/keys.toml;
            lock = ./crates/cli/tests/fixtures/no-such.lock;
          }).signing
            { };
      in
      fails missing.id && fails missing.check;
    # With `lock = null`, `check` names no lock and reads the absent one as empty (--new-lock): a
    # first use, never cakeys' refusal of a missing lock (17).
    assert
      let
        unlocked =
          (
            (self.lib.mkKeys {
              inherit cakeys;
              config = ./crates/cli/tests/fixtures/keys.toml;
            }).signing
              { }
          ).check;
      in
      !(pkgs.lib.hasInfix "--lock" unlocked) && pkgs.lib.hasInfix " --new-lock " unlocked;
    # No scheme: the CLI verifies every ID the spec computes; a scheme also requires it.
    assert pkgs.lib.hasInfix "check signing-cert --token softhsm" signing-cert.check;
    assert pkgs.lib.hasInfix "check signing-cert.id.certhash"
      (keys.signing-cert { scheme = "certhash"; }).check;
    # What `check` prints: the bare URI unless the call passes `check`'s own flags.
    assert !(pkgs.lib.hasInfix "--format" signing.check || pkgs.lib.hasInfix "--uri-" signing.check);
    assert pkgs.lib.hasSuffix
      "--spec signing-soft --format pkcs11-provider-pem --uri-module --uri-pin source"
      (keys.signing {
        checkArgs = [
          "--format"
          "pkcs11-provider-pem"
          "--uri-module"
          "--uri-pin"
          "source"
        ];
      }).check;
    assert pkgs.lib.hasSuffix "check 'a b; echo pwned #' --token 'my token' --spec 'it'\\''s'"
      odd.check;
    pkgs.runCommand "cakeys-lib-check" { } ''
      echo ${pkgs.lib.escapeShellArg (keys.signing { }).check} > $out
    '';
}
# Linux hosts only: the NixOS VM tests, and the fuzz smoke run, whose targets include the
# tpm2-pkcs11 store and TPMS_ATTEST parsers (tpm2-tss is not packaged for darwin).
// pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
  # Every fuzz target, built with libFuzzer, for a fixed seed and input count.
  fuzz = fuzz.smoke;
  vm = mkTest "vm";
  module = import ./nix/module-test.nix {
    inherit pkgs cakeys pcsc-probe;
    softhsm = softhsm-unwrap-value-len-tested;
    module = self.nixosModules.default;
  };
  tpm = import ./nix/tpm-test.nix {
    inherit pkgs cakeys;
    module = self.nixosModules.default;
  };
  # examples/: each example's run.sh on throwaway tokens (a software TPM among them), and its
  # Nix files evaluated.
  examples = pkgs.callPackage ./nix/examples.nix { inherit self cakeys; };
  # The NixOS module's assertions, evaluated only (no VM): each configuration it must refuse is
  # refused with its own message, and a sound one passes them all.
  module-assertions =
    let
      eval =
        m:
        (pkgs.nixos {
          imports = [
            self.nixosModules.default
            m
          ];
          services.cakeys.package = cakeys;
        }).config;
      # The failing assertions of the module's own (the rest of NixOS's minimal configuration
      # has its own complaints, a missing root file system among them).
      refused =
        m:
        map (a: a.message) (
          builtins.filter (a: !a.assertion && pkgs.lib.hasPrefix "services.cakeys" a.message)
            (eval m).assertions
        );
      check = extra: {
        services.cakeys.checks.k = {
          config = ./crates/cli/tests/fixtures/keys.toml;
          lock = "/var/lib/cakeys/keys.lock";
          requiredBy = [ "signer.service" ];
        }
        // extra;
      };
      says = needle: m: builtins.any (pkgs.lib.hasInfix needle) (refused m);
      # The module's own warnings.
      warns = m: builtins.filter (pkgs.lib.hasPrefix "services.cakeys") (eval m).warnings;
      pcscd = names: {
        services.cakeys.sandbox.pcscd.enable = true;
        services.cakeys.tokens = pkgs.lib.genAttrs names (_: {
          pcscd = true;
        });
      };
    in
    assert refused (check { }) == [ ];
    assert says "--uri-pin value" (check {
      args = [
        "--uri-pin"
        "value"
      ];
    });
    assert says "--uri-pin value" (check {
      args = [ "--uri-pin=value" ];
    });
    assert
      refused (check {
        args = [
          "--uri-pin"
          "value"
        ];
        outputFile = "/run/cakeys/k.pem";
      }) == [ ];
    assert says "requiredBy is empty" (check {
      requiredBy = [ ];
    });
    assert says "sandbox.pcscd.enable" { services.cakeys.tokens.p.pcscd = true; };
    assert
      refused {
        services.cakeys.sandbox.pcscd.enable = true;
        services.cakeys.tokens.p.pcscd = true;
      } == [ ];
    # pcscd serves every reader: two tokens granted it share every card, which is said (review
    # 2026-11-23 C-9); one token alone is not.
    assert warns (pcscd [ "p" ]) == [ ];
    assert builtins.any (pkgs.lib.hasInfix "serves every reader") (
      warns (pcscd [
        "a"
        "b"
      ])
    );
    pkgs.runCommand "cakeys-module-assertions" { } "touch $out";
}
# x86_64-linux only, as Kani is packaged (nix/kani.nix): the Kani proofs in cakeys_core::fuzzing.
// pkgs.lib.optionalAttrs (cakeys.kani != null) {
  inherit (cakeys) kani;
}
