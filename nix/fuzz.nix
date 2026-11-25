# cargo-fuzz targets (fuzz/, docs/DEVELOPMENT.md, "Verification beyond tests"), in two settings:
#
# - `smoke`: `nix flake check`'s checks.fuzz — every target built with libFuzzer and run for a
#   fixed number of inputs from a fixed seed, starting from the test fixtures. Deterministic, so
#   a failure is a reproducible crash, not flakiness; it guards against regressions, while
#   finding new bugs is the long run's job.
#
# - `run`: apps.fuzz, `nix run .#fuzz -- <target> [libFuzzer flags]` in a checkout — as long as
#   you let it, keeping its corpus in fuzz/corpus/<target> and any crash in fuzz/artifacts/.
#
# Both use the stable rustc: cargo-fuzz's nightly flags are unlocked with RUSTC_BOOTSTRAP=1, and
# the sanitizer is off (`-s none`): the targets are safe Rust, so libFuzzer's coverage feedback
# and Rust's own checks (panics, overflow in the debug-assertions build) are what find bugs.
#
# No AddressSanitizer run either. The one C the targets reach is tpm2-tss's unmarshalling
# (libtss2-mu, under tss-esapi in tpms_attest), and `cargo fuzz -s address` instruments only the
# Rust it compiles: the prebuilt C stays uninstrumented, so ASan would see an overflow there only
# if it happened to corrupt the allocator. nixpkgs' rustc ships no sanitizer runtime either (no
# librustc-*_rt.asan.a), so the run would need another toolchain. Finding memory errors in tpm2-tss takes an instrumented tpm2-tss,
# which is that project's own fuzzing, not this check's.
{
  lib,
  rustPlatform,
  cargo-fuzz,
  writeShellApplication,
  runCommand,
  cargo,
  rustc,
  stdenv,
  openssl,
  pkg-config,
  tpm2-tss,
  sqlite,
  coreutils,
}:
let
  # The targets are fuzz/Cargo.toml's `[[bin]]` entries, the one list. A file under
  # fuzz/fuzz_targets/ that no entry names would be neither built nor run, so evaluation refuses
  # it.
  bins = (lib.importTOML ../fuzz/Cargo.toml).bin;
  targets = map (b: b.name) bins;
  unlisted = lib.subtractLists (map (b: baseNameOf b.path) bins) (
    lib.attrNames (builtins.readDir ../fuzz/fuzz_targets)
  );

  # Seed corpora from the test fixtures: certificates, the providers' root bundles, their and the
  # import keys' SPKIs, a
  # lock, a config, a bundle, the key files, the fixture PIV chain, tpm2-pkcs11's malformed P-521 point and the
  # committed profiles. Called from the repository root.
  seed = ''
    F=crates/cli/tests/fixtures
    for t in ${lib.concatStringsSep " " targets}; do mkdir -p "fuzz/corpus/$t"; done
    cp --update=none "$F"/*.der fuzz/corpus/certificate/
    # PEM bundles and DER certificates, as a user names them for the EK (chain::certs_of).
    cp --update=none "$F"/*.der crates/tpm2-pkcs11/roots/*.pem crates/ykcs11/roots/*.pem fuzz/corpus/cert_bundle/
    cp --update=none "$F/keys.lock" fuzz/corpus/lock/
    # Hex of whole bytes in mixed case, for hex to mutate.
    [ -e fuzz/corpus/hex/hex ] || printf 0aFF09bc >fuzz/corpus/hex/hex
    cp --update=none "$F/keys.toml" fuzz/corpus/config/
    cp --update=none crates/camigrate/tests/fixtures/sample.bundle.toml fuzz/corpus/bundle/
    cp --update=none crates/camigrate/tests/fixtures/keyfiles/* fuzz/corpus/key_file/
    cp --update=none crates/tpm2-pkcs11/tests/fixtures/*.yaml fuzz/corpus/tpm_store_row/
    for p in profiles/modules/*/*.toml profiles/layers/*.toml profiles/hardware/*.toml; do
      cp --update=none "$p" "fuzz/corpus/profile/$(basename "$(dirname "$p")")-$(basename "$p")"
    done
    # The piv_chain input: the slot certificate's DER after its big-endian two-byte length, then
    # the device certificate's.
    Y=crates/ykcs11/tests/fixtures
    if [ ! -e fuzz/corpus/piv_chain/fixture ]; then
      openssl x509 -in "$Y/slot.pem" -outform DER -out slot.der
      openssl x509 -in "$Y/f9.pem" -outform DER -out f9.der
      n=$(wc -c <slot.der)
      printf "\\x$(printf %02x $((n >> 8)))\\x$(printf %02x $((n & 255)))" >fuzz/corpus/piv_chain/fixture
      cat slot.der f9.der >>fuzz/corpus/piv_chain/fixture
      rm slot.der f9.der
    fi
    # `04 85 <133 bytes>`: the short-form length tpm2-pkcs11 1.10.1 writes for a P-521 point.
    { printf '\x04\x85'; head -c 133 /dev/zero | tr '\0' '\4'; } >fuzz/corpus/p521_point/malformed
    for p in "$F"/*.pem; do
      openssl pkey -in "$p" -pubout -outform DER -out "fuzz/corpus/public_key/$(basename "$p" .pem).spki"
    done
    for c in "$F"/*.der; do
      openssl x509 -inform DER -in "$c" -noout -pubkey |
        openssl pkey -pubin -outform DER -out "fuzz/corpus/public_key/$(basename "$c" .der).spki"
    done
  '';

  # The crates fuzz/Cargo.lock shares with Cargo.lock at a version or source Cargo.lock does not
  # have: the fuzzed parsers would not be the shipped ones (review 2026-11-24 A, "fuzz/Cargo.lock
  # vs Cargo.lock").
  drift =
    let
      rows = lock: (lib.importTOML lock).package;
      key = p: "${p.name} ${p.version} ${p.source or "path"}";
      shipped = lib.genAttrs (map key (rows ../Cargo.lock)) (_: true);
      named = lib.genAttrs (map (p: p.name) (rows ../Cargo.lock)) (_: true);
    in
    map key (lib.filter (p: named ? ${p.name} && !(shipped ? ${key p})) (rows ../fuzz/Cargo.lock));
in
assert lib.assertMsg (
  unlisted == [ ]
) "fuzz/fuzz_targets/ has files no [[bin]] in fuzz/Cargo.toml names: ${toString unlisted}";
rec {
  inherit targets;

  smoke = rustPlatform.buildRustPackage {
    pname = "cakeys-fuzz-smoke";
    version = "0.1.0";
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../crates
        ../profiles
        ../fuzz/Cargo.toml
        ../fuzz/Cargo.lock
        ../fuzz/fuzz_targets
      ];
    };
    cargoRoot = "fuzz";
    # cryptoki is a git source at a pinned rev (Cargo.toml), fetched with builtins.fetchGit.
    cargoLock = {
      lockFile = ../fuzz/Cargo.lock;
      allowBuiltinFetchGit = true;
    };
    # The tpm2-pkcs11 crate (the tpm_store_row and tpms_attest targets) links tpm2-tss's ESAPI
    # and sqlite.
    nativeBuildInputs = [
      cargo-fuzz
      openssl
      pkg-config
    ];
    buildInputs = [
      tpm2-tss
      sqlite
    ];
    RUSTC_BOOTSTRAP = 1;
    buildPhase = ''
      runHook preBuild
      (cd fuzz && cargo fuzz build -s none --release --debug-assertions)
      runHook postBuild
    '';
    doCheck = true;
    checkPhase = ''
      runHook preCheck
      ${seed}
      for t in ${lib.concatStringsSep " " targets}; do
        echo "fuzz $t"
        (cd fuzz && cargo fuzz run -s none --release --debug-assertions "$t" -- -seed=1 -runs=100000)
      done
      runHook postCheck
    '';
    installPhase = "touch $out";
  };

  # checks.fuzz-lock: fuzz/Cargo.lock still holds every crate the fuzz crate and the workspace
  # crates it reaches need, each it shares with Cargo.lock at Cargo.lock's version. fuzz/ is its
  # own workspace with its own lock, which only `smoke` reads, on Linux in CI's vm job: a
  # dependency the workspace gained without that lock kept the job red from 38967ae to 61b7000.
  # `cargo metadata --locked`, offline, from the sources `smoke` vendors from that lock, needs no
  # build, so it runs in the light job and on every system.
  lock =
    runCommand "cakeys-fuzz-lock"
      {
        nativeBuildInputs = [ cargo ];
        inherit (smoke) src cargoDeps;
      }
      ''
        ${lib.optionalString (drift != [ ]) ''
          echo "fuzz/Cargo.lock has ${lib.concatStringsSep ", " drift}, which Cargo.lock does not:" \
            "cargo update --manifest-path fuzz/Cargo.toml -p <crate> --precise <Cargo.lock's version>" >&2
          exit 1
        ''}
        export CARGO_HOME=$PWD/.cargo-home
        mkdir -p $CARGO_HOME
        # The vendored crates in place of crates.io and of cryptoki's git source, as checks.deny
        # reads them (nix/deny.nix).
        sed "s|directory = \"cargo-vendor-dir\"|directory = \"$cargoDeps\"|" \
          $cargoDeps/.cargo/config.toml >$CARGO_HOME/config.toml
        cp -r $src src
        chmod -R u+w src
        if ! cargo metadata --locked --offline --format-version 1 --manifest-path src/fuzz/Cargo.toml >/dev/null; then
          echo "fuzz/Cargo.lock does not hold what fuzz/Cargo.toml and the crates it reaches need:" \
            "cargo update --manifest-path fuzz/Cargo.toml --workspace" >&2
          exit 1
        fi
        touch $out
      '';

  run = writeShellApplication {
    name = "cakeys-fuzz";
    runtimeInputs = [
      cargo
      rustc
      cargo-fuzz
      stdenv.cc
      openssl
      pkg-config
      # The seed step's `cp --update=none` is GNU; darwin's own cp has no --update.
      coreutils
    ];
    # The tpm2-pkcs11 targets link tpm2-tss and sqlite, found through pkg-config.
    runtimeEnv.PKG_CONFIG_PATH = lib.makeSearchPath "lib/pkgconfig" [
      tpm2-tss.dev
      sqlite.dev
    ];
    text = ''
      if [ $# -lt 1 ]; then
        echo "usage: nix run .#fuzz -- <${lib.concatStringsSep "|" targets}> [libFuzzer flags]" >&2
        exit 2
      fi
      [ -f fuzz/Cargo.toml ] || { echo "run from the repository root" >&2; exit 2; }
      ${seed}
      target=$1
      shift
      cd fuzz
      RUSTC_BOOTSTRAP=1 exec cargo fuzz run -s none --release --debug-assertions "$target" -- "$@"
    '';
  };
}
