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
{
  lib,
  rustPlatform,
  cargo-fuzz,
  writeShellApplication,
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
  targets = [
    "public_key"
    "certificate"
    "lock"
    "config"
    "bundle"
    "key_file"
    "tpm_store_row"
    "tpms_attest"
    "piv_chain"
    "p521_point"
    "profile"
    "hex"
    "attest_encoding"
  ];

  # Seed corpora from the test fixtures: certificates, their and the import keys' SPKIs, a
  # lock, a config, a bundle, the key files, the fixture PIV chain, tpm2-pkcs11's malformed P-521 point and the
  # committed profiles. Called from the repository root.
  seed = ''
    F=crates/cli/tests/fixtures
    for t in ${lib.concatStringsSep " " targets}; do mkdir -p "fuzz/corpus/$t"; done
    cp --update=none "$F"/*.der fuzz/corpus/certificate/
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
in
{
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
    cargoLock.lockFile = ../fuzz/Cargo.lock;
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
