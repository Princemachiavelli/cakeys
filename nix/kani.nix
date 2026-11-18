# Kani, the bit-precise model checker for Rust (docs/OPEN.md, "Kani, through bolero"), built
# from source: Kani ships prebuilt bundles that its `cargo kani setup` downloads and patchelfs,
# and fd/nix-kani, the one flake for it, is years behind. This builds what Kani's own release
# bundle holds, the way `cargo build-dev` builds it in Kani's repository:
#
# - kani-driver and kani-compiler (a rustc driver: it links the nightly's librustc_driver),
#   built with the nightly Kani's rust-toolchain.toml names;
# - the sysroots kani-compiler verifies against (lib/, playback/lib, no_core/lib): std and
#   Kani's libraries compiled by kani-compiler itself with `-Z build-std`, so std's own
#   dependencies are vendored too — from kani/library-Cargo.lock, the nightly's
#   library/Cargo.lock checked in (and compared against the toolchain's when building) so
#   reading it is no import-from-derivation;
# - CBMC and Kissat from nixpkgs (Kani 0.68.0 pins CBMC 6.11.0, which nixpkgs has; Kissat
#   4.0.1, where nixpkgs has 4.0.4 — Kissat runs only for `--solver kissat`, CaDiCaL inside
#   CBMC being the default), found on PATH as the bundle's bin/ would be.
#
# kani-driver takes the folder above its own bin/ as the installation, and the nightly's cargo
# from its toolchain/ there: libexec/kani-<version> is that folder, and bin/kani and
# bin/cargo-kani wrap the driver (the name it runs under picks the mode) with the nightly,
# CBMC, Kissat and gcc on PATH. kani-cov (coverage
# reports) and cbmc-viewer (`--visualize`) are left out. x86_64-linux only.
{
  lib,
  stdenv,
  runCommand,
  makeWrapper,
  craneLib,
  rustBin,
  kani-src,
  charon-src,
  cbmc,
  kissat,
}:
let
  version = "0.68.0";
  # Kani's rust-toolchain.toml.
  nightly = "nightly-2026-08-21";
  toolchain = rustBin.nightly."2026-08-21".minimal.override {
    extensions = [
      "rust-src"
      "rustc-dev"
      "llvm-tools"
      "rustfmt"
    ];
  };
  craneNightly = craneLib.overrideToolchain (_: toolchain);

  # Kani's tree with its charon submodule (an optional dependency of kani-compiler, but cargo
  # reads its manifest all the same); the other submodules are Kani's own tests.
  src = runCommand "kani-${version}-source" { } ''
    cp -r ${kani-src} $out
    chmod -R u+w $out
    rmdir $out/charon
    cp -r ${charon-src} $out/charon
  '';

  # kani-compiler's build script links it with an rpath into $RUSTUP_HOME/toolchains/<nightly>
  # (and one to ../toolchain/lib, the bundle's): a store path, so the rpath stays valid.
  rustupHome = runCommand "kani-rustup-home" { } ''
    mkdir -p $out/toolchains
    ln -s ${toolchain} $out/toolchains/${nightly}
  '';
in
craneNightly.mkCargoDerivation {
  pname = "kani";
  inherit version src;
  cargoArtifacts = null;
  doInstallCargoArtifacts = false;
  cargoVendorDir = craneNightly.vendorMultipleCargoDeps {
    inherit (craneNightly.findCargoFiles kani-src) cargoConfigs;
    cargoLockList = [
      "${kani-src}/Cargo.lock"
      ./kani/library-Cargo.lock
    ];
  };
  nativeBuildInputs = [ makeWrapper ];
  env = {
    RUSTUP_HOME = rustupHome;
    RUSTUP_TOOLCHAIN = nightly;
    # A dependency missing from the vendored sources is an error, not a network attempt.
    CARGO_NET_OFFLINE = "true";
  };
  preBuild = ''
    if ! cmp -s ${./kani/library-Cargo.lock} ${toolchain}/lib/rustlib/src/rust/library/Cargo.lock; then
      echo "nix/kani/library-Cargo.lock is not ${nightly}'s library/Cargo.lock: copy it again" >&2
      exit 1
    fi
  '';
  # build-kani: the binaries into target/kani/bin, then the three sysroots.
  buildPhaseCargoCommand = "cargo build-dev --release";
  installPhaseCommand = ''
    base=$out/libexec/kani-${version}
    mkdir -p $base/bin $base/library $out/bin
    cp target/kani/bin/kani-driver target/kani/bin/kani-compiler $base/bin/
    cp -r target/kani/lib target/kani/playback target/kani/no_core $base/
    cp -r library/kani library/kani_macros library/std $base/library/
    printf %s ${nightly} >$base/rust-toolchain-version
    ln -s ${toolchain} $base/toolchain
    # The nightly's rustc first on PATH, as rustup's proxy would make it for the bundle: cargo
    # runs `rustc -vV` from PATH, for `cargo metadata` and the build scripts. gcc: goto-cc
    # preprocesses Kani's C library with it.
    for name in kani cargo-kani; do
      makeWrapper $base/bin/kani-driver $out/bin/$name --argv0 $name \
        --prefix PATH : ${
          lib.makeBinPath [
            toolchain
            cbmc
            kissat
            stdenv.cc
          ]
        }
    done
  '';
  # The rlibs carry rustc's metadata, which strip would not keep.
  dontStrip = true;
  doInstallCheck = true;
  installCheckPhase = ''
    if ldd $out/libexec/kani-${version}/bin/kani-compiler | grep -q 'not found'; then
      ldd $out/libexec/kani-${version}/bin/kani-compiler
      exit 1
    fi
    $out/bin/kani --version
  '';
  meta = {
    description = "Bit-precise model checker for Rust, with CBMC";
    homepage = "https://github.com/model-checking/kani";
    license = with lib.licenses; [
      mit
      asl20
    ];
    platforms = [ "x86_64-linux" ];
    mainProgram = "cargo-kani";
  };
}
