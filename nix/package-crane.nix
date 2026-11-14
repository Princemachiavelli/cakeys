# cakeys, caprobe and camigrate built with crane: the dependencies once per Cargo.lock
# (`buildDepsOnly`), reused by this build, its tests, clippy and their reruns, so a source change
# rebuilds only the workspace's own crates. `nix flake check` uses it (checks.nix); packages.cakeys
# is the regular build (nix/package.nix). What both share is in nix/package-common.nix.
{
  lib,
  callPackage,
  craneLib,
  rustc,
  # See nix/package-common.nix.
  withTpm2 ? null,
}:
let
  common = callPackage ./package-common.nix (
    lib.optionalAttrs (withTpm2 != null) { inherit withTpm2; }
  );
  features = "--features ${lib.concatStringsSep "," common.features}";
  scope = lib.escapeShellArgs (
    common.cargoScope ++ lib.optional common.noDefaultFeatures "--no-default-features"
  );

  # The cryptoki patches (nix/package-common.nix), on crane's vendored copy.
  cargoVendorDir = craneLib.vendorCargoDeps {
    inherit (common.args) src;
    overrideVendorCargoPackage =
      p: drv:
      if p.name == "cryptoki" && p.version == common.cryptoki.version then
        drv.overrideAttrs (old: {
          patches = (old.patches or [ ]) ++ common.cryptoki.patches;
        })
      else
        drv;
  };

  # What the dependencies' build and every build on it share. Unit tests live in every crate,
  # not just the tools (the default members).
  base = {
    inherit (common.args)
      pname
      version
      src
      nativeBuildInputs
      buildInputs
      ;
    inherit cargoVendorDir;
    # What nixpkgs' Rust builder sets: libsqlite3-sys links the system sqlite (buildInputs).
    LIBSQLITE3_SYS_USE_PKG_CONFIG = 1;
    strictDeps = true;
    cargoExtraArgs = "--locked ${scope} ${features}";
  };
  cargoArtifacts = craneLib.buildDepsOnly base;

  # Without the `tpm2` and `ykcs11` features: the tools build without tpm2-tss and sqlite (their
  # own dependency set).
  minimal = base // {
    pname = "cakeys-minimal";
    buildInputs = [ ];
    cargoExtraArgs = "--locked --no-default-features --features camigrate/kwp";
    doCheck = false;
  };
in
craneLib.buildPackage (
  common.args
  // base
  // {
    inherit cargoArtifacts;
    # One thread: the token suites open a session per test on one module (docs/OPEN.md, "Engineering").
    cargoTestExtraArgs = "-- --test-threads=1";
    passthru = {
      # Clippy with -D warnings over every target: the workspace lints (Cargo.toml
      # [workspace.lints]: unsafe_code deny, clippy::pedantic with one blanket allow) travel with
      # every build, editor and this check.
      clippy = craneLib.cargoClippy (
        base
        // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        }
      );
      minimal = craneLib.buildPackage (minimal // { cargoArtifacts = craneLib.buildDepsOnly minimal; });
      # Line and region coverage of the whole test run, the token suites included: the tests
      # spawn instrumented binaries, so what a CLI test reaches inside cakeys, caprobe and
      # camigrate counts. Not a check (it rebuilds everything instrumented and passes whatever
      # the numbers are): `nix build .#coverage`, then read result/summary.txt and, for where
      # the next test should go, result/missing.txt (docs/DEVELOPMENT.md).
      coverage = craneLib.cargoLlvmCov (
        base
        // {
          # Nothing to reuse: the instrumented build shares no object with the plain one.
          cargoArtifacts = null;
          # The llvm-tools of this rustc's own LLVM: nixpkgs' rustc ships no llvm-tools-preview.
          LLVM_COV = "${rustc.llvmPackages.llvm}/bin/llvm-cov";
          LLVM_PROFDATA = "${rustc.llvmPackages.llvm}/bin/llvm-profdata";
          nativeBuildInputs = base.nativeBuildInputs ++ common.args.nativeCheckInputs;
          # The token test environment, around the build phase: cargo-llvm-cov tests there.
          preBuild = common.args.preCheck;
          cargoLlvmCovExtraArgs = "--no-report -- --test-threads=1";
          postBuild = ''
            mkdir -p $out
            cargo llvm-cov report --release --lcov --output-path $out/lcov.info
            cargo llvm-cov report --release --summary-only > $out/summary.txt
            cargo llvm-cov report --release --show-missing-lines > $out/missing.txt
          ''
          + common.args.postCheck;
        }
      );
    };
  }
)
