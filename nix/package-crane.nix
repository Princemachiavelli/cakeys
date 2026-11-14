# cakeys, caprobe and camigrate built with crane: the dependencies once per Cargo.lock
# (`buildDepsOnly`), reused by this build, its tests, clippy and their reruns, so a source change
# rebuilds only the workspace's own crates. `nix flake check` uses it (checks.nix); packages.cakeys
# is the regular build (nix/package.nix). What both share is in nix/package-common.nix.
{
  lib,
  callPackage,
  craneLib,
}:
let
  common = callPackage ./package-common.nix { };
  features = "--features ${lib.concatStringsSep "," common.features}";

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
    cargoExtraArgs = "--locked --workspace ${features}";
  };
  cargoArtifacts = craneLib.buildDepsOnly base;

  # Without the `tpm2` and `ykcs11` features: the tools build without tpm2-tss and sqlite (their
  # own dependency set).
  minimal = base // {
    pname = "cakeys-minimal";
    buildInputs = [ ];
    cargoExtraArgs = "--locked --no-default-features ${features}";
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
    };
  }
)
