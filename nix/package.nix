# cakeys, caprobe and camigrate: the regular `buildRustPackage` build (packages.cakeys). What it
# shares with the crane build the checks use is in nix/package-common.nix.
{
  lib,
  callPackage,
  rustPlatform,
  # See nix/package-common.nix.
  withTpm2 ? null,
}:
let
  common = callPackage ./package-common.nix (
    lib.optionalAttrs (withTpm2 != null) { inherit withTpm2; }
  );
in
rustPlatform.buildRustPackage (
  common.args
  // {
    cargoLock.lockFile = ../Cargo.lock;

    # The cryptoki patches (nix/package-common.nix), on the vendored copy.
    postPatch = ''
      applied=0
      for d in "$cargoDepsCopy"/cryptoki-${common.cryptoki.version} "$cargoDepsCopy"/*/cryptoki-${common.cryptoki.version}; do
        if [ -d "$d" ]; then
      ${
        lib.concatMapStrings (p: "    patch -d \"$d\" -p1 < ${p}\n") common.cryptoki.patches
      }    applied=$((applied + 1))
        fi
      done
      [ "$applied" = 1 ] || { echo "cryptoki-${common.cryptoki.version} not found exactly once in $cargoDepsCopy" >&2; exit 1; }
    '';

    # One thread: the token suites open a session per test on one module (docs/OPEN.md, "Engineering").
    dontUseCargoParallelTests = true;
    # Unit tests live in every crate, not just the tools (the default members).
    cargoTestFlags = common.cargoScope;
    buildNoDefaultFeatures = common.noDefaultFeatures;
    buildFeatures = common.features;
  }
)
