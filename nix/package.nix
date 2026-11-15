# cakeys, caprobe and camigrate: the regular `buildRustPackage` build (packages.cakeys). What it
# shares with the crane build the checks use is in nix/package-common.nix.
{
  lib,
  callPackage,
  rustPlatform,
  stdenv,
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

    # The tests as the crane check runs them (nix/package-crane.nix): cargo-nextest, one process
    # per test, each through nix/test-tokens.sh (cargo's target runner) with a token set of its
    # own. So they run in parallel, and no test meets what another left on a token: several
    # change the token itself (a second token under its label, a locked PIN, tpm2-pkcs11 store
    # rows).
    useNextest = true;
    ${"CARGO_TARGET_${stdenv.hostPlatform.rust.cargoEnvVarTarget}_RUNNER"} = "bash ${./test-tokens.sh}";
    # Unit tests live in every crate, not just the tools (the default members).
    cargoTestFlags = common.cargoScope;
    buildNoDefaultFeatures = common.noDefaultFeatures;
    buildFeatures = common.features;
  }
)
