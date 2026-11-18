# The flake's own derivations (flake.nix): cakeys and the tools around it. The packages,
# apps, checks and devShell outputs all draw from this one set.
{
  pkgs,
  pkgsCloudhsm,
  advisory-db,
  craneLib,
  rustBin,
}:
let
  # The toolchain at Cargo.toml's rust-version, for checks.msrv: rust-overlay names releases in
  # full (1.89 is 1.89.0).
  msrvToolchain =
    let
      v = (pkgs.lib.importTOML ./Cargo.toml).workspace.package.rust-version;
    in
    rustBin.stable.${if pkgs.lib.length (pkgs.lib.splitString "." v) == 2 then "${v}.0" else v}.minimal;
in
rec {
  cakeys = pkgs.callPackage ./nix/package.nix { };
  # The same build with crane (nix/package-crane.nix): its dependencies built once per
  # Cargo.lock, so the checks (and their clippy and minimal builds) rebuild only cakeys' crates.
  cakeys-crane = pkgs.callPackage ./nix/package-crane.nix { inherit craneLib msrvToolchain; };
  # The module measurer, the key mover (README.md, "Three tools") and the fault-injecting PKCS#11
  # module (docs/FAULT_SHIM.md): outputs of the same build.
  inherit (cakeys) caprobe camigrate;
  p11-fault = cakeys.p11fault;
  pcsc-probe = pkgs.callPackage ./nix/pcsc-probe.nix { };
  mezura = pkgs.callPackage ./nix/mezura.nix { };
  # A second opinion on the reference modules beside caprobe's profiles (docs/PLAN.md A6).
  pkcs11-check = pkgs.callPackage ./nix/pkcs11-check.nix { };
  # OpenTofu and the AWS CLI for scripts/cloud/aws.sh (docs/CLOUD_HSM.md).
  cloud-tools = pkgs.callPackage ./nix/cloud-tools.nix { };
  # Google's Cloud KMS PKCS#11 library, and its FIPS build, x86_64-linux only.
  kmsp11 = pkgs.callPackage ./nix/kmsp11.nix { };
  kmsp11-fips = pkgs.callPackage ./nix/kmsp11.nix { fips = true; };
  # The AWS CloudHSM client, unfree, x86_64-linux only: cloudhsm-pkcs11, cloudhsm-cli,
  # cloudhsm-dyn (the OpenSSL engine) and cloudhsm-openssl-provider.
  cloudhsm = import ./nix/cloudhsm.nix {
    inherit (pkgsCloudhsm)
      lib
      stdenv
      fetchurl
      dpkg
      autoPatchelfHook
      ;
  };
  # cargo-deny: the sandboxed checks.deny (advisories against the pinned
  # RustSec database, licenses, bans, sources) and the online apps.deny-online (yanked —
  # registry metadata the sandbox has no network for). Configuration: deny.toml.
  deny = pkgs.callPackage ./nix/deny.nix {
    inherit advisory-db;
    cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
  };
  # cargo-fuzz (fuzz/): a fixed-seed smoke run in checks.fuzz, and apps.fuzz for long runs.
  fuzz = pkgs.callPackage ./nix/fuzz.nix { };
  # SoftHSM with the upstream/softhsm/ patch (CKA_VALUE_LEN on unwrapped keys, SoftHSMv2 #628),
  # and the same with SoftHSM's own test suite run: checks.softhsm-unwrap-value-len.
  softhsm-unwrap-value-len = pkgs.callPackage ./nix/softhsm-unwrap-value-len.nix { };
  softhsm-unwrap-value-len-tested = pkgs.callPackage ./nix/softhsm-unwrap-value-len.nix {
    withTests = true;
  };
  # The walkthrough of cakeys' main ideas on SoftHSM and kryoptic: apps.demo, checks.demo.
  demo = pkgs.callPackage ./nix/demo.nix { inherit cakeys; };
  # The demo the checks run, on the crane build.
  demo-crane = pkgs.callPackage ./nix/demo.nix { cakeys = cakeys-crane; };
}
