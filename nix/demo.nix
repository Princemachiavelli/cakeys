# The cakeys demo (nix/demo.sh): `nix run .#demo` walks through it with pauses; `checks.demo`
# runs it straight through in the build sandbox, so a change in cakeys' behaviour fails the
# check instead of silently breaking the demo.
{
  pkgs,
  cakeys,
}:
let
  demo = pkgs.writeShellApplication {
    name = "cakeys-demo";
    runtimeInputs = with pkgs; [
      cakeys
      cakeys.camigrate
      softhsm
      opensc
      openssl
      jq
      gawk
    ];
    runtimeEnv = {
      SOFTHSM_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
      KRYOPTIC_MODULE = "${pkgs.kryoptic}/lib/libkryoptic_pkcs11.so";
      CAKEYS_LIB = ./lib.nix;
    };
    text = builtins.readFile ./demo.sh;
  };
in
{
  inherit demo;
  # Without nix-instantiate in the sandbox, act 2 skips the evaluation and keeps the check.
  check = pkgs.runCommand "cakeys-demo-check" { } ''
    set -o pipefail
    export HOME=$TMPDIR
    # The demo plays a developer at a terminal, who records the lock; inside a build cakeys
    # refuses lock writes (they would be lost), as the reference suites also unset it.
    unset NIX_BUILD_TOP
    DEMO_PAUSE=0 ${pkgs.lib.getExe demo} 2>&1 | tee $out
  '';
}
