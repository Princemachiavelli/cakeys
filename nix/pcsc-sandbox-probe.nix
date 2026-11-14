# pcsc-probe run inside the Nix build sandbox; the probe's output and exit code are the build's
# result. A raw `derivation` over three store paths, so apps.pcsc-sandbox-probe can evaluate it
# outside the flake, with no nixpkgs and no source tree. A fresh nonce makes a new derivation,
# so it runs every time.
{
  system,
  bash,
  coreutils,
  pcsc-probe,
  nonce,
}:
derivation {
  name = "pcsc-sandbox-probe-${nonce}";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      rc=0
      { ${coreutils}/bin/id; ${pcsc-probe}/bin/pcsc-probe || rc=$?; echo "exit=$rc"; } > $out 2>&1
    ''
  ];
}
