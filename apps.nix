# The flake's `apps` output (flake.nix): `nix run .#<name>`. Each runs on the host, outside
# the sandbox.
{
  pkgs,
  self,
  demo,
  deny,
  fuzz,
  pcsc-probe,
}:
let
  inherit (pkgs.stdenv.hostPlatform) system;
in
{
  # nix run .#demo (-- --keep to leave the tokens and keys.toml for poking around)
  demo = {
    type = "app";
    program = pkgs.lib.getExe demo.demo;
    meta.description = "Walk through cakeys on two software tokens: pinned identity, the Nix view, drift, one identity across modules, export plans";
  };
  # The one cargo-deny check the sandbox cannot make: yanked releases, against the live
  # crates.io index (see `deny` in pkgs.nix). Network, host-side, uncached.
  deny-online = {
    type = "app";
    program = pkgs.lib.getExe deny.online;
    meta.description = "cargo-deny with current yanked flags: fetch the live index, then the pinned-database check with --deny yanked";
  };
  # Fuzz one target for as long as you like: nix run .#fuzz -- lock -max_total_time=600
  fuzz = {
    type = "app";
    program = pkgs.lib.getExe fuzz.run;
    meta.description = "Run a cargo-fuzz target (public_key, certificate, lock, config) from the repository root";
  };
  # Host-side PC/SC check.
  pcsc-probe = {
    type = "app";
    program = pkgs.lib.getExe pcsc-probe;
    meta.description = "Print raw PC/SC context and reader-list return codes";
  };
  # Same probe from inside the Nix build sandbox (needs /run/pcscd in sandbox-paths): builds
  # the flake's legacyPackages.pcscSandboxProbe with a fresh nonce.
  pcsc-sandbox-probe = {
    type = "app";
    meta.description = "Run pcsc-probe inside the Nix build sandbox (uncached)";
    program = pkgs.lib.getExe (
      pkgs.writeShellApplication {
        name = "pcsc-sandbox-probe";
        text = ''
          out=$(nix build --impure --no-link --print-out-paths --expr \
            "(builtins.getFlake \"path:${self}\").legacyPackages.${system}.pcscSandboxProbe { nonce = \"$(date +%s%N)\"; }")
          cat "$out"
        '';
      }
    );
  };
}
