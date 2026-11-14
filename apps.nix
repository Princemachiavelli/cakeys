# The flake's `apps` output (flake.nix): `nix run .#<name>`. Each runs on the host, outside
# the sandbox.
{
  pkgs,
  demo,
  deny,
  fuzz,
  pcsc-probe,
}:
let
  inherit (pkgs.stdenv.hostPlatform) system;
  probe = builtins.path {
    path = ./nix/pcsc-sandbox-probe.nix;
    name = "pcsc-sandbox-probe.nix";
  };
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
  # nix/pcsc-sandbox-probe.nix with a fresh nonce. builtins.path copies that one file, not the
  # source tree, and builtins.storePath gives each store path the context that puts it in the
  # sandbox.
  pcsc-sandbox-probe = {
    type = "app";
    meta.description = "Run pcsc-probe inside the Nix build sandbox (uncached)";
    program = pkgs.lib.getExe (
      pkgs.writeShellApplication {
        name = "pcsc-sandbox-probe";
        text = ''
          out=$(nix build --impure --no-link --print-out-paths --expr \
            "import ${probe} {
              system = \"${system}\";
              bash = builtins.storePath \"${pkgs.bash}\";
              coreutils = builtins.storePath \"${pkgs.coreutils}\";
              pcsc-probe = builtins.storePath \"${pcsc-probe}\";
              nonce = \"$(date +%s%N)\";
            }")
          cat "$out"
        '';
      }
    );
  };
}
