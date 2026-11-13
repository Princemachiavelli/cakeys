# Formatters and linters for `nix fmt` (the flake's formatter) and `checks.formatting`.
{ pkgs, ... }:
let
  toml = (pkgs.formats.toml { }).generate;

  rumdlConfig = toml "rumdl.toml" {
    global.disable = [
      "MD013" # line length: prose wraps near 100 columns, tables and URLs do not
      "MD014" # `$` before commands: console blocks mix commands and their output
      "MD025" # several top-level headings: PLAN.md is a set of documents in one file
      "MD036" # bold paragraph labels: the research notes use them as run-in headings
    ];
    # docs/working/RESPONSE.md is a reply verbatim: one quoted question after another, each answered inline.
    per-file-ignores."docs/working/RESPONSE.md" = [
      "MD028"
      "MD041"
    ];
  };

  typosConfig = toml "typos.toml" {
    # Git commit hashes (`a110ba8a`): hex, not words.
    default.extend-ignore-re = [ "\\b[0-9a-f]{7,40}\\b" ];
    default.extend-words = {
      # keep-sorted start
      COSE = "COSE"; # CBOR Object Signing and Encryption
      FO = "FO"; # fixed-output (derivation)
      GOST = "GOST"; # the Russian cipher and signature standards
      PARMS = "PARMS"; # TPM2 structure names (TPMS_*_PARMS)
      fpr = "fpr"; # GnuPG's fingerprint record
      # keep-sorted end
    };
  };
in
{
  projectRootFile = "flake.nix";

  programs = {
    # keep-sorted start block=yes
    deadnix.enable = true;
    keep-sorted.enable = true;
    nixfmt.enable = true;
    rumdl-check.enable = true;
    rumdl-format.enable = true;
    rustfmt.enable = true; # settings in rustfmt.toml, shared with `cargo fmt` and editors
    shellcheck.enable = true;
    shfmt.enable = true;
    statix.enable = true;
    taplo = {
      enable = true;
      # The width rustfmt.toml uses: dependency tables stay on one line.
      settings.formatting.column_width = 120;
    };
    typos = {
      enable = true;
      configFile = toString typosConfig;
    };
    # keep-sorted end
  };

  settings = {
    formatter = {
      # The Nix fixers rewrite code, so they run before nixfmt lays it out (lower runs first).
      deadnix.priority = 1;
      statix.priority = 2;
      nixfmt.priority = 3;
      rumdl-check.options = [
        "--config"
        "${rumdlConfig}"
        "--no-cache"
      ];
      rumdl-format.options = [
        "--config"
        "${rumdlConfig}"
        "--no-cache"
      ];
    };
    global.excludes = [
      # Binary and key material, and exact upstream bytes: never rewritten.
      "*.der"
      "*.patch"
      "*.pem"
      # Generated lock files.
      "*.lock"
    ];
  };
}
