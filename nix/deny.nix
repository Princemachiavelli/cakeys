# cargo-deny (NEXT.md §1), in two settings:
#
# - `check`: `nix flake check`'s checks.deny — advisories against the pinned RustSec
#   database, licenses, duplicate crates and sources, all offline in the sandbox: the crate
#   graph vendored from Cargo.lock, the database from the advisory-db flake input. Nothing
#   is fetched at build time, so the check is reproducible with the flake.lock.
#
# - `online`: the one part that needs the network — yanked releases. Yanked-ness is
#   crates.io registry metadata, not a RustSec advisory, so the database input cannot carry
#   it; cargo-deny reads it from cargo's index cache, which only `cargo fetch` fills with
#   the current flags. The app (apps.deny-online) runs on the host: a throwaway CARGO_HOME,
#   `cargo fetch --locked` for the live index, the pinned database, and the same check with
#   --deny yanked. Like the YubiKey suite, it cannot run in the sandbox.
{
  lib,
  cargo,
  cargo-deny,
  runCommand,
  writeShellApplication,
  advisory-db,
  cargoDeps,
}:
let
  # cargo-deny names a database directory after the last path segment of each db-urls entry
  # plus XxHash64 (seed 0xca80de71) of the lowercased URL — url_to_db_path in cargo-deny's
  # src/advisories/helpers/db.rs. With the default db-urls (deny.toml leaves it unset) that
  # is advisory-db-3157b0e258782691. If a cargo-deny bump ever changes the scheme, this
  # check fails on the missing database; it cannot silently scan nothing.
  db = "advisory-db-3157b0e258782691";

  # The database where cargo-deny's db-path looks for it ($CARGO_HOME/advisory-dbs by
  # default): the pinned tree plus a fresh FETCH_HEAD, whose modification time is what
  # cargo-deny reads offline to decide the database is not stale (90 days by default).
  # The copy is made writable: it comes from the read-only store, and the online app
  # cleans its CARGO_HOME up afterwards.
  install-db = ''
    db_dir="$CARGO_HOME/advisory-dbs/${db}"
    mkdir -p "$db_dir/.git"
    cp -r "${advisory-db}/." "$db_dir/"
    chmod -R u+w "$db_dir"
    touch "$db_dir/.git/FETCH_HEAD"
  '';

  # What `cargo metadata` and cargo-deny read: the workspace manifests and lockfile, the
  # deny.toml above, and the crate sources (harmless to include, and cargo can be particular
  # about writable paths).
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../deny.toml
      ../crates
    ];
  };
in
{
  check =
    runCommand "cakeys-cargo-deny"
      {
        nativeBuildInputs = [
          cargo # cargo-deny shells out to `cargo metadata`
          cargo-deny
        ];
      }
      ''
        export CARGO_HOME=$PWD/.cargo-home
        mkdir -p $CARGO_HOME

        # cargo metadata offline: the vendored crates in place of crates.io.
        cat >$CARGO_HOME/config.toml <<EOF
        [source.crates-io]
        replace-with = "vendored-sources"

        [source.vendored-sources]
        directory = "${cargoDeps}"
        EOF

        ${install-db}

        # A writable copy: cargo may not write into the store, and metadata touches paths.
        cp -r ${src} ./workspace
        cd ./workspace

        # Advisories (vulnerabilities, unmaintained; yanked allowed offline — see the file
        # header), bans, licenses and sources.
        cargo deny --offline check
        touch $out
      '';

  online = writeShellApplication {
    name = "cakeys-deny-online";
    runtimeInputs = [
      cargo
      cargo-deny
    ];
    text = ''
      # Run from the repository root (or pass CAKEYS_DENY_ONLINE_DIR): the directory whose
      # Cargo.lock and deny.toml are checked.
      dir=''${CAKEYS_DENY_ONLINE_DIR:-$PWD}
      if [ ! -f "$dir/Cargo.lock" ]; then
        echo "no Cargo.lock in $dir: run from the repository root, or set CAKEYS_DENY_ONLINE_DIR" >&2
        exit 2
      fi

      home=$(mktemp -d)
      trap 'rm -rf "$home"' EXIT
      export CARGO_HOME="$home/cargo"
      mkdir -p "$CARGO_HOME"

      # The only network step: cargo reads the live index entry of every locked crate, so
      # the yanked flags cargo-deny will read are current. The crate downloads are a side
      # effect; --locked keeps Cargo.lock untouched.
      cargo fetch --locked --manifest-path "$dir/Cargo.toml" >/dev/null

      ${install-db}

      # Same check as the sandbox's checks.deny, minus the vendoring (fetch downloaded the
      # crates), with the yanked level deny.toml leaves at allow offline raised to deny.
      cd "$dir"
      cargo deny --offline check --deny yanked
    '';
  };
}
