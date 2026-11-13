# cargo-deny (NEXT.md §1): advisories against the pinned RustSec database, and licenses,
# duplicate crates and sources over the same graph — all offline, so the check is
# reproducible: the crate graph comes from the vendored Cargo.lock, the database from the
# advisory-db flake input. Nothing is fetched at build time.
{
  lib,
  cargo,
  cargo-deny,
  runCommand,
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

    # The advisory database where cargo-deny's db-path looks for it ($CARGO_HOME/advisory-dbs
    # by default): the pinned tree plus a fresh FETCH_HEAD, whose modification time is what
    # cargo-deny reads offline to decide the database is not stale (90 days by default).
    db_dir=$CARGO_HOME/advisory-dbs/${db}
    mkdir -p $db_dir/.git
    cp -r ${advisory-db}/. $db_dir/
    touch $db_dir/.git/FETCH_HEAD

    # A writable copy: cargo may not write into the store, and metadata touches paths.
    cp -r ${src} ./workspace
    cd ./workspace

    cargo deny --offline check
    touch $out
  ''
