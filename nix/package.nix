{
  lib,
  rustPlatform,
  softhsm,
}:

rustPlatform.buildRustPackage {
  pname = "key-mgmnt";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # Integration tests drive a real SoftHSM token inside the build sandbox.
  nativeCheckInputs = [ softhsm ];
  preCheck = ''
    export SOFTHSM2_CONF=$TMPDIR/softhsm2.conf
    mkdir -p $TMPDIR/softhsm-tokens
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
      $TMPDIR/softhsm-tokens > $SOFTHSM2_CONF
    softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678
    export KM_TEST_MODULE=${softhsm}/lib/softhsm/libsofthsm2.so
    export KM_TEST_REQUIRE=1
  '';
  dontUseCargoParallelTests = true;
  # Unit tests live in every crate, not just the CLI (the default member).
  cargoTestFlags = [ "--workspace" ];

  meta = {
    description = "Content-addressed identity for PKCS#11 objects";
    mainProgram = "key-mgmnt";
    license = with lib.licenses; [
      mit
      asl20
    ];
    platforms = lib.platforms.linux;
  };
}
