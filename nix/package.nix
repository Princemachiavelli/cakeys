{
  lib,
  rustPlatform,
  softhsm,
  swtpm,
  tpm2-pkcs11,
  tpm2-tools,
  tpm2-abrmd,
  dbus,
  p11-kit,
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

  # Integration tests drive a real SoftHSM token, the same SoftHSM through p11-kit forwarding,
  # and tpm2-pkcs11 on a software TPM (behind tpm2-abrmd on a private D-Bus) inside the build
  # sandbox.
  nativeCheckInputs = [
    softhsm
    swtpm
    tpm2-pkcs11
    tpm2-tools
    tpm2-abrmd
    dbus
    p11-kit
  ];
  preCheck = ''
    export SOFTHSM2_CONF=$TMPDIR/softhsm2.conf
    mkdir -p $TMPDIR/softhsm-tokens
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
      $TMPDIR/softhsm-tokens > $SOFTHSM2_CONF
    softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678
    export KM_TEST_MODULE=${softhsm}/lib/softhsm/libsofthsm2.so
    export KM_TEST_REQUIRE=1

    # p11-kit forwarding: a second SoftHSM token behind `p11-kit server` (short socket path).
    SOFTHSM_MODULE=$KM_TEST_MODULE bash ${./p11kit-test-env.sh} up $TMPDIR/p11
    . $TMPDIR/p11/env
    export KM_P11KIT_CLIENT=${lib.getLib p11-kit}/lib/pkcs11/p11-kit-client.so
    export KM_P11KIT_REQUIRE=1

    export HOME=$TMPDIR
    bash ${./tpm2-test-env.sh} up $TMPDIR/tpm || { tail -n 20 $TMPDIR/tpm/*.log; exit 1; }
    . $TMPDIR/tpm/env
    export KM_TPM_MODULE=${lib.getLib tpm2-pkcs11}/lib/libtpm2_pkcs11.so
    export KM_TPM_REQUIRE=1
  '';
  postCheck = ''
    bash ${./p11kit-test-env.sh} down $TMPDIR/p11
    bash ${./tpm2-test-env.sh} down $TMPDIR/tpm
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
