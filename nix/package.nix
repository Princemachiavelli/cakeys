{
  lib,
  rustPlatform,
  softhsm,
  swtpm,
  tpm2-pkcs11,
  tpm2-tools,
  tpm2-abrmd,
  tpm2-tss,
  sqlite,
  dbus,
  p11-kit,
  pkg-config,
}:

rustPlatform.buildRustPackage {
  pname = "cakeys";
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

  # tss-esapi (the native TPM2_Certify attestation path of cakeys-tpm2-pkcs11) links
  # tpm2-tss's ESAPI and TCTI loader at build time; the runtime closure picks the libraries
  # up through the link. rusqlite's `bundled` feature serves plain cargo builds, but nixpkgs'
  # Rust builder sets LIBSQLITE3_SYS_USE_PKG_CONFIG, which makes libsqlite3-sys link the
  # system sqlite instead — so it must be here.
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    tpm2-tss
    sqlite
  ];

  # cryptoki 0.12.1 (and main) gives KeyType::SHA224/384/512_HMAC the value of CKK_SHA256_HMAC, so those key
  # types can be neither created nor told apart. Minimal local fix until upstream has one
  # (upstream/rust-cryptoki/). Without it, cakeys refuses those key types.
  postPatch = ''
    applied=0
    for d in "$cargoDepsCopy"/cryptoki-0.12.1 "$cargoDepsCopy"/*/cryptoki-0.12.1; do
      if [ -d "$d" ]; then
        patch -d "$d" -p1 < ${./patches/cryptoki-hmac-key-types.patch}
        applied=$((applied + 1))
      fi
    done
    [ "$applied" = 1 ] || { echo "cryptoki-0.12.1 not found exactly once in $cargoDepsCopy" >&2; exit 1; }
  '';

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
    export CAKEYS_TEST_MODULE=${softhsm}/lib/softhsm/libsofthsm2.so
    export CAKEYS_TEST_REQUIRE=1

    # p11-kit forwarding: a second SoftHSM token behind `p11-kit server` (short socket path).
    SOFTHSM_MODULE=$CAKEYS_TEST_MODULE bash ${./p11kit-test-env.sh} up $TMPDIR/p11
    . $TMPDIR/p11/env
    export CAKEYS_P11KIT_CLIENT=${lib.getLib p11-kit}/lib/pkcs11/p11-kit-client.so
    export CAKEYS_P11KIT_REQUIRE=1

    export HOME=$TMPDIR
    bash ${./tpm2-test-env.sh} up $TMPDIR/tpm || { tail -n 20 $TMPDIR/tpm/*.log; exit 1; }
    . $TMPDIR/tpm/env
    export CAKEYS_TPM_MODULE=${lib.getLib tpm2-pkcs11}/lib/libtpm2_pkcs11.so
    export CAKEYS_TPM_REQUIRE=1
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
    mainProgram = "cakeys";
    license = with lib.licenses; [
      mit
      asl20
    ];
    platforms = lib.platforms.linux;
  };
}
