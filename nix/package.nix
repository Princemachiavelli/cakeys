{
  lib,
  stdenv,
  rustPlatform,
  softhsm,
  kryoptic,
  opensc,
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

let
  # The tpm2 feature (cakeys-tpm2-pkcs11) is Linux only: tss-esapi-sys ships no prebuilt bindings
  # for aarch64-darwin, and tpm2-pkcs11 and its tools are not packaged there, so there is no
  # module for it to attest. Darwin builds the CLI with ykcs11 alone.
  tpm2 = stdenv.hostPlatform.isLinux;
  # What `cargo test` and clippy (checks.clippy) cover: the workspace, less the TPM crate and
  # with the CLI's features narrowed where tpm2 is off. A crate excluded but still a default
  # feature would be built anyway.
  cargoScope = [
    "--workspace"
  ]
  ++ lib.optionals (!tpm2) [
    "--exclude"
    "cakeys-tpm2-pkcs11"
    "--no-default-features"
    "--features"
    "cakeys/ykcs11"
  ];
  sharedLibrary = stdenv.hostPlatform.extensions.sharedLibrary;
in
rustPlatform.buildRustPackage {
  pname = "cakeys";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      # The capability profiles (docs/PROVIDERS.md): embedded in the binary, and the vendored
      # OASIS headers the pinned baseline-regeneration test reads.
      ../profiles
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # tss-esapi (the native TPM2_Certify attestation path of cakeys-tpm2-pkcs11) links
  # tpm2-tss's ESAPI and TCTI loader at build time; the runtime closure picks the libraries
  # up through the link. rusqlite's `bundled` feature serves plain cargo builds, but nixpkgs'
  # Rust builder sets LIBSQLITE3_SYS_USE_PKG_CONFIG, which makes libsqlite3-sys link the
  # system sqlite instead — so it must be here.
  nativeBuildInputs = [ pkg-config ];
  buildInputs = lib.optionals tpm2 [
    tpm2-tss
    sqlite
  ];
  buildNoDefaultFeatures = !tpm2;
  buildFeatures = lib.optional (!tpm2) "ykcs11";
  # The test run's features come from cargoScope (cargoTestFlags): the hook's own flags would
  # repeat them unqualified, which `--workspace` rejects.
  checkNoDefaultFeatures = false;
  checkFeatures = [ ];

  # cryptoki 0.12.1 (and main) gives KeyType::SHA224/384/512_HMAC the value of CKK_SHA256_HMAC, so those key
  # types can be neither created nor told apart. Minimal local fix until upstream has one
  # (upstream/rust-cryptoki/). Without it, cakeys refuses those key types. It also has no
  # CKM_AES_KEY_WRAP_KWP (RFC 5649 under its PKCS#11 3.0 ID, which kryoptic offers): the second
  # patch adds it for export and import (MIGRATE.md). The constant is already in cryptoki-sys.
  postPatch = ''
    applied=0
    for d in "$cargoDepsCopy"/cryptoki-0.12.1 "$cargoDepsCopy"/*/cryptoki-0.12.1; do
      if [ -d "$d" ]; then
        patch -d "$d" -p1 < ${./patches/cryptoki-hmac-key-types.patch}
        patch -d "$d" -p1 < ${./patches/cryptoki-aes-key-wrap-kwp.patch}
        applied=$((applied + 1))
      fi
    done
    [ "$applied" = 1 ] || { echo "cryptoki-0.12.1 not found exactly once in $cargoDepsCopy" >&2; exit 1; }
  '';

  # Integration tests drive real SoftHSM and kryoptic tokens, SoftHSM through p11-kit forwarding,
  # and, on Linux, tpm2-pkcs11 on a software TPM (behind tpm2-abrmd on a private D-Bus) inside
  # the build sandbox.
  nativeCheckInputs = [
    softhsm
    p11-kit
    opensc
  ]
  ++ lib.optionals tpm2 [
    swtpm
    tpm2-pkcs11
    tpm2-tools
    tpm2-abrmd
    dbus
  ];
  preCheck = ''
    export SOFTHSM2_CONF=$TMPDIR/softhsm2.conf
    mkdir -p $TMPDIR/softhsm-tokens
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
      $TMPDIR/softhsm-tokens > $SOFTHSM2_CONF
    softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678
    export CAKEYS_TEST_MODULE=${softhsm}/lib/softhsm/libsofthsm2.so
    export CAKEYS_TEST_REQUIRE=1

    # kryoptic (PKCS#11 3.2): the shared reference suite runs against it too. The slot table
    # ends the file: the suite appends a mechanism deny list to it (tests/common/mod.rs).
    export KRYOPTIC_CONF=$TMPDIR/kryoptic.conf
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' $TMPDIR/kryoptic.sql > $KRYOPTIC_CONF
    export CAKEYS_KRYOPTIC_MODULE=${kryoptic}/lib/libkryoptic_pkcs11${sharedLibrary}
    pkcs11-tool --module $CAKEYS_KRYOPTIC_MODULE --init-token --slot 1 --so-pin 5678 --label kmtest > /dev/null
    pkcs11-tool --module $CAKEYS_KRYOPTIC_MODULE --token-label kmtest --login --login-type so \
      --so-pin 5678 --init-pin --pin 1234 > /dev/null
    export CAKEYS_KRYOPTIC_REQUIRE=1

    # p11-kit forwarding: a second SoftHSM token behind `p11-kit server` (short socket path).
    SOFTHSM_MODULE=$CAKEYS_TEST_MODULE bash ${./p11kit-test-env.sh} up $TMPDIR/p11
    . $TMPDIR/p11/env
    export CAKEYS_P11KIT_CLIENT=${lib.getLib p11-kit}/lib/pkcs11/p11-kit-client.so
    export CAKEYS_P11KIT_REQUIRE=1

    export HOME=$TMPDIR
  ''
  + lib.optionalString tpm2 ''
    bash ${./tpm2-test-env.sh} up $TMPDIR/tpm || { tail -n 20 $TMPDIR/tpm/*.log; exit 1; }
    . $TMPDIR/tpm/env
    export CAKEYS_TPM_MODULE=${lib.getLib tpm2-pkcs11}/lib/libtpm2_pkcs11.so
    export CAKEYS_TPM_REQUIRE=1
  '';
  postCheck = ''
    bash ${./p11kit-test-env.sh} down $TMPDIR/p11
  ''
  + lib.optionalString tpm2 ''
    bash ${./tpm2-test-env.sh} down $TMPDIR/tpm
  '';
  # One thread: the token suites open a session per test on one module (NEXT.md §1, minor).
  dontUseCargoParallelTests = true;
  # Unit tests live in every crate, not just the CLI (the default member).
  cargoTestFlags = cargoScope;

  passthru = { inherit cargoScope; };

  meta = {
    description = "Content-addressed identity for PKCS#11 objects";
    mainProgram = "cakeys";
    license = with lib.licenses; [
      mit
      asl20
    ];
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
