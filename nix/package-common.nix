# What both builds of the workspace share (nix/package.nix, the regular `buildRustPackage`, and
# nix/package-crane.nix, crane's, which `nix flake check` uses): the source, the outputs, the
# inputs, the cryptoki patches, the features and the integration-test environment. Each builder
# adds only what is its own.
{
  lib,
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
{
  # cryptoki 0.12.1 (and main) gives KeyType::SHA224/384/512_HMAC the value of CKK_SHA256_HMAC, so those key
  # types can be neither created nor told apart. Minimal local fix until upstream has one
  # (upstream/rust-cryptoki/). Without it, cakeys refuses those key types. It also has no
  # CKM_AES_KEY_WRAP_KWP (RFC 5649 under its PKCS#11 3.0 ID, which kryoptic offers): the second
  # patch adds it for export and import (docs/CAMIGRATE.md). The third adds CKM_RSA_AES_KEY_WRAP (RSA-OAEP
  # of a fresh AES key, then RFC 5649 under it), the one wrap of a CKA_WRAP_WITH_TRUSTED key whose
  # only trusted key is the transport key (docs/CAMIGRATE.md D2, `enforced`). Both constants and the
  # parameter struct are already in cryptoki-sys.
  cryptoki = {
    version = "0.12.1";
    patches = [
      ./patches/cryptoki-hmac-key-types.patch
      ./patches/cryptoki-aes-key-wrap-kwp.patch
      ./patches/cryptoki-rsa-aes-key-wrap.patch
    ];
  };

  # The mechanisms only the patched cryptoki above can name (CKM_AES_KEY_WRAP_KWP,
  # CKM_RSA_AES_KEY_WRAP): camigrate uses them only with this feature.
  features = [ "camigrate/kwp" ];

  # The derivation attributes both builders take as they are.
  args = {
    pname = "cakeys";
    version = "0.1.0";

    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
        # The capability profiles (docs/CAPROBE.md): embedded in the binary, and the vendored
        # OASIS headers the pinned baseline-regeneration test reads.
        ../profiles
      ];
    };

    # The tools of one workspace (README.md, "Three tools"), from one build whose check phase
    # tests them together, each in its own output: `out` holds cakeys, `caprobe` the module
    # measurer and `camigrate` the key mover, so cakeys' closure carries neither.
    outputs = [
      "out"
      "caprobe"
      "camigrate"
    ];
    postInstall = ''
      moveToOutput bin/caprobe "$caprobe"
      moveToOutput bin/camigrate "$camigrate"
    '';

    # tss-esapi (the native TPM2_Certify attestation path of cakeys-tpm2-pkcs11) links
    # tpm2-tss's ESAPI and TCTI loader at build time; the runtime closure picks the libraries
    # up through the link. rusqlite's `bundled` feature serves plain cargo builds, but nixpkgs'
    # Rust builder sets LIBSQLITE3_SYS_USE_PKG_CONFIG, which makes libsqlite3-sys link the
    # system sqlite instead — so it must be here (and crane's build sets it itself).
    nativeBuildInputs = [ pkg-config ];
    buildInputs = [
      tpm2-tss
      sqlite
    ];

    # Integration tests drive real SoftHSM and kryoptic tokens, SoftHSM through p11-kit forwarding,
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
      opensc
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
      export CAKEYS_KRYOPTIC_MODULE=${kryoptic}/lib/libkryoptic_pkcs11.so
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
      bash ${./tpm2-test-env.sh} up $TMPDIR/tpm || { tail -n 20 $TMPDIR/tpm/*.log; exit 1; }
      . $TMPDIR/tpm/env
      export CAKEYS_TPM_MODULE=${lib.getLib tpm2-pkcs11}/lib/libtpm2_pkcs11.so
      export CAKEYS_TPM_REQUIRE=1
    '';
    postCheck = ''
      bash ${./p11kit-test-env.sh} down $TMPDIR/p11
      bash ${./tpm2-test-env.sh} down $TMPDIR/tpm
    '';

    meta = {
      description = "Content-addressed identity for PKCS#11 objects";
      mainProgram = "cakeys";
      license = with lib.licenses; [
        mit
        asl20
      ];
      platforms = lib.platforms.linux;
    };
  };
}
