# What the workspace's build (nix/package-crane.nix: the checks' build and, without its check
# phase, packages.cakeys) is made of: the source, the outputs, the inputs, the cryptoki patches,
# the features and the integration-test environment.
{
  lib,
  stdenv,
  callPackage,
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
  openssl,
  pkcs11-provider,
  pkg-config,
  quint,
  # The tpm2 feature (cakeys-tpm2-pkcs11) is Linux only: tss-esapi-sys ships no prebuilt bindings
  # for aarch64-darwin, and tpm2-pkcs11 and its tools are not packaged there, so there is no
  # module for it to attest. Darwin builds the tools with ykcs11 alone; `withTpm2 = false` builds
  # and tests that configuration on Linux too:
  #   nix build --impure --expr '(builtins.getFlake "path:.").packages.x86_64-linux.cakeys-crane.override { withTpm2 = false; }'
  withTpm2 ? stdenv.hostPlatform.isLinux,
}:
let
  tpm2 = withTpm2;
  # kryoptic's module is a .dylib on darwin; SoftHSM's and p11-kit's client stay .so.
  inherit (stdenv.hostPlatform.extensions) sharedLibrary;
  # A cross build runs no check phase (it cannot execute its tests), but the strings below would
  # still make every token package a dependency, built for the host platform — and kryoptic
  # does not cross-compile. So the test environment exists only where the tests can run. The
  # modules it names are host packages on purpose: the test binaries load them.
  canCheck = stdenv.buildPlatform.canExecute stdenv.hostPlatform;
  # The SoftHSM the tests drive: nixpkgs' with upstream/softhsm/'s patches
  # (nix/softhsm-unwrap-value-len.nix), as scripts/local-tests.sh uses. Without them OpenSSL
  # through pkcs11-provider, which reads `check --format pkcs11-provider-pem`'s key file,
  # deadlocks in C_Login.
  softhsmForTests = callPackage ./softhsm-unwrap-value-len.nix { inherit softhsm; };
  # nixpkgs' tpm2-pkcs11 with upstream/tpm2-pkcs11/'s vendor-mechanism patches, the module the
  # provider's vendor path is tested with; nixpkgs' own tests the store path.
  tpm2VendorModule = callPackage ./tpm2-pkcs11-vendor.nix { inherit tpm2-pkcs11; };
in
{
  # cryptoki is parallaxsecond/rust-cryptoki's main at the rev in Cargo.toml (the crate is 0.12.0
  # there; main has the vendor mechanisms in C_GetMechanismList, 6cc2278, and the single-part
  # Session::sign_single, d1b283e, which 0.12.1 lacks), with these patches on it. Main and 0.12.1
  # alike give KeyType::SHA224/384/512_HMAC the value of CKK_SHA256_HMAC, so those key types can be
  # neither created nor told apart. Minimal local fix until upstream has one
  # (upstream/rust-cryptoki/). Without it, cakeys refuses those key types. It also has no
  # CKM_AES_KEY_WRAP_KWP (RFC 5649 under its PKCS#11 3.0 ID, which kryoptic offers): the second
  # patch adds it for export and import (docs/CAMIGRATE.md). The third adds CKM_RSA_AES_KEY_WRAP (RSA-OAEP
  # of a fresh AES key, then RFC 5649 under it), the one wrap of a CKA_WRAP_WITH_TRUSTED key whose
  # only trusted key is the transport key (docs/CAMIGRATE.md D2, `enforced`). Both constants and the
  # parameter struct are already in cryptoki-sys. The fourth keeps a CKA_ALLOWED_MECHANISMS entry
  # cryptoki has no name for (385 of the 3.2 mechanisms; a vendor one main keeps already) as its
  # value, where main refuses the whole attribute (docs/OPEN.md). The fifth is the upstream draft
  # itself, not a local copy: an RvError converts back to its CK_RV and names its CKR_* constant
  # (upstream/rust-cryptoki/PR-RV-VALUE.md). Drop each as the main in Cargo.toml gets it. The
  # patches are relative to the crate (cryptoki/), a subdirectory of the vendored git checkout.
  cryptoki = {
    version = "0.12.0";
    patches = [
      ./patches/cryptoki-hmac-key-types.patch
      ./patches/cryptoki-aes-key-wrap-kwp.patch
      ./patches/cryptoki-rsa-aes-key-wrap.patch
      ./patches/cryptoki-allowed-mechanisms-unnamed.patch
      ../upstream/rust-cryptoki/0003-Add-RvError-to-CK_RV-and-its-name.patch
    ];
  };

  # What only the patched cryptoki above has, as each tool's one `patched-cryptoki` feature
  # (review D3): the mechanisms it names (CKM_AES_KEY_WRAP_KWP, CKM_RSA_AES_KEY_WRAP), which
  # camigrate uses and caprobe probes (`kwp`). caprobe refuses to write a profile without them; tests hold each tool's feature to its parts and fail when the patched binding
  # is linked without them.
  features = [
    "cakeys/patched-cryptoki"
    "caprobe/patched-cryptoki"
    "camigrate/patched-cryptoki"
  ]
  ++ lib.optionals (!tpm2) [
    "cakeys/ykcs11"
    "caprobe/ykcs11"
    "camigrate/ykcs11"
  ];
  # Whether the tests can run here: what preCheck and the check phase's report depend on.
  inherit canCheck;
  # Without tpm2, the default features (tpm2 and ykcs11) are off and ykcs11 comes back through
  # `features`.
  noDefaultFeatures = !tpm2;
  # What the tests and clippy cover: the workspace, less the TPM crate where tpm2 is off (a
  # crate excluded but still pulled in by a default feature would be built anyway).
  cargoScope = [
    "--workspace"
  ]
  ++ lib.optionals (!tpm2) [
    "--exclude"
    "cakeys-tpm2-pkcs11"
  ];

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
        # The coverage file and the object tables the tests pin (docs/CAPROBE.md, "Coverage"):
        # not profiles, so out of the tree `--profiles` loads.
        ../spec-coverage
        # cargo-nextest's configuration: the slow-test timeout.
        ../.config/nextest.toml
        # The exit-code table the tests hold to `KmError::exit_code`.
        ../docs/CAKEYS.md
        # The config reference the `config_doc` test reads.
        ../docs/CONFIG.md
        # A YubiKey's lock, the one from real hardware the lock round trip reads
        # (`cakeys_core::fuzzing`).
        ../examples/yubikey-secureboot.lock
        # The tests' runner: cakeys' validate tests hold its list of untraced tests to the tests
        # that run their own p11-fault.
        ../nix/test-tokens.sh
      ];
    };

    # The tools of one workspace (README.md, "Three tools"), from one build whose check phase
    # tests them together, each in its own output: `out` holds cakeys, `caprobe` the module
    # measurer and `camigrate` the key mover, so cakeys' closure carries neither. `p11fault` holds
    # lib/libp11_fault.so, the PKCS#11 module that forwards to a real one and misbehaves on request
    # (docs/FAULT_SHIM.md): the test suites load it, and so can any other PKCS#11 client.
    outputs = [
      "out"
      "caprobe"
      "camigrate"
      "p11fault"
    ];
    postInstall = ''
      moveToOutput bin/caprobe "$caprobe"
      moveToOutput bin/camigrate "$camigrate"
      moveToOutput lib/libp11_fault${sharedLibrary} "$p11fault"
      # The rlib half of the crate (its unit tests) is no output.
      rm -rf "$out/lib"

      # Tab completion, each tool's own (`COMPLETE=<shell> tool`, clap_complete), in the output
      # that holds the tool. Written from the output's final place: fish's script names the binary.
      completions() { # tool output
        local bin="$2/bin/$1" share="$2/share" tmp
        # Through a file: BSD install (darwin) cannot copy from a pipe (/dev/stdin).
        tmp=$(mktemp)
        COMPLETE=bash "$bin" >"$tmp" && install -D "$tmp" "$share/bash-completion/completions/$1"
        COMPLETE=zsh "$bin" >"$tmp" && install -D "$tmp" "$share/zsh/site-functions/_$1"
        COMPLETE=fish "$bin" >"$tmp" && install -D "$tmp" "$share/fish/vendor_completions.d/$1.fish"
        rm -f "$tmp"
      }
      completions cakeys "$out"
      completions caprobe "$caprobe"
      completions camigrate "$camigrate"
    '';

    # tss-esapi (the native TPM2_Certify attestation path of cakeys-tpm2-pkcs11) links
    # tpm2-tss's ESAPI and TCTI loader at build time; the runtime closure picks the libraries
    # up through the link. rusqlite's `bundled` feature serves plain cargo builds, but nixpkgs'
    # Rust builder sets LIBSQLITE3_SYS_USE_PKG_CONFIG, which makes libsqlite3-sys link the
    # system sqlite instead — so it must be here (and crane's build sets it itself).
    nativeBuildInputs = [ pkg-config ];
    buildInputs = lib.optionals tpm2 [
      tpm2-tss
      sqlite
    ];

    # Integration tests drive real SoftHSM and kryoptic tokens, SoftHSM through p11-kit forwarding,
    # and, with tpm2, tpm2-pkcs11 on a software TPM (behind tpm2-abrmd on a private D-Bus) inside
    # the build sandbox.
    nativeCheckInputs = [
      softhsmForTests
      p11-kit
      opensc
      openssl
      # crates/core/tests/lock_mbt.rs simulates crates/core/spec/lock.qnt with it.
      quint
    ]
    ++ lib.optionals tpm2 [
      swtpm
      tpm2-pkcs11
      tpm2VendorModule
      tpm2-tools
      tpm2-abrmd
      dbus
    ];
    preCheck = lib.optionalString canCheck ''
      # The software tokens and every suite's variables, as every harness sets them up
      # (nix/token-env.sh's test_env; scripts/local-tests.sh calls it too). kryoptic (PKCS#11
      # 3.2) runs the shared reference suite as well.
      export CAKEYS_TOKEN_ENV_SH=${./token-env.sh}
      . $CAKEYS_TOKEN_ENV_SH
      test_env $TMPDIR \
        ${softhsmForTests}/lib/softhsm/libsofthsm2.so \
        ${kryoptic}/lib/libkryoptic_pkcs11${sharedLibrary} \
        ${lib.getLib p11-kit}/lib/pkcs11/p11-kit-client.so \
        ${./p11kit-test-env.sh} ${./tpm2-test-env.sh} \
        ${pkcs11-provider}/lib/ossl-modules ${lib.optionalString tpm2 "${lib.getLib tpm2-pkcs11}/lib/libtpm2_pkcs11.so ${lib.getLib tpm2VendorModule}/lib/libtpm2_pkcs11.so"}

      export HOME=$TMPDIR
    '';

    meta = {
      description = "Content-addressed identity for PKCS#11 objects";
      mainProgram = "cakeys";
      license = lib.licenses.bsd3;
      platforms = lib.platforms.linux ++ lib.platforms.darwin;
    };
  };
}
