# SoftHSM as the tests see it, the one SoftHSM this repository tests and probes against (the
# check phase, scripts/local-tests.sh, scripts/regen-profiles.sh, pkcs11-check-compare): named for
# its first patch, it carries all four of upstream/softhsm/.
#
# SoftHSM 2.7 with upstream/softhsm/ applied: C_UnwrapKey sets CKA_VALUE_LEN (SoftHSMv2 #628);
# multi-part CKM_ECDSA_SHA* (#857) and no static teardown (#897), both on main after 2.7.0,
# backported; its own crypto in a private OpenSSL library context (#834), so OpenSSL through
# pkcs11-provider over SoftHSM neither deadlocks in C_Login nor crashes at exit. The check phase
# and scripts/local-tests.sh test against it. `withTests` also runs SoftHSM's own cppunit suite,
# which the patches extend, on Linux only: on darwin libtool builds libsofthsm2.so as a bundle
# (MH_BUNDLE), and the macOS linker cannot link the suite's p11test against a bundle. Drop each
# patch when a SoftHSM release carries it.
{
  lib,
  stdenv,
  softhsm,
  cppunit,
  pkg-config,
  withTests ? false,
}:
softhsm.overrideAttrs (old: {
  pname = "softhsm-unwrap-value-len";
  patches = (old.patches or [ ]) ++ [
    ../upstream/softhsm/0001-C_UnwrapKey-set-CKA_VALUE_LEN-on-the-unwrapped-secret-key.patch
    ../upstream/softhsm/0002-backport-857-multipart-hashed-ECDSA.patch
    ../upstream/softhsm/0003-backport-897-no-static-teardown.patch
    ../upstream/softhsm/0004-private-OpenSSL-library-context.patch
  ];
  # configure finds cppunit through pkg-config at configure time, so it is a build input,
  # not only a check input.
  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ lib.optional withTests pkg-config;
  buildInputs = (old.buildInputs or [ ]) ++ lib.optional withTests cppunit;
  doCheck = withTests && !stdenv.hostPlatform.isDarwin;
})
