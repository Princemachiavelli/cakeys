# SoftHSM 2.7 with upstream/softhsm/ applied: C_UnwrapKey sets CKA_VALUE_LEN (SoftHSMv2 #628).
# `withTests` also runs SoftHSM's own cppunit suite, which the patch extends. Drop this
# when a SoftHSM release carries the fix.
{
  lib,
  softhsm,
  cppunit,
  pkg-config,
  withTests ? false,
}:
softhsm.overrideAttrs (old: {
  pname = "softhsm-unwrap-value-len";
  patches = (old.patches or [ ]) ++ [
    ../upstream/softhsm/0001-C_UnwrapKey-set-CKA_VALUE_LEN-on-the-unwrapped-secret-key.patch
  ];
  # configure finds cppunit through pkg-config at configure time, so it is a build input,
  # not only a check input.
  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ lib.optional withTests pkg-config;
  buildInputs = (old.buildInputs or [ ]) ++ lib.optional withTests cppunit;
  doCheck = withTests;
})
