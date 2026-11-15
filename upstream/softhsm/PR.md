# PR for softhsm/SoftHSMv2: `CKA_VALUE_LEN` on unwrapped secret keys

Status: **filed** as [#925](https://github.com/softhsm/SoftHSMv2/pull/925) (2026-11-14, open;
CodeRabbit had no actionable comments). It fixes
[#628](https://github.com/softhsm/SoftHSMv2/issues/628); the older PR #650 has the same core
change, unmerged.

- When a release with the fix is out, drop `nix/softhsm-unwrap-value-len.nix`,
  `checks.softhsm-unwrap-value-len` and this directory's patch, and read the `[manual]` entry
  in `profiles/modules/softhsm/2.7.toml` again.

Made against 2.7.0 and checked there (`make check` passes with it; the new assertions fail
without it). Upstream main's autotools build fails to link `p11test` (`MutexFactory`) with or
without the change, so it could not be run on `7380895`.

Local equivalent: `nix/softhsm-unwrap-value-len.nix` applies the patch to nixpkgs' `softhsm`.

---

**Title:** C_UnwrapKey: set CKA_VALUE_LEN on the unwrapped secret key

**Body (as filed):**

C_UnwrapKey stored the recovered CKA_VALUE of a secret key but left CKA_VALUE_LEN at its default
of 0, so an unwrapped 256-bit AES key reported CKA_VALUE_LEN 0. A template cannot supply it: the
attribute is refused with CKR_ATTRIBUTE_READ_ONLY, as PKCS#11 (v2.40 4.1.2, footnote 6) says it
must not be specified when unwrapping, and the mechanism contributes it with CKA_VALUE.

Set CKA_VALUE_LEN to the length of the recovered value for every secret key type that has the
attribute. The tests check it after an AES unwrap of a generic secret key and an RSA unwrap of an
AES key, and that a Triple DES key, which has no CKA_VALUE_LEN, still unwraps to its value
without one.

Fixes #628
