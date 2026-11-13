# Draft PR for tpm2-software/tpm2-pkcs11

Status: **draft, not filed.** Before opening it:

- Signed off in ~/srcs/tpm2-pkcs11. Consider adding to the commit message: "The library's own
  C_SignInit parses it too, so P-521 keys could not sign (CKR_HOST_MEMORY)." (found 2026-11-11).
- Upstream requires the PR to pass their CI. The checks below ran through
  nixpkgs' build with `--enable-integration`, not their Docker image.

Checked on 2026-11-11 against master `a5156c5` (2026-10-10) and release
1.10.1: both still have the bug (`src/lib/tpm.c:3624`,
`tools/tpm2_pkcs11/utils.py:254`). There is no existing issue or PR: the
searches for P-521/secp521r1/EC_POINT length/DER length only hit the
unrelated #579, #742 and #953.

---

**Title:** tpm: encode the P-521 CKA_EC_POINT as DER

**Body:**

`CKA_EC_POINT` is the DER encoding of an OCTET STRING holding the X9.62
uncompressed point (PKCS#11 v2.40 §2.3.3). Both the library
(`src/lib/tpm.c`) and `tpm2_ptool` (`asn1_format_ec_point_uncompressed()`)
build the header by hand as `04 <len>`, with the length always in one byte.
DER allows that short form only for lengths up to 127 (X.690 §8.1.3.4).
A NIST P-521 point is 133 bytes, so tpm2-pkcs11 returns

    04 85 04 <X:66> <Y:66>

where the correct encoding is `04 81 85 04 ...`: `0x85` as a first length
byte means "five length bytes follow". P-256 (65 bytes) and P-384 (97 bytes)
points are below the limit and unaffected.

Strict DER parsers reject the attribute. With 1.10.1 on swtpm:

    $ pkcs11-tool --module libtpm2_pkcs11.so --login --keypairgen --key-type EC:secp521r1 --label r
    $ pkcs11-tool --module libtpm2_pkcs11.so --login --read-object --type pubkey --label r -o r.der
    error: cannot obtain and parse EC_POINT

The same export works for `EC:secp384r1`.

Changes:

- **library:** encode the point with `i2d_ASN1_OCTET_STRING()`, as the
  existing TODO suggested, instead of a hand-built header. The `len > 255`
  guard and the manual buffer go away.
- **tpm2_ptool:** emit the long form (`81 <len>`) for lengths of 128 or more,
  which covers `tpm2_ptool addkey --algorithm=ecc521`.
- **test:** `test_ecc_keygen_p521_ec_point_is_der` in `pkcs-keygen.int`
  generates a P-521 key pair, then requires `CKA_EC_POINT` to be
  `3 + 133` bytes and to decode completely with `d2i_ASN1_OCTET_STRING()`.
  It skips if the TPM does not implement P-521.

Testing, through nixpkgs' tpm2-pkcs11 1.10.1 build (`--enable-unit
--enable-integration`, swtpm):

- with the patch: `# TOTAL: 28  # PASS: 26  # SKIP: 2  # FAIL: 0`;
- with only the new test, without the fix:
  `FAIL: test/integration/pkcs-keygen.int`
  (`[ FAILED ] test_ecc_keygen_p521_ec_point_is_der`);
- with the patch, `pkcs11-tool --read-object` exports the P-521 public key.
  `openssl pkey` reads it, and its SHA-256 equals the SubjectPublicKeyInfo
  hash an independent strict DER consumer computes from `CKA_EC_POINT`.

The library's own sign path parses the attribute too
(`ssl_util_attrs_to_evp()` from `sign_opdata_new()`), so P-521 keys cannot
sign at all on 1.10.1. Both `CKM_ECDSA` and `CKM_ECDSA_SHA512` fail in
`C_SignInit`:

    ERROR ... src/lib/ssl_util.c: d2i_ASN1_OCTET_STRING: ... too long
    error: PKCS11 function C_SignInit failed: rv = CKR_HOST_MEMORY (0x2)

With the patch, in a fresh token store, both mechanisms sign (132-byte
signatures).

Side note, not changed here: when `asn1_format_ec_point_uncompressed()` gets
an odd-length hex coordinate, it prepends `"00"` (two digits) where one
digit is needed. tpm2-tools prints whole bytes, so this does not seem
reachable today.

The CHANGELOG is not touched, since entries appear to be added at release.
Suggested entry under *Fixed*: "CKA_EC_POINT of NIST P-521 keys was not
valid DER (one-byte length for a 133-byte point)."
