//! The provider for tpm2-pkcs11 (tpm2-software). These quirks were observed with 1.10.1 on
//! swtpm:
//!
//! - `CKM_AES_KEY_GEN` is advertised, but `C_GenerateKey` returns `CKR_FUNCTION_NOT_SUPPORTED`,
//!   so secret keys cannot be created through PKCS#11. Create them with `tpm2_ptool addkey` or
//!   `tpm2_ptool import`, and adopt them.
//! - The `CKA_EC_POINT` of a P-521 key has a malformed DER length: `04 85 <133 bytes>` instead of
//!   `04 81 85 <133 bytes>`. Both `src/lib/tpm.c` and `tools/tpm2_pkcs11/utils.py` always write
//!   the length as one byte. Shorter points are not affected. An upstream fix is drafted in
//!   `upstream/tpm2-pkcs11/` (the bug is not fixed as of master a5156c5 and 1.10.1).
//!
//! What the module *can do* is data in profiles/modules/tpm2-pkcs11/1.10+swtpm.toml
//! (docs/CAPROBE.md): the key generation that is advertised but broken, the absence of wrapping
//! and unwrapping, and the `tpm2_ptool` import with its accept rows. This crate keeps only
//! behavior: the point repair, and the `tpm-certify` commitment (docs/DESIGN.md §3.7), because
//! this is the one module with usable attestation that is reachable outside PKCS#11. The module
//! itself exposes no attestation, so `attest` reaches the TPM through tss-esapi and the module's
//! sqlite store (see `attest`). A module that is patched with the `CKM_TPM2_CERTIFY` vendor
//! mechanism (`upstream/tpm2-pkcs11/`) certifies through PKCS#11 instead, and the store is not
//! opened.

mod attest;
mod ptool;

use cakeys_core::Result;
use cakeys_core::config::Options;
use cakeys_core::id::Scheme;
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::provider::{AttestationCap, PlaintextKind, PlaintextVia, Provider, Topic};
use cakeys_pkcs11::token::ModuleInfo;
use std::borrow::Cow;

/// The tpm2-pkcs11 provider (see the crate's documentation).
pub struct Tpm2Pkcs11;

impl Provider for Tpm2Pkcs11 {
    fn name(&self) -> &'static str {
        "tpm2-pkcs11"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "tpm2-software.github.io"
    }

    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        fix_ec_point(raw)
    }

    fn hint(&self, about: Topic) -> Option<&'static str> {
        (about == Topic::Generate).then_some(
            "secret keys cannot be generated through tpm2-pkcs11; create them with `tpm2_ptool addkey` or `tpm2_ptool import` and adopt them (`lock`, never `cakeys create`)",
        )
    }

    fn attestation(&self) -> Option<AttestationCap> {
        Some(AttestationCap {
            scheme: Scheme::TpmCertify,
            // TPM2_Certify proves any loaded object that has a private area, which means private
            // and secret keys. Public-key objects and certificates have no blob to certify.
            classes: &[ObjectClass::PrivateKey, ObjectClass::SecretKey],
            // An imported key is loaded like any other key (its CKA_LOCAL is false in the
            // record).
            imported: true,
            attest: attest::attest,
        })
    }

    fn check_options(&self, token: &str, options: &Options) -> Result<()> {
        attest::Tpm2Options::of(token, options).map(drop)
    }

    fn plaintext_import(&self) -> PlaintextVia {
        PlaintextVia::Tool(PlaintextKind::Tpm2Ptool, ptool::import)
    }
}

/// Re-encodes exactly the malformed form `04 <len> <len bytes>` with `len >= 0x80` as proper DER
/// (`04 81 <len> ...`). Any other input is passed through unchanged to the strict parser. This
/// includes `04 81 80 <128 bytes>`, which has the malformed form but is already the DER of 128
/// bytes.
#[must_use]
pub fn fix_ec_point(raw: &[u8]) -> Cow<'_, [u8]> {
    match raw {
        [0x04, len, rest @ ..] if *len >= 0x80 && rest.len() == *len as usize && !is_der_octets(raw) => {
            let mut v = Vec::with_capacity(raw.len() + 1);
            v.extend_from_slice(&[0x04, 0x81, *len]);
            v.extend_from_slice(rest);
            Cow::Owned(v)
        }
        _ => Cow::Borrowed(raw),
    }
}

/// Returns whether `raw` is the DER of an OCTET STRING of 128 to 255 bytes:
/// `04 81 <len> <len bytes>`.
fn is_der_octets(raw: &[u8]) -> bool {
    matches!(raw, [0x04, 0x81, len, rest @ ..] if *len >= 0x80 && rest.len() == usize::from(*len))
}

/// The property that the fuzz target (`fuzz/fuzz_targets/p521_point.rs`) and the proptest below
/// check on any bytes, and that the Kani proof in this module checks for every input of up to
/// 258 bytes. The module also exposes the attestation's parsers for arbitrary input
/// (`tpm_store_row.rs`, `tpms_attest.rs`).
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    pub use crate::attest::fuzzing::{store_row, tpms_attest};

    use super::fix_ec_point;
    use std::borrow::Cow;

    /// Checks `fix_ec_point` on `raw`. It must repair exactly the malformed
    /// `04 <len> <len bytes>` with `len >= 0x80` that is not already DER. What it repairs must
    /// be the DER of the same point, what it does not repair must be the input unchanged, and a
    /// repaired value must not be changed again.
    ///
    /// # Panics
    ///
    /// Panics when any of these conditions does not hold.
    pub fn ec_point_fix(raw: &[u8]) {
        let short =
            |raw: &[u8]| matches!(raw, [0x04, len, rest @ ..] if *len >= 0x80 && rest.len() == usize::from(*len));
        let der = matches!(raw, [0x04, 0x81, len, rest @ ..] if *len >= 0x80 && rest.len() == usize::from(*len));
        let malformed = short(raw) && !der;
        let fixed = fix_ec_point(raw);
        assert_eq!(matches!(fixed, Cow::Owned(_)), malformed, "{raw:02x?}");
        match fixed {
            Cow::Borrowed(same) => assert_eq!(same, raw),
            Cow::Owned(fixed) => {
                // `04 81 <len> <len bytes>` is the long form of the length that the input wrote
                // in the short form.
                assert_eq!(&fixed[..2], &[0x04, 0x81]);
                assert_eq!(usize::from(fixed[2]), fixed.len() - 3);
                assert_eq!(&fixed[3..], &raw[2..]);
                assert!(matches!(fix_ec_point(&fixed), Cow::Borrowed(_)), "a repaired point is repaired again");
            }
        }
    }

    /// Checks `ec_point_fix` for every input of up to `04 81 ff` and its 255 bytes, which
    /// covers every shape that it repairs or leaves unchanged. The proof takes 1m42s and
    /// 5.7 GB (`checks.kani`). The input is a fixed array and a length, not a `Vec`, because
    /// CBMC turns a heap value of symbolic length into array constraints, and the copy of
    /// the point inside `fix_ec_point` is already most of the cost (docs/OPEN.md, "Kani and
    /// fuzzing").
    #[cfg(kani)]
    mod proofs {
        #[kani::proof]
        #[kani::unwind(260)]
        fn ec_point_fix() {
            let b: [u8; 258] = kani::any();
            let n: usize = kani::any();
            kani::assume(n <= 258);
            super::ec_point_fix(&b[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        /// Runs `fuzzing::ec_point_fix` on any bytes, and on inputs that are built with the shape
        /// `04 <len> <len bytes>`, because random bytes rarely have that shape, which is the shape
        /// that the function repairs when `len >= 0x80`. The inputs are longer than the inputs of
        /// the Kani proof in `fuzzing::proofs`.
        #[test]
        fn ec_point_fix_holds_on_any_bytes(
            shaped: bool,
            len: u8,
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300),
        ) {
            if shaped {
                let body = bytes.iter().copied().chain(std::iter::repeat(0)).take(usize::from(len));
                fuzzing::ec_point_fix(&[0x04, len].into_iter().chain(body).collect::<Vec<_>>());
            } else {
                fuzzing::ec_point_fix(&bytes);
            }
        }
    }

    #[test]
    fn fixes_only_the_short_form_overflow() {
        let point = [0x04u8; 133];
        let mut bad = vec![0x04, 0x85];
        bad.extend_from_slice(&point);
        let mut good = vec![0x04, 0x81, 0x85];
        good.extend_from_slice(&point);
        assert_eq!(fix_ec_point(&bad).as_ref(), good.as_slice());
        // Valid DER, short points, raw points and wrong lengths are left unchanged.
        assert!(matches!(fix_ec_point(&good), Cow::Borrowed(_)));
        let p256 = [&[0x04, 0x41][..], &[0x04; 65]].concat();
        assert!(matches!(fix_ec_point(&p256), Cow::Borrowed(_)));
        assert!(matches!(fix_ec_point(&point), Cow::Borrowed(_)));
        assert!(matches!(fix_ec_point(&bad[..bad.len() - 1]), Cow::Borrowed(_)));
        // The DER of 128 bytes can also be read as the short form (length `81`, followed by
        // 129 bytes). `ec_point_fix_holds_on_any_bytes` found this case, which the fuzz target
        // had never reached.
        let der128 = [&[0x04, 0x81, 0x80][..], &[0x04; 128]].concat();
        assert!(matches!(fix_ec_point(&der128), Cow::Borrowed(_)));
    }
}
