//! tpm2-pkcs11 (tpm2-software). Quirks observed with 1.10.1 on swtpm:
//!
//! - `CKM_AES_KEY_GEN` is advertised but `C_GenerateKey` returns `CKR_FUNCTION_NOT_SUPPORTED`,
//!   so secret keys cannot be created through PKCS#11: create them with `tpm2_ptool addkey` or
//!   `import` and adopt them.
//! - `CKA_EC_POINT` of P-521 keys has a malformed DER length: `04 85 <133 bytes>` instead of
//!   `04 81 85 <133 bytes>` (the length is always written as one byte; both `src/lib/tpm.c` and
//!   `tools/tpm2_pkcs11/utils.py`). Shorter points are unaffected. Upstream fix drafted in
//!   `upstream/tpm2-pkcs11/` (unfixed as of master a5156c5 and 1.10.1).
//!
//! What the module *can do* — the advertised-but-broken key generation, never wrapping or
//! unwrapping, the `tpm2_ptool` import and its accept rows — is data:
//! profiles/modules/tpm2-pkcs11/1.10+swtpm.toml (docs/CAPROBE.md). What stays here is behaviour:
//! the point repair, and the one module with usable attestation reachable outside PKCS#11,
//! the `tpm-certify` commitment (docs/DESIGN.md §3.7) — the module itself exposes no
//! attestation, so `attest` reaches the TPM through tss-esapi and the module's sqlite store
//! (see [`attest`]).

pub mod attest;
mod ptool;

use cakeys_core::Result;
use cakeys_core::config::Options;
use cakeys_core::id::Scheme;
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::provider::{AttestCtx, AttestationCap, Attested, ImportCtx, PlaintextKind, Provider, Report};
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

    fn repair<'a>(&self, report: Report<'a>) -> Report<'a> {
        match report {
            Report::EcPoint(Cow::Borrowed(raw)) => Report::EcPoint(fix_ec_point(raw)),
            Report::EcPoint(Cow::Owned(raw)) => Report::EcPoint(Cow::Owned(fix_ec_point(&raw).into_owned())),
            other => other,
        }
    }

    fn hint(&self) -> Option<&'static str> {
        Some(
            "secret keys cannot be generated through tpm2-pkcs11; create them with `tpm2_ptool addkey` or `tpm2_ptool import` and adopt them (`lock`, never `cakeys create`)",
        )
    }

    fn attestation(&self) -> Option<AttestationCap> {
        Some(AttestationCap {
            scheme: Scheme::TpmCertify,
            // TPM2_Certify proves any loaded object with its private area — private and secret
            // keys; public-key objects and certificates have no certifiable blob.
            classes: &[ObjectClass::PrivateKey, ObjectClass::SecretKey],
        })
    }

    fn check_options(&self, token: &str, options: &Options) -> Result<()> {
        attest::Tpm2Options::of(token, options).map(drop)
    }

    fn attest(&self, ctx: &AttestCtx<'_>) -> Result<Attested> {
        attest::attest(ctx)
    }

    fn import_plaintext(&self, ctx: &ImportCtx<'_>) -> Result<()> {
        ptool::import(ctx)
    }

    fn plaintext_import(&self) -> PlaintextKind {
        PlaintextKind::Tpm2Ptool
    }
}

/// Re-encode exactly the malformed form `04 <len> <len bytes>` with `len >= 0x80` as proper DER
/// (`04 81 <len> ...`). Anything else is passed through untouched for the strict parser — also
/// `04 81 80 <128 bytes>`, which has that form but is already DER of 128 bytes.
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

/// `raw` is an OCTET STRING of 128 to 255 bytes in DER: `04 81 <len> <len bytes>`.
fn is_der_octets(raw: &[u8]) -> bool {
    matches!(raw, [0x04, 0x81, len, rest @ ..] if *len >= 0x80 && rest.len() == usize::from(*len))
}

/// The property the fuzz target (`fuzz/fuzz_targets/p521_point.rs`) and the proptest below
/// check on any bytes.
pub mod fuzzing {
    use super::fix_ec_point;
    use std::borrow::Cow;

    /// `fix_ec_point` on `raw`: it repairs exactly the malformed `04 <len> <len bytes>` with
    /// `len >= 0x80` that is not already DER, what it repairs is DER of the same point, what it
    /// leaves alone is the input, and a repaired value is left alone.
    ///
    /// # Panics
    ///
    /// When any of that does not hold.
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
                // `04 81 <len> <len bytes>`: the long form of the length the input wrote short.
                assert_eq!(&fixed[..2], &[0x04, 0x81]);
                assert_eq!(usize::from(fixed[2]), fixed.len() - 3);
                assert_eq!(&fixed[3..], &raw[2..]);
                assert!(matches!(fix_ec_point(&fixed), Cow::Borrowed(_)), "a repaired point is repaired again");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        /// `fuzzing::ec_point_fix` on any bytes, and on `04 <len> <len bytes>` built on purpose
        /// (random bytes rarely have that shape, the one it repairs when `len >= 0x80`). Not a
        /// Kani proof: the shape needs 130 bytes or more, and the repair copies them to the heap
        /// at symbolic length, which took more than 8 GB (docs/OPEN.md, "Kani and fuzzing").
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
        // Already valid DER, short points, raw points and wrong lengths are left alone.
        assert!(matches!(fix_ec_point(&good), Cow::Borrowed(_)));
        let p256 = [&[0x04, 0x41][..], &[0x04; 65]].concat();
        assert!(matches!(fix_ec_point(&p256), Cow::Borrowed(_)));
        assert!(matches!(fix_ec_point(&point), Cow::Borrowed(_)));
        assert!(matches!(fix_ec_point(&bad[..bad.len() - 1]), Cow::Borrowed(_)));
        // DER of 128 bytes reads as the short form too (`81`, then 129 bytes): found by
        // `ec_point_fix_holds_on_any_bytes`, which the fuzz target had never reached.
        let der128 = [&[0x04, 0x81, 0x80][..], &[0x04; 128]].concat();
        assert!(matches!(fix_ec_point(&der128), Cow::Borrowed(_)));
    }
}
