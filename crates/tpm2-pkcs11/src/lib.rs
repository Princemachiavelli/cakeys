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
//! It is also the one module with usable attestation reachable outside PKCS#11: the
//! `tpm-certify` commitment (docs/DESIGN.md §3.7) certifies the token's keys natively with
//! `TPM2_Certify` — the module itself exposes no attestation, so `attest` reaches the TPM
//! through tss-esapi and the module's sqlite store (see [`attest`]).

pub mod attest;

use cakeys_core::Result;
use cakeys_core::config::Options;
use cakeys_core::id::Scheme;
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::provider::{AttestCtx, AttestationCap, Attested, Provider};
use cakeys_pkcs11::token::ModuleInfo;
use cryptoki::mechanism::MechanismType;
use std::borrow::Cow;

pub struct Tpm2Pkcs11;

impl Provider for Tpm2Pkcs11 {
    fn name(&self) -> &'static str {
        "tpm2-pkcs11"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "tpm2-software.github.io"
    }

    fn mechanisms(&self, advertised: Vec<MechanismType>) -> Vec<MechanismType> {
        advertised
            .into_iter()
            .filter(|m| *m != MechanismType::AES_KEY_GEN && *m != MechanismType::GENERIC_SECRET_KEY_GEN)
            .collect()
    }

    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        fix_ec_point(raw)
    }

    fn hint(&self) -> Option<&'static str> {
        Some(
            "secret keys cannot be generated through tpm2-pkcs11; create them with `tpm2_ptool addkey` or `tpm2_ptool import` and adopt them (no autoCreate)",
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
}

/// Re-encode exactly the malformed form `04 <len> <len bytes>` with `len >= 0x80` as proper DER
/// (`04 81 <len> ...`). Anything else is passed through untouched for the strict parser.
pub fn fix_ec_point(raw: &[u8]) -> Cow<'_, [u8]> {
    match raw {
        [0x04, len, rest @ ..] if *len >= 0x80 && rest.len() == *len as usize => {
            let mut v = Vec::with_capacity(raw.len() + 1);
            v.extend_from_slice(&[0x04, 0x81, *len]);
            v.extend_from_slice(rest);
            Cow::Owned(v)
        }
        _ => Cow::Borrowed(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
