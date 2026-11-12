//! Yubico ykcs11 (YubiKey PIV). Two quirks are handled generically elsewhere: its
//! `CKA_PUBLIC_KEY_INFO` reports length 0 and then `CKR_ARGUMENTS_BAD` (tolerated by the
//! token layer for every module), and its fixed per-slot `CKA_LABEL`/`CKA_ID` set.
//!
//! What lives here is the `piv-attestation` commitment (docs/DESIGN.md §3.7): the provider
//! finds the module-exposed attestation certificates, and the pure chain verification and
//! canonical digest are in [`attest`] — verified against both a fixture chain and Yubico's
//! own published roots and intermediates.

mod attest;

use crate::attest::{pem_certs, piv_pool, verify_piv_attestation, ATTESTATION_LABEL};
use cakeys_pkcs11::provider::{AttestationCap, AttestCtx, Attested, Provider};
use cakeys_core::config::{Locator, ObjectCfg};
use cakeys_pkcs11::token::ModuleInfo;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cakeys_core::id::Scheme;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use std::sync::LazyLock;

pub struct Ykcs11;

/// Anchors: Yubico's pinned PIV roots. The intermediate pool (the untrusted store) is only
/// needed when a chain uses it, so both are parsed lazily, once per process.
static ANCHORS: LazyLock<Vec<attest::Cert>> = LazyLock::new(|| {
    let mut a = pem_certs(include_str!("../roots/yubico-piv-ca-1.pem")).expect("embedded Yubico PIV root parses");
    a.extend(pem_certs(include_str!("../roots/yubico-ca-1.pem")).expect("embedded Yubico attestation root parses"));
    a
});

/// The pooled intermediates a PIV chain may use: Yubico's published pool narrowed to the PIV
/// CAs and the generic intermediates above them (`attest::piv_pool`).
static INTERMEDIATES: LazyLock<Vec<attest::Cert>> = LazyLock::new(|| {
    piv_pool(pem_certs(include_str!("../roots/yubico-intermediate.pem")).expect("embedded Yubico intermediates parse"))
});

impl Provider for Ykcs11 {
    fn name(&self) -> &'static str {
        "ykcs11"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer.starts_with("Yubico")
    }

    /// ykcs11 generates (and deletes) only after `C_Login(CKU_SO)` with the PIV management key.
    fn manages_as_so(&self) -> bool {
        true
    }

    /// ykcs11 generates into the slot the template's `CKA_ID` names and gives each slot fixed
    /// labels, so a key to create is located by `CKA_ID` alone.
    fn check_create(&self, _object: &ObjectCfg, loc: &Locator) -> Result<()> {
        if loc.label.is_some() {
            return Err(KmError::Validation(
                "ykcs11 ignores CKA_LABEL when generating and fixes each slot's labels; locate a key \
                 to create by CKA_ID alone (01-04: slots 9a/9c/9d/9e, 05-18: retired slots 82-95)"
                    .into(),
            ));
        }
        match loc.id.as_deref().and_then(piv_slot) {
            Some(_) => Ok(()),
            None => Err(KmError::Validation(format!(
                "ykcs11 generates into the PIV slot named by CKA_ID; {:?} names none (01-04: slots \
                 9a/9c/9d/9e, 05-18: retired slots 82-95)",
                loc.id.as_deref().unwrap_or("")
            ))),
        }
    }

    /// ykcs11's `C_DestroyObject` writes an empty certificate to the slot and hides the slot's
    /// objects for the rest of the session; the key stays and is listed again by the next one
    /// (verified on a YubiKey 5, firmware 5.7.4, ykcs11 2.7.3).
    fn keeps_destroyed_keys(&self, loc: &Locator) -> Option<String> {
        let slot = loc.id.as_deref().and_then(piv_slot).map_or("<slot>".to_owned(), |s| format!("{s:02x}"));
        Some(format!(
            "ykcs11 clears only the slot's certificate and leaves the key in the slot; delete it with \
             `ykman piv keys delete {slot}`"
        ))
    }

    fn attestation(&self) -> Option<AttestationCap> {
        Some(AttestationCap {
            scheme: Scheme::PivAttestation,
            // PIV attests the asymmetric keys generated on the device; secret keys, data
            // objects and certificates have none.
            classes: &[Class::PrivateKey, Class::PublicKey],
        })
    }

    fn attest(&self, ctx: &AttestCtx<'_>) -> Result<Attested> {
        // The slot's attestation certificate shares the key's CKA_ID and carries the slot in
        // its label; ykcs11 mints it when it lists the slot's objects, needing no login (seen
        // on a YubiKey 5, firmware 5.7.4).
        let Some(Attribute::Id(id)) = ctx
            .session
            .get_attributes(ctx.key, &[AttributeType::Id])
            .map_err(|e| KmError::Unavailable(format!("C_GetAttributeValue (CKA_ID): {e}")))?
            .into_iter()
            .next()
        else {
            return Err(KmError::Unsupported("the key object exposes no CKA_ID to find its attestation by".into()));
        };
        let spki = ctx
            .required_spki()?
            .ok_or_else(|| KmError::Unsupported("PIV attests asymmetric keys only".into()))?;
        let slot = find_attestation_cert(ctx, &id)?;
        let device = find_device_cert(ctx)?;
        let a = verify_piv_attestation(&slot, &device, &ANCHORS, &INTERMEDIATES, spki)?;
        Ok(Attested { scheme: Scheme::PivAttestation, id: a.id, root: a.root })
    }
}

/// The PIV key slot ykcs11 places a `CKA_ID` in (hex, one byte): 01-04 are 9a/9c/9d/9e, 05-18 the
/// retired slots 82-95 (ykcs11's fixed object table).
fn piv_slot(id: &str) -> Option<u8> {
    if id.len() != 2 {
        return None;
    }
    match u8::from_str_radix(id, 16).ok()? {
        n @ 1..=4 => Some([0x9a, 0x9c, 0x9d, 0x9e][usize::from(n) - 1]),
        n @ 5..=0x18 => Some(0x82 + (n - 5)),
        _ => None,
    }
}

/// The slot's attestation certificate DER: exactly one certificate object under the key's
/// `CKA_ID` whose label carries the slot suffix after `ATTESTATION_LABEL`.
fn find_attestation_cert(ctx: &AttestCtx<'_>, id: &[u8]) -> Result<Vec<u8>> {
    let label_prefix = format!("{ATTESTATION_LABEL} ");
    let found = ctx
        .session
        .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::Id(id.to_vec())])
        .map_err(|e| KmError::Unavailable(format!("C_FindObjects (attestation): {e}")))?;
    let mut certs = Vec::new();
    for h in found {
        let label = match ctx.session.get_attributes(h, &[AttributeType::Label]) {
            Ok(v) => v.into_iter().next(),
            Err(_) => None,
        };
        // The f9 device certificate shares the prefix but not the key's CKA_ID; require a
        // non-empty slot suffix so the two can never be confused.
        if let Some(Attribute::Label(l)) = label
            && String::from_utf8_lossy(&l).strip_prefix(&label_prefix).is_some_and(|slot| !slot.is_empty())
        {
            match ctx.session.get_attributes(h, &[AttributeType::Value]) {
                Ok(v) => match v.into_iter().next() {
                    Some(Attribute::Value(der)) => certs.push(der),
                    _ => return Err(KmError::Unsupported("the attestation certificate has no readable CKA_VALUE".into())),
                },
                Err(e) => return Err(KmError::Unavailable(format!("C_GetAttributeValue (attestation): {e}"))),
            }
        }
    }
    match certs.len() {
        1 => Ok(certs.remove(0)),
        0 => Err(KmError::Unsupported(format!(
            "no attestation certificate for this key on '{}': Yubico attests only keys generated on \
             device (imported keys have none)",
            ctx.token_name
        ))),
        n => Err(KmError::Ambiguous(format!("{n} attestation certificates share the key's CKA_ID"))),
    }
}

/// The f9 device attestation certificate (bare label, no slot suffix): the key that signed the
/// slot certificate, itself signed by a pinned Yubico root.
fn find_device_cert(ctx: &AttestCtx<'_>) -> Result<Vec<u8>> {
    let found = ctx
        .session
        .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::Label(ATTESTATION_LABEL.as_bytes().to_vec())])
        .map_err(|e| KmError::Unavailable(format!("C_FindObjects (device attestation): {e}")))?;
    let mut certs = Vec::new();
    for h in found {
        match ctx.session.get_attributes(h, &[AttributeType::Value]) {
            Ok(v) => match v.into_iter().next() {
                Some(Attribute::Value(der)) => certs.push(der),
                _ => return Err(KmError::Unsupported("the device attestation certificate has no readable CKA_VALUE".into())),
            },
            Err(e) => return Err(KmError::Unavailable(format!("C_GetAttributeValue (device attestation): {e}"))),
        }
    }
    match certs.len() {
        1 => Ok(certs.remove(0)),
        0 => Err(KmError::Unsupported(format!(
            "the device attestation certificate (slot f9) is not exposed on '{}'; cakeys \
             verifies slot attestations to a pinned Yubico root through it, never to the slot \
             certificate alone",
            ctx.token_name
        ))),
        n => Err(KmError::Ambiguous(format!("{n} objects carry the f9 device certificate label"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ykcs11's fixed CKA_ID table: 01-04 the four PIV slots, 05-18 the twenty retired slots;
    /// 19 (f9, the device attestation key) and anything else is no key slot to generate into.
    #[test]
    fn cka_ids_map_to_piv_slots() {
        assert_eq!(piv_slot("01"), Some(0x9a));
        assert_eq!(piv_slot("04"), Some(0x9e));
        assert_eq!(piv_slot("05"), Some(0x82));
        assert_eq!(piv_slot("18"), Some(0x95));
        for bad in ["00", "19", "1", "0101", "zz", ""] {
            assert_eq!(piv_slot(bad), None, "{bad}");
        }
        let loc = |label: Option<&str>, id: Option<&str>| Locator { label: label.map(Into::into), id: id.map(Into::into) };
        let obj = ObjectCfg::new(Class::PrivateKey, Some(cakeys_core::types::KeyType::Ec));
        assert!(Ykcs11.check_create(&obj, &loc(None, Some("01"))).is_ok());
        assert!(matches!(Ykcs11.check_create(&obj, &loc(Some("x"), Some("01"))), Err(KmError::Validation(_))));
        assert!(matches!(Ykcs11.check_create(&obj, &loc(None, Some("19"))), Err(KmError::Validation(_))));
        assert!(Ykcs11.keeps_destroyed_keys(&loc(None, Some("18"))).unwrap().contains("ykman piv keys delete 95"));
    }
}
