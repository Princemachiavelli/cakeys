//! Yubico ykcs11 (YubiKey PIV). Two quirks are handled generically elsewhere: its
//! `CKA_PUBLIC_KEY_INFO` reports length 0 and then `CKR_ARGUMENTS_BAD` (tolerated by the
//! token layer for every module), and its fixed per-slot `CKA_LABEL`/`CKA_ID` set.
//!
//! What lives here is the `piv-attestation` commitment (docs/DESIGN.md §3.7): the provider
//! finds the module-exposed attestation certificates, and the pure chain verification and
//! canonical digest are in [`attest`] — verified against both a fixture chain and Yubico's
//! own published roots and intermediates.

mod attest;

use crate::attest::{pem_certs, verify_piv_attestation, ATTESTATION_LABEL};
use cakeys_pkcs11::provider::{AttestationCap, AttestCtx, Attested, Provider};
use cakeys_pkcs11::token::ModuleInfo;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cakeys_core::{KmError, Result};

pub struct Ykcs11;

/// Anchors: Yubico's pinned PIV roots. The intermediate pool (the untrusted store) is only
/// needed when a chain uses it, so parse both lazily but only once per process.
fn anchors() -> &'static Vec<attest::Cert> {
    static ANCHORS: std::sync::OnceLock<Vec<attest::Cert>> = std::sync::OnceLock::new();
    ANCHORS.get_or_init(|| {
        let mut a = pem_certs(include_str!("../roots/yubico-piv-ca-1.pem")).expect("embedded Yubico PIV root parses");
        a.extend(pem_certs(include_str!("../roots/yubico-ca-1.pem")).expect("embedded Yubico attestation root parses"));
        a
    })
}

fn intermediates() -> &'static Vec<attest::Cert> {
    static POOL: std::sync::OnceLock<Vec<attest::Cert>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| pem_certs(include_str!("../roots/yubico-intermediate.pem")).expect("embedded Yubico intermediates parse"))
}

impl Provider for Ykcs11 {
    fn name(&self) -> &'static str {
        "ykcs11"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer.starts_with("Yubico")
    }

    fn attestation(&self) -> Option<AttestationCap> {
        Some(AttestationCap {
            scheme: "piv-attestation",
            kind: "yubico-piv",
            // PIV attests the asymmetric keys generated on the device; secret keys, data
            // objects and certificates have none.
            classes: &["CKO_PRIVATE_KEY", "CKO_PUBLIC_KEY"],
        })
    }

    fn attest(&self, ctx: &AttestCtx<'_>) -> Result<Attested> {
        // The slot's attestation certificate shares the key's CKA_ID and carries the slot in
        // its label; ykcs11 mints it at session open, which needs the PIV management key
        // authenticated in the underlying ykpiv state.
        let Some(Attribute::Id(id)) = ctx
            .session
            .get_attributes(ctx.key, &[AttributeType::Id])
            .map_err(|e| KmError::Unavailable(format!("C_GetAttributeValue (CKA_ID): {e}")))?
            .into_iter()
            .next()
        else {
            return Err(KmError::Unsupported("the key object exposes no CKA_ID to find its attestation by".into()));
        };
        let slot = find_attestation_cert(ctx, &id)?;
        let device = find_device_cert(ctx)?;
        let a = verify_piv_attestation(&slot, &device, anchors(), intermediates(), ctx.spki)?;
        Ok(Attested { scheme: "piv-attestation", id: a.id, root: a.root })
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
        if let Some(Attribute::Label(l)) = label {
            if String::from_utf8_lossy(&l).strip_prefix(&label_prefix).is_some_and(|slot| !slot.is_empty()) {
                match ctx.session.get_attributes(h, &[AttributeType::Value]) {
                    Ok(v) => match v.into_iter().next() {
                        Some(Attribute::Value(der)) => certs.push(der),
                        _ => return Err(KmError::Unsupported("the attestation certificate has no readable CKA_VALUE".into())),
                    },
                    Err(e) => return Err(KmError::Unavailable(format!("C_GetAttributeValue (attestation): {e}"))),
                }
            }
        }
    }
    match certs.len() {
        1 => Ok(certs.remove(0)),
        0 => Err(KmError::Unsupported(format!(
            "no attestation certificate for this key on '{}': Yubico attests only keys generated on \
             device (imported keys have none), and ykcs11 mints the certificate at session open, \
             which needs the PIV management key",
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
