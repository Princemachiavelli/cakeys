//! The provider for Yubico ykcs11 (`YubiKey` PIV). Two quirks are handled generically elsewhere.
//! Its `CKA_PUBLIC_KEY_INFO` reports a length of 0 and then fails with `CKR_ARGUMENTS_BAD`, which
//! the token layer tolerates for every module. Its set of `CKA_LABEL` and `CKA_ID` values is fixed
//! for each slot.
//!
//! This crate contains the `piv-attestation` commitment (docs/DESIGN.md §3.7). The provider finds
//! the attestation certificates that the module exposes, the private `attest` module checks what
//! the chain asserts and computes the canonical digest, and `cakeys_core::chain` walks the chain.
//! The chain walk is tested against both a fixture chain and Yubico's own published roots and
//! intermediates.

mod attest;

use crate::attest::{ATTESTATION_LABEL, piv_pool, verify_piv_attestation};
use cakeys_core::chain::{Cert, pem_certs};
use cakeys_core::config::Locator;
use cakeys_core::id::Scheme;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{Check, KmError, Reason, Result};
use cakeys_pkcs11::provider::{AttestCtx, AttestationCap, Attested, PlaintextKind, PlaintextVia, Provider};
use cakeys_pkcs11::token::{ModuleInfo, read_attribute};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use std::sync::LazyLock;

/// The ykcs11 provider (see the crate's documentation).
pub struct Ykcs11;

/// The trust anchors, which are Yubico's pinned PIV roots. The intermediate pool (the untrusted
/// store) is needed only when a chain uses it, so both are parsed lazily, once per process.
static ANCHORS: LazyLock<Vec<Cert>> = LazyLock::new(|| {
    let mut a = pem_certs(include_str!("../roots/yubico-piv-ca-1.pem")).expect("embedded Yubico PIV root parses");
    a.extend(pem_certs(include_str!("../roots/yubico-ca-1.pem")).expect("embedded Yubico attestation root parses"));
    a
});

/// The pooled intermediates that a PIV chain may use: Yubico's published pool, narrowed to the
/// PIV CAs and the generic intermediates above them (`attest::piv_pool`).
static INTERMEDIATES: LazyLock<Vec<Cert>> = LazyLock::new(|| {
    piv_pool(pem_certs(include_str!("../roots/yubico-intermediate.pem")).expect("embedded Yubico intermediates parse"))
});

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/piv_chain.rs`). They run the PIV
/// attestation chain on arbitrary certificates, which must be read or refused with an error, and
/// never cause a panic.
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    /// Reads `bytes` as a slot attestation certificate and the device certificate that signed
    /// it: a big-endian two-byte length, the slot certificate's DER, and then the device
    /// certificate's DER. It verifies them as `check` verifies a chain, including the dates,
    /// against Yubico's pinned roots and the test fixture's root.
    ///
    /// # Errors
    ///
    /// Any error from the chain's verification.
    pub fn piv_attestation(bytes: &[u8]) -> cakeys_core::Result<()> {
        super::attest::fuzz_piv_attestation(bytes, &super::ANCHORS, &super::INTERMEDIATES)
    }
}

impl Ykcs11 {
    /// Checks the locator of a key to create. ykcs11 generates into the slot that the template's
    /// `CKA_ID` names and gives each slot fixed labels, so a key to create is located by
    /// `CKA_ID` alone.
    ///
    /// # Errors
    ///
    /// `Validation` for a locator with a label, or for a locator whose `CKA_ID` names no PIV
    /// slot.
    fn check_create(loc: &Locator) -> Result<()> {
        if loc.label.is_some() {
            return Err(KmError::Validation(
                "ykcs11 ignores CKA_LABEL when generating and fixes each slot's labels; locate a key \
                 to create by CKA_ID alone (01-04: slots 9a/9c/9d/9e, 05-18: retired slots 82-95)"
                    .into(),
            ));
        }
        match loc.id.as_deref().and_then(piv_slot) {
            Some(_) => Ok(()),
            None => Err(KmError::Validation(
                format!(
                    "ykcs11 generates into the PIV slot named by CKA_ID; {:?} names none (01-04: slots \
                 9a/9c/9d/9e, 05-18: retired slots 82-95)",
                    loc.id.as_deref().unwrap_or("")
                )
                .into(),
            )),
        }
    }

    /// Returns the message for a key that ykcs11 does not destroy. ykcs11's `C_DestroyObject`
    /// writes an empty certificate to the slot and hides the slot's objects for the rest of the
    /// session. The key stays, and the next session lists it again (verified on a `YubiKey` 5,
    /// firmware 5.7.4, ykcs11 2.7.3).
    #[must_use]
    fn keeps_destroyed_keys(loc: &Locator) -> String {
        let slot = loc.id.as_deref().and_then(piv_slot).map_or("<slot>".to_owned(), |s| format!("{s:02x}"));
        format!(
            "ykcs11 clears only the slot's certificate and leaves the key in the slot; delete it with \
             `ykman piv keys delete {slot}`"
        )
    }
}

impl Provider for Ykcs11 {
    fn name(&self) -> &'static str {
        "ykcs11"
    }

    /// Recognizes Yubico's PIV module by its `C_GetInfo` description as well as by its
    /// manufacturer, because `yubihsm_pkcs11` (`YubiHSM` 2) reports the same manufacturer,
    /// "Yubico (www.yubico.com)" \[run\], and is not a PIV token (ykcs11 lib.rs F1).
    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "Yubico (www.yubico.com)" && m.description.starts_with("PKCS#11 PIV Library")
    }

    /// ykcs11 generates (and deletes) only after `C_Login(CKU_SO)` with the PIV management key.
    fn manages_as_so(&self) -> bool {
        true
    }

    /// A key is imported by `C_CreateObject`, as the SO, into its PIV slot.
    fn plaintext_import(&self) -> PlaintextVia {
        PlaintextVia::CreateObject(PlaintextKind::PivImport)
    }

    /// A key, whether generated or imported, goes into the PIV slot that its locator's `CKA_ID`
    /// names, and the `CKA_ID` alone decides the slot. A key never goes into slot f9, which holds
    /// the attestation key (`CKA_ID` 19), because that key cannot be restored.
    fn placement(&self, loc: &Locator) -> Result<()> {
        Self::check_create(loc)
    }

    /// A key is never reported as deleted, because ykcs11 keeps it (the advice names `ykman`).
    /// Any other object is removed. The core code asks this before any SO login (review
    /// 2026-11-24 B-2).
    fn deletion(&self, class: Class, loc: &Locator) -> Result<()> {
        if class.is_key() {
            return Err(KmError::Unsupported(Self::keeps_destroyed_keys(loc).into()));
        }
        Ok(())
    }

    /// The repaired pairs are `CKA_DERIVE` of EC and X25519 private keys ([`Self::policy_flag`]).
    fn repairs(&self) -> &'static [(AttributeType, KeyType)] {
        &[(AttributeType::Derive, KeyType::EC), (AttributeType::Derive, KeyType::EC_MONTGOMERY)]
    }

    /// ykcs11 reports `CKA_DERIVE` as false on every private key, from a fixed table for each
    /// slot (`pvtkey_objects`, ykcs11/objects.c) \[src\], although its `C_DeriveKey` derives with
    /// any EC or X25519 key in any slot \[src\]\[run\]. A spec-compliant module reports what the
    /// key does, so the repair reports true.
    fn policy_flag(&self, attr: AttributeType, reported: bool, private_key_type: &dyn Fn() -> Option<KeyType>) -> bool {
        reported
            || (attr == AttributeType::Derive
                && matches!(private_key_type(), Some(KeyType::EC | KeyType::EC_MONTGOMERY)))
    }

    /// The only companion is the device's on-demand attestation certificate of the slot
    /// (`CN=YubiKey PIV Attestation <slot>`), which shares the `CKA_ID` of any key in the slot
    /// \[run\]. ykcs11's placeholder (`CN=YubiKey PIV Slot <slot>`, serial 0, self-issued) is not a
    /// companion, because ykcs11 writes it for every key that it generates
    /// (`token_generate_key`, ykcs11/token.c) \[src\]. So a real key that `cakeys create` made has
    /// the placeholder just as a probe's key does (review 2026-11-23 D-1).
    fn scratch_companion(&self, id: &[u8], cert: &[u8]) -> bool {
        use x509_cert::der::Decode;
        let [id] = id else { return false };
        let Some(slot) = piv_slot(&format!("{id:02x}")) else { return false };
        x509_cert::Certificate::from_der(cert)
            .is_ok_and(|c| c.tbs_certificate().subject().to_string() == format!("CN=YubiKey PIV Attestation {slot:x}"))
    }

    fn attestation(&self) -> Option<AttestationCap> {
        Some(AttestationCap {
            scheme: Scheme::PivAttestation,
            // PIV attests the asymmetric keys that were generated on the device. Secret keys,
            // data objects and certificates have no attestation.
            classes: &[Class::PrivateKey, Class::PublicKey],
            // An imported key has no attestation certificate, and its slot keeps the key.
            imported: false,
            attest,
        })
    }
}

/// Returns the slot's PIV attestation of `ctx.key`, verified against Yubico's roots
/// ([`AttestationCap::attest`]).
fn attest(ctx: &AttestCtx<'_>) -> Result<Attested> {
    // The slot's attestation certificate shares the key's `CKA_ID` and carries the slot in its
    // label. ykcs11 creates it when it lists the slot's objects, without a login (observed on a
    // YubiKey 5, firmware 5.7.4).
    let Some(Attribute::Id(id)) = read_attribute("CKA_ID", ctx.session.get_attributes(ctx.key, &[AttributeType::Id]))?
    else {
        return Err(KmError::Unsupported("the key object exposes no CKA_ID to find its attestation by".into()));
    };
    let spki = ctx.required_spki()?.ok_or_else(|| KmError::Unsupported("PIV attests asymmetric keys only".into()))?;
    let slot = find_attestation_cert(ctx, &id)?;
    let device = find_device_cert(ctx)?;
    let (a, warning) =
        ctx.chain_time.verify(|at| verify_piv_attestation(&slot, &device, &ANCHORS, &INTERMEDIATES, spki, at))?;
    Ok(Attested { scheme: Scheme::PivAttestation, id: a.id, root: a.root, warning, caveat: None })
}

/// Returns the PIV key slot in which ykcs11 places a `CKA_ID` (hex, one byte). 01-04 are the
/// slots 9a/9c/9d/9e, and 05-18 are the retired slots 82-95 (ykcs11's fixed object table).
fn piv_slot(id: &str) -> Option<u8> {
    let [n] = cakeys_core::hex::decode(id)?[..] else { return None };
    match n {
        n @ 1..=4 => Some([0x9a, 0x9c, 0x9d, 0x9e][usize::from(n) - 1]),
        n @ 5..=0x18 => Some(0x82 + (n - 5)),
        _ => None,
    }
}

/// Returns the DER of the slot's attestation certificate. There must be exactly one certificate
/// object under the key's `CKA_ID` whose label carries the slot suffix after
/// `ATTESTATION_LABEL`.
fn find_attestation_cert(ctx: &AttestCtx<'_>, id: &[u8]) -> Result<Vec<u8>> {
    let label_prefix = format!("{ATTESTATION_LABEL} ");
    let found = ctx
        .session
        .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::Id(id.to_vec())])
        .map_err(|e| KmError::Unavailable(format!("C_FindObjects (attestation): {e}").into()))?;
    let mut certs = Vec::new();
    for h in found {
        let label = read_attribute("CKA_LABEL", ctx.session.get_attributes(h, &[AttributeType::Label]))?;
        // The f9 device certificate shares the prefix but not the key's `CKA_ID`. Require a
        // non-empty slot suffix, so that the two can never be confused.
        if let Some(Attribute::Label(l)) = label
            && String::from_utf8_lossy(&l).strip_prefix(&label_prefix).is_some_and(|slot| !slot.is_empty())
        {
            certs.push(certificate_value(ctx, h, "attestation")?);
        }
    }
    match certs.len() {
        1 => Ok(certs.remove(0)),
        0 => Err(KmError::Unsupported(
            format!(
                "no attestation certificate for this key on '{}': Yubico attests only keys generated on \
             device (imported keys have none)",
                ctx.token_name
            )
            .into(),
        )),
        n => Err(KmError::Ambiguous(Reason::check(
            Check::AttestPivUnique,
            format!("{n} attestation certificates share the key's CKA_ID"),
        ))),
    }
}

/// Returns the DER (`CKA_VALUE`) of the certificate object `h`. The errors name it `what`.
fn certificate_value(ctx: &AttestCtx<'_>, h: cryptoki::object::ObjectHandle, what: &str) -> Result<Vec<u8>> {
    match read_attribute(what, ctx.session.get_attributes(h, &[AttributeType::Value]))? {
        Some(Attribute::Value(der)) => Ok(der),
        _ => Err(KmError::Unsupported(format!("the {what} certificate has no readable CKA_VALUE").into())),
    }
}

/// Returns the f9 device attestation certificate (with the bare label and no slot suffix). It
/// holds the key that signed the slot certificate, and a pinned Yubico root signed it.
fn find_device_cert(ctx: &AttestCtx<'_>) -> Result<Vec<u8>> {
    let found = ctx
        .session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(ATTESTATION_LABEL.as_bytes().to_vec()),
        ])
        .map_err(|e| KmError::Unavailable(format!("C_FindObjects (device attestation): {e}").into()))?;
    let mut certs =
        found.into_iter().map(|h| certificate_value(ctx, h, "device attestation")).collect::<Result<Vec<_>>>()?;
    match certs.len() {
        1 => Ok(certs.remove(0)),
        0 => Err(KmError::Unsupported(
            format!(
                "the device attestation certificate (slot f9) is not exposed on '{}'; cakeys \
             verifies slot attestations to a pinned Yubico root through it, never to the slot \
             certificate alone",
                ctx.token_name
            )
            .into(),
        )),
        n => Err(KmError::Ambiguous(Reason::check(
            Check::AttestPivUnique,
            format!("{n} objects carry the f9 device certificate label"),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ykcs11 claims its own module and no other Yubico module. The test uses the `C_GetInfo`
    /// strings of yubico-piv-tool 2.7.3's `libykcs11.so` and yubihsm-shell 2.8.0's
    /// `yubihsm_pkcs11.so` \[run\], which are padded as the fixed fields of `CK_INFO` are.
    #[test]
    fn only_the_piv_module_is_ykcs11() {
        let module = |manufacturer: &str, description: &str| ModuleInfo {
            path: String::new(),
            hash: None,
            // The strings are unpadded, as `token::module_info` passes them (review 2026-11-23
            // B-26).
            description: description.into(),
            manufacturer: manufacturer.into(),
            version: String::new(),
            cryptoki: String::new(),
        };
        assert!(Ykcs11.matches(&module("Yubico (www.yubico.com)", "PKCS#11 PIV Library (SP-800-73)")));
        assert!(!Ykcs11.matches(&module("Yubico (www.yubico.com)", "YubiHSM PKCS#11 Library")));
        assert!(!Ykcs11.matches(&module("SoftHSM", "Implementation of PKCS11")));
    }

    /// ykcs11's fixed `CKA_ID` table: 01-04 are the four PIV slots, and 05-18 are the twenty
    /// retired slots. 19 (f9, the device attestation key) and any other value are not key slots
    /// into which a key can be generated.
    #[test]
    fn cka_ids_map_to_piv_slots() {
        assert_eq!(piv_slot("01"), Some(0x9a));
        assert_eq!(piv_slot("04"), Some(0x9e));
        assert_eq!(piv_slot("05"), Some(0x82));
        assert_eq!(piv_slot("18"), Some(0x95));
        for bad in ["00", "19", "1", "0101", "zz", ""] {
            assert_eq!(piv_slot(bad), None, "{bad}");
        }
        let loc =
            |label: Option<&str>, id: Option<&str>| Locator { label: label.map(Into::into), id: id.map(Into::into) };
        assert!(Ykcs11::check_create(&loc(None, Some("01"))).is_ok());
        assert!(matches!(Ykcs11::check_create(&loc(Some("x"), Some("01"))), Err(KmError::Validation(_))));
        assert!(matches!(Ykcs11::check_create(&loc(None, Some("19"))), Err(KmError::Validation(_))));
        // The same rule is the provider's static placement, which the gate and imports check
        // (review 2026-11-23 B-3): never slot f9 (19), and never by label.
        assert!(Ykcs11.placement(&loc(None, Some("18"))).is_ok());
        for bad in [loc(None, Some("19")), loc(Some("k"), None), loc(Some("k"), Some("05")), loc(None, None)] {
            assert!(matches!(Ykcs11.placement(&bad), Err(KmError::Validation(_))), "{bad:?}");
        }
        assert!(Ykcs11::keeps_destroyed_keys(&loc(None, Some("18"))).contains("ykman piv keys delete 95"));
    }

    /// Returns the DER of a PEM fixture that holds one certificate.
    fn der(pem: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(pem.as_bytes()).unwrap().1
    }

    /// Next to the probe's own certificate in its scratch slot, only the device's attestation of
    /// that slot may be present (the fixture was exported from slot 95 of the `YubiKey` here).
    /// ykcs11's placeholder is never a companion, because every key that ykcs11 generates has
    /// one, including a real key (review 2026-11-23 D-1: the placeholder used to mark a slot as
    /// scratch). A real certificate, another slot's attestation, and an ID that is not a PIV slot
    /// (f9's `CKA_ID`, or a two-byte ID) are not companions either.
    #[test]
    fn only_the_slots_attestation_sits_beside_the_probes_certificate() {
        let placeholder = der(include_str!("../tests/fixtures/placeholder95.pem"));
        let attestation = der(include_str!("../tests/fixtures/attest95.pem"));
        let real = der(include_str!("../tests/fixtures/slot.pem"));
        let slot95 = [0x18];
        assert!(Ykcs11.scratch_companion(&slot95, &attestation));
        assert!(!Ykcs11.scratch_companion(&[0x17], &attestation));
        for other in [&placeholder, &real, &b"not DER".to_vec()] {
            assert!(!Ykcs11.scratch_companion(&slot95, other));
        }
        assert!(!Ykcs11.scratch_companion(&[0x19], &attestation));
        assert!(!Ykcs11.scratch_companion(&[0x00, 0x18], &attestation));
    }
}
