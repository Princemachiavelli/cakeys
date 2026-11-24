//! Yubico ykcs11 (`YubiKey` PIV). Two quirks are handled generically elsewhere: its
//! `CKA_PUBLIC_KEY_INFO` reports length 0 and then `CKR_ARGUMENTS_BAD` (tolerated by the
//! token layer for every module), and its fixed per-slot `CKA_LABEL`/`CKA_ID` set.
//!
//! What lives here is the `piv-attestation` commitment (docs/DESIGN.md §3.7): the provider
//! finds the module-exposed attestation certificates, the private `attest` module checks what
//! the chain asserts and computes the canonical digest, and the chain walk is
//! `cakeys_core::chain`'s — verified against both a fixture chain and Yubico's own published
//! roots and intermediates.

mod attest;

use crate::attest::{ATTESTATION_LABEL, piv_pool, verify_piv_attestation};
use cakeys_core::chain::{Cert, pem_certs};
use cakeys_core::config::Locator;
use cakeys_core::id::Scheme;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Msg, Result};
use cakeys_pkcs11::Token;
use cakeys_pkcs11::provider::{AttestCtx, AttestationCap, Attested, Create, Destroy, PlaintextKind, Provider, Report};
use cakeys_pkcs11::token::ModuleInfo;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use std::sync::LazyLock;

/// The ykcs11 provider (see the crate's documentation).
pub struct Ykcs11;

/// Anchors: Yubico's pinned PIV roots. The intermediate pool (the untrusted store) is only
/// needed when a chain uses it, so both are parsed lazily, once per process.
static ANCHORS: LazyLock<Vec<Cert>> = LazyLock::new(|| {
    let mut a = pem_certs(include_str!("../roots/yubico-piv-ca-1.pem")).expect("embedded Yubico PIV root parses");
    a.extend(pem_certs(include_str!("../roots/yubico-ca-1.pem")).expect("embedded Yubico attestation root parses"));
    a
});

/// The pooled intermediates a PIV chain may use: Yubico's published pool narrowed to the PIV
/// CAs and the generic intermediates above them (`attest::piv_pool`).
static INTERMEDIATES: LazyLock<Vec<Cert>> = LazyLock::new(|| {
    piv_pool(pem_certs(include_str!("../roots/yubico-intermediate.pem")).expect("embedded Yubico intermediates parse"))
});

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/piv_chain.rs`): the PIV attestation
/// chain on arbitrary certificates, read or refused with an error, never a panic.
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    /// `bytes` as a slot attestation certificate and the device certificate that signed it: a
    /// big-endian two-byte length, the slot's DER, then the device's; verified as `check`
    /// verifies a chain, dates included, to Yubico's pinned roots and to the test fixture's.
    ///
    /// # Errors
    ///
    /// Whatever the chain's verification refuses.
    pub fn piv_attestation(bytes: &[u8]) -> cakeys_core::Result<()> {
        super::attest::fuzz_piv_attestation(bytes, &super::ANCHORS, &super::INTERMEDIATES)
    }
}

impl Ykcs11 {
    /// ykcs11 generates into the slot the template's `CKA_ID` names and gives each slot fixed
    /// labels, so a key to create is located by `CKA_ID` alone.
    ///
    /// # Errors
    ///
    /// `Validation` for a locator with a label, or whose `CKA_ID` names no PIV slot.
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

    /// ykcs11's `C_DestroyObject` writes an empty certificate to the slot and hides the slot's
    /// objects for the rest of the session; the key stays and is listed again by the next one
    /// (verified on a `YubiKey` 5, firmware 5.7.4, ykcs11 2.7.3).
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

    /// Yubico's PIV module by its `C_GetInfo` description as well: `yubihsm_pkcs11` (`YubiHSM` 2)
    /// reports the same manufacturer, "Yubico (www.yubico.com)" \[run\], and is no PIV token
    /// (ykcs11 lib.rs F1).
    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer.starts_with("Yubico") && m.description.starts_with("PKCS#11 PIV Library")
    }

    /// ykcs11 generates (and deletes) only after `C_Login(CKU_SO)` with the PIV management key.
    fn manages_as_so(&self) -> bool {
        true
    }

    /// A key comes in by `C_CreateObject` as SO into its PIV slot.
    fn plaintext_import(&self) -> PlaintextKind {
        PlaintextKind::PivImport
    }

    /// A key, generated or imported, goes into the PIV slot its locator's `CKA_ID` names, by
    /// that alone: never f9's attestation key (`CKA_ID` 19), which cannot be restored.
    fn placement(&self, loc: &Locator) -> Result<()> {
        Self::check_create(loc)
    }

    /// A key goes where its locator says (by `CKA_ID` alone, a PIV slot), as SO.
    fn create(&self, tok: &Token, req: &Create<'_>) -> Result<Option<cakeys_pkcs11::token::CreateNote>> {
        self.placement(req.locator)?;
        tok.create_declared(req)
    }

    /// A key is never claimed deleted (ykcs11 keeps it; the advice names `ykman`); anything else is, as SO.
    fn destroy(&self, tok: &Token, req: &Destroy<'_>) -> Result<usize> {
        if req.object.class.is_key() {
            let advice = Self::keeps_destroyed_keys(req.locator);
            return Err(KmError::Unsupported(
                format!("deleting {} on '{}': {advice}", req.object.class, tok.name).into(),
            ));
        }
        tok.destroy_plain(req)
    }

    /// ykcs11 reports `CKA_DERIVE` false on every private key, from a fixed per-slot table
    /// (`pvtkey_objects`, ykcs11/objects.c) \[src\], while its `C_DeriveKey` derives with any EC
    /// or X25519 key in any slot \[src\]\[run\]. A spec-compliant module reports what the key does.
    fn repair<'a>(&self, report: Report<'a>) -> Report<'a> {
        match report {
            Report::PolicyFlag { attr, reported, private_key_type } => Report::PolicyFlag {
                attr,
                reported: reported
                    || (attr == AttributeType::Derive
                        && matches!(private_key_type(), Some(KeyType::EC | KeyType::EC_MONTGOMERY))),
                private_key_type,
            },
            other => other,
        }
    }

    /// The device's on-demand attestation certificate of the slot (`CN=YubiKey PIV Attestation
    /// <slot>`), which shares the `CKA_ID` of any key there \[run\]. ykcs11's placeholder
    /// (`CN=YubiKey PIV Slot <slot>`, serial 0, self-issued) is no companion: ykcs11 writes it
    /// for every key it generates (`token_generate_key`, ykcs11/token.c) \[src\], so a real key
    /// `cakeys create` made carries it as much as a probe's (review 2026-11-23 D-1).
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
            // PIV attests the asymmetric keys generated on the device; secret keys, data
            // objects and certificates have none.
            classes: &[Class::PrivateKey, Class::PublicKey],
            // An imported key has no attestation certificate, and its slot keeps it.
            imported: false,
        })
    }

    fn attest(&self, ctx: &AttestCtx<'_>) -> Result<Attested> {
        // The slot's attestation certificate shares the key's CKA_ID and carries the slot in
        // its label; ykcs11 mints it when it lists the slot's objects, needing no login (seen
        // on a YubiKey 5, firmware 5.7.4).
        let Some(Attribute::Id(id)) =
            read_attribute("CKA_ID", ctx.session.get_attributes(ctx.key, &[AttributeType::Id]))?
        else {
            return Err(KmError::Unsupported("the key object exposes no CKA_ID to find its attestation by".into()));
        };
        let spki =
            ctx.required_spki()?.ok_or_else(|| KmError::Unsupported("PIV attests asymmetric keys only".into()))?;
        let slot = find_attestation_cert(ctx, &id)?;
        let device = find_device_cert(ctx)?;
        let (a, warning) =
            ctx.chain_time.verify(|at| verify_piv_attestation(&slot, &device, &ANCHORS, &INTERMEDIATES, spki, at))?;
        Ok(Attested { scheme: Scheme::PivAttestation, id: a.id, root: a.root, warning, caveat: None })
    }
}

/// The PIV key slot ykcs11 places a `CKA_ID` in (hex, one byte): 01-04 are 9a/9c/9d/9e, 05-18 the
/// retired slots 82-95 (ykcs11's fixed object table).
fn piv_slot(id: &str) -> Option<u8> {
    let [n] = cakeys_core::hex::decode(id)?[..] else { return None };
    match n {
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
        .map_err(|e| KmError::Unavailable(format!("C_FindObjects (attestation): {e}").into()))?;
    let mut certs = Vec::new();
    for h in found {
        let label = read_attribute("CKA_LABEL", ctx.session.get_attributes(h, &[AttributeType::Label]))?;
        // The f9 device certificate shares the prefix but not the key's CKA_ID; require a
        // non-empty slot suffix so the two can never be confused.
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
        n => Err(KmError::Ambiguous(format!("{n} attestation certificates share the key's CKA_ID").into())),
    }
}

/// The DER (`CKA_VALUE`) of the certificate object `h`, named `what` in its errors.
fn certificate_value(ctx: &AttestCtx<'_>, h: cryptoki::object::ObjectHandle, what: &str) -> Result<Vec<u8>> {
    match read_attribute(what, ctx.session.get_attributes(h, &[AttributeType::Value]))? {
        Some(Attribute::Value(der)) => Ok(der),
        _ => Err(KmError::Unsupported(format!("the {what} certificate has no readable CKA_VALUE").into())),
    }
}

/// One attribute read: the attribute, `None` when the module has none to show (absent or
/// sensitive, which cryptoki leaves out of the result), and any other failure `Unavailable` with
/// the module's return value. A failed `CKA_LABEL` read is never taken for "no label", which would
/// pass over the attestation certificate and blame the key's origin (lib.rs F2).
///
/// # Errors
///
/// `Unavailable` when `C_GetAttributeValue` fails.
fn read_attribute(
    what: &str,
    read: std::result::Result<Vec<Attribute>, cryptoki::error::Error>,
) -> Result<Option<Attribute>> {
    match read {
        Ok(v) => Ok(v.into_iter().next()),
        Err(e) => Err(KmError::Unavailable(
            Msg::from(format!("C_GetAttributeValue ({what}): {e}")).with_rv(cakeys_pkcs11::token::rv_of(&e)),
        )),
    }
}

/// The f9 device attestation certificate (bare label, no slot suffix): the key that signed the
/// slot certificate, itself signed by a pinned Yubico root.
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
        n => Err(KmError::Ambiguous(format!("{n} objects carry the f9 device certificate label").into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ykcs11 claims its own module and no other Yubico one: the `C_GetInfo` strings
    /// yubico-piv-tool 2.7.3's `libykcs11.so` and yubihsm-shell 2.8.0's `yubihsm_pkcs11.so` carry
    /// \[run\], padded as `CK_INFO`'s fixed fields are.
    #[test]
    fn only_the_piv_module_is_ykcs11() {
        let module = |manufacturer: &str, description: &str| ModuleInfo {
            path: String::new(),
            hash: None,
            description: format!("{description:<32}"),
            manufacturer: format!("{manufacturer:<32}"),
            version: String::new(),
            cryptoki: String::new(),
        };
        assert!(Ykcs11.matches(&module("Yubico (www.yubico.com)", "PKCS#11 PIV Library (SP-800-73)")));
        assert!(!Ykcs11.matches(&module("Yubico (www.yubico.com)", "YubiHSM PKCS#11 Library")));
        assert!(!Ykcs11.matches(&module("SoftHSM", "Implementation of PKCS11")));
    }

    /// A failed attribute read is unavailable (16) with the module's return value, never "no
    /// label", which would pass over the attestation certificate and report the key as imported
    /// (lib.rs F2); an attribute the module has none of is `None`.
    #[test]
    fn a_failed_attribute_read_is_unavailable() {
        use cryptoki::context::Function;
        use cryptoki::error::{Error as CkError, RvError};
        let failed = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::GetAttributeValue);
        let e = read_attribute("CKA_LABEL", Err(failed)).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("CKA_LABEL")), "{e}");
        assert_eq!(e.rv(), Some(0x8000_0001));
        assert_eq!(read_attribute("CKA_LABEL", Ok(vec![])).unwrap(), None);
        let label = Attribute::Label(b"X.509 Certificate for PIV Attestation 9a".to_vec());
        assert_eq!(read_attribute("CKA_LABEL", Ok(vec![label.clone()])).unwrap(), Some(label));
    }

    /// ykcs11's fixed `CKA_ID` table: 01-04 the four PIV slots, 05-18 the twenty retired slots;
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
        let loc =
            |label: Option<&str>, id: Option<&str>| Locator { label: label.map(Into::into), id: id.map(Into::into) };
        assert!(Ykcs11::check_create(&loc(None, Some("01"))).is_ok());
        assert!(matches!(Ykcs11::check_create(&loc(Some("x"), Some("01"))), Err(KmError::Validation(_))));
        assert!(matches!(Ykcs11::check_create(&loc(None, Some("19"))), Err(KmError::Validation(_))));
        // The same rule is the provider's static placement, which the gate and imports ask
        // (review 2026-11-23 B-3): never f9 (19), never by label.
        assert!(Ykcs11.placement(&loc(None, Some("18"))).is_ok());
        for bad in [loc(None, Some("19")), loc(Some("k"), None), loc(Some("k"), Some("05")), loc(None, None)] {
            assert!(matches!(Ykcs11.placement(&bad), Err(KmError::Validation(_))), "{bad:?}");
        }
        assert!(Ykcs11::keeps_destroyed_keys(&loc(None, Some("18"))).contains("ykman piv keys delete 95"));
    }

    /// The DER of a one-certificate PEM fixture.
    fn der(pem: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(pem.as_bytes()).unwrap().1
    }

    /// Beside the probe's own certificate in its scratch slot, only the device's attestation of
    /// that slot may sit (exported from slot 95 of the `YubiKey` here). ykcs11's placeholder is
    /// never one: every key ykcs11 generates has it, a real key's too (review 2026-11-23 D-1:
    /// it used to mark a slot as scratch). Nor is a real certificate, another slot's
    /// attestation, or no PIV slot at all (f9's `CKA_ID`, a two-byte ID).
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
