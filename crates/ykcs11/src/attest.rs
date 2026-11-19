//! `YubiKey` PIV attestation (`piv-attestation`, docs/DESIGN.md §3.7), verified on the host.
//!
//! ykcs11 exposes, per key slot, the on-demand attestation certificate the device signed with
//! its attestation key in slot f9 (`"X.509 Certificate for PIV Attestation 9a"`, sharing the
//! slot's `CKA_ID`). Yubico signs each device's f9 certificate with a PIV CA; cakeys verifies
//! the whole chain to a *pinned* root — never to f9 alone, because a holder of the management
//! key can overwrite f9.
//!
//! The commitment hashes the certificate's asserted fields, not its bytes: the device
//! generates the certificate on demand with a random serial and a randomized ECDSA signature,
//! so only the asserted content is stable.

use cakeys_core::id;
use cakeys_core::{KmError, Result};
use x509_cert::certificate::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{DateTime, Decode, Encode, Header, Reader, SliceReader};

/// The label prefix ykcs11 gives every slot's attestation certificate (suffix: the slot, e.g.
/// "9a"); the slot f9 device certificate itself has the bare label without a suffix.
pub(crate) const ATTESTATION_LABEL: &str = "X.509 Certificate for PIV Attestation";

/// Yubico's PIV attestation extension OIDs (the Yubico Attestation OID arc 1.3.6.1.4.1.41482.3).
const FIRMWARE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");
const SERIAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
const PIN_TOUCH_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");
const FORMFACTOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.9");

/// Signature algorithm OIDs the chain verifier dispatches on: PIV devices sign with
/// ECDSA-SHA256 when the attesting key is EC and SHA256-PKCS#1v1.5 when it is RSA, and the
/// pinned Yubico roots are RSA-2048 signing with SHA-256 or SHA-512.
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// A parsed certificate with its DER bytes.
pub(crate) struct Cert {
    der: Vec<u8>,
    parsed: Certificate,
}

impl Cert {
    pub(crate) fn from_der(der: Vec<u8>) -> Result<Cert> {
        let parsed =
            Certificate::from_der(&der).map_err(|e| KmError::Conflict(format!("parsing certificate: {e}").into()))?;
        Ok(Cert { der, parsed })
    }

    /// The bytes the signature was computed over: the `tbsCertificate` sliced from the
    /// certificate's original DER, never re-encoded, so verification is exact.
    /// `self.parsed.tbs_certificate()` is the decoded structure, whose bytes would come from
    /// `to_der()`: those equal the signed bytes only when decoding lost nothing, and der 0.8
    /// accepts an explicitly encoded DEFAULT (a `version [0] v1`) that its encoder then omits.
    fn tbs(&self) -> Result<&[u8]> {
        // Certificate is SEQUENCE { tbsCertificate, signatureAlgorithm, signature }: the first
        // TLV after the outer header, header included.
        let mut reader =
            SliceReader::new(&self.der).map_err(|e| KmError::Conflict(format!("certificate DER: {e}").into()))?;
        Header::decode(&mut reader)
            .and_then(|_| reader.tlv_bytes())
            .map_err(|e| KmError::Conflict(format!("certificate has no tbsCertificate: {e}").into()))
    }

    /// The raw signature value: the BIT STRING content, minus the unused-bits byte.
    fn signature(&self) -> &[u8] {
        self.parsed.signature().raw_bytes()
    }

    /// The subject's canonical SPKI — for the device certificate, the attestation key itself.
    fn spki(&self) -> Result<Vec<u8>> {
        id::spki_canonical(
            &self
                .parsed
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}").into()))?,
        )
    }

    fn subject_der(&self) -> Vec<u8> {
        self.parsed.tbs_certificate().subject().to_der().unwrap_or_default()
    }

    fn issuer_der(&self) -> Vec<u8> {
        self.parsed.tbs_certificate().issuer().to_der().unwrap_or_default()
    }

    /// Whether `at` (seconds since the Unix epoch) falls within the validity period, both ends
    /// included (RFC 5280 §4.1.2.5). Asked under `check` only (ISSUES.md B8).
    fn valid_at(&self, at: u64) -> Result<()> {
        let validity = self.parsed.tbs_certificate().validity();
        let (from, to) =
            (validity.not_before.to_unix_duration().as_secs(), validity.not_after.to_unix_duration().as_secs());
        if (from..=to).contains(&at) {
            return Ok(());
        }
        let show = |s: u64| {
            DateTime::from_unix_duration(std::time::Duration::from_secs(s))
                .map_or_else(|_| s.to_string(), |t| t.to_string())
        };
        Err(KmError::Conflict(
            format!(
                "attestation chain: '{}' is not valid at {} (valid from {} to {}); `check --at <time>` judges the \
                 chain at another time, `--ignore-validity` skips the dates",
                self.parsed.tbs_certificate().subject(),
                show(at),
                show(from),
                show(to)
            )
            .into(),
        ))
    }

    /// The raw `extnValue` of the extension with this OID, empty when absent.
    fn extension(&self, oid: &ObjectIdentifier) -> Vec<u8> {
        self.parsed
            .tbs_certificate()
            .extensions()
            .and_then(|ext| ext.iter().find(|e| &e.extn_id == oid))
            .map(|e| e.extn_value.as_bytes().to_vec())
            .unwrap_or_default()
    }

    /// The name link of the chain: whether this certificate's subject is `cert`'s issuer.
    fn issued(&self, cert: &Cert) -> bool {
        self.subject_der() == cert.issuer_der()
    }
}

/// Parse every PEM `CERTIFICATE` block of `pem` (the embedded anchor and pool files).
pub(crate) fn pem_certs(pem: &str) -> Result<Vec<Cert>> {
    let bad = |e| KmError::Validation(format!("pem certificates: {e}").into());
    Certificate::load_pem_chain(pem.as_bytes())
        .map_err(bad)?
        .into_iter()
        .map(|parsed| Ok(Cert { der: parsed.to_der().map_err(bad)?, parsed }))
        .collect()
}

/// The computed `piv-attestation` commitment: the canonical ID, and the anchor it verified to.
#[derive(Debug)]
pub(crate) struct PivAttested {
    pub id: String,
    pub root: String,
}

/// Verify the slot's attestation certificate and the device certificate that signed it against
/// the pinned anchors (with Yubico's intermediate pool), then commit over what they assert.
///
/// `spki` is the canonical SPKI of the object's material — the same bytes its `rfc7093m4` ID
/// hashes. The attestation must name exactly that key: this is what makes an attested identity
/// *verifiable as key identity* on a token where no attestation exists. A copy of the key on
/// another token cannot attest (Yubico attests only keys generated on the device); the shared
/// `rfc7093m4`, which the attestation's subject is checked against, still links the material.
///
/// `at` (seconds since the Unix epoch), under `check` only: every certificate, from the slot's
/// to the pinned root, must be valid then (ISSUES.md B8).
pub(crate) fn verify_piv_attestation(
    slot: &[u8],
    device: &[u8],
    anchors: &[Cert],
    pool: &[Cert],
    spki: &[u8],
    at: Option<u64>,
) -> Result<PivAttested> {
    let slot = Cert::from_der(slot.to_vec())?;
    let device = Cert::from_der(device.to_vec())?;
    // The device certificate must chain to a pinned root, and the slot certificate must be
    // signed by that same device attestation key.
    let anchor = chain_to_anchor(&device, anchors, pool, at)?;
    if let Some(at) = at {
        slot.valid_at(at)?;
    }
    verify_signed_by(&slot, &device).map_err(|e| {
        KmError::Conflict(
            format!("the slot attestation certificate is not signed by the device attestation key: {e}").into(),
        )
    })?;
    // The attested key is the certificate's subject: it must be the material the identity is
    // for, or the attestation attests something else (13, never a pass).
    let subject = slot.spki()?;
    if spki != subject {
        return Err(KmError::Conflict(
            format!(
                "the attestation names the public key {}, but the object's material is {}",
                id::sri(&subject),
                id::sri(spki)
            )
            .into(),
        ));
    }
    Ok(PivAttested {
        id: id::piv_attestation_id(
            &device.spki()?,
            &subject,
            &slot.extension(&FIRMWARE),
            &slot.extension(&SERIAL),
            &slot.extension(&PIN_TOUCH_POLICY),
            &slot.extension(&FORMFACTOR),
        ),
        root: id::sri(&anchor.spki()?),
    })
}

/// The fuzz target's input (`crate::fuzzing::piv_attestation`): a big-endian two-byte length,
/// the slot certificate's DER, then the device certificate's; verified at a fixed time (2030)
/// against the slot certificate's own key, to Yubico's pinned roots with their pool and to the
/// test fixture's root, which a fuzzed chain can reach. Never in a product: the fixture root is
/// a test key.
#[cfg(any(test, feature = "fuzzing", kani))]
pub(crate) fn fuzz_piv_attestation(bytes: &[u8], anchors: &[Cert], pool: &[Cert]) -> Result<()> {
    static FIXTURE_ROOT: std::sync::LazyLock<Vec<Cert>> = std::sync::LazyLock::new(|| {
        pem_certs(include_str!("../tests/fixtures/root.pem")).expect("the fixture root parses")
    });
    let short = || KmError::Validation("shorter than its length prefix".into());
    let [hi, lo, rest @ ..] = bytes else { return Err(short()) };
    let (slot, device) = rest.split_at_checked(usize::from(u16::from_be_bytes([*hi, *lo]))).ok_or_else(short)?;
    let spki = Cert::from_der(slot.to_vec()).and_then(|c| c.spki()).unwrap_or_default();
    let at = Some(1_893_456_000);
    verify_piv_attestation(slot, device, anchors, pool, &spki, at)
        .or_else(|_| verify_piv_attestation(slot, device, &FIXTURE_ROOT, &[], &spki, at))
        .map(drop)
}

/// The pooled Yubico intermediates a PIV chain may pass through: the PIV attestation CAs and
/// the generic "Attestation Intermediate" CAs above them. Yubico's published pool also holds
/// the FIDO, `OpenPGP`, SD and `YubiHSM` attestation CAs under the same "Yubico Attestation Root
/// 1"; a device certificate issued by one of those is not PIV evidence, so they are left out.
pub(crate) fn piv_pool(pool: Vec<Cert>) -> Vec<Cert> {
    pool.into_iter()
        .filter(|c| {
            let subject = c.parsed.tbs_certificate().subject().to_string();
            ["CN=Yubico PIV Attestation", "CN=Yubico Attestation Intermediate"].iter().any(|p| subject.starts_with(p))
        })
        .collect()
}

/// `basicConstraints` (2.5.29.19).
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

impl Cert {
    /// Whether this certificate may issue a chain with `below` CA certificates under it (the
    /// device f9 certificate counts as one): `basicConstraints` CA, within its `pathLen`.
    fn may_issue(&self, below: u8) -> Result<()> {
        let subject = self.parsed.tbs_certificate().subject().to_string();
        let bc = self
            .parsed
            .tbs_certificate()
            .extensions()
            .and_then(|ext| ext.iter().find(|e| e.extn_id == BASIC_CONSTRAINTS))
            .map(|e| x509_cert::ext::pkix::BasicConstraints::from_der(e.extn_value.as_bytes()))
            .transpose()
            .map_err(|e| KmError::Conflict(format!("attestation chain: '{subject}' basicConstraints: {e}").into()))?;
        match bc {
            Some(bc) if bc.ca && bc.path_len_constraint.is_none_or(|n| n >= below) => Ok(()),
            Some(bc) if bc.ca => Err(KmError::Conflict(
                format!(
                    "attestation chain: '{subject}' allows {} CA certificate(s) below it, the chain has {below}",
                    bc.path_len_constraint.unwrap_or_default()
                )
                .into(),
            )),
            _ => Err(KmError::Conflict(format!("attestation chain: '{subject}' is not a CA").into())),
        }
    }
}

/// Walk `cert`'s issuer chain through Yubico's pooled intermediates until a pinned anchor is
/// reached, verifying every signature and every issuer's `basicConstraints` on the host; the
/// anchor is what the lock pins. Real chains are one link (f9 ← classic root) or three
/// (f9 ← PIV intermediate ← attestation intermediate ← root, firmware 5.7.4+). With `at`,
/// every certificate of the walk must be valid then, `cert` and the anchor included.
fn chain_to_anchor<'a>(cert: &Cert, anchors: &'a [Cert], pool: &[Cert], at: Option<u64>) -> Result<&'a Cert> {
    let bad = |what: String| KmError::Conflict(format!("attestation chain: {what}").into());
    let valid = |c: &Cert| at.map_or(Ok(()), |at| c.valid_at(at));
    valid(cert)?;
    let mut current = cert;
    // CA certificates below the next issuer, `cert` (the device certificate) included.
    for below in 1..=3 {
        if let Some(issuer) = pool.iter().find(|c| c.issued(current)) {
            issuer.may_issue(below)?;
            verify_signed_by(current, issuer)?;
            valid(issuer)?;
            current = issuer;
            continue;
        }
        if let Some(anchor) = anchors.iter().find(|a| a.issued(current)) {
            anchor.may_issue(below)?;
            verify_signed_by(current, anchor)?;
            valid(anchor)?;
            return Ok(anchor);
        }
        return Err(bad(format!(
            "'{}' is signed by no pinned root and no pooled PIV intermediate",
            current.parsed.tbs_certificate().subject()
        )));
    }
    Err(bad("longer than 3 links; not a PIV attestation chain".into()))
}

/// Verify that `cert`'s signature (over its original `tbsCertificate` bytes) was made by
/// `signer`'s key, with the signature algorithm the certificate names: ECDSA (DER) with the
/// hash the algorithm names, whatever the curve, or RSA PKCS#1 v1.5 (`cakeys_core::sig`).
fn verify_signed_by(cert: &Cert, signer: &Cert) -> Result<()> {
    use cakeys_core::sig::{self, Encoding, HashAlg};
    let spki = signer.spki()?;
    let (tbs, s) = (cert.tbs()?, cert.signature());
    let ecdsa = |hash| sig::ecdsa(&spki, tbs, s, Encoding::Der, Some(hash));
    let verdict = match cert.parsed.signature_algorithm().oid {
        ECDSA_SHA256 => ecdsa(HashAlg::Sha256),
        ECDSA_SHA384 => ecdsa(HashAlg::Sha384),
        ECDSA_SHA512 => ecdsa(HashAlg::Sha512),
        RSA_SHA256 => sig::rsa_pkcs1v15::<sha2::Sha256>(&spki, tbs, s),
        RSA_SHA384 => sig::rsa_pkcs1v15::<sha2::Sha384>(&spki, tbs, s),
        RSA_SHA512 => sig::rsa_pkcs1v15::<sha2::Sha512>(&spki, tbs, s),
        oid => return Err(KmError::Unsupported(format!("signature algorithm {oid}").into())),
    };
    let sri = id::sri(&spki);
    match verdict {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => {
            Err(KmError::Conflict(format!("certificate signature does not verify against {sri}: {e}").into()))
        }
        None => Err(KmError::Conflict(
            format!("the signer {sri} holds no key for the certificate's signature algorithm").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    /// A fixture public key's canonical SPKI, from its PEM.
    fn spki_of(name: &str) -> Vec<u8> {
        id::spki_canonical(&der_of(name)).unwrap()
    }

    /// A fixture certificate's DER, from its PEM.
    fn der_of(name: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(&fixture(name)).unwrap().1
    }

    /// The embedded Yubico anchors and intermediate pool parse, and every published
    /// intermediate chains to an anchor — the real chain walk, on Yubico's own certificates.
    #[test]
    fn the_yubico_roots_are_pinned() {
        let mut anchors = pem_certs(include_str!("../roots/yubico-piv-ca-1.pem")).unwrap();
        anchors.extend(pem_certs(include_str!("../roots/yubico-ca-1.pem")).unwrap());
        assert_eq!(anchors.len(), 2);
        let pool = pem_certs(include_str!("../roots/yubico-intermediate.pem")).unwrap();
        assert_eq!(pool.len(), 15, "Yubico published 15 intermediates (2025-02-03)");
        // Pinned by digest: updating the roots directory is a deliberate diff. The classic PIV
        // root (RSA-2048, "Yubico PIV Root CA Serial 263751") signs the f9 certificates of
        // firmware before 5.7.4; "Yubico Attestation Root 1" terminates the chains after.
        assert_eq!(
            anchors[0].spki().map(|s| id::sri(&s)).unwrap(),
            "sha256-Sxhbd4PXkvkCzZYM0clBeXfYjTB3sWvJ69zvcxPy4p4="
        );
        assert_eq!(
            anchors[1].spki().map(|s| id::sri(&s)).unwrap(),
            "sha256-H0PiuI6WSl0DuAWLuqztaBmcklYgDxuyjqqy+CoeBvI="
        );
        // The whole published pool chains to the pinned roots.
        for c in &pool {
            chain_to_anchor(c, &anchors, &pool, None).unwrap();
        }
        // A PIV chain passes only through the PIV CAs and the generic intermediates above them;
        // the other products' CAs (FIDO, OpenPGP, SD, YubiHSM) issue no PIV device certificate.
        let piv: Vec<String> = piv_pool(pem_certs(include_str!("../roots/yubico-intermediate.pem")).unwrap())
            .iter()
            .map(|c| c.parsed.tbs_certificate().subject().to_string())
            .collect();
        assert_eq!(
            piv,
            [
                "CN=Yubico Attestation Intermediate A 1",
                "CN=Yubico Attestation Intermediate B 1",
                "CN=Yubico PIV Attestation A 1",
                "CN=Yubico PIV Attestation B 1",
                "CN=Yubico PIV Attestation B2 1",
            ]
        );
    }

    /// Every issuer in the walk must be a CA within its pathLen: Yubico's FIDO CAs carry
    /// `pathlen:0`, so even under the pinned root they cannot issue a device certificate.
    #[test]
    fn issuers_must_be_cas_within_their_path_length() {
        let pool = pem_certs(include_str!("../roots/yubico-intermediate.pem")).unwrap();
        let named = |cn: &str| pool.iter().find(|c| c.parsed.tbs_certificate().subject().to_string() == cn).unwrap();
        named("CN=Yubico FIDO Attestation A 1").may_issue(0).unwrap();
        let err = named("CN=Yubico FIDO Attestation A 1").may_issue(1).unwrap_err();
        assert!(err.to_string().contains("allows 0 CA certificate(s) below it"), "{err}");
        named("CN=Yubico PIV Attestation A 1").may_issue(1).unwrap();
        assert!(named("CN=Yubico PIV Attestation A 1").may_issue(2).is_err());
        // The fixture slot certificate is an end entity (CA:FALSE).
        let slot = Cert::from_der(der_of("slot.pem")).unwrap();
        assert!(slot.may_issue(0).unwrap_err().to_string().contains("is not a CA"));
    }

    /// The fixture chain (root → device f9 → slot attestation) verifies to its anchor, and the
    /// commitment is the pinned digest of what it asserts. Material the attestation does not
    /// name is a conflict — the cross-check that keeps an attestation an identity.
    #[test]
    fn fixture_chain_verifies_and_pins() {
        let anchors = pem_certs(&String::from_utf8(fixture("root.pem")).unwrap()).unwrap();
        let attested = verify_piv_attestation(
            &der_of("slot.pem"),
            &der_of("f9.pem"),
            &anchors,
            &[],
            &spki_of("slotpub.pem"),
            None,
        )
        .unwrap();
        assert_eq!(attested.id, "sha256-gKyFL3YX9/6UtxWv5JbcU4a5Rj5Ev9IVC0SV25gIQoc=");
        assert_eq!(attested.root, id::sri(&anchors[0].spki().unwrap()));
        // Other material: the attestation names the slot's key, not another key's.
        let err = verify_piv_attestation(
            &der_of("slot.pem"),
            &der_of("f9.pem"),
            &anchors,
            &[],
            &spki_of("slot2pub.pem"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("the attestation names"), "{err}");
        // No pinned anchor: f9 overwritten with a self-made key, or another vendor's device.
        let err =
            verify_piv_attestation(&der_of("slot.pem"), &der_of("f9.pem"), &[], &[], &spki_of("slotpub.pem"), None)
                .unwrap_err();
        assert!(err.to_string().contains("signed by no pinned root"), "{err}");
    }

    /// The fuzz target's input format reaches the whole chain: the fixture chain, length-prefixed
    /// as `nix/fuzz.nix` seeds it, verifies; a short or cut input is refused, never a panic.
    #[test]
    fn the_fuzz_entry_point_reads_the_fixture_chain() {
        let (slot, device) = (der_of("slot.pem"), der_of("f9.pem"));
        let input = [&u16::try_from(slot.len()).unwrap().to_be_bytes()[..], &slot, &device].concat();
        fuzz_piv_attestation(&input, &[], &[]).unwrap();
        assert!(fuzz_piv_attestation(&input[..1], &[], &[]).is_err());
        assert!(fuzz_piv_attestation(&input[..40], &[], &[]).is_err());
    }

    /// Under `check`, every certificate of the chain is held to its validity period (ISSUES.md
    /// B8): the fixture chain is valid from 2026-11-12 to 2036-11-09, so it verifies in 2030
    /// and is a conflict before and after, naming the time and the period; without a time
    /// (`--ignore-validity`) the dates are not read. Every other verb warns: out of its dates the
    /// chain verifies, the dated failure its warning (`ChainTime::Warn`).
    #[test]
    fn check_holds_the_chain_to_its_dates() {
        let anchors = pem_certs(&String::from_utf8(fixture("root.pem")).unwrap()).unwrap();
        let at = |s: &str| s.parse::<DateTime>().unwrap().unix_duration().as_secs();
        let verify = |t| {
            verify_piv_attestation(&der_of("slot.pem"), &der_of("f9.pem"), &anchors, &[], &spki_of("slotpub.pem"), t)
        };
        verify(Some(at("2030-01-01T00:00:00Z"))).unwrap();
        for t in ["2020-01-01T00:00:00Z", "2040-01-01T00:00:00Z"] {
            let err = verify(Some(at(t))).unwrap_err();
            assert!(
                matches!(err, KmError::Conflict(_)) && err.to_string().contains(&format!("is not valid at {t}")),
                "{err}"
            );
            assert!(err.to_string().contains("--ignore-validity"), "{err}");
        }
        verify(None).unwrap();
        let late = at("2040-01-01T00:00:00Z");
        let (_, warning) = cakeys_pkcs11::ChainTime::Warn(late).verify(verify).unwrap();
        assert!(warning.as_deref().is_some_and(|w| w.contains("is not valid at 2040-01-01T00:00:00Z")), "{warning:?}");
        assert!(cakeys_pkcs11::ChainTime::At(late).verify(verify).is_err());
        let on_time = cakeys_pkcs11::ChainTime::Warn(at("2030-01-01T00:00:00Z")).verify(verify).unwrap();
        assert_eq!(on_time.1, None);
    }
}
