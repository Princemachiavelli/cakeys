//! X.509 attestation chains, verified on the host: a certificate walked through a pool of
//! intermediates to one of a set of pinned anchors, every signature checked over the bytes its
//! issuer signed. The `YubiKey` PIV attestation (ykcs11) and the TPM's EK certificate
//! (tpm2-pkcs11) both build on it; what a chain must assert is theirs.

use crate::{KmError, Result, id};
use x509_cert::certificate::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{DateTime, Decode, Encode, Header, Reader, SliceReader, Tagged};

/// Signature algorithm OIDs the chain verifier dispatches on: ECDSA and RSA PKCS#1 v1.5 with
/// SHA-2. PIV devices sign with ECDSA-SHA256 when the attesting key is EC and
/// SHA256-PKCS#1v1.5 when it is RSA, and the pinned Yubico roots are RSA-2048 signing with
/// SHA-256 or SHA-512.
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// `basicConstraints` (2.5.29.19).
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `keyUsage` (2.5.29.15).
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `extendedKeyUsage` (2.5.29.37).
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// `tcg-kp-EKCertificate` (2.23.133.8.1): the purpose TCG's EK credential profile gives an
/// Endorsement Key certificate ([`Cert::serves`]).
pub const TCG_KP_EK_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.1");

/// The extensions a certificate of a walk may mark critical: those the walk or its callers read
/// (basicConstraints, keyUsage, extendedKeyUsage), and two that restrict nothing an attestation
/// relies on but that issuers mark critical — subjectAltName (a TCG EK certificate with an empty
/// subject) and certificatePolicies (Yubico's intermediates). Any other critical extension
/// (nameConstraints, policyConstraints, a vendor's) may constrain the certificate in a way the
/// walk does not enforce, so RFC 5280 §4.2 refuses it (review 2026-11-23 A-3).
const UNDERSTOOD: [ObjectIdentifier; 5] = [
    BASIC_CONSTRAINTS,
    KEY_USAGE,
    EXTENDED_KEY_USAGE,
    ObjectIdentifier::new_unwrap("2.5.29.17"),
    ObjectIdentifier::new_unwrap("2.5.29.32"),
];

/// A parsed certificate with its DER bytes.
#[derive(Debug)]
pub struct Cert {
    der: Vec<u8>,
    parsed: Certificate,
}

impl Cert {
    /// Parse one DER certificate, keeping `der` as its bytes.
    ///
    /// # Errors
    ///
    /// `Conflict` when `der` is no certificate.
    pub fn from_der(der: Vec<u8>) -> Result<Cert> {
        let parsed =
            Certificate::from_der(&der).map_err(|e| KmError::Conflict(format!("parsing certificate: {e}").into()))?;
        Ok(Cert { der, parsed })
    }

    /// The certificate's DER, as it was read.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The decoded certificate.
    #[must_use]
    pub fn parsed(&self) -> &Certificate {
        &self.parsed
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

    /// The subject's canonical SPKI ([`id::spki_canonical`]): for a PIV device certificate, the
    /// attestation key itself.
    ///
    /// # Errors
    ///
    /// `Conflict` when the SPKI does not encode; [`id::spki_canonical`]'s `Unsupported` for a
    /// key cakeys does not hash.
    pub fn spki(&self) -> Result<Vec<u8>> {
        id::spki_canonical(
            &self
                .parsed
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}").into()))?,
        )
    }

    /// Whether `at` (seconds since the Unix epoch) falls within the validity period, both ends
    /// included (RFC 5280 §4.1.2.5). Asked under `check` only (ISSUES.md B8).
    ///
    /// # Errors
    ///
    /// `Conflict` naming the time and the period when `at` is outside it.
    pub fn valid_at(&self, at: u64) -> Result<()> {
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
    #[must_use]
    pub fn extension(&self, oid: &ObjectIdentifier) -> Vec<u8> {
        self.parsed
            .tbs_certificate()
            .extensions()
            .and_then(|ext| ext.iter().find(|e| &e.extn_id == oid))
            .map(|e| e.extn_value.as_bytes().to_vec())
            .unwrap_or_default()
    }

    /// The name link of the chain: whether this certificate's subject is `cert`'s issuer,
    /// compared as decoded Names (nothing is re-encoded, so nothing can fail to encode).
    #[must_use]
    pub fn issued(&self, cert: &Cert) -> bool {
        self.parsed.tbs_certificate().subject() == cert.parsed.tbs_certificate().issuer()
    }

    /// Whether the certificate may serve `purpose`: it names no purposes (no
    /// `extendedKeyUsage`), or names that one (RFC 5280 §4.2.1.12). An EK certificate is held to
    /// [`TCG_KP_EK_CERTIFICATE`] (review 2026-11-23 A-3).
    ///
    /// # Errors
    ///
    /// `Conflict` when its `extendedKeyUsage` does not decode.
    pub fn serves(&self, purpose: &ObjectIdentifier) -> Result<bool> {
        let eku: Option<x509_cert::ext::pkix::ExtendedKeyUsage> =
            self.decoded(&EXTENDED_KEY_USAGE, "extendedKeyUsage")?;
        Ok(eku.is_none_or(|eku| eku.0.contains(purpose)))
    }

    /// The extension with this OID, decoded as `T`; `None` when absent.
    ///
    /// # Errors
    ///
    /// `Conflict` naming the certificate and `what` when the extension does not decode.
    fn decoded<T>(&self, oid: &ObjectIdentifier, what: &str) -> Result<Option<T>>
    where
        T: for<'a> Decode<'a, Error = x509_cert::der::Error>,
    {
        self.parsed
            .tbs_certificate()
            .extensions()
            .and_then(|ext| ext.iter().find(|e| &e.extn_id == oid))
            .map(|e| T::from_der(e.extn_value.as_bytes()))
            .transpose()
            .map_err(|e| {
                KmError::Conflict(
                    format!("attestation chain: '{}' {what}: {e}", self.parsed.tbs_certificate().subject()).into(),
                )
            })
    }

    /// Whether this certificate may issue a chain with `below` CA certificates under it (the
    /// certificate the walk started from counts as one): `basicConstraints` CA, within its
    /// `pathLen`, and a `keyUsage`, when it has one, with `keyCertSign` (RFC 5280 §4.2.1.3; review
    /// 2026-11-23 A-3).
    fn may_issue(&self, below: u16) -> Result<()> {
        let subject = self.parsed.tbs_certificate().subject().to_string();
        let bc: Option<x509_cert::ext::pkix::BasicConstraints> =
            self.decoded(&BASIC_CONSTRAINTS, "basicConstraints")?;
        match bc {
            Some(bc) if bc.ca && bc.path_len_constraint.is_none_or(|n| u16::from(n) >= below) => {}
            Some(bc) if bc.ca => {
                return Err(KmError::Conflict(
                    format!(
                        "attestation chain: '{subject}' allows {} CA certificate(s) below it, the chain has {below}",
                        bc.path_len_constraint.unwrap_or_default()
                    )
                    .into(),
                ));
            }
            _ => return Err(KmError::Conflict(format!("attestation chain: '{subject}' is not a CA").into())),
        }
        let ku: Option<x509_cert::ext::pkix::KeyUsage> = self.decoded(&KEY_USAGE, "keyUsage")?;
        if ku.is_some_and(|ku| !ku.key_cert_sign()) {
            return Err(KmError::Conflict(
                format!("attestation chain: '{subject}' may not sign certificates: its keyUsage lacks keyCertSign")
                    .into(),
            ));
        }
        Ok(())
    }

    /// RFC 5280 §4.2: a certificate with a critical extension outside [`UNDERSTOOD`] is refused,
    /// since it may constrain the certificate in a way the walk does not enforce.
    fn no_unknown_critical(&self) -> Result<()> {
        let unknown = self
            .parsed
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.critical && !UNDERSTOOD.contains(&e.extn_id));
        match unknown {
            None => Ok(()),
            Some(e) => Err(KmError::Conflict(
                format!(
                    "attestation chain: '{}' has the critical extension {}, which cakeys does not process",
                    self.parsed.tbs_certificate().subject(),
                    e.extn_id
                )
                .into(),
            )),
        }
    }
}

/// Parse every PEM `CERTIFICATE` block of `pem` (anchor and pool files), keeping each block's
/// decoded bytes as the certificate's DER: a re-encoding could differ from the bytes the issuer
/// signed (see `Cert::tbs`). Text between the blocks is skipped.
///
/// # Errors
///
/// `Validation` for a block without its END line, one that does not decode, one of another
/// kind than `CERTIFICATE`, or a certificate that does not parse.
pub fn pem_certs(pem: &str) -> Result<Vec<Cert>> {
    let bad = |e: String| KmError::Validation(format!("pem certificates: {e}").into());
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN ") {
        let block = &rest[start..];
        // The block runs to the dashes closing its END line.
        let end = block
            .find("-----END ")
            .and_then(|e| block[e + 9..].find("-----").map(|close| e + 9 + close + 5))
            .ok_or_else(|| bad("a BEGIN line without its END line".into()))?;
        let (label, der) = x509_cert::der::pem::decode_vec(&block.as_bytes()[..end]).map_err(|e| bad(e.to_string()))?;
        if label != "CERTIFICATE" {
            return Err(bad(format!("a {label} block, not a CERTIFICATE")));
        }
        let parsed = Certificate::from_der(&der).map_err(|e| bad(e.to_string()))?;
        certs.push(Cert { der, parsed });
        rest = &block[end..];
    }
    Ok(certs)
}

/// A file's certificates: a PEM bundle (any number of `CERTIFICATE` blocks, read by
/// [`pem_certs`]) when the bytes are text holding a BEGIN line, else one DER certificate.
///
/// # Errors
///
/// [`pem_certs`]'s for a PEM bundle; [`Cert::from_der`]'s for anything else.
pub fn certs_of(bytes: &[u8]) -> Result<Vec<Cert>> {
    match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN ") => pem_certs(text),
        _ => Ok(vec![Cert::from_der(bytes.to_vec())?]),
    }
}

/// Walk `cert`'s issuer chain through the intermediates of `pool` until one of `anchors` is
/// reached, verifying every signature and every issuer's `basicConstraints` (CA, within its
/// `pathLen`) and `keyUsage` (`keyCertSign`, when present) on the host, and refusing any
/// certificate of the walk with a critical extension it does not process; the anchor reached is
/// the answer, and what a caller pins. The walk
/// takes at most `max_links` signatures, `cert`'s own included. `pathLen` counts the CA
/// certificates below an issuer (RFC 5280 §4.2.1.9), `cert` among them as `start` says: the
/// caller's knowledge of what it is walking from, never what `cert` claims of itself. With `at`,
/// every certificate of the walk must be valid then, `cert` and the anchor included.
///
/// # Errors
///
/// `Conflict` when no walk reaches an anchor: a signature that does not verify, an issuer that
/// is not a CA or is outside its dates, a chain longer than `max_links`, or no issuer at all.
/// `Unsupported` for a signature algorithm other than ECDSA or RSA PKCS#1 v1.5 with SHA-2.
pub fn chain_to_anchor<'a>(
    cert: &Cert,
    start: Start,
    anchors: &'a [Cert],
    pool: &[Cert],
    at: Option<u64>,
    max_links: u8,
) -> Result<&'a Cert> {
    if let Some(at) = at {
        cert.valid_at(at)?;
    }
    cert.no_unknown_critical()?;
    let below = match start {
        Start::EndEntity => 0,
        Start::Intermediate => 1,
    };
    issuer_chain(cert, Walk { links: 1, below }, anchors, pool, at, max_links)
}

/// What [`chain_to_anchor`] walks from, which decides whether it counts against its issuers'
/// `pathLen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// An end-entity certificate (an EK certificate): not counted, so a `pathlen:0` CA may sign it.
    EndEntity,
    /// A CA below the chain (a PIV device certificate, which signs the slot's): counted.
    Intermediate,
}

/// Where a walk is: the signatures it has taken (`current`'s included), and the CA certificates
/// below the next issuer. Both are wider than `max_links`, so neither can wrap on a cyclic pool.
#[derive(Clone, Copy)]
struct Walk {
    links: u16,
    below: u16,
}

/// The rest of [`chain_to_anchor`]'s walk above `current`, at `walk`. Every certificate whose
/// subject is `current`'s issuer is tried, pooled intermediates first, then anchors: one subject
/// may name two keys (a re-keyed CA), and a chain through the second must not fail on the first
/// one's signature. When none links, the first candidate's error is the answer.
fn issuer_chain<'a>(
    current: &Cert,
    walk: Walk,
    anchors: &'a [Cert],
    pool: &[Cert],
    at: Option<u64>,
    max_links: u8,
) -> Result<&'a Cert> {
    let bad = |what: String| KmError::Conflict(format!("attestation chain: {what}").into());
    if walk.links > u16::from(max_links) {
        return Err(bad(format!("longer than {max_links} links")));
    }
    let link = |issuer: &Cert| -> Result<()> {
        issuer.no_unknown_critical()?;
        issuer.may_issue(walk.below)?;
        verify_signed_by(current, issuer)?;
        at.map_or(Ok(()), |at| issuer.valid_at(at))
    };
    let mut first_error = None;
    for issuer in pool.iter().filter(|c| c.issued(current)) {
        let above = Walk { links: walk.links + 1, below: walk.below + 1 };
        match link(issuer).and_then(|()| issuer_chain(issuer, above, anchors, pool, at, max_links)) {
            Ok(anchor) => return Ok(anchor),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    for anchor in anchors.iter().filter(|a| a.issued(current)) {
        match link(anchor) {
            Ok(()) => return Ok(anchor),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or_else(|| {
        bad(format!(
            "'{}' is signed by no pinned root and no intermediate given",
            current.parsed.tbs_certificate().subject()
        ))
    }))
}

/// Verify that `cert`'s signature (over its original `tbsCertificate` bytes) was made by
/// `signer`'s key, with the signature algorithm the certificate names: ECDSA (DER) with the
/// hash the algorithm names, whatever the curve, or RSA PKCS#1 v1.5 ([`crate::sig`]). The
/// unsigned outer `signatureAlgorithm` must equal the signed `tbsCertificate.signature`, OID
/// and parameters (RFC 5280 §4.1.1.2).
///
/// # Errors
///
/// `Conflict` when the two algorithms differ, the signature does not verify, or `signer` holds
/// no key of the algorithm's kind; `Unsupported` for another signature algorithm.
pub fn verify_signed_by(cert: &Cert, signer: &Cert) -> Result<()> {
    use crate::sig::{self, Encoding, HashAlg};
    let (outer, inner) = (cert.parsed.signature_algorithm(), cert.parsed.tbs_certificate().signature());
    if outer != inner {
        let show = |a: &x509_cert::spki::AlgorithmIdentifierOwned| match &a.parameters {
            None => a.oid.to_string(),
            Some(p) => format!("{} with {} parameters", a.oid, p.tag()),
        };
        return Err(KmError::Conflict(
            format!(
                "certificate '{}': its signatureAlgorithm {} is not the signed tbsCertificate.signature {}",
                cert.parsed.tbs_certificate().subject(),
                show(outer),
                show(inner)
            )
            .into(),
        ));
    }
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

    /// The test chain (root → device f9 → slot attestation) and a `YubiKey`'s own slot 95
    /// attestation, copied from ykcs11's fixtures.
    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    /// A fixture certificate's DER, from its PEM.
    fn der_of(name: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(&fixture(name)).unwrap().1
    }

    fn cert(name: &str) -> Cert {
        Cert::from_der(der_of(name)).unwrap()
    }

    /// Every issuer in the walk must be a CA within its pathLen: Yubico's FIDO CAs carry
    /// `pathlen:0`, so even under the pinned root they cannot issue a device certificate. The
    /// pool is ykcs11's, the file its build pins.
    #[test]
    fn issuers_must_be_cas_within_their_path_length() {
        let pool = pem_certs(include_str!("../../ykcs11/roots/yubico-intermediate.pem")).unwrap();
        let named = |cn: &str| pool.iter().find(|c| c.parsed.tbs_certificate().subject().to_string() == cn).unwrap();
        named("CN=Yubico FIDO Attestation A 1").may_issue(0).unwrap();
        let err = named("CN=Yubico FIDO Attestation A 1").may_issue(1).unwrap_err();
        assert!(err.to_string().contains("allows 0 CA certificate(s) below it"), "{err}");
        named("CN=Yubico PIV Attestation A 1").may_issue(1).unwrap();
        assert!(named("CN=Yubico PIV Attestation A 1").may_issue(2).is_err());
        // The fixture slot certificate is an end entity (CA:FALSE).
        assert!(cert("slot.pem").may_issue(0).unwrap_err().to_string().contains("is not a CA"));
    }

    /// The walk takes at most `max_links` signatures: slot ← f9 ← root is two, so it reaches
    /// the root under a limit of 2 and is refused under 1. With no issuer at all, the error
    /// names the certificate. A limit of 255 on a pool whose certificate issues itself ends.
    #[test]
    fn the_walk_is_bounded_by_max_links() {
        let (root, f9, slot) =
            (pem_certs(&String::from_utf8(fixture("root.pem")).unwrap()).unwrap(), cert("f9.pem"), cert("slot.pem"));
        let pool = [f9];
        let anchor = chain_to_anchor(&slot, Start::EndEntity, &root, &pool, None, 2).unwrap();
        assert_eq!(anchor.der(), root[0].der());
        let e = chain_to_anchor(&slot, Start::EndEntity, &root, &pool, None, 1).unwrap_err();
        assert!(matches!(&e, KmError::Conflict(m) if m.contains("attestation chain: longer than 1 links")), "{e}");
        let e = chain_to_anchor(&pool[0], Start::Intermediate, &[], &[], None, 3).unwrap_err();
        assert!(
            matches!(&e, KmError::Conflict(m) if m.contains(
                "'CN=Test PIV Device Attestation 452000752' is signed by no pinned root and no intermediate given"
            )),
            "{e}"
        );
        // The self-signed root in the pool links to itself at every step: the count stops it.
        let e = chain_to_anchor(&pool[0], Start::Intermediate, &[], &root, None, u8::MAX).unwrap_err();
        assert!(e.to_string().contains("longer than 255 links"), "{e}");
    }

    /// Whether the starting certificate counts against `pathLen` is the caller's to say: AMD's
    /// fTPM EK certificate sits under a `pathlen:0` intermediate, which may sign an end entity
    /// but not a CA. Walked as an intermediate, the same certificate is refused, whatever it
    /// claims of itself. The chain is tpm2-pkcs11's (its roots, which its build pins).
    #[test]
    fn the_caller_says_whether_the_start_counts_against_path_length() {
        let bundle = certs_of(include_bytes!("../../tpm2-pkcs11/tests/fixtures/amd-ftpm-ek-ecc.pem")).unwrap();
        let roots = pem_certs(include_str!("../../tpm2-pkcs11/roots/amd-ftpm-ecc-root.pem")).unwrap();
        let (leaf, pool) = (&bundle[0], &bundle[1..]);
        let anchor = chain_to_anchor(leaf, Start::EndEntity, &roots, pool, None, 3).unwrap();
        assert_eq!(anchor.der(), roots[0].der());
        let e = chain_to_anchor(leaf, Start::Intermediate, &roots, pool, None, 3).unwrap_err();
        assert!(e.to_string().contains("allows 0 CA certificate(s) below it, the chain has 1"), "{e}");
    }

    /// A file's certificates: a PEM bundle of two keeps both blocks' bytes, a DER certificate is
    /// one, and anything else is refused.
    #[test]
    fn certs_of_reads_a_pem_bundle_or_one_der_certificate() {
        let bundle = [fixture("f9.pem"), fixture("root.pem")].concat();
        let certs = certs_of(&bundle).unwrap();
        assert_eq!(certs.iter().map(Cert::der).collect::<Vec<_>>(), [&der_of("f9.pem")[..], &der_of("root.pem")[..]]);
        let certs = certs_of(&der_of("slot.pem")).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].der(), der_of("slot.pem"));
        assert!(certs_of(b"not a certificate").is_err());
        assert!(certs_of(&der_of("slot.pem")[..100]).is_err());
        let key = x509_cert::der::pem::encode_string("PRIVATE KEY", x509_cert::der::pem::LineEnding::LF, &[0x05, 0x00]);
        assert!(certs_of(key.unwrap().as_bytes()).is_err());
    }

    /// A DER TLV: `tag`, the definite length, `body`.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut out = vec![tag];
        match len {
            0..0x80 => out.push(u8::try_from(len).unwrap()),
            0x80..0x100 => out.extend([0x81, u8::try_from(len).unwrap()]),
            _ => out.extend([&[0x82][..], &u16::try_from(len).unwrap().to_be_bytes()].concat()),
        }
        out.extend_from_slice(body);
        out
    }

    /// A certificate assembled from its three parts: `tbs` and `signature_algorithm` as given,
    /// and `cert`'s own signature value.
    fn reassembled(tbs: &[u8], signature_algorithm: &[u8], cert: &Cert) -> Vec<u8> {
        let signature = cert.parsed.signature().to_der().unwrap();
        tlv(0x30, &[tbs, signature_algorithm, &signature].concat())
    }

    /// The outer signatureAlgorithm, which the signature does not cover, must be the signed
    /// `tbsCertificate.signature`, parameters included: the slot certificate's outer
    /// ECDSA-SHA256 with added NULL parameters, or with another hash, is refused before any
    /// signature check (attest.rs F2). Its own outer algorithm still verifies.
    #[test]
    fn the_outer_signature_algorithm_is_the_signed_one() {
        let (slot, device) = (cert("slot.pem"), cert("f9.pem"));
        let tbs = slot.tbs().unwrap().to_vec();
        let own = slot.parsed.signature_algorithm().to_der().unwrap();
        let as_is = Cert::from_der(reassembled(&tbs, &own, &slot)).unwrap();
        verify_signed_by(&as_is, &device).unwrap();
        // A YubiKey's own slot attestation (slot 95, firmware 5.7.4) passes the comparison.
        let real = cert("attest95.pem");
        assert_eq!(real.parsed.signature_algorithm(), real.parsed.tbs_certificate().signature());
        let with_null = tlv(0x30, &[&ECDSA_SHA256.to_der().unwrap()[..], &[0x05, 0x00]].concat());
        let other_hash = tlv(0x30, &ECDSA_SHA384.to_der().unwrap());
        for (outer, shown) in
            [(with_null, "1.2.840.10045.4.3.2 with NULL parameters"), (other_hash, "1.2.840.10045.4.3.3")]
        {
            let swapped = Cert::from_der(reassembled(&tbs, &outer, &slot)).unwrap();
            let e = verify_signed_by(&swapped, &device).unwrap_err();
            assert!(
                matches!(&e, KmError::Conflict(m) if m.contains(&format!("signatureAlgorithm {shown} is not the signed"))),
                "{e}"
            );
        }
    }

    /// The certificates read from PEM keep the bytes the PEM holds, never a re-encoding: a
    /// `tbsCertificate` with an explicit `version [0] v1` (a DEFAULT, which DER omits and der's
    /// encoder drops) keeps it, so its signature is checked over what its issuer signed
    /// (attest.rs F3). Blocks of another kind are refused.
    #[test]
    fn pem_certificates_keep_their_bytes() {
        let slot = cert("slot.pem");
        let t = slot.parsed.tbs_certificate();
        let alg = t.signature().to_der().unwrap();
        let tbs = tlv(
            0x30,
            &[
                &[0xa0, 0x03, 0x02, 0x01, 0x00][..], // version [0] v1, explicit
                &t.serial_number().to_der().unwrap(),
                &alg,
                &t.issuer().to_der().unwrap(),
                &t.validity().to_der().unwrap(),
                &t.subject().to_der().unwrap(),
                &t.subject_public_key_info().to_der().unwrap(),
            ]
            .concat(),
        );
        let der = reassembled(&tbs, &alg, &slot);
        // The precondition: der reads this certificate and re-encodes it differently.
        assert_ne!(Certificate::from_der(&der).unwrap().to_der().unwrap(), der);
        let pem = x509_cert::der::pem::encode_string("CERTIFICATE", x509_cert::der::pem::LineEnding::LF, &der).unwrap();
        let root = String::from_utf8(fixture("root.pem")).unwrap();
        let certs = pem_certs(&format!("{root}some text between blocks\n{pem}")).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].der, der_of("root.pem"));
        assert_eq!(certs[1].der, der);
        assert_eq!(certs[1].tbs().unwrap(), &tbs[..]);
        let key = x509_cert::der::pem::encode_string("PRIVATE KEY", x509_cert::der::pem::LineEnding::LF, &[0x05, 0x00]);
        let e = pem_certs(&format!("{root}{}", key.unwrap())).err().unwrap();
        assert!(e.to_string().contains("a PRIVATE KEY block"), "{e}");
    }

    /// A chain-rules fixture (tests/fixtures/chain-rules/make.sh).
    fn rule(name: &str) -> Cert {
        cert(&format!("chain-rules/{name}.pem"))
    }

    /// What the walk enforces beyond basicConstraints (RFC 5280; review 2026-11-23 A-3): an
    /// issuer whose keyUsage lacks keyCertSign signs no certificate, and a certificate with a
    /// critical extension the walk does not process (nameConstraints here) is refused wherever
    /// it sits. A certificate that names its purposes serves only those. Each fixture chain
    /// differs from the valid `ok` one in its one rule (openssl verifies `ok` and refuses
    /// `no-certsign`).
    #[test]
    fn issuers_sign_certificates_and_critical_extensions_are_understood() {
        let walk = |leaf: &str, root: &str| {
            chain_to_anchor(&rule(leaf), Start::EndEntity, &[rule(root)], &[], None, 2).map(|_| ())
        };
        walk("ok-leaf", "ok-root").unwrap();
        walk("ek-leaf", "ok-root").unwrap();
        let e = walk("no-certsign-leaf", "no-certsign-root").unwrap_err();
        assert!(e.to_string().contains("may not sign certificates: its keyUsage lacks keyCertSign"), "{e}");
        let e = walk("constrained-leaf", "constrained-root").unwrap_err();
        assert!(e.to_string().contains("has the critical extension 2.5.29.30, which cakeys does not process"), "{e}");
        let e = chain_to_anchor(&rule("constrained-root"), Start::Intermediate, &[rule("ok-root")], &[], None, 2)
            .unwrap_err();
        assert!(e.to_string().contains("critical extension 2.5.29.30"), "as the start of a walk: {e}");
        assert!(rule("ok-leaf").serves(&TCG_KP_EK_CERTIFICATE).unwrap(), "names no purpose: any");
        assert!(rule("ek-leaf").serves(&TCG_KP_EK_CERTIFICATE).unwrap());
        assert!(!rule("server-leaf").serves(&TCG_KP_EK_CERTIFICATE).unwrap());
    }

    /// The chain's name links compare the decoded Names (attest.rs F4).
    #[test]
    fn issuers_are_linked_by_name() {
        let [root, f9, slot] = ["root.pem", "f9.pem", "slot.pem"].map(cert);
        assert!(root.issued(&f9) && f9.issued(&slot) && root.issued(&root));
        assert!(!root.issued(&slot) && !slot.issued(&f9) && !f9.issued(&root));
    }

    /// A CA certificate with the fixture root's subject and another key: the name matches, the
    /// signature does not.
    fn decoy_root() -> Cert {
        let mut der = der_of("root.pem");
        let root = Cert::from_der(der.clone()).unwrap();
        let spki = root.parsed.tbs_certificate().subject_public_key_info().to_der().unwrap();
        let at = der.windows(spki.len()).position(|w| w == spki).unwrap();
        // A byte in the middle of the RSA modulus.
        der[at + spki.len() / 2] ^= 0x01;
        Cert::from_der(der).unwrap()
    }

    /// Every issuer whose subject matches is tried: a pooled certificate or an earlier anchor
    /// with the root's subject but another key (a re-keyed CA) does not hide the root that
    /// signed the chain (attest.rs F5). With only the decoy, its signature error is the answer.
    #[test]
    fn every_name_matching_issuer_is_tried() {
        let root = pem_certs(&String::from_utf8(fixture("root.pem")).unwrap()).unwrap().remove(0);
        let root_sri = id::sri(&root.spki().unwrap());
        let device = cert("f9.pem");
        let verify = |anchors: &[Cert], pool: &[Cert]| {
            chain_to_anchor(&device, Start::Intermediate, anchors, pool, None, 3)
                .and_then(Cert::spki)
                .map(|s| id::sri(&s))
        };
        let anchors = [Cert::from_der(root.der.clone()).unwrap()];
        assert_eq!(verify(&anchors, &[decoy_root()]).unwrap(), root_sri);
        let anchors = [decoy_root(), Cert::from_der(root.der.clone()).unwrap()];
        assert_eq!(verify(&anchors, &[]).unwrap(), root_sri);
        let e = verify(&[decoy_root()], &[]).unwrap_err();
        assert!(matches!(&e, KmError::Conflict(m) if m.contains("does not verify")), "{e}");
    }
}
