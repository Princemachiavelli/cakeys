//! The verification of X.509 attestation chains on the host. The walk starts at a certificate
//! and follows its issuers through a pool of intermediates until it reaches one of a set of
//! pinned anchors. It checks every signature over the bytes that the issuer signed. The `YubiKey`
//! PIV attestation (ykcs11) and the TPM's EK certificate (tpm2-pkcs11) both use this module, and
//! each of them decides what its chain must assert.

use crate::{Check, KmError, Reason, Result, id};
use x509_cert::certificate::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{DateTime, Decode, Encode, Header, Reader, SliceReader, Tagged};

/// The signature algorithm OIDs by which the chain verifier selects the verification: ECDSA and
/// RSA PKCS#1 v1.5 with SHA-2. PIV devices sign with ECDSA-SHA256 when the attesting key is an EC
/// key and with SHA256-PKCS#1v1.5 when it is an RSA key. The pinned Yubico roots are RSA-2048 keys
/// that sign with SHA-256 or SHA-512.
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
/// `tcg-kp-EKCertificate` (2.23.133.8.1): the purpose that TCG's EK credential profile assigns to
/// an Endorsement Key certificate ([`Cert::serves`]).
pub const TCG_KP_EK_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.1");

/// The extensions that a certificate of a walk may mark as critical. These are the extensions
/// that the walk or its callers read (basicConstraints, keyUsage and extendedKeyUsage), and two
/// extensions that restrict nothing on which an attestation relies but that issuers mark as
/// critical: subjectAltName (in a TCG EK certificate with an empty subject) and
/// certificatePolicies (in Yubico's intermediates). Any other critical extension
/// (nameConstraints, policyConstraints, or a vendor's extension) may constrain the certificate in
/// a way that the walk does not enforce, so the walk refuses it, as RFC 5280 §4.2 requires
/// (review 2026-11-23 A-3).
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
    /// Parses one DER certificate and keeps `der` as its bytes.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` when `der` is not a certificate.
    pub fn from_der(der: Vec<u8>) -> Result<Cert> {
        let parsed = Certificate::from_der(&der)
            .map_err(|e| KmError::Conflict(Reason::malformed(format!("parsing certificate: {e}"))))?;
        Ok(Cert { der, parsed })
    }

    /// Returns the certificate's DER, as it was read.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the decoded certificate.
    #[must_use]
    pub fn parsed(&self) -> &Certificate {
        &self.parsed
    }

    /// Returns the bytes over which the signature was computed: the `tbsCertificate`, cut from the
    /// certificate's original DER and never encoded again, so that the verification checks
    /// exactly the signed bytes. `self.parsed.tbs_certificate()` is the decoded structure, whose
    /// bytes would come from `to_der()`. Those bytes equal the signed bytes only when the decoding
    /// lost nothing, and der 0.8 accepts an explicitly encoded DEFAULT value (a `version [0] v1`)
    /// that its encoder then omits.
    fn tbs(&self) -> Result<&[u8]> {
        // A Certificate is SEQUENCE { tbsCertificate, signatureAlgorithm, signature }, so the
        // `tbsCertificate` is the first TLV after the outer header, including its own header.
        let mut reader = SliceReader::new(&self.der)
            .map_err(|e| KmError::Conflict(Reason::malformed(format!("certificate DER: {e}"))))?;
        Header::decode(&mut reader)
            .and_then(|_| reader.tlv_bytes())
            .map_err(|e| KmError::Conflict(Reason::malformed(format!("certificate has no tbsCertificate: {e}"))))
    }

    /// Returns the raw signature value: the content of the BIT STRING without the byte that
    /// counts the unused bits.
    fn signature(&self) -> &[u8] {
        self.parsed.signature().raw_bytes()
    }

    /// Returns the canonical SPKI of the subject ([`id::spki_canonical`]). For a PIV device
    /// certificate, that is the attestation key itself.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` when the SPKI cannot be encoded, and the `Unsupported` of
    /// [`id::spki_canonical`] for a key that cakeys does not hash.
    pub fn spki(&self) -> Result<Vec<u8>> {
        id::spki_canonical(
            &self
                .parsed
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .map_err(|e| KmError::Conflict(Reason::malformed(format!("encoding SPKI: {e}"))))?,
        )
    }

    /// Checks whether `at` (seconds since the Unix epoch) is within the validity period,
    /// including both ends (RFC 5280 §4.1.2.5). Only `check` asks this (ISSUES.md B8).
    ///
    /// # Errors
    ///
    /// Returns `Conflict`, which names the time and the period, when `at` is outside the period.
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
        Err(KmError::Conflict(Reason::check(
            Check::ChainValidity,
            format!(
                "attestation chain: '{}' is not valid at {} (valid from {} to {}); `check --at <time>` judges the \
                 chain at another time, `--ignore-validity` skips the dates",
                self.parsed.tbs_certificate().subject(),
                show(at),
                show(from),
                show(to)
            ),
        )))
    }

    /// Returns the raw `extnValue` of the extension with this OID, or an empty value when the
    /// certificate has no such extension.
    #[must_use]
    pub fn extension(&self, oid: &ObjectIdentifier) -> Vec<u8> {
        self.parsed
            .tbs_certificate()
            .extensions()
            .and_then(|ext| ext.iter().find(|e| &e.extn_id == oid))
            .map(|e| e.extn_value.as_bytes().to_vec())
            .unwrap_or_default()
    }

    /// Returns whether this certificate's subject is the issuer of `cert`. The comparison uses
    /// the decoded Names, so nothing is encoded again and no encoding can fail. A matching name
    /// does not prove that this certificate issued `cert`, so this function is private to the
    /// crate, as [`verify_signed_by`] is. Callers check a link with [`link`] (review 2026-11-24
    /// A-7).
    #[must_use]
    pub(crate) fn issued(&self, cert: &Cert) -> bool {
        self.parsed.tbs_certificate().subject() == cert.parsed.tbs_certificate().issuer()
    }

    /// Returns whether the certificate may serve `purpose`: either it names no purposes (it has
    /// no `extendedKeyUsage`), or it names `purpose` (RFC 5280 §4.2.1.12). An EK certificate must
    /// serve [`TCG_KP_EK_CERTIFICATE`] (review 2026-11-23 A-3).
    ///
    /// # Errors
    ///
    /// Returns `Conflict` when its `extendedKeyUsage` does not decode.
    pub fn serves(&self, purpose: &ObjectIdentifier) -> Result<bool> {
        let eku: Option<x509_cert::ext::pkix::ExtendedKeyUsage> =
            self.decoded(&EXTENDED_KEY_USAGE, "extendedKeyUsage")?;
        Ok(eku.is_none_or(|eku| eku.0.contains(purpose)))
    }

    /// Returns the extension with this OID, decoded as `T`, or `None` when the certificate has no
    /// such extension.
    ///
    /// # Errors
    ///
    /// Returns `Conflict`, which names the certificate and `what`, when the extension does not
    /// decode.
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
                KmError::Conflict(Reason::malformed(format!(
                    "attestation chain: '{}' {what}: {e}",
                    self.parsed.tbs_certificate().subject()
                )))
            })
    }

    /// Checks whether this certificate may issue a chain with `below` CA certificates under it
    /// (the certificate from which the walk started counts as one when `Start::Intermediate`
    /// says so). The certificate must be a CA in `basicConstraints`, `below` must be within its
    /// `pathLen`, and its `keyUsage`, when it has one, must include `keyCertSign` (RFC 5280
    /// §4.2.1.3; review 2026-11-23 A-3).
    fn may_issue(&self, below: u16) -> Result<()> {
        let subject = self.parsed.tbs_certificate().subject().to_string();
        let bc: Option<x509_cert::ext::pkix::BasicConstraints> =
            self.decoded(&BASIC_CONSTRAINTS, "basicConstraints")?;
        match bc {
            Some(bc) if bc.ca && bc.path_len_constraint.is_none_or(|n| u16::from(n) >= below) => {}
            Some(bc) if bc.ca => {
                return Err(KmError::Conflict(Reason::check(
                    Check::ChainCa,
                    format!(
                        "attestation chain: '{subject}' allows {} CA certificate(s) below it, the chain has {below}",
                        bc.path_len_constraint.unwrap_or_default()
                    ),
                )));
            }
            _ => {
                return Err(KmError::Conflict(Reason::check(
                    Check::ChainCa,
                    format!("attestation chain: '{subject}' is not a CA"),
                )));
            }
        }
        let ku: Option<x509_cert::ext::pkix::KeyUsage> = self.decoded(&KEY_USAGE, "keyUsage")?;
        if ku.is_some_and(|ku| !ku.key_cert_sign()) {
            return Err(KmError::Conflict(Reason::check(
                Check::ChainCa,
                format!("attestation chain: '{subject}' may not sign certificates: its keyUsage lacks keyCertSign"),
            )));
        }
        Ok(())
    }

    /// Refuses a certificate with a critical extension that is not in [`UNDERSTOOD`], because such
    /// an extension may constrain the certificate in a way that the walk does not enforce (RFC
    /// 5280 §4.2).
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
            Some(e) => Err(KmError::Conflict(Reason::check(
                Check::ChainCriticalExtension,
                format!(
                    "attestation chain: '{}' has the critical extension {}, which cakeys does not process",
                    self.parsed.tbs_certificate().subject(),
                    e.extn_id
                ),
            ))),
        }
    }
}

/// Parses every PEM `CERTIFICATE` block of `pem` (the anchor and pool files), and keeps the
/// decoded bytes of each block as the certificate's DER. A new encoding could differ from the
/// bytes that the issuer signed (see `Cert::tbs`). Text between the blocks is skipped.
///
/// # Errors
///
/// Returns `Validation` for a block without its END line, a block that does not decode, a block
/// of a kind other than `CERTIFICATE`, or a certificate that does not parse.
pub fn pem_certs(pem: &str) -> Result<Vec<Cert>> {
    let bad = |e: String| KmError::Validation(format!("pem certificates: {e}").into());
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN ") {
        let block = &rest[start..];
        // The block ends with the dashes that close its END line.
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

/// Returns the certificates of a file. When the bytes are text that contains a BEGIN line, the
/// file is a PEM bundle with any number of `CERTIFICATE` blocks, which [`pem_certs`] reads.
/// Otherwise, the file is one DER certificate.
///
/// # Errors
///
/// Returns the errors of [`pem_certs`] for a PEM bundle, and the errors of [`Cert::from_der`] for
/// anything else.
pub fn certs_of(bytes: &[u8]) -> Result<Vec<Cert>> {
    match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN ") => pem_certs(text),
        _ => Ok(vec![Cert::from_der(bytes.to_vec())?]),
    }
}

/// Walks the issuer chain of `cert` through the intermediates of `pool` until it reaches one of
/// `anchors`, and returns that anchor, which the caller pins. On the host, the walk verifies
/// every signature, the `basicConstraints` of every issuer (it must be a CA, within its
/// `pathLen`), and its `keyUsage` (it must include `keyCertSign`, when present). The walk refuses
/// any certificate with a critical extension that it does not process.
///
/// The walk verifies at most `max_links` signatures, including the signature of `cert`.
/// `pathLen` counts the CA certificates below an issuer (RFC 5280 §4.2.1.9). `start` says
/// whether `cert` counts among them. The caller decides this from what it knows about the
/// certificate, never from what `cert` claims about itself. With `at`, every certificate of the
/// walk must be valid at that time, including `cert` and the anchor.
///
/// # Errors
///
/// Returns `Conflict` when no walk reaches an anchor: because a signature does not verify, an
/// issuer is not a CA or is outside its validity period, the chain is longer than `max_links`, or
/// a certificate has no issuer at all. Returns `Unsupported` for a signature algorithm other than
/// ECDSA or RSA PKCS#1 v1.5 with SHA-2.
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
    issuer_chain(cert, Walk { links: 1, below: below(start) }, anchors, pool, at, max_links)
}

/// The kind of certificate from which [`chain_to_anchor`] starts. The kind decides whether the
/// certificate counts against the `pathLen` of its issuers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// An end-entity certificate (an EK certificate). It is not counted, so a CA with `pathlen:0`
    /// may sign it.
    EndEntity,
    /// A CA at the bottom of the chain (a PIV device certificate, which signs the slot
    /// certificate). It is counted.
    Intermediate,
}

/// The state of a walk: the number of signatures that it has verified (including the signature of
/// `current`), and the number of CA certificates below the next issuer. Both counters are `u16`
/// and `max_links` is a `u8`, so the length check stops a walk through a cyclic pool before
/// either counter can overflow.
#[derive(Clone, Copy)]
struct Walk {
    links: u16,
    below: u16,
}

/// Continues the walk of [`chain_to_anchor`] above `current`, in the state `walk`. The function
/// tries every certificate whose subject is the issuer of `current`, first the intermediates of
/// the pool and then the anchors. One subject may name two keys (a CA that got a new key), and a
/// chain through the second key must not fail because of the first key's signature. When no
/// candidate links, the function returns the first candidate's error.
fn issuer_chain<'a>(
    current: &Cert,
    walk: Walk,
    anchors: &'a [Cert],
    pool: &[Cert],
    at: Option<u64>,
    max_links: u8,
) -> Result<&'a Cert> {
    let bad = |check, what: String| KmError::Conflict(Reason::check(check, format!("attestation chain: {what}")));
    if walk.links > u16::from(max_links) {
        return Err(bad(Check::ChainLength, format!("longer than {max_links} links")));
    }
    let link = |issuer: &Cert| issued_by(current, issuer, walk.below, at);
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
        bad(
            Check::ChainAnchor,
            format!(
                "'{}' is signed by no pinned root and no intermediate given",
                current.parsed.tbs_certificate().subject()
            ),
        )
    }))
}

/// Checks whether `issuer` issued `cert`, with every rule that a link of the walk of
/// [`chain_to_anchor`] checks. `cert` must have no critical extension that cakeys does not
/// process and must be valid at `at`. `issuer` may issue it (a CA within its `pathLen`, with
/// `keyCertSign` when it has a `keyUsage`), must have no such critical extension, must be valid at
/// `at`, and its key must have made the signature of `cert`. `start` says what kind of
/// certificate `cert` is, as for the walk. The one link that a caller checks outside a walk (the
/// PIV slot certificate, which the device certificate signs) is checked here, and never by the
/// signature alone (review 2026-11-24 A-7: the check of the slot link skipped the issuer's CA
/// flag and `keyUsage` and the slot certificate's critical extensions).
///
/// # Errors
///
/// Returns `Conflict` when `cert` or `issuer` breaks a rule or the signature does not verify.
/// Returns `Unsupported` for a signature algorithm other than ECDSA or RSA PKCS#1 v1.5 with SHA-2.
pub fn link(cert: &Cert, start: Start, issuer: &Cert, at: Option<u64>) -> Result<()> {
    if let Some(at) = at {
        cert.valid_at(at)?;
    }
    cert.no_unknown_critical()?;
    issued_by(cert, issuer, below(start), at)
}

/// Returns the number of CA certificates that the starting certificate adds below its issuer.
fn below(start: Start) -> u16 {
    match start {
        Start::EndEntity => 0,
        Start::Intermediate => 1,
    }
}

/// Checks the issuer's rules of a link ([`link`]). `issuer` may issue a chain with `below` CA
/// certificates under it, has no critical extension that cakeys does not process, is valid at
/// `at`, and signed `current`. The walk checks the rules for `current` itself once, either where
/// the walk starts or when `current` was checked as an issuer.
fn issued_by(current: &Cert, issuer: &Cert, below: u16, at: Option<u64>) -> Result<()> {
    issuer.no_unknown_critical()?;
    issuer.may_issue(below)?;
    verify_signed_by(current, issuer)?;
    at.map_or(Ok(()), |at| issuer.valid_at(at))
}

/// Verifies that the key of `signer` made the signature of `cert` (over the original
/// `tbsCertificate` bytes), with the signature algorithm that the certificate names. That is
/// ECDSA (DER) with the hash that the algorithm names, on any curve, or RSA PKCS#1 v1.5
/// ([`crate::sig`]). The unsigned outer `signatureAlgorithm` must equal the signed
/// `tbsCertificate.signature`, both the OID and the parameters (RFC 5280 §4.1.1.2).
///
/// # Errors
///
/// Returns `Conflict` when the two algorithms differ, the signature does not verify, or `signer`
/// holds no key of the algorithm's kind. Returns `Unsupported` for any other signature
/// algorithm.
///
/// This function checks only the signature and not the other rules of a link. It is private to
/// the crate, so that no caller outside the walk checks a link with it alone ([`link`]; review
/// 2026-11-24 A-7).
pub(crate) fn verify_signed_by(cert: &Cert, signer: &Cert) -> Result<()> {
    use crate::sig::{self, Encoding, HashAlg};
    let (outer, inner) = (cert.parsed.signature_algorithm(), cert.parsed.tbs_certificate().signature());
    if outer != inner {
        let show = |a: &x509_cert::spki::AlgorithmIdentifierOwned| match &a.parameters {
            None => a.oid.to_string(),
            Some(p) => format!("{} with {} parameters", a.oid, p.tag()),
        };
        return Err(KmError::Conflict(Reason::check(
            Check::ChainSignature,
            format!(
                "certificate '{}': its signatureAlgorithm {} is not the signed tbsCertificate.signature {}",
                cert.parsed.tbs_certificate().subject(),
                show(outer),
                show(inner)
            ),
        )));
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
        Some(Err(e)) => Err(KmError::Conflict(Reason::check(
            Check::ChainSignature,
            format!("certificate signature does not verify against {sri}: {e}"),
        ))),
        None => Err(KmError::Conflict(Reason::check(
            Check::ChainSignature,
            format!("the signer {sri} holds no key for the certificate's signature algorithm"),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directory with the test chain (root → device f9 → slot attestation) and the slot 95
    /// attestation of a real `YubiKey`, copied from ykcs11's fixtures.
    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    /// Returns the DER of a fixture certificate, read from its PEM.
    fn der_of(name: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(&fixture(name)).unwrap().1
    }

    fn cert(name: &str) -> Cert {
        Cert::from_der(der_of(name)).unwrap()
    }

    /// Every issuer in the walk must be a CA within its `pathLen`. Yubico's FIDO CAs have
    /// `pathlen:0`, so they cannot issue a device certificate, even under the pinned root. The
    /// pool is ykcs11's pool, from the file that its build pins.
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

    /// The walk verifies at most `max_links` signatures. The chain slot ← f9 ← root has two
    /// signatures, so the walk reaches the root with a limit of 2 and is refused with a limit of 1.
    /// When a certificate has no issuer at all, the error names the certificate. A walk with a
    /// limit of 255 through a pool whose certificate issues itself ends.
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
        // The self-signed root in the pool links to itself at every step, and the count of
        // signatures stops the walk.
        let e = chain_to_anchor(&pool[0], Start::Intermediate, &[], &root, None, u8::MAX).unwrap_err();
        assert!(e.to_string().contains("longer than 255 links"), "{e}");
    }

    /// The caller decides whether the starting certificate counts against `pathLen`. AMD's fTPM
    /// EK certificate is under an intermediate with `pathlen:0`, which may sign an end entity but
    /// not a CA. When the walk starts from the same certificate as an intermediate, it refuses the
    /// certificate, whatever the certificate claims about itself. The chain is tpm2-pkcs11's
    /// (with its roots, which its build pins).
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

    /// Reads the certificates of a file: a PEM bundle of two certificates keeps the bytes of both
    /// blocks, a DER file is one certificate, and anything else is refused.
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

    /// Returns a DER TLV: `tag`, the definite length, and `body`.
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

    /// Returns a certificate assembled from three parts: `tbs` and `signature_algorithm` as
    /// given, and the signature value of `cert`.
    fn reassembled(tbs: &[u8], signature_algorithm: &[u8], cert: &Cert) -> Vec<u8> {
        let signature = cert.parsed.signature().to_der().unwrap();
        tlv(0x30, &[tbs, signature_algorithm, &signature].concat())
    }

    /// The outer signatureAlgorithm, which the signature does not cover, must equal the signed
    /// `tbsCertificate.signature`, including the parameters. When the slot certificate's outer
    /// ECDSA-SHA256 gets added NULL parameters, or a different hash, the certificate is refused
    /// before any signature check (attest.rs F2). With its own outer algorithm, it still
    /// verifies.
    #[test]
    fn the_outer_signature_algorithm_is_the_signed_one() {
        let (slot, device) = (cert("slot.pem"), cert("f9.pem"));
        let tbs = slot.tbs().unwrap().to_vec();
        let own = slot.parsed.signature_algorithm().to_der().unwrap();
        let as_is = Cert::from_der(reassembled(&tbs, &own, &slot)).unwrap();
        verify_signed_by(&as_is, &device).unwrap();
        // The slot attestation of a real YubiKey (slot 95, firmware 5.7.4) passes the comparison.
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

    /// The certificates read from PEM keep the bytes that the PEM holds, and never a new
    /// encoding. A `tbsCertificate` with an explicit `version [0] v1` (a DEFAULT value, which DER
    /// omits and der's encoder drops) keeps that field, so its signature is checked over the
    /// bytes that its issuer signed (attest.rs F3). Blocks of another kind are refused.
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
        // The precondition of the test: der reads this certificate and encodes it differently.
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

    /// Returns a fixture certificate from tests/fixtures/chain-rules (made by `make.sh` there).
    fn rule(name: &str) -> Cert {
        cert(&format!("chain-rules/{name}.pem"))
    }

    /// Checks the rules that the walk enforces in addition to basicConstraints (RFC 5280; review
    /// 2026-11-23 A-3). An issuer whose keyUsage lacks keyCertSign cannot sign a certificate, and
    /// a certificate with a critical extension that the walk does not process (here,
    /// nameConstraints) is refused at any position in the chain. A certificate that names its
    /// purposes serves only those purposes. Each fixture chain differs from the valid `ok` chain
    /// in one rule (openssl verifies `ok` and refuses `no-certsign`).
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

    /// A link that is checked outside a walk is held to the walk's rules (review 2026-11-24 A-7).
    /// The test uses the `piv-` fixtures, and each of them differs from `piv-slot` ← `piv-device`
    /// in one rule. An issuer that is not a CA, or whose keyUsage lacks keyCertSign, cannot issue
    /// a certificate. A certificate with a critical extension that cakeys does not process is
    /// refused. A signature by another key does not verify. The certificate must be valid at
    /// `at`. An end entity does not count against `pathLen`, but an intermediate does.
    #[test]
    fn a_link_keeps_the_walks_rules() {
        let (slot, device) = (rule("piv-slot"), rule("piv-device"));
        link(&slot, Start::EndEntity, &device, None).unwrap();
        link(&device, Start::Intermediate, &rule("piv-root"), None).unwrap();
        let refused = |cert: &str, issuer: &str| link(&rule(cert), Start::EndEntity, &rule(issuer), None).unwrap_err();
        let e = refused("piv-slot-no-certsign", "piv-device-no-certsign");
        assert!(e.to_string().contains("may not sign certificates: its keyUsage lacks keyCertSign"), "{e}");
        let e = refused("piv-slot-critical", "piv-device");
        assert!(e.to_string().contains("has the critical extension 1.2.3.4"), "{e}");
        let e = refused("piv-slot-no-certsign", "piv-device");
        assert!(e.to_string().contains("signature does not verify"), "{e}");
        let e = refused("piv-slot", "piv-slot");
        assert!(e.to_string().contains("is not a CA"), "{e}");
        let from = slot.parsed().tbs_certificate().validity().not_before.to_unix_duration().as_secs();
        link(&slot, Start::EndEntity, &device, Some(from)).unwrap();
        let e = link(&slot, Start::EndEntity, &device, Some(from - 1)).unwrap_err();
        assert!(e.to_string().contains("piv-slot' is not valid at"), "{e}");
    }

    /// The name links of the chain compare the decoded Names (attest.rs F4).
    #[test]
    fn issuers_are_linked_by_name() {
        let [root, f9, slot] = ["root.pem", "f9.pem", "slot.pem"].map(cert);
        assert!(root.issued(&f9) && f9.issued(&slot) && root.issued(&root));
        assert!(!root.issued(&slot) && !slot.issued(&f9) && !f9.issued(&root));
    }

    /// Returns a CA certificate with the subject of the fixture root but a different key. Its
    /// name matches, but a signature check with its key fails.
    fn decoy_root() -> Cert {
        let mut der = der_of("root.pem");
        let root = Cert::from_der(der.clone()).unwrap();
        let spki = root.parsed.tbs_certificate().subject_public_key_info().to_der().unwrap();
        let at = der.windows(spki.len()).position(|w| w == spki).unwrap();
        // The test changes a byte in the middle of the RSA modulus.
        der[at + spki.len() / 2] ^= 0x01;
        Cert::from_der(der).unwrap()
    }

    /// The walk tries every issuer whose subject matches. A certificate in the pool, or an earlier
    /// anchor, with the root's subject but a different key (a CA that got a new key) does not hide
    /// the root that signed the chain (attest.rs F5). When only the decoy is present, the walk
    /// returns its signature error.
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
