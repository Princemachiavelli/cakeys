//! Passphrase-protected key files (MIGRATE.md D2 `file`, D4; phase 4b): for a target cakeys
//! cannot reach, one private key leaves as a PKCS#8 `EncryptedPrivateKeyInfo` (`pkcs8-pbes2`,
//! PEM) or as PKCS#12 with its certificate (`pkcs12`, what Java, Windows and cloud key vaults
//! import). Plaintext-equivalent at rest, guarded only by the passphrase: only behind
//! `--allow-host-plaintext` and a `--passphrase-file`. Both encrypt the key with PBES2:
//! PBKDF2-HMAC-SHA256 and AES-256-CBC; PKCS#12's integrity is an HMAC-SHA256 under its own KDF.
//! Every plaintext buffer is zeroized; nothing here formats a key or the passphrase.

use cakeys_core::{KmError, Result};
use der::asn1::{ContextSpecific, ObjectIdentifier, OctetString};
use der::{Any, Decode as _, Encode as _};
use hmac::{KeyInit as _, Mac as _};
use pkcs8::EncryptedPrivateKeyInfoRef;
use pkcs8::pkcs5::pbes2;
use pkcs12::cms::content_info::ContentInfo;
use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
use pkcs12::{CertBag, DigestInfo, MacData, Pfx, SafeBag};
use x509_cert::spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

/// PBKDF2-HMAC-SHA256 iterations for the key (OWASP's 2023 recommendation).
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// PKCS#12 KDF iterations for the MAC key (integrity only; the key is under PBES2 above).
const MAC_ITERATIONS: i32 = 10_000;
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

/// What a key file held: the private key (PKCS#8), the certificate a PKCS#12 carried, and the
/// method that names the format.
pub struct Read {
    pub pkcs8: Zeroizing<Vec<u8>>,
    pub certificate: Option<Vec<u8>>,
    pub method: cakeys_core::migrate::Method,
}

fn bad(what: impl std::fmt::Display) -> KmError {
    KmError::Validation(format!("the key file: {what}"))
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}")))?;
    Ok(b)
}

/// `pkcs8` encrypted under `pass`: the DER of an `EncryptedPrivateKeyInfo`.
fn encrypt(pkcs8: &[u8], pass: &str) -> Result<Vec<u8>> {
    let params =
        pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(PBKDF2_ITERATIONS, &random::<16>()?, random::<16>()?)
            .map_err(|e| KmError::Unavailable(format!("PBES2 parameters: {e}")))?;
    let info = pkcs8::PrivateKeyInfoRef::try_from(pkcs8).map_err(|_| bad("the key is not PKCS#8"))?;
    let doc =
        info.encrypt_with_params(params, pass).map_err(|e| KmError::Unavailable(format!("PBES2 encryption: {e}")))?;
    Ok(doc.as_bytes().to_vec())
}

/// `pkcs8-pbes2`: the key as a PEM `ENCRYPTED PRIVATE KEY`.
///
/// # Errors
///
/// `Unavailable` when the random number generator or the encryption fails.
pub fn write_pkcs8(pkcs8: &[u8], pass: &str) -> Result<String> {
    let der = encrypt(pkcs8, pass)?;
    der::pem::encode_string("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF, &der)
        .map_err(|e| KmError::Unavailable(format!("PEM encoding: {e}")))
}

/// `pkcs12`: the key (PBES2, as `write_pkcs8`) beside its `certificate`, both tagged with
/// `local_key_id` so importers pair them, under an HMAC-SHA256 MAC. DER.
///
/// # Errors
///
/// `Unavailable` when the random number generator, the encryption or the encoding fails.
pub fn write_pkcs12(pkcs8: &[u8], certificate: &[u8], pass: &str, local_key_id: &[u8]) -> Result<Vec<u8>> {
    let enc = |e: der::Error| KmError::Unavailable(format!("PKCS#12 encoding: {e}"));
    let attrs = || -> Result<x509_cert::attr::Attributes> {
        let id = Any::encode_from(&OctetString::new(local_key_id).map_err(enc)?).map_err(enc)?;
        let attr = x509_cert::attr::Attribute { oid: ID_LOCAL_KEY_ID, values: [id].to_vec().try_into().map_err(enc)? };
        [attr].to_vec().try_into().map_err(enc)
    };
    let key_bag = SafeBag {
        bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        bag_value: encrypt(pkcs8, pass)?,
        bag_attributes: Some(attrs()?),
    };
    let cert_bag = SafeBag {
        bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
        bag_value: CertBag {
            cert_id: pkcs12::PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(certificate).map_err(enc)?,
        }
        .to_der()
        .map_err(enc)?,
        bag_attributes: Some(attrs()?),
    };
    let data = |bytes: Vec<u8>| -> Result<ContentInfo> {
        Ok(ContentInfo {
            content_type: ID_DATA,
            content: Any::encode_from(&OctetString::new(bytes).map_err(enc)?).map_err(enc)?,
        })
    };
    let safe = vec![data(vec![cert_bag].to_der().map_err(enc)?)?, data(vec![key_bag].to_der().map_err(enc)?)?];
    let auth_safe = safe.to_der().map_err(enc)?;
    let salt = random::<16>()?;
    let mac = mac(pass, &salt, MAC_ITERATIONS, &auth_safe)?;
    let pfx = Pfx {
        version: pkcs12::pfx::Version::V3,
        auth_safe: data(auth_safe)?,
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned { oid: ID_SHA256, parameters: Some(Any::null()) },
                digest: OctetString::new(mac).map_err(enc)?,
            },
            mac_salt: OctetString::new(salt.to_vec()).map_err(enc)?,
            iterations: MAC_ITERATIONS,
        }),
    };
    pfx.to_der().map_err(enc)
}

/// HMAC-SHA256 of `data` under the PKCS#12 MAC key of `pass` and `salt`.
fn mac(pass: &str, salt: &[u8], iterations: i32, data: &[u8]) -> Result<Vec<u8>> {
    let key = Zeroizing::new(
        derive_key_utf8::<sha2::Sha256>(pass, salt, Pkcs12KeyType::Mac, iterations, 32)
            .map_err(|e| KmError::Validation(format!("the PKCS#12 MAC key: {e}")))?,
    );
    let mut m =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).map_err(|_| KmError::Unavailable("HMAC key".into()))?;
    m.update(data);
    Ok(m.finalize().into_bytes().to_vec())
}

/// Read a key file: a PEM `ENCRYPTED PRIVATE KEY` (`pkcs8-pbes2`) or a DER PKCS#12 (`pkcs12`,
/// its MAC checked first), decrypted under `pass`.
///
/// # Errors
///
/// `Validation` (17) for a file that is neither, a PKCS#12 without a MAC or with another MAC
/// digest than SHA-256, without exactly one key, or with an encrypted (rather than plain) bag
/// container; `HashMismatch` (10) for a wrong passphrase (the MAC, or the padding check).
pub fn read(bytes: &[u8], pass: &str) -> Result<Read> {
    use cakeys_core::migrate::Method;
    let wrong = || KmError::HashMismatch {
        what: "the key file's passphrase".into(),
        expected: "the passphrase it was written with".into(),
        got: "another".into(),
    };
    if bytes.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let text = std::str::from_utf8(bytes).map_err(bad)?;
        let (label, der) = der::pem::decode_vec(text.as_bytes()).map_err(bad)?;
        if label != "ENCRYPTED PRIVATE KEY" {
            return Err(bad(format!("a PEM {label}")));
        }
        let pkcs8 = decrypt(&der, pass).ok_or_else(wrong)?;
        return Ok(Read { pkcs8, certificate: None, method: Method::Pkcs8Pbes2 });
    }
    let pfx = Pfx::from_der(bytes).map_err(|e| bad(format!("neither an encrypted PKCS#8 PEM nor PKCS#12: {e}")))?;
    let auth_safe = octets(&pfx.auth_safe)?;
    let mac_data = pfx.mac_data.ok_or_else(|| bad("a PKCS#12 without a MAC"))?;
    if mac_data.mac.algorithm.oid != ID_SHA256 {
        return Err(bad(format!("a PKCS#12 MAC by {}, not SHA-256", mac_data.mac.algorithm.oid)));
    }
    let want = mac(pass, mac_data.mac_salt.as_bytes(), mac_data.iterations, &auth_safe)?;
    if !cakeys_core::pop::ct_eq(&want, mac_data.mac.digest.as_bytes()) {
        return Err(wrong());
    }
    let (mut pkcs8, mut certificate) = (None, None);
    for info in Vec::<ContentInfo>::from_der(&auth_safe).map_err(bad)? {
        for bag in Vec::<SafeBag>::from_der(&octets(&info)?).map_err(bad)? {
            let value = ContextSpecific::<Any>::from_der(&bag.bag_value).map_err(bad)?.value.to_der().map_err(bad)?;
            if bag.bag_id == pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
                if pkcs8.is_some() {
                    return Err(bad("a PKCS#12 with more than one key"));
                }
                pkcs8 = Some(decrypt(&value, pass).ok_or_else(wrong)?);
            } else if bag.bag_id == pkcs12::PKCS_12_CERT_BAG_OID && certificate.is_none() {
                certificate = Some(CertBag::from_der(&value).map_err(bad)?.cert_value.as_bytes().to_vec());
            }
        }
    }
    let pkcs8 = pkcs8.ok_or_else(|| bad("a PKCS#12 without a shrouded key bag"))?;
    Ok(Read { pkcs8, certificate, method: Method::Pkcs12 })
}

/// The content of a `data` `ContentInfo`: its octets. Anything else (password-encrypted bag
/// containers) is not read.
fn octets(info: &ContentInfo) -> Result<Vec<u8>> {
    if info.content_type != ID_DATA {
        return Err(bad(format!("a PKCS#12 container of type {}, not data", info.content_type)));
    }
    Ok(info.content.decode_as::<OctetString>().map_err(bad)?.as_bytes().to_vec())
}

/// The PKCS#8 in an `EncryptedPrivateKeyInfo` under `pass`; `None` when it does not decrypt
/// (a wrong passphrase fails the padding check), or is no such structure.
fn decrypt(der: &[u8], pass: &str) -> Option<Zeroizing<Vec<u8>>> {
    let doc = EncryptedPrivateKeyInfoRef::try_from(der).ok()?.decrypt(pass).ok()?;
    Some(Zeroizing::new(doc.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256_pkcs8() -> Vec<u8> {
        der::pem::decode_vec(include_bytes!("../../cli/tests/fixtures/tpm-import-p256.pem")).unwrap().1
    }

    /// Both formats round-trip under the passphrase, a wrong one is 10, and the PKCS#12 carries
    /// the certificate.
    #[test]
    fn key_files_round_trip_and_refuse_another_passphrase() {
        let key = p256_pkcs8();
        let pem = write_pkcs8(&key, "pass phrase").unwrap();
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let r = read(pem.as_bytes(), "pass phrase").unwrap();
        assert_eq!(
            (r.pkcs8.as_slice(), r.certificate, r.method),
            (key.as_slice(), None, cakeys_core::migrate::Method::Pkcs8Pbes2)
        );
        assert!(matches!(read(pem.as_bytes(), "other"), Err(KmError::HashMismatch { .. })));
        let cert = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");
        let p12 = write_pkcs12(&key, cert, "pass phrase", b"id").unwrap();
        let r = read(&p12, "pass phrase").unwrap();
        assert_eq!((r.pkcs8.as_slice(), r.certificate.as_deref()), (key.as_slice(), Some(cert.as_slice())));
        assert!(matches!(read(&p12, "other"), Err(KmError::HashMismatch { .. })));
        assert!(matches!(read(b"not a key file", "x"), Err(KmError::Validation(_))));
    }
}
