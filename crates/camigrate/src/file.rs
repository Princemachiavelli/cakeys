//! Passphrase-protected key files (docs/CAMIGRATE.md D2 `file`, D4; phase 4b): for a target cakeys
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
pub(crate) const PBKDF2_ITERATIONS: u32 = 600_000;
/// PKCS#12 KDF iterations for the MAC key: as many as for the key. Both derive from the one
/// passphrase, so the cheaper of the two is what a guess costs.
const MAC_ITERATIONS: i32 = 600_000;
/// The most KDF iterations a key file read here may ask for: a file is input, and its count is
/// otherwise how long this process hangs.
const MAX_ITERATIONS: u32 = 10_000_000;
/// The most encrypted containers a PKCS#12 read here may hold: each runs a KDF of up to
/// [`MAX_ITERATIONS`], so this bounds a file's work beside its MAC's and its key's. OpenSSL
/// writes one (the certificates).
const MAX_ENCRYPTED_CONTAINERS: usize = 2;
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_ENCRYPTED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
/// PKCS#12's `keyBag` (RFC 7292 §4.2.1): a key not encrypted, which `openssl pkcs12 -keypbe NONE`
/// writes. Refused by name.
const ID_KEY_BAG: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.1");
/// What a PKCS#12 written before OpenSSL 3, or with `-legacy`, is refused with: how to re-export it.
const LEGACY_P12: &str = "a PKCS#12 from before OpenSSL 3 or `-legacy`; re-export it: \
                          openssl pkcs12 -in old.p12 -legacy -nodes | openssl pkcs12 -export -out new.p12";

/// What a key file held: the private key (PKCS#8), the certificates a PKCS#12 carried (the
/// first is the key's, as exporters write it), and the method that names the format.
pub(crate) struct Read {
    pub pkcs8: Zeroizing<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
    pub method: cakeys_core::migrate::Method,
}

fn bad(what: impl std::fmt::Display) -> KmError {
    KmError::Validation(format!("the key file: {what}").into())
}

/// Why a key file was not opened, by [`decrypt`].
pub(crate) enum Unopened {
    /// The passphrase does not open it, or it is damaged.
    Wrong,
    /// It names more KDF work than this process will do, or a scheme other than PBES2.
    Refused(KmError),
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
    Ok(b)
}

/// `pkcs8` encrypted under `pass`: the DER of an `EncryptedPrivateKeyInfo`.
fn encrypt(pkcs8: &[u8], pass: &str) -> Result<Vec<u8>> {
    let params =
        pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(PBKDF2_ITERATIONS, &random::<16>()?, random::<16>()?)
            .map_err(|e| KmError::Unavailable(format!("PBES2 parameters: {e}").into()))?;
    let info = pkcs8::PrivateKeyInfoRef::try_from(pkcs8).map_err(|_| bad("the key is not PKCS#8"))?;
    let doc = info
        .encrypt_with_params(params, pass)
        .map_err(|e| KmError::Unavailable(format!("PBES2 encryption: {e}").into()))?;
    Ok(doc.as_bytes().to_vec())
}

/// `pkcs8-pbes2`: the key as a PEM `ENCRYPTED PRIVATE KEY`.
///
/// # Errors
///
/// `Unavailable` when the random number generator or the encryption fails.
pub(crate) fn write_pkcs8(pkcs8: &[u8], pass: &str) -> Result<String> {
    let der = encrypt(pkcs8, pass)?;
    der::pem::encode_string("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF, &der)
        .map_err(|e| KmError::Unavailable(format!("PEM encoding: {e}").into()))
}

/// `pkcs12`: the key (PBES2, as `write_pkcs8`) beside its `certificate`, both tagged with
/// `local_key_id` so importers pair them, under an HMAC-SHA256 MAC. DER.
///
/// # Errors
///
/// `Unavailable` when the random number generator, the encryption or the encoding fails.
pub(crate) fn write_pkcs12(pkcs8: &[u8], certificate: &[u8], pass: &str, local_key_id: &[u8]) -> Result<Vec<u8>> {
    let enc = |e: der::Error| KmError::Unavailable(format!("PKCS#12 encoding: {e}").into());
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
            .map_err(|e| KmError::Validation(format!("the PKCS#12 MAC key: {e}").into()))?,
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
/// `Validation` (17) for a file that is neither (a PEM file holding anything but one
/// `ENCRYPTED PRIVATE KEY` block), a PKCS#12 without a MAC or with another MAC digest than
/// SHA-256, without exactly one key, with more than [`MAX_ENCRYPTED_CONTAINERS`] encrypted
/// containers or a legacy-encrypted one, with a certificate bag that is not X.509, with an
/// iteration count out of range, or for a wrong passphrase (the MAC, or the
/// padding check): bad input, never the "other material than the lock pins" that 10 means.
pub(crate) fn read(bytes: &[u8], pass: &str) -> Result<Read> {
    use cakeys_core::migrate::Method;
    // PEM wherever its block starts, as an object's own file is read (`keyfile::pem_blocks`):
    // after a byte-order mark, a blank line or OpenSSL's `Bag Attributes` text too.
    if let Some(text) = crate::keyfile::pem_text(bytes) {
        let blocks = crate::keyfile::pem_blocks(text)
            .map_err(|e| bad(e.into_msg().map_or_else(String::new, cakeys_core::Msg::into_text)))?;
        let block = match blocks.as_slice() {
            [("ENCRYPTED PRIVATE KEY", block)] => *block,
            [(label, _)] => return Err(bad(format!("a PEM {label}, not an ENCRYPTED PRIVATE KEY"))),
            _ => return Err(bad(format!("{} PEM blocks, where one ENCRYPTED PRIVATE KEY is meant", blocks.len()))),
        };
        let (_, der) = der::pem::decode_vec(block.as_bytes()).map_err(bad)?;
        let pkcs8 = decrypt_pkcs8(&der, pass)?;
        return Ok(Read { pkcs8, certificates: Vec::new(), method: Method::Pkcs8Pbes2 });
    }
    let pfx = Pfx::from_der(bytes).map_err(|e| bad(format!("neither an encrypted PKCS#8 PEM nor PKCS#12: {e}")))?;
    let auth_safe = octets(&pfx.auth_safe)?;
    let mac_data = pfx.mac_data.ok_or_else(|| bad("a PKCS#12 without a MAC"))?;
    if mac_data.mac.algorithm.oid != ID_SHA256 {
        return Err(bad(format!("a PKCS#12 MAC by {}, not SHA-256: {LEGACY_P12}", mac_data.mac.algorithm.oid)));
    }
    if !u32::try_from(mac_data.iterations).is_ok_and(|n| (1..=MAX_ITERATIONS).contains(&n)) {
        return Err(bad(format!("a PKCS#12 MAC of {} iterations", mac_data.iterations)));
    }
    let want = mac(pass, mac_data.mac_salt.as_bytes(), mac_data.iterations, &auth_safe)?;
    if !cakeys_core::pop::ct_eq(&want, mac_data.mac.digest.as_bytes()) {
        return Err(wrong());
    }
    let (mut pkcs8, mut certificates) = (None, Vec::new());
    let infos = Vec::<ContentInfo>::from_der(&auth_safe).map_err(bad)?;
    // Each encrypted container runs a KDF of its own: bounded per file, not only per KDF.
    let encrypted = infos.iter().filter(|i| i.content_type == ID_ENCRYPTED_DATA).count();
    if encrypted > MAX_ENCRYPTED_CONTAINERS {
        return Err(bad(format!(
            "a PKCS#12 of {encrypted} encrypted containers, each its own key derivation (at most \
             {MAX_ENCRYPTED_CONTAINERS} are read)"
        )));
    }
    for info in infos {
        let bags = if info.content_type == ID_ENCRYPTED_DATA { encrypted_octets(&info, pass)? } else { octets(&info)? };
        for bag in Vec::<SafeBag>::from_der(&bags).map_err(bad)? {
            // A key bag's value is the key itself: wiped as the containers are.
            let value = Zeroizing::new(
                ContextSpecific::<Any>::from_der(&bag.bag_value).map_err(bad)?.value.to_der().map_err(bad)?,
            );
            if bag.bag_id == ID_KEY_BAG {
                // Said as what it is, not as a file without a key (review 2026-11-23 C-22).
                return Err(bad(
                    "a PKCS#12 whose key is not encrypted (a keyBag, `-keypbe NONE`); re-export it with a key \
                     encryption: `openssl pkcs12 -in old.p12 -nodes | openssl pkcs12 -export -out new.p12`",
                ));
            }
            if bag.bag_id == pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
                if pkcs8.is_some() {
                    return Err(bad("a PKCS#12 with more than one key"));
                }
                pkcs8 = Some(decrypt_pkcs8(&value, pass)?);
            } else if bag.bag_id == pkcs12::PKCS_12_CERT_BAG_OID {
                let cert = CertBag::from_der(&value).map_err(bad)?;
                if cert.cert_id != pkcs12::PKCS_12_X509_CERT_OID {
                    return Err(bad(format!("a certificate bag of type {}, not an X.509 certificate", cert.cert_id)));
                }
                certificates.push(cert.cert_value.as_bytes().to_vec());
            }
        }
    }
    let pkcs8 = pkcs8.ok_or_else(|| bad("a PKCS#12 without a shrouded key bag"))?;
    Ok(Read { pkcs8, certificates, method: Method::Pkcs12 })
}

/// What a wrong passphrase, or a damaged file, is refused with.
fn wrong() -> KmError {
    bad("it does not open under this passphrase (a wrong passphrase, or a damaged file)")
}

/// The PKCS#8 an `EncryptedPrivateKeyInfo` holds under `pass`, or why not (17).
pub(crate) fn decrypt_pkcs8(der: &[u8], pass: &str) -> Result<Zeroizing<Vec<u8>>> {
    decrypt(der, pass).map_err(|e| match e {
        Unopened::Wrong => wrong(),
        Unopened::Refused(e) => e,
    })
}

/// The content of a `data` `ContentInfo`: its octets. Any other type than this and
/// `encryptedData` ([`encrypted_octets`]) is not read. Wiped when dropped, as a key bag in it
/// may be.
fn octets(info: &ContentInfo) -> Result<Zeroizing<Vec<u8>>> {
    if info.content_type != ID_DATA {
        return Err(bad(format!("a PKCS#12 container of type {}, not data", info.content_type)));
    }
    Ok(Zeroizing::new(info.content.decode_as::<OctetString>().map_err(bad)?.as_bytes().to_vec()))
}

/// The content of an `encryptedData` `ContentInfo` under `pass`: where OpenSSL 3 puts the
/// certificate bags by default, PBES2-encrypted like the key. A legacy scheme (RC2, 3DES) is
/// refused with the re-export hint. Wiped when dropped: what is decrypted may hold a key.
fn encrypted_octets(info: &ContentInfo, pass: &str) -> Result<Zeroizing<Vec<u8>>> {
    let data = info.content.decode_as::<pkcs12::cms::encrypted_data::EncryptedData>().map_err(bad)?;
    let content = &data.enc_content_info;
    if content.content_type != ID_DATA {
        return Err(bad(format!("a PKCS#12 encrypted container of type {}, not data", content.content_type)));
    }
    let ciphertext = content.encrypted_content.as_ref().ok_or_else(|| bad("a PKCS#12 encrypted container, empty"))?;
    let scheme = pkcs8::pkcs5::EncryptionScheme::from_der(&content.content_enc_alg.to_der().map_err(bad)?)
        .map_err(|_| bad(LEGACY_P12))?;
    let pkcs8::pkcs5::EncryptionScheme::Pbes2(params) = &scheme else { return Err(bad(LEGACY_P12)) };
    if let Some(why) = kdf_refused(params) {
        return Err(bad(why));
    }
    scheme.decrypt(pass, ciphertext.as_bytes()).map(Zeroizing::new).map_err(|_| wrong())
}

/// Why a PBES2 key file is not opened on its KDF parameters alone: more work than this process
/// will do (a file is input, and its count is otherwise how long this process hangs).
fn kdf_refused(params: &pbes2::Parameters) -> Option<String> {
    if let Some(k) = params.kdf.pbkdf2()
        && too_many(k.iteration_count)
    {
        return Some(format!("PBKDF2 with {} iterations", k.iteration_count));
    }
    if let Some(k) = params.kdf.scrypt()
        && too_much_scrypt(k.cost_parameter, k.block_size.into(), k.parallelization.into())
    {
        return Some("scrypt parameters beyond what this process spends".into());
    }
    None
}

/// Whether a key file's KDF iteration count is more than this process will run.
fn too_many(iterations: u32) -> bool {
    iterations > MAX_ITERATIONS
}

/// Whether a key file's scrypt parameters ask for more than this process will spend: scrypt
/// holds 128 × N × r bytes, so N × r is capped at 2²³ (1 GiB; OpenSSL's default is 2¹⁷), and p,
/// which multiplies the time, at 16.
fn too_much_scrypt(n: u64, r: u64, p: u64) -> bool {
    n.saturating_mul(r) > 1 << 23 || p > 16
}

/// The PKCS#8 in an `EncryptedPrivateKeyInfo` under `pass`: `Wrong` when it does not decrypt (a
/// wrong passphrase fails the padding check) or is no such structure; `Refused` for a scheme
/// other than PBES2 (a key bag of a legacy PKCS#12) or more KDF work than this process does.
fn decrypt(der: &[u8], pass: &str) -> std::result::Result<Zeroizing<Vec<u8>>, Unopened> {
    let info = EncryptedPrivateKeyInfoRef::try_from(der).map_err(|_| Unopened::Wrong)?;
    // The file names its own KDF cost: bounded, like the PKCS#12 MAC's.
    let Some(params) = info.encryption_algorithm.pbes2() else { return Err(Unopened::Refused(bad(LEGACY_P12))) };
    if let Some(why) = kdf_refused(params) {
        return Err(Unopened::Refused(bad(why)));
    }
    let doc = info.decrypt(pass).map_err(|_| Unopened::Wrong)?;
    Ok(Zeroizing::new(doc.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256_pkcs8() -> Vec<u8> {
        der::pem::decode_vec(include_bytes!("../../cli/tests/fixtures/tpm-import-p256.pem")).unwrap().1
    }

    /// Both formats round-trip under the passphrase, a wrong one is 17, and the PKCS#12 carries
    /// the certificate.
    #[test]
    fn key_files_round_trip_and_refuse_another_passphrase() {
        let key = p256_pkcs8();
        let pem = write_pkcs8(&key, "pass phrase").unwrap();
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let r = read(pem.as_bytes(), "pass phrase").unwrap();
        assert_eq!(
            (r.pkcs8.as_slice(), r.certificates.is_empty(), r.method),
            (key.as_slice(), true, cakeys_core::migrate::Method::Pkcs8Pbes2)
        );
        assert!(matches!(read(pem.as_bytes(), "other"), Err(KmError::Validation(_))));
        let cert = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");
        let p12 = write_pkcs12(&key, cert, "pass phrase", b"id").unwrap();
        let r = read(&p12, "pass phrase").unwrap();
        assert_eq!((r.pkcs8.as_slice(), r.certificates.as_slice()), (key.as_slice(), [cert.to_vec()].as_slice()));
        assert!(matches!(read(&p12, "other"), Err(KmError::Validation(_))));
        assert!(matches!(read(b"not a key file", "x"), Err(KmError::Validation(_))));
    }

    /// Each file is encrypted under its own salt and IV, and a PKCS#12 changed after it was
    /// written fails its MAC, under the right passphrase too.
    #[test]
    fn key_files_are_salted_and_authenticated() {
        let key = p256_pkcs8();
        assert_ne!(write_pkcs8(&key, "pass phrase").unwrap(), write_pkcs8(&key, "pass phrase").unwrap());
        let cert = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");
        let p12 = write_pkcs12(&key, cert, "pass phrase", b"id").unwrap();
        // A byte of the certificate, inside the authenticated content.
        let at = p12.windows(cert.len()).position(|w| w == cert).unwrap() + cert.len() / 2;
        let mut tampered = p12.clone();
        tampered[at] ^= 1;
        assert!(read(&p12, "pass phrase").is_ok());
        assert!(matches!(read(&tampered, "pass phrase"), Err(KmError::Validation(_))));
    }

    fn data(bytes: Vec<u8>) -> ContentInfo {
        ContentInfo { content_type: ID_DATA, content: Any::encode_from(&OctetString::new(bytes).unwrap()).unwrap() }
    }

    /// A PKCS#12 of `auth_safe`, under a MAC by the digest and iterations of `mac_by` (computed
    /// when the reader would get as far as checking it).
    fn pfx(auth_safe: ContentInfo, mac_by: Option<(ObjectIdentifier, i32)>) -> Vec<u8> {
        let mac_data = mac_by.map(|(oid, iterations)| {
            let digest = match octets(&auth_safe) {
                Ok(content) if (1..=MAC_ITERATIONS).contains(&iterations) => {
                    mac("pass", b"salt", iterations, &content).unwrap()
                }
                _ => vec![0; 32],
            };
            MacData {
                mac: DigestInfo {
                    algorithm: AlgorithmIdentifierOwned { oid, parameters: Some(Any::null()) },
                    digest: OctetString::new(digest).unwrap(),
                },
                mac_salt: OctetString::new(b"salt".to_vec()).unwrap(),
                iterations,
            }
        });
        Pfx { version: pkcs12::pfx::Version::V3, auth_safe, mac_data }.to_der().unwrap()
    }

    fn refusal(bytes: &[u8]) -> String {
        match read(bytes, "pass") {
            Err(KmError::Validation(m)) => m.into_text(),
            Err(e) => panic!("not a validation error: {e}"),
            Ok(_) => panic!("the file was read"),
        }
    }

    /// A file is input: what this tool would not have written is refused (17) by name, before
    /// any key in it is used.
    #[test]
    fn key_files_of_another_shape_are_refused() {
        let key_bag = SafeBag {
            bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: encrypt(&p256_pkcs8(), "pass").unwrap(),
            bag_attributes: None,
        };
        let safe = |bags: Vec<SafeBag>| data(vec![data(bags.to_der().unwrap())].to_der().unwrap());
        let sha256 = Some((ID_SHA256, MAC_ITERATIONS));
        let sha1 = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
        let cases = [
            (pfx(safe(vec![]), None), "a PKCS#12 without a MAC"),
            (pfx(safe(vec![]), Some((sha1, MAC_ITERATIONS))), "not SHA-256"),
            (pfx(safe(vec![]), Some((ID_SHA256, 0))), "a PKCS#12 MAC of 0 iterations"),
            (pfx(safe(vec![]), Some((ID_SHA256, i32::MAX))), "iterations"),
            (pfx(safe(vec![]), sha256), "a PKCS#12 without a shrouded key bag"),
            (pfx(safe(vec![key_bag.clone(), key_bag.clone()]), sha256), "a PKCS#12 with more than one key"),
            (pfx(ContentInfo { content_type: ID_SHA256, ..safe(vec![]) }, sha256), "not data"),
            (
                pfx(data(vec![ContentInfo { content_type: ID_SHA256, ..data(vec![]) }].to_der().unwrap()), sha256),
                "not data",
            ),
        ];
        for (file, want) in cases {
            let got = refusal(&file);
            assert!(got.contains(want), "{want}: {got}");
        }
        assert!(read(&pfx(safe(vec![key_bag.clone()]), sha256), "pass").is_ok());
        assert!(refusal(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nnot base64\n").starts_with("the key file: "));

        // A key file naming more KDF iterations than this process will run is not opened: it is
        // turned away on the count alone (running them would take this test minutes). The bound
        // first, so a wrong one fails here rather than running the count.
        assert!(too_many(MAX_ITERATIONS + 1) && !too_many(MAX_ITERATIONS) && !too_many(PBKDF2_ITERATIONS));
        // scrypt's memory, likewise: OpenSSL's default passes, 16 GiB or a p of thousands does not.
        assert!(!too_much_scrypt(1 << 14, 8, 1) && !too_much_scrypt(1 << 20, 8, 1));
        assert!(too_much_scrypt(1 << 24, 8, 1) && too_much_scrypt(1 << 14, 8, 4096) && too_much_scrypt(u64::MAX, 8, 1));
        let params = pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(MAX_ITERATIONS + 1, &[0; 16], [0; 16]);
        let slow = pkcs8::EncryptedPrivateKeyInfoOwned {
            encryption_algorithm: params.unwrap().into(),
            encrypted_data: OctetString::new(vec![0; 32]).unwrap(),
        };
        assert!(matches!(decrypt(&slow.to_der().unwrap(), "pass"), Err(Unopened::Refused(_))));

        // Every certificate is read, in the file's order: the key's first, as exporters write it.
        let cert_bag = |der: &[u8]| SafeBag {
            bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
            bag_value: CertBag { cert_id: pkcs12::PKCS_12_X509_CERT_OID, cert_value: OctetString::new(der).unwrap() }
                .to_der()
                .unwrap(),
            bag_attributes: None,
        };
        let chain = pfx(safe(vec![cert_bag(b"leaf"), cert_bag(b"issuer"), key_bag.clone()]), sha256);
        assert_eq!(read(&chain, "pass").unwrap().certificates, [b"leaf".to_vec(), b"issuer".to_vec()]);

        // A certificate bag of another type than X.509 (an SDSI certificate) is refused by name,
        // not read as DER (review file.rs F3).
        let sdsi = SafeBag {
            bag_value: CertBag {
                cert_id: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.2"),
                cert_value: OctetString::new(b"(certificate)".as_slice()).unwrap(),
            }
            .to_der()
            .unwrap(),
            ..cert_bag(b"")
        };
        let got = refusal(&pfx(safe(vec![sdsi, key_bag]), sha256));
        assert!(got.contains("not an X.509 certificate"), "{got}");

        // Every encrypted container runs a KDF: past MAX_ENCRYPTED_CONTAINERS the file is
        // refused before any of them runs (review file.rs F2).
        let encrypted = ContentInfo { content_type: ID_ENCRYPTED_DATA, ..data(vec![]) };
        let many = vec![encrypted; MAX_ENCRYPTED_CONTAINERS + 1];
        let got = refusal(&pfx(data(many.to_der().unwrap()), sha256));
        assert!(got.contains("3 encrypted containers"), "{got}");
    }

    /// An encrypted PKCS#8 PEM reads wherever its block starts: after a byte-order mark, a blank
    /// line or OpenSSL's `Bag Attributes` text (review file.rs F4). Another PEM, or several
    /// blocks, is refused by name.
    #[test]
    fn an_encrypted_pem_reads_wherever_its_block_starts() {
        let key = p256_pkcs8();
        let pem = write_pkcs8(&key, "pass").unwrap();
        for lead in ["\u{feff}", "\n", "Bag Attributes\n    localKeyId: 01 02\nKey Attributes: <No Attributes>\n"] {
            let read = read(format!("{lead}{pem}").as_bytes(), "pass").unwrap_or_else(|e| panic!("{lead:?}: {e}"));
            assert_eq!(*read.pkcs8, key, "{lead:?}");
        }
        let cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(refusal(cert.as_bytes()).contains("a PEM CERTIFICATE, not an ENCRYPTED PRIVATE KEY"));
        assert!(refusal(format!("{cert}{pem}").as_bytes()).contains("2 PEM blocks"));
    }
}
