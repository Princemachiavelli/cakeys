//! Reads the files in which objects are born (docs/FILE.md). Such a file is the file that an
//! object's `migrate.file` names. This module reads it, in the formats that deployments use, into
//! the material from which a pair that says `origin = "file"` is created. A file's format is
//! recognised by its content, never by its extension. Every private-key format is normalised to
//! PKCS#8 `PrivateKeyInfo`, so a key from a file always takes the same host path
//! (`host::create_and_record`). A data object is its file's bytes as they are. A secret key is its
//! value's bytes, or hex or base64 text of those bytes. Every plaintext buffer is zeroized, and no
//! code here formats a key or a passphrase into a string.

use crate::file;
use base64::Engine as _;
use cakeys_core::config::{Encoding, ObjectCfg};
use cakeys_core::id::{self, Curve, Scheme};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::{KeyType, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use der::asn1::AnyRef;
use der::{Decode as _, Tagged as _};
use zeroize::Zeroizing;

/// The material that an object takes from its file.
pub(crate) struct Material {
    /// A private key's PKCS#8, a secret key's value, a certificate's DER, a public key's SPKI, or
    /// a data object's value.
    pub bytes: Zeroizing<Vec<u8>>,
    /// A private key's canonical SPKI.
    pub spki: Option<Vec<u8>>,
    /// The format, as the lock's `provenance.origin.method` records it.
    pub method: Method,
    /// `file` for secret material, `public` for the rest.
    pub exposure: Exposure,
}

/// One item that a structured file (PEM or DER) holds.
enum Entry {
    /// A private key, normalised to PKCS#8, and the format it came in.
    Key(Zeroizing<Vec<u8>>, Method),
    /// A certificate's DER.
    Certificate(Vec<u8>),
    /// A public key's SPKI.
    PublicKey(Vec<u8>),
}

/// Returns the refusal for a file: invalid input (17). The caller adds the file's name.
fn bad(what: impl std::fmt::Display) -> KmError {
    KmError::Validation(what.to_string().into())
}

/// The message that refuses OpenSSL's encrypted PEM format from before PKCS#8
/// (`Proc-Type: 4,ENCRYPTED`).
const LEGACY_PEM: &str = "a legacy encrypted PEM (Proc-Type/DEK-Info: one MD5 pass derives its key); convert it: \
                          openssl pkcs8 -topk8 -v2 aes-256-cbc -in old.pem -out new.pem";

/// The PEM blocks that carry nothing that an object takes, and that are skipped: curve parameters
/// and Diffie-Hellman parameters, which `openssl ecparam -genkey` and server bundles write next to
/// a key.
const SKIPPED: [&str; 3] = ["EC PARAMETERS", "DH PARAMETERS", "X9.42 DH PARAMETERS"];

/// Returns what `object` takes from the file content `bytes`: a private key's PKCS#8, a
/// certificate, a public key or a value. `private_data` marks a data object that a spec declares
/// `CKA_PRIVATE = true`. `pass` opens an encrypted key file. `encoding` is a secret key's
/// `migrate.encoding`.
///
/// # Errors
///
/// `Validation` (17) in these cases: a file that holds no such object, or several where one is
/// expected; an object of another type than `object`'s; a format that is refused, with the command
/// that converts it; an encrypted file without a passphrase, or with a passphrase that does not
/// open it; a secret key's value of another length; or a secret key's value in text that neither
/// `valueLen` nor `encoding` says how to read.
pub(crate) fn read(
    bytes: &[u8],
    object: &ObjectCfg,
    private_data: bool,
    pass: Option<&str>,
    encoding: Option<Encoding>,
) -> Result<Material> {
    let curve = object.curve().ok();
    let entries = |bytes| entries(bytes, pass, curve);
    match object.class {
        Class::SecretKey => secret(bytes, object, encoding),
        Class::Data => Ok(Material {
            bytes: Zeroizing::new(bytes.to_vec()),
            spki: None,
            method: if private_data { Method::Raw } else { Method::Public },
            exposure: if private_data { Exposure::File } else { Exposure::Public },
        }),
        Class::PrivateKey => {
            let (pkcs8, method) = one_key(entries(bytes)?)?;
            // A SEC1 key that was given the object's curve but is on another curve does not read
            // as a key at all. A malformed key, or a key of an algorithm that cakeys does not
            // read, also fails here, and the message says so.
            let spki = cakeys_core::plaintext::spki_of_pkcs8(&pkcs8).map_err(|e| {
                bad(format!("its key does not read as a key of the object's type ({e}); the object is {object}"))
            })?;
            let spki = id::spki_canonical(&spki)?;
            check_type(&spki, object)?;
            Ok(Material { bytes: pkcs8, spki: Some(spki), method, exposure: Exposure::File })
        }
        Class::Certificate => {
            let der = certificate(entries(bytes)?)?;
            Ok(Material { bytes: Zeroizing::new(der), spki: None, method: Method::Public, exposure: Exposure::Public })
        }
        Class::PublicKey => {
            let spki = id::spki_canonical(&public_key(entries(bytes)?)?)?;
            check_type(&spki, object)?;
            Ok(Material { bytes: Zeroizing::new(spki), spki: None, method: Method::Public, exposure: Exposure::Public })
        }
    }
}

/// A key file's private key (PKCS #8 DER), the certificates next to it in the file, and the format
/// in which it was read.
pub(crate) type PrivateKey = (Zeroizing<Vec<u8>>, Vec<Vec<u8>>, Method);

/// Returns the one private key that the file content `bytes` holds, as PKCS#8 with the format that
/// it came in, and the certificates next to it. This is what `import --in` takes from a key file,
/// in every format that [`read`] reads (review 2026-11-23 C-6). A key file names no object; the
/// lock finds the object by the key's identity. `pass` opens an encrypted file.
///
/// # Errors
///
/// The same errors as [`read`] for a private key.
pub(crate) fn private_key(bytes: &[u8], pass: Option<&str>) -> Result<PrivateKey> {
    let entries = entries(bytes, pass, None)?;
    let certificates =
        entries.iter().filter_map(|e| if let Entry::Certificate(c) = e { Some(c.clone()) } else { None }).collect();
    let (pkcs8, method) = one_key(entries)?;
    Ok((pkcs8, certificates, method))
}

/// Returns whether the file content `bytes` holds a private key, plain or encrypted. It decides by
/// the shape of the content alone, before anything is decoded. This matters because the import of
/// a certificate object from a PEM bundle or a PKCS#12 file decodes the private key next to it, so
/// that import also puts key plaintext in this process's memory.
///
/// The function uses the same scan that the reader uses to decode ([`pem_blocks`], [`der_kind`]),
/// so the two never disagree on what a file holds. A PEM file that the scan cannot split is taken
/// to hold a private key.
pub(crate) fn holds_private_key(bytes: &[u8]) -> bool {
    match pem_text(bytes) {
        Some(text) => pem_blocks(text).map_or(true, |blocks| blocks.iter().any(|(label, _)| is_private(label))),
        None => der_kind(bytes).is_some_and(DerKind::is_private),
    }
}

/// Returns whether a PEM label names a private key, in any of its formats (for example, encrypted
/// or OpenSSH).
fn is_private(label: &str) -> bool {
    label.contains("PRIVATE KEY")
}

/// Returns the file as PEM text when it is UTF-8 that contains a BEGIN line, and `None` otherwise
/// (for DER).
pub(crate) fn pem_text(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok().filter(|t| t.contains("-----BEGIN "))
}

/// Returns the IDs that the host computes from `m`, which the token must show once it holds the
/// object: the `rfc7093m4` of a key, the `certhash` of a certificate, or the `valuehash` of a data
/// object. The list is empty for a secret key, because only the token computes its commitments
/// (docs/FILE.md F3).
pub(crate) fn host_ids(object: &ObjectCfg, m: &Material) -> Vec<(Scheme, String)> {
    match object.class {
        Class::PrivateKey => m.spki.iter().map(|s| (Scheme::Rfc7093m4, id::sri(s))).collect(),
        Class::PublicKey => vec![(Scheme::Rfc7093m4, id::sri(&m.bytes))],
        Class::Certificate => vec![(Scheme::Certhash, id::sri(&m.bytes))],
        Class::Data => vec![(Scheme::Valuehash, id::sri(&m.bytes))],
        Class::SecretKey => Vec::new(),
    }
}

/// Returns the certificate among `certificates` whose public key is `spki` (canonical), which is
/// the certificate that a key file carries for its key.
pub(crate) fn key_certificate(certificates: &[Vec<u8>], spki: &[u8]) -> Option<Vec<u8>> {
    certificates.iter().find(|c| id::cert_spki(c).is_ok_and(|s| s == spki)).cloned()
}

/// Returns a secret key's value, which must be exactly the object's `valueLen` long when the object
/// has one. The value is the file's bytes, or hex or base64 text of those bytes, as `encoding`
/// says. Without `encoding`, the length decides: a file of exactly `valueLen` bytes is the value
/// itself, and any other file must be hex or base64 text of that many bytes. These three forms
/// never have the same length. Loading keys.toml requires `valueLen` or `encoding` (docs/FILE.md
/// F4), because the first file read would otherwise pin a guess as the object's identity (F3).
fn secret(bytes: &[u8], object: &ObjectCfg, encoding: Option<Encoding>) -> Result<Material> {
    if bytes.is_empty() {
        return Err(bad("it is empty, and a secret key's file holds its value"));
    }
    let want = object.value_len;
    let value = match (encoding, want) {
        (Some(e), _) => decode(bytes, e).ok_or_else(|| bad(format!("it is not {e} text, as migrate.encoding says")))?,
        (None, Some(n)) => detect(bytes, n)?,
        (None, None) => return Err(bad("neither the key's valueLen nor migrate.encoding says how to read it")),
    };
    let len = value.len() as u64;
    if len == 0 {
        return Err(bad("it holds no value, and a secret key's file holds its value"));
    }
    if let Some(want) = want
        && len != want
    {
        let e = encoding.filter(|e| *e != Encoding::Raw).map_or_else(String::new, |e| format!(" of {e}"));
        return Err(bad(format!("it holds {len} bytes{e}, and the key is {want}")));
    }
    Ok(Material { bytes: value, spki: None, method: Method::Raw, exposure: Exposure::File })
}

/// Returns the value that `bytes` spells in `encoding`. For hex and base64 text, all whitespace is
/// removed first, because hex dumps and base64 tools wrap their lines. Returns `None` when `bytes`
/// is not valid text in that encoding.
fn decode(bytes: &[u8], encoding: Encoding) -> Option<Zeroizing<Vec<u8>>> {
    let text: Zeroizing<Vec<u8>> = Zeroizing::new(bytes.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect());
    let value = match encoding {
        Encoding::Raw => bytes.to_vec(),
        Encoding::Hex => cakeys_core::hex::decode(std::str::from_utf8(&text).ok()?)?,
        Encoding::Base64 => base64::engine::general_purpose::STANDARD.decode(&*text).ok()?,
    };
    Some(Zeroizing::new(value))
}

/// Returns a secret key's `n`-byte value from a file whose encoding is not configured
/// ([`secret`]).
fn detect(bytes: &[u8], n: u64) -> Result<Zeroizing<Vec<u8>>> {
    // Check for the value itself first, before any whitespace is removed, because a key's bytes
    // may have any value.
    if bytes.len() as u64 == n {
        return Ok(Zeroizing::new(bytes.to_vec()));
    }
    let (hex, base64) = (decode(bytes, Encoding::Hex), decode(bytes, Encoding::Base64));
    let of_n = |v: &Zeroizing<Vec<u8>>| v.len() as u64 == n;
    let read = match (hex, base64) {
        (Some(v), _) | (_, Some(v)) if of_n(&v) => return Ok(v),
        (Some(v), _) => format!("; as hex it is {} bytes", v.len()),
        (None, Some(v)) => format!("; as base64 it is {} bytes", v.len()),
        (None, None) => String::new(),
    };
    Err(bad(format!(
        "it holds {} bytes, and the key is {n}: the value itself, or hex ({} digits) or base64 ({} characters) of \
         it{read}",
        bytes.len(),
        2 * n,
        n.div_ceil(3) * 4
    )))
}

/// Returns the file's one private key, and refuses a file with no private key or with several.
fn one_key(entries: Vec<Entry>) -> Result<(Zeroizing<Vec<u8>>, Method)> {
    let mut keys = entries.into_iter().filter_map(|e| match e {
        Entry::Key(k, m) => Some((k, m)),
        _ => None,
    });
    match (keys.next(), keys.next()) {
        (Some(key), None) => Ok(key),
        (None, _) => Err(bad("it holds no private key")),
        (Some(_), Some(_)) => Err(bad("it holds more than one private key; one object is one key")),
    }
}

/// Returns the file's certificate. When the file holds a private key, this is the certificate whose
/// public key matches that key. Otherwise, it is the file's only certificate.
fn certificate(entries: Vec<Entry>) -> Result<Vec<u8>> {
    let mut certs = Vec::new();
    let mut key = None;
    for e in entries {
        match e {
            Entry::Certificate(c) => certs.push(c),
            Entry::Key(k, _) if key.is_none() => key = Some(k),
            Entry::Key(..) => return Err(bad("it holds more than one private key")),
            Entry::PublicKey(_) => {}
        }
    }
    if certs.is_empty() {
        return Err(bad("it holds no certificate"));
    }
    if let Some(k) = key {
        let spki = id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(&k)?)?;
        return key_certificate(&certs, &spki)
            .ok_or_else(|| bad("none of its certificates is for the private key beside it"));
    }
    match <[Vec<u8>; 1]>::try_from(certs) {
        Ok([cert]) => Ok(cert),
        Err(certs) => Err(bad(format!(
            "it holds {} certificates and no private key to say which is meant; one certificate per file",
            certs.len()
        ))),
    }
}

/// Returns the file's public key: its one `PUBLIC KEY`, or else the public half of its one private
/// key.
fn public_key(entries: Vec<Entry>) -> Result<Vec<u8>> {
    let (mut spkis, mut keys) = (Vec::new(), Vec::new());
    for e in entries {
        match e {
            Entry::PublicKey(s) => spkis.push(s),
            Entry::Key(k, _) => keys.push(k),
            Entry::Certificate(_) => {}
        }
    }
    match (spkis.as_slice(), keys.as_slice()) {
        ([spki], _) => Ok(spki.clone()),
        ([], [key]) => cakeys_core::plaintext::spki_of_pkcs8(key),
        ([], []) => Err(bad("it holds no public key, nor a private key to take one from")),
        _ => Err(bad("it holds more than one public key")),
    }
}

/// Checks that the key `spki` (canonical) is of `object`'s type: RSA, or EC or Edwards on the
/// object's curve. An RSA key must also have as many bits as `modulusBits` says.
fn check_type(spki: &[u8], object: &ObjectCfg) -> Result<()> {
    let curve = id::KeyAlg::of_spki(spki).map(id::KeyAlg::curve).map_err(|e| bad(format!("its key: {e}")))?;
    let fits = match (object.key_type, curve) {
        (Some(KeyType::Rsa), None) => {
            use rsa::traits::PublicKeyParts as _;
            let key = id::rsa_of_spki(spki).map_err(|e| bad(format!("its RSA key: {e}")))?;
            let bits = u64::from(key.n().bit_width_vartime());
            if let Some(want) = object.modulus_bits.filter(|w| *w != bits) {
                return Err(bad(format!("its RSA key has {bits} bits, and the object declares {want}")));
            }
            true
        }
        (Some(KeyType::Ec | KeyType::EcEdwards), Some(c)) => object.curve().is_ok_and(|want| want == c),
        _ => false,
    };
    if fits {
        return Ok(());
    }
    let what = curve.map_or("an RSA key".to_owned(), |c| format!("a key on {}", c.name()));
    Err(bad(format!("it holds {what}, and the object is {object}")))
}

/// Returns everything that a PEM or DER file holds, with private keys normalised to PKCS#8.
/// `curve` is the object's curve, for a SEC1 key that names none.
fn entries(bytes: &[u8], pass: Option<&str>, curve: Option<Curve>) -> Result<Vec<Entry>> {
    match pem_text(bytes) {
        Some(text) => pem_entries(text, pass, curve),
        None => der_entry(bytes, pass, curve),
    }
}

/// Returns the blocks of a PEM file, each with its label. A block is found wherever its BEGIN
/// marker starts on a line, and the text between blocks (such as OpenSSL's `Bag Attributes`) is
/// skipped. Both [`holds_private_key`] and [`pem_entries`] read the file through this function.
pub(crate) fn pem_blocks(text: &str) -> Result<Vec<(&str, &str)>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let block = &rest[start..];
        let label_len =
            block["-----BEGIN ".len()..].find("-----").ok_or_else(|| bad("a PEM BEGIN line without its end"))?;
        let label = &block["-----BEGIN ".len()..][..label_len];
        let end_line = format!("-----END {label}-----");
        let end = block.find(&end_line).ok_or_else(|| bad(format!("a PEM {label} block without its END line")))?;
        let block = &block[..end + end_line.len()];
        rest = &rest[start + block.len()..];
        out.push((label, block));
    }
    Ok(out)
}

/// Decodes the blocks of a PEM file ([`pem_blocks`]) by their labels.
fn pem_entries(text: &str, pass: Option<&str>, curve: Option<Curve>) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for (label, block) in pem_blocks(text)? {
        if block.contains("Proc-Type:") {
            return Err(bad(LEGACY_PEM));
        }
        if SKIPPED.contains(&label) {
            continue;
        }
        let (_, der) =
            der::pem::decode_vec(block.as_bytes()).map_err(|e| bad(format!("its PEM {label} block: {e}")))?;
        let der = Zeroizing::new(der);
        out.push(match label {
            "PRIVATE KEY" => Entry::Key(pkcs8(&der)?, Method::Pkcs8),
            "ENCRYPTED PRIVATE KEY" => Entry::Key(encrypted(&der, pass)?, Method::Pkcs8Pbes2),
            "RSA PRIVATE KEY" => Entry::Key(from_pkcs1(&der)?, Method::Pkcs1),
            "EC PRIVATE KEY" => Entry::Key(from_sec1(&der, curve)?, Method::Sec1),
            "CERTIFICATE" => Entry::Certificate(certificate_der(&der)?),
            "PUBLIC KEY" => Entry::PublicKey(der.to_vec()),
            "OPENSSH PRIVATE KEY" => {
                return Err(bad("an OpenSSH private key; convert it: ssh-keygen -p -m PKCS8 -f <file>"));
            }
            "RSA PUBLIC KEY" => {
                return Err(bad(
                    "a PKCS#1 RSA PUBLIC KEY; convert it: openssl rsa -RSAPublicKey_in -pubout -in <file>",
                ));
            }
            other => return Err(bad(format!("a PEM {other} block, which camigrate does not read"))),
        });
    }
    Ok(out)
}

/// Returns what a DER file holds: a certificate, a public key, a private key in any of its
/// formats, or the key and the certificates of a PKCS#12 file.
fn der_entry(der: &[u8], pass: Option<&str>, curve: Option<Curve>) -> Result<Vec<Entry>> {
    match der_kind(der) {
        Some(DerKind::Certificate) => Ok(vec![Entry::Certificate(der.to_vec())]),
        Some(DerKind::PublicKey) => Ok(vec![Entry::PublicKey(der.to_vec())]),
        Some(DerKind::Pkcs8) => Ok(vec![Entry::Key(Zeroizing::new(der.to_vec()), Method::Pkcs8)]),
        Some(DerKind::EncryptedPkcs8) => Ok(vec![Entry::Key(encrypted(der, pass)?, Method::Pkcs8Pbes2)]),
        Some(DerKind::Pkcs12) => {
            let pass = pass.ok_or_else(|| bad("a PKCS#12, and no passphrase is given for it"))?;
            let read = file::read(der, pass)?;
            let mut out = vec![Entry::Key(read.pkcs8, Method::Pkcs12)];
            out.extend(read.certificates.into_iter().map(Entry::Certificate));
            Ok(out)
        }
        Some(DerKind::Pkcs1) => Ok(vec![Entry::Key(from_pkcs1(der)?, Method::Pkcs1)]),
        Some(DerKind::Sec1) => Ok(vec![Entry::Key(from_sec1(der, curve)?, Method::Sec1)]),
        None => {
            Err(bad("neither PEM nor a DER certificate, public key, private key (PKCS#8, PKCS#1, SEC1) or PKCS#12"))
        }
    }
}

/// The kind of a DER file, recognised by its shape in the order in which [`der_entry`] decodes
/// it. [`holds_private_key`] also uses it.
#[derive(Clone, Copy)]
enum DerKind {
    Certificate,
    PublicKey,
    Pkcs8,
    EncryptedPkcs8,
    Pkcs12,
    Pkcs1,
    Sec1,
}

impl DerKind {
    /// Whether a file of this kind holds a private key (a PKCS#12 carries one).
    fn is_private(self) -> bool {
        !matches!(self, DerKind::Certificate | DerKind::PublicKey)
    }
}

fn der_kind(der: &[u8]) -> Option<DerKind> {
    if x509_cert::Certificate::from_der(der).is_ok() {
        return Some(DerKind::Certificate);
    }
    if x509_cert::spki::SubjectPublicKeyInfoRef::from_der(der).is_ok() {
        return Some(DerKind::PublicKey);
    }
    if pkcs8::PrivateKeyInfoRef::try_from(der).is_ok() {
        return Some(DerKind::Pkcs8);
    }
    if pkcs8::EncryptedPrivateKeyInfoRef::try_from(der).is_ok() {
        return Some(DerKind::EncryptedPkcs8);
    }
    if pkcs12::Pfx::from_der(der).is_ok() {
        return Some(DerKind::Pkcs12);
    }
    match structure(der)? {
        Structure::Pkcs1 => Some(DerKind::Pkcs1),
        Structure::Sec1 => Some(DerKind::Sec1),
    }
}

/// The private-key structures that are recognised by their shape. PKCS#1 is nine INTEGERs, of which
/// the first is 0. SEC1 is INTEGER 1 and an OCTET STRING, followed by optional tagged fields.
enum Structure {
    Pkcs1,
    Sec1,
}

fn structure(der: &[u8]) -> Option<Structure> {
    let fields = Vec::<AnyRef>::from_der(der).ok()?;
    let int = |f: &AnyRef, v: u8| f.tag() == der::Tag::Integer && f.value() == [v];
    match fields.as_slice() {
        [first, rest @ ..] if rest.len() == 8 && int(first, 0) && rest.iter().all(|f| f.tag() == der::Tag::Integer) => {
            Some(Structure::Pkcs1)
        }
        [first, key, ..] if int(first, 1) && key.tag() == der::Tag::OctetString => Some(Structure::Sec1),
        _ => None,
    }
}

/// Returns a PKCS#8 `PrivateKeyInfo` after it checks that `der` is one.
fn pkcs8(der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    pkcs8::PrivateKeyInfoRef::try_from(der).map_err(|e| bad(format!("its PRIVATE KEY: {e}")))?;
    Ok(Zeroizing::new(der.to_vec()))
}

/// Decrypts an `EncryptedPrivateKeyInfo` with `pass`.
fn encrypted(der: &[u8], pass: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    let pass = pass.ok_or_else(|| bad("an encrypted private key, and no passphrase is given for it"))?;
    file::decrypt_pkcs8(der, pass)
}

/// Returns a certificate's DER after it checks that `der` is a certificate.
fn certificate_der(der: &[u8]) -> Result<Vec<u8>> {
    x509_cert::Certificate::from_der(der).map_err(|e| bad(format!("its CERTIFICATE: {e}")))?;
    Ok(der.to_vec())
}

/// `rsaEncryption` (RFC 8017).
const RSA_ENCRYPTION: [u8; 11] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const NULL: [u8; 2] = [0x05, 0x00];

/// Converts a PKCS#1 `RSAPrivateKey` to PKCS#8 (RFC 5208), with the algorithm `rsaEncryption`
/// and NULL parameters.
fn from_pkcs1(der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !matches!(structure(der), Some(Structure::Pkcs1)) {
        return Err(bad("its RSA PRIVATE KEY is not a two-prime PKCS#1 key"));
    }
    Ok(wrap(&[&RSA_ENCRYPTION, &NULL], der))
}

/// Converts a SEC1 `ECPrivateKey` to PKCS#8 (RFC 5915), with the algorithm `id-ecPublicKey` and
/// the curve that the key names. When the key names no curve, it uses `object_curve`, the
/// object's curve; a key on another curve is then refused by the type check.
fn from_sec1(der: &[u8], object_curve: Option<Curve>) -> Result<Zeroizing<Vec<u8>>> {
    let fields = Vec::<AnyRef>::from_der(der).map_err(|e| bad(format!("its EC PRIVATE KEY: {e}")))?;
    let named = fields.iter().skip(2).find(|f| f.tag() == sec1_parameters()).map(|f| f.value());
    let curve = match named {
        Some(params) => {
            Curve::from_params(params).ok_or_else(|| bad("its EC PRIVATE KEY is on a curve cakeys does not know"))?
        }
        None => object_curve
            .filter(|c| !c.edwards())
            .ok_or_else(|| bad("its EC PRIVATE KEY names no curve, and the object is no EC key to take one from"))?,
    };
    Ok(wrap(&[&EC_PUBLIC_KEY, curve.params()], der))
}

/// The tag of a SEC1 key's `parameters`, `[0]`, which names its curve.
fn sec1_parameters() -> der::Tag {
    der::Tag::ContextSpecific { constructed: true, number: der::TagNumber(0) }
}

/// Builds `PrivateKeyInfo { version 0, algorithm { parts }, privateKey OCTET STRING { key } }`.
/// The buffers are sized in advance, so that a buffer never grows and leaves an unzeroized copy of
/// the key behind.
fn wrap(algorithm: &[&[u8]], key: &[u8]) -> Zeroizing<Vec<u8>> {
    let alg: Vec<u8> = algorithm.concat();
    let mut body = Zeroizing::new(Vec::with_capacity(key.len() + alg.len() + 32));
    body.extend_from_slice(&[0x02, 0x01, 0x00]);
    tlv(0x30, &alg, &mut body);
    tlv(0x04, key, &mut body);
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 8));
    tlv(0x30, &body, &mut out);
    out
}

/// Appends one DER tag-length-value to `out`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a short length is below 0x80, and a long one's count of bytes is at most a usize's 8"
)]
fn tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture key file, as OpenSSL wrote it (tests/fixtures/keyfiles/make.sh).
    fn fixture(name: &str) -> Vec<u8> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keyfiles");
        std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn object(class: Class, key_type: Option<KeyType>, curve: Option<&str>) -> ObjectCfg {
        ObjectCfg { curve: curve.map(str::to_owned), ..ObjectCfg::new(class, key_type) }
    }

    fn p256() -> ObjectCfg {
        object(Class::PrivateKey, Some(KeyType::Ec), Some("secp256r1"))
    }

    const PASS: Option<&str> = Some("pass phrase");

    fn refusal(r: Result<Material>) -> String {
        match r {
            Err(KmError::Validation(m)) => m.into_text(),
            Err(e) => panic!("not a validation error: {e}"),
            Ok(m) => panic!("read, by {}", m.method),
        }
    }

    /// Checks one P-256 key in each format in which OpenSSL writes it. Every file reads as the same
    /// key with its format recorded, and the host path parses the PKCS#8 to which the key is
    /// normalised.
    #[test]
    fn every_format_of_a_key_reads_as_that_key() {
        let want = id::spki_canonical(&fixture("p256.pub.der")).unwrap();
        for (file, method) in [
            ("p256.pkcs8.pem", Method::Pkcs8),
            ("p256.pkcs8.der", Method::Pkcs8),
            ("p256.sec1.pem", Method::Sec1),
            ("p256.sec1.der", Method::Sec1),
            ("p256.enc.pem", Method::Pkcs8Pbes2),
            ("p256.p12", Method::Pkcs12),
            ("p256.bundle.pem", Method::Sec1),
        ] {
            let m = read(&fixture(file), &p256(), false, PASS, None).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(
                (m.spki.as_deref(), &m.method, m.exposure),
                (Some(want.as_slice()), &method, Exposure::File),
                "{file}"
            );
            cakeys_core::plaintext::private_from_pkcs8(&m.bytes, KeyType::Ec, Some(cakeys_core::id::Curve::P256))
                .unwrap();
            assert_eq!(host_ids(&p256(), &m), [(Scheme::Rfc7093m4, id::sri(&want))], "{file}");
        }
        let rsa = object(Class::PrivateKey, Some(KeyType::Rsa), None);
        let spki = |file| read(&fixture(file), &rsa, false, None, None).unwrap().spki.unwrap();
        assert_eq!(spki("rsa2048.pkcs1.pem"), spki("rsa2048.pkcs8.pem"));
        assert_eq!(spki("rsa2048.pkcs1.der"), spki("rsa2048.pkcs8.pem"));
        let m = read(&fixture("rsa2048.pkcs1.pem"), &rsa, false, None, None).unwrap();
        assert_eq!(m.method, Method::Pkcs1);
        cakeys_core::plaintext::private_from_pkcs8(&m.bytes, KeyType::Rsa, None).unwrap();
        let ed = object(Class::PrivateKey, Some(KeyType::EcEdwards), Some("edwards25519"));
        assert_eq!(read(&fixture("ed25519.pkcs8.pem"), &ed, false, None, None).unwrap().method, Method::Pkcs8);
    }

    /// Checks that the refusal of a PKCS#8 whose key does not decode gives the reason next to the
    /// type as which the key was read (review keyfile.rs F2). A key that claims RSA but is not a
    /// valid RSA key is reported with the decoding error, not only as a key "of another type".
    #[test]
    fn a_key_that_does_not_decode_says_why() {
        // PrivateKeyInfo { version 0, rsaEncryption, OCTET STRING 01 02 03 }.
        let garbage = [
            0x30, 0x17, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00, 0x04, 0x03, 0x01, 0x02, 0x03,
        ];
        let rsa = object(Class::PrivateKey, Some(KeyType::Rsa), None);
        let said = refusal(read(&garbage, &rsa, false, None, None));
        assert!(said.contains("does not read as a key of the object's type"), "{said}");
        assert!(said.contains("RSA private key"), "{said}");
    }

    /// Checks that a SEC1 key that names no curve takes the object's curve, and that the key must
    /// then be on that curve.
    #[test]
    fn a_sec1_key_without_parameters_takes_the_objects_curve() {
        use der::Encode as _;
        let der = fixture("p256.sec1.der");
        let fields: Vec<AnyRef> = Vec::from_der(&der).unwrap();
        let bare: Vec<AnyRef> = fields.into_iter().filter(|f| f.tag() != sec1_parameters()).collect();
        let bare = bare.to_der().unwrap();
        assert!(bare.len() < der.len());
        let m = read(&bare, &p256(), false, None, None).unwrap();
        assert_eq!(m.spki, read(&der, &p256(), false, None, None).unwrap().spki);
        let p384 = object(Class::PrivateKey, Some(KeyType::Ec), Some("secp384r1"));
        assert!(refusal(read(&bare, &p384, false, None, None)).contains("the object is"));
        let rsa = object(Class::PrivateKey, Some(KeyType::Rsa), None);
        assert!(refusal(read(&bare, &rsa, false, None, None)).contains("names no curve"));
    }

    /// Checks that a certificate object takes its file's one certificate, or the certificate for
    /// the key next to it. A public key object takes its file's `PUBLIC KEY`, or the public half of
    /// the key next to it.
    #[test]
    fn certificates_and_public_keys_are_taken_as_the_file_says() {
        let cert = ObjectCfg { certificate_type: Some("CKC_X_509".into()), ..object(Class::Certificate, None, None) };
        let want = fixture("p256.crt.der");
        for file in ["p256.crt.pem", "p256.crt.der", "p256.bundle.pem", "p256.p12"] {
            let m = read(&fixture(file), &cert, false, PASS, None).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(
                (m.bytes.as_slice(), &m.method, m.exposure),
                (want.as_slice(), &Method::Public, Exposure::Public),
                "{file}"
            );
            assert_eq!(host_ids(&cert, &m), [(Scheme::Certhash, id::sri(&want))]);
        }
        assert!(refusal(read(&fixture("two-certs.pem"), &cert, false, None, None)).contains("2 certificates"));
        assert!(refusal(read(&fixture("p256.pkcs8.pem"), &cert, false, None, None)).contains("no certificate"));
        let public = object(Class::PublicKey, Some(KeyType::Ec), Some("secp256r1"));
        let want = id::spki_canonical(&fixture("p256.pub.der")).unwrap();
        for file in ["p256.pub.pem", "p256.pub.der", "p256.pkcs8.pem", "p256.sec1.pem"] {
            let m = read(&fixture(file), &public, false, None, None).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(m.bytes.as_slice(), want.as_slice(), "{file}");
        }
    }

    /// Checks that a file that camigrate does not read is refused (17) with the name of its format,
    /// and with the command that converts it when there is one, before any key in it is used.
    #[test]
    fn files_of_another_shape_are_refused_with_the_way_out() {
        let p256 = p256();
        let ssh = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        let crl = b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
        let cases: [(&[u8], Option<&str>, &str); 8] = [
            (&fixture("p256.legacy-enc.pem"), PASS, "openssl pkcs8 -topk8"),
            (&fixture("p256.legacy.p12"), PASS, "openssl pkcs12 -in old.p12 -legacy"),
            // A PKCS#12 file whose key is in a plain keyBag is reported as such, not as a file
            // without a key (review 2026-11-23 C-22).
            (&fixture("p256.nokeypbe.p12"), PASS, "whose key is not encrypted (a keyBag, `-keypbe NONE`)"),
            (&fixture("p256.enc.pem"), None, "no passphrase is given"),
            (&fixture("p256.enc.pem"), Some("other"), "does not open under this passphrase"),
            (ssh, None, "ssh-keygen -p -m PKCS8"),
            (crl, None, "a PEM X509 CRL block"),
            (b"no key here", None, "neither PEM nor"),
        ];
        for (bytes, pass, want) in cases {
            let got = refusal(read(bytes, &p256, false, pass, None));
            assert!(got.contains(want), "{want}: {got}");
        }
        // A key of another type than the object's.
        let p384 = object(Class::PrivateKey, Some(KeyType::Ec), Some("secp384r1"));
        assert!(refusal(read(&fixture("p256.pkcs8.pem"), &p384, false, None, None)).contains("a key on secp256r1"));
        assert!(refusal(read(&fixture("rsa2048.pkcs1.pem"), &p256, false, None, None)).contains("an RSA key"));
        let rsa3072 = ObjectCfg { modulus_bits: Some(3072), ..object(Class::PrivateKey, Some(KeyType::Rsa), None) };
        assert!(refusal(read(&fixture("rsa2048.pkcs1.pem"), &rsa3072, false, None, None)).contains("2048 bits"));
        // Two keys in one file.
        let two = [fixture("p256.pkcs8.pem"), fixture("ca.pkcs8.pem")].concat();
        assert!(refusal(read(&two, &p256, false, None, None)).contains("more than one private key"));
    }

    /// Checks that a file that holds a private key, in any format, is told apart from a file that
    /// does not, before anything in it is decoded.
    #[test]
    fn private_keys_are_seen_before_they_are_decoded() {
        for file in [
            "p256.pkcs8.pem",
            "p256.pkcs8.der",
            "p256.sec1.der",
            "p256.enc.pem",
            "p256.legacy-enc.pem",
            "p256.p12",
            "p256.bundle.pem",
            "rsa2048.pkcs1.der",
        ] {
            assert!(holds_private_key(&fixture(file)), "{file}");
        }
        for file in ["p256.crt.pem", "p256.crt.der", "p256.pub.der", "two-certs.pem", "note.bin", "aes256.key"] {
            assert!(!holds_private_key(&fixture(file)), "{file}");
        }
    }

    /// Checks that the gate (`holds_private_key`) and the reader never disagree (camigrate
    /// keyfile.rs F1). For every file from which the reader decodes a private key, the gate must
    /// say that the file holds one. This is checked for every fixture, and for each fixture changed
    /// in the ways in which real files arrive: a BEGIN after other text on its line, an indented
    /// BEGIN, CRLF line ends, a certificate before the key, and a block without its END line. A key
    /// that the gate missed would be decoded without `--allow-host-plaintext`.
    #[test]
    fn the_gate_sees_every_key_the_reader_decodes() {
        let files = [
            "p256.pkcs8.pem",
            "p256.pkcs8.der",
            "p256.sec1.der",
            "p256.enc.pem",
            "p256.p12",
            "p256.bundle.pem",
            "rsa2048.pkcs1.der",
            "rsa2048.pkcs1.pem",
            "p256.sec1.pem",
            "ed25519.pkcs8.pem",
            "p256.pub.pem",
            "p256.crt.pem",
            "p256.crt.der",
            "p256.pub.der",
            "two-certs.pem",
            "note.bin",
        ];
        let mangled = |bytes: &[u8]| -> Vec<Vec<u8>> {
            let Ok(text) = std::str::from_utf8(bytes) else { return vec![bytes.to_vec()] };
            let cert = String::from_utf8(fixture("p256.crt.pem")).unwrap();
            vec![
                text.into(),
                text.replacen("-----BEGIN ", "pasted: -----BEGIN ", 1).into(),
                text.replace("-----BEGIN ", "  -----BEGIN ").into(),
                text.replace('\n', "\r\n").into(),
                (cert + text).into(),
                text.replacen("-----END ", "-----FINISH ", 1).into(),
            ]
        };
        let decodes_a_key = |bytes: &[u8]| {
            entries(bytes, PASS, Some(Curve::P256)).is_ok_and(|e| e.iter().any(|e| matches!(e, Entry::Key(..))))
        };
        for file in files {
            for (i, bytes) in mangled(&fixture(file)).iter().enumerate() {
                if decodes_a_key(bytes) {
                    assert!(holds_private_key(bytes), "{file}, mangled #{i}: the reader decodes a key the gate missed");
                }
            }
        }
        // The case the review found: a BEGIN after text on its line.
        let pasted = String::from_utf8(fixture("p256.pkcs8.pem")).unwrap().replacen("-----BEGIN", "key: -----BEGIN", 1);
        assert!(decodes_a_key(pasted.as_bytes()) && holds_private_key(pasted.as_bytes()));
    }

    /// Checks that a secret key is its value: the file's bytes, or hex or base64 text of those
    /// bytes, however the lines wrap. The object's `valueLen` tells the forms apart, or
    /// `migrate.encoding` names the form. Text without either is refused, never guessed. A data
    /// object is its file's bytes as they are.
    #[test]
    fn secret_keys_are_their_value_and_data_objects_their_bytes() {
        let aes = ObjectCfg { value_len: Some(32), ..object(Class::SecretKey, Some(KeyType::Aes), None) };
        let key = fixture("aes256.key");
        let value = |file: &[u8], o: &ObjectCfg, e: Option<Encoding>| read(file, o, false, None, e).map(|m| m.bytes);
        let m = read(&key, &aes, false, None, None).unwrap();
        assert_eq!((m.bytes.as_slice(), &m.method, m.exposure), (key.as_slice(), &Method::Raw, Exposure::File));
        assert_eq!(host_ids(&aes, &m), []);
        let hex = fixture("aes256.hex");
        let wrapped = |text: &[u8], at: usize| text.chunks(at).collect::<Vec<_>>().join(&b"\n"[..]);
        let spellings = [
            (hex.clone(), Encoding::Hex),
            ([&hex[..], b"\n"].concat(), Encoding::Hex),
            (hex.to_ascii_uppercase(), Encoding::Hex),
            (wrapped(&hex, 60), Encoding::Hex),
            (fixture("aes256.b64"), Encoding::Base64),
            (wrapped(fixture("aes256.b64").trim_ascii(), 16), Encoding::Base64),
        ];
        for (text, e) in &spellings {
            let what = String::from_utf8_lossy(text);
            assert_eq!(value(text, &aes, None).unwrap().as_slice(), key.as_slice(), "{what}");
            assert_eq!(value(text, &aes, Some(*e)).unwrap().as_slice(), key.as_slice(), "{what}");
        }
        // A file of exactly valueLen bytes is the value itself, even when some of its bytes are
        // whitespace or hex digits.
        let ascii = b"0123456789abcdef0123456789abcde\n";
        assert_eq!(value(ascii, &aes, None).unwrap().as_slice(), ascii);
        assert_eq!(value(ascii, &aes, Some(Encoding::Raw)).unwrap().as_slice(), ascii);
        // Hex digits are also base64 characters, and when they are read as base64, they spell
        // another length.
        assert!(refusal(read(&hex, &aes, false, None, Some(Encoding::Base64))).contains("48 bytes of base64"));
        assert!(refusal(read(&key, &aes, false, None, Some(Encoding::Base64))).contains("not base64 text"));
        assert!(refusal(read(&key, &aes, false, None, Some(Encoding::Hex))).contains("not hex text"));
        assert!(refusal(read(&hex, &aes, false, None, Some(Encoding::Raw))).contains("64 bytes, and the key is 32"));
        assert!(refusal(read(&hex[..30], &aes, false, None, None)).contains("as hex it is 15 bytes"));
        assert!(refusal(read(&hex[..32], &aes, false, None, Some(Encoding::Hex))).contains("16 bytes of hex"));
        let short = refusal(read(&[0; 16], &aes, false, None, None));
        assert!(short.contains("16 bytes, and the key is 32") && short.contains("64 digits") && short.contains("44"));
        assert!(refusal(read(&[], &aes, false, None, None)).contains("empty"));
        assert!(refusal(read(b"\n", &aes, false, None, Some(Encoding::Hex))).contains("no value"));

        // Without valueLen, the length decides nothing, so the encoding must name the form
        // (loading keys.toml requires one of the two).
        let any = object(Class::SecretKey, Some(KeyType::GenericSecret), None);
        assert!(refusal(read(&key, &any, false, None, None)).contains("neither the key's valueLen"));
        assert_eq!(value(&key, &any, Some(Encoding::Raw)).unwrap().as_slice(), key.as_slice());
        assert_eq!(value(&hex, &any, Some(Encoding::Hex)).unwrap().as_slice(), key.as_slice());
        assert_eq!(value(&fixture("aes256.b64"), &any, Some(Encoding::Base64)).unwrap().as_slice(), key.as_slice());
        assert_eq!(value(b"mysecret", &any, Some(Encoding::Raw)).unwrap().as_slice(), b"mysecret");

        let data = object(Class::Data, None, None);
        let note = fixture("note.bin");
        let m = read(&note, &data, false, None, None).unwrap();
        assert_eq!((&m.method, m.exposure), (&Method::Public, Exposure::Public));
        assert_eq!(host_ids(&data, &m), [(Scheme::Valuehash, id::sri(&note))]);
        let m = read(&note, &data, true, None, None).unwrap();
        assert_eq!((&m.method, m.exposure), (&Method::Raw, Exposure::File));
        let m = read(&hex, &data, false, None, None).unwrap();
        assert_eq!(m.bytes.as_slice(), hex.as_slice(), "a data object's hex text is its value");
    }
}
