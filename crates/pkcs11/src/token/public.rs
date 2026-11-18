//! A public object's attributes from its value: what `C_CreateObject` takes for a certificate, a
//! data object or a public key. camigrate creates public objects with them (docs/CAMIGRATE.md,
//! `public`), and caprobe asks a module to create each kind (`docs/CAPROBE_MIGRATION.md`).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use rsa::traits::PublicKeyParts as _;
use x509_cert::der::{Decode as _, Encode as _};

/// The class and value of the public `object` from `bytes`: a certificate's DER with its
/// subject, issuer and serial number, a data object's value, or a public key from its canonical
/// SPKI ([`public_key_attrs`]). No locator, `CKA_TOKEN` or policy: the caller's.
///
/// # Errors
///
/// `Conflict` when `bytes` is not what the class holds; `Validation` for a class that is no
/// public object.
pub fn public_object_attrs(object: &ObjectCfg, bytes: &[u8]) -> Result<Vec<Attribute>> {
    match object.class {
        Class::Certificate => {
            let cert = x509_cert::Certificate::from_der(bytes)
                .map_err(|e| KmError::Conflict(format!("the value is not an X.509 certificate: {e}").into()))?;
            let tbs = cert.tbs_certificate();
            let enc = |r: x509_cert::der::Result<Vec<u8>>| r.map_err(|e| KmError::Conflict(e.to_string().into()));
            Ok(vec![
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Subject(enc(tbs.subject().to_der())?),
                Attribute::Issuer(enc(tbs.issuer().to_der())?),
                Attribute::SerialNumber(enc(tbs.serial_number().to_der())?),
                Attribute::Value(bytes.to_vec()),
            ])
        }
        Class::Data => Ok(vec![Attribute::Class(ObjectClass::DATA), Attribute::Value(bytes.to_vec())]),
        Class::PublicKey => {
            let mut t = vec![Attribute::Class(ObjectClass::PUBLIC_KEY)];
            t.extend(public_key_attrs(object, bytes)?);
            Ok(t)
        }
        class => Err(KmError::Validation(format!("a {class} is not a public object").into())),
    }
}

/// A public key's material from its canonical SPKI, in PKCS#11's encoding: an EC or Edwards
/// point as a DER OCTET STRING beside the curve's parameters, an RSA key as its modulus and
/// exponent. `object` gives the key type and curve.
///
/// # Errors
///
/// `Conflict` when the SPKI is not a key of `object`'s type; `Validation` for an object with no
/// curve cakeys knows.
pub fn public_key_attrs(object: &ObjectCfg, spki: &[u8]) -> Result<Vec<Attribute>> {
    let bad = |e: &dyn std::fmt::Display| KmError::Conflict(format!("the public key: {e}").into());
    if object.key_type == Some(Kt::Rsa) {
        let key = cakeys_core::id::rsa_of_spki(spki).map_err(|e| bad(&e))?;
        return Ok(vec![
            Attribute::KeyType(KeyType::RSA),
            Attribute::Modulus(key.n().to_be_bytes_trimmed_vartime().to_vec()),
            Attribute::PublicExponent(key.e().to_be_bytes_trimmed_vartime().to_vec()),
        ]);
    }
    let curve = curve_of(object)?;
    let info = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki).map_err(|e| bad(&e))?;
    let point = info.subject_public_key.as_bytes().ok_or_else(|| bad(&"the key is not whole bytes"))?;
    let point = x509_cert::der::asn1::OctetStringRef::new(point).and_then(|o| o.to_der()).map_err(|e| bad(&e))?;
    Ok(vec![
        Attribute::KeyType(if curve.edwards() { KeyType::EC_EDWARDS } else { KeyType::EC }),
        Attribute::EcParams(curve.params().to_vec()),
        Attribute::EcPoint(point),
    ])
}
