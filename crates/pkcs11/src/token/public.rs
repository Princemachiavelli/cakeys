//! The attributes of a public object, built from its value. These are the attributes that
//! `C_CreateObject` takes for a certificate, a data object or a public key. camigrate creates
//! public objects with them (docs/CAMIGRATE.md, `public`), and caprobe asks a module to create
//! each kind of object with them (`docs/archive/CAPROBE_MIGRATION.md`).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use cakeys_core::id::KeyAlg;
use rsa::traits::PublicKeyParts as _;
use x509_cert::der::{Decode as _, Encode as _};

/// Returns the class and the value attributes of the public `object`, built from `bytes`. For a
/// certificate, these are its DER with its subject, issuer and serial number. For a data object,
/// this is its value. For a public key, these are built from its canonical SPKI
/// ([`public_key_attrs`]). The result has no locator, `CKA_TOKEN` or policy attributes, because
/// the caller adds them.
///
/// # Errors
///
/// `Conflict` when `bytes` is not the kind of value that the class holds. `Validation` for a
/// class that is not a public object.
pub fn public_object_attrs(object: Object<'_>, bytes: &[u8]) -> Result<Vec<Attribute>> {
    match object.class {
        Class::Certificate => {
            let cert = x509_cert::Certificate::from_der(bytes).map_err(|e| {
                KmError::Conflict(Reason::check(
                    Check::CertificateDecodes,
                    format!("the value is not an X.509 certificate: {e}"),
                ))
            })?;
            let tbs = cert.tbs_certificate();
            let enc = |r: x509_cert::der::Result<Vec<u8>>| {
                r.map_err(|e| KmError::Conflict(Reason::check(Check::CertificateDecodes, e.to_string())))
            };
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

/// Returns a public key's material, built from its canonical SPKI, in the PKCS#11 encoding. An EC
/// or Edwards point becomes a DER OCTET STRING next to the curve's parameters, and an RSA key
/// becomes its modulus and exponent. `object` gives the key type and the curve, and the SPKI's
/// algorithm (and, for an EC key, its curve) must match them.
///
/// # Errors
///
/// `Conflict` when the SPKI cannot be decoded, or when it is not a key of the type and curve of
/// `object`.
pub fn public_key_attrs(object: Object<'_>, spki: &[u8]) -> Result<Vec<Attribute>> {
    let bad = |e: &dyn std::fmt::Display| {
        KmError::Conflict(Reason::check(Check::PublicKeyType, format!("the public key: {e}")))
    };
    let declared = object.curve().map_or(KeyAlg::Rsa, KeyAlg::Ec);
    let held = KeyAlg::of_spki(spki).map_err(|e| bad(&e))?;
    let curve = match (held, declared) {
        (KeyAlg::Rsa, KeyAlg::Rsa) => {
            let key = cakeys_core::id::rsa_of_spki(spki).map_err(|e| bad(&e))?;
            return Ok(vec![
                Attribute::KeyType(KeyType::RSA),
                Attribute::Modulus(key.n().to_be_bytes_trimmed_vartime().to_vec()),
                Attribute::PublicExponent(key.e().to_be_bytes_trimmed_vartime().to_vec()),
            ]);
        }
        (KeyAlg::Ec(held), KeyAlg::Ec(declared)) if held == declared => declared,
        _ => {
            let name = |k: KeyAlg| match k {
                KeyAlg::Rsa => "an RSA key".to_owned(),
                KeyAlg::Ec(c) => format!("a {} key", c.display()),
            };
            return Err(bad(&format_args!("{}, where the object is {}", name(held), name(declared))));
        }
    };
    let info = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki).map_err(|e| bad(&e))?;
    let point = info.subject_public_key.as_bytes().ok_or_else(|| bad(&"the key is not whole bytes"))?;
    let point = x509_cert::der::asn1::OctetStringRef::new(point).and_then(|o| o.to_der()).map_err(|e| bad(&e))?;
    Ok(vec![
        Attribute::KeyType(if curve.edwards() { KeyType::EC_EDWARDS } else { KeyType::EC }),
        Attribute::EcParams(curve.params().to_vec()),
        Attribute::EcPoint(point),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::asn1::{Any, BitString, ObjectIdentifier};
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    /// Returns an SPKI that names a key on the curve `c`, with its algorithm written as RFC 5480
    /// and RFC 8410 write it, which is the form that `KeyAlg::of_spki` reads. The point is
    /// arbitrary bytes.
    fn spki_on(c: Curve) -> Vec<u8> {
        let algorithm = if c.edwards() {
            AlgorithmIdentifierOwned { oid: ObjectIdentifier::from_der(c.params()).unwrap(), parameters: None }
        } else {
            AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                parameters: Some(Any::from_der(c.params()).unwrap()),
            }
        };
        SubjectPublicKeyInfoOwned { algorithm, subject_public_key: BitString::from_bytes(&[4; 33]).unwrap() }
            .to_der()
            .unwrap()
    }

    fn key_on(c: Curve) -> ObjectCfg {
        let mut o = ObjectCfg::new(Class::PublicKey, Some(if c.edwards() { Kt::EcEdwards } else { Kt::Ec }));
        o.curve = Some(c.name().into());
        o
    }

    /// A public key's SPKI must have the object's key type and curve (public.rs F1). Every curve
    /// paired with every other curve and with RSA, in both directions, is a conflict (exit 13)
    /// that names both. The result is never `CKA_EC_PARAMS` of one curve next to the point of a
    /// key on another curve.
    #[test]
    fn the_spki_must_be_the_objects_type_and_curve() {
        let rsa = id::rsa_spki(&[0xc5; 256], &[1, 0, 1]).unwrap();
        let mut rsa_object = ObjectCfg::new(Class::PublicKey, Some(Kt::Rsa));
        rsa_object.modulus_bits = Some(2048);
        assert!(public_key_attrs(Object::new(&rsa_object).unwrap(), &rsa).is_ok());
        for declared in Curve::ALL {
            let object = key_on(declared);
            for held in Curve::ALL {
                let made = public_key_attrs(Object::new(&object).unwrap(), &spki_on(held));
                if held == declared {
                    assert!(made.unwrap().contains(&Attribute::EcParams(declared.params().to_vec())));
                    continue;
                }
                let e = made.unwrap_err();
                assert!(
                    matches!(&e, KmError::Conflict(m) if m.contains(held.display()) && m.contains(declared.display())),
                    "{declared:?} given {held:?}: {e}"
                );
            }
            let e = public_key_attrs(Object::new(&object).unwrap(), &rsa).unwrap_err();
            assert!(matches!(&e, KmError::Conflict(m) if m.contains("an RSA key")), "{e}");
            let e = public_key_attrs(Object::new(&rsa_object).unwrap(), &spki_on(declared)).unwrap_err();
            assert!(matches!(&e, KmError::Conflict(m) if m.contains(declared.display())), "{e}");
        }
        let e = public_key_attrs(Object::new(&key_on(Curve::P256)).unwrap(), b"no SPKI").unwrap_err();
        assert!(matches!(e, KmError::Conflict(_)), "{e}");
    }
}
