//! Moving a public object (MIGRATE.md phase 2, the `public` method): a certificate, a public key
//! or a data object needs no wrapping. The source object is verified against the lock, its
//! material taken from what that check established — a public key from its canonical SPKI, a
//! certificate's attributes from its DER — and created on the target under the target spec's
//! locator and attributes. It is then recorded through `ops::realise_import`, the lock rules
//! `cakeys realise` uses: a mismatch (10) removes what was just created and leaves the lock as
//! it was.

use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::Token;
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{class_of, curve_of, locator_attrs};
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use x509_cert::der::{Decode as _, Encode as _};

/// What moving one object did.
pub enum Moved {
    /// Created on the target and recorded with its `origin`.
    Imported,
    /// The target already holds it, recorded and verified: a re-run moves nothing.
    AlreadyThere,
}

/// Move the public object `src` (realised on `from`) to `dst` on `to`, and record it in `lock`.
///
/// # Errors
///
/// Whatever `ops::verify` refuses on the source; `Conflict` (13) when an object of its class
/// sits under the target locator without a realisation of `dst` (a public key object holding
/// the same key is that object: recorded, not created again); `Unavailable` (16) for a target session
/// without login; `Unsupported` (15) when the target refuses `C_CreateObject`; and, after the
/// creation, whatever `ops::realise_import` refuses — a hash mismatch (10) included — with what
/// was created removed again.
pub fn import(
    src: &Target,
    from: &Token,
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    if lock.realisation(dst.spec_name, dst.token_name).is_some() {
        ops::verify(dst, to, lock, notes)?;
        return Ok(Moved::AlreadyThere);
    }
    ops::verify(src, from, lock, notes)?;
    let template = template(src, from, dst, to)?;
    // If-None-Match (MIGRATE.md D6): never into an occupied locator, and only where the session
    // can see everything under it.
    if !to.logged_in {
        return Err(KmError::Unavailable(format!(
            "{dst}: a session without login cannot tell the locator is free; configure pinFile or pinEnv \
             for token '{}'",
            dst.token_name
        )));
    }
    // Per class (`Token::occupied`): the key and certificate a public object usually sits beside
    // are no collision, and a public key a key's import already created there is this object.
    let spki = match src.object.class {
        Class::PublicKey => Some(from.spki(one(from, src)?, &src.on_token.locator)?),
        _ => None,
    };
    let occupied = to.occupied(dst.object, &dst.on_token.locator, spki.as_deref())?;
    if occupied.colliding > 0 {
        return Err(KmError::Conflict(format!(
            "{} object(s) of its class already sit under the locator of {dst}, and the lock records no \
             realisation there; refusing to import over them",
            occupied.colliding
        )));
    }
    let create = || {
        to.raw()
            .create_object(&template)
            .map_err(|e| to.unsupported(format!("{dst}: importing into '{}': C_CreateObject: {e}", to.name)))
    };
    let created = match occupied.public_half {
        Some(_) => None,
        None if to.provider.manages_as_so() => Some(to.as_so("importing an object", create)?),
        None => Some(create()?),
    };
    let origin = Origin {
        from: src.token_name.to_owned(),
        method: Method::Public.name(),
        exposure: Exposure::Public,
        declared: false,
    };
    match ops::realise_import(dst, to, lock, origin, notes) {
        Ok(_) => Ok(Moved::Imported),
        Err(e) => {
            // Only what this import created: other objects may share the locator.
            match to.destroy_handles(dst.object, &dst.on_token.locator, created.as_slice()) {
                Ok(0) => {}
                Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {e}")),
                Err(d) => notes.say(format!("the object just imported for {dst} is still on the token ({d})")),
            }
            Err(e)
        }
    }
}

/// The creation template: the class and type, the material, `CKA_TOKEN`, the target locator and
/// the target spec's declared attributes.
fn template(src: &Target, from: &Token, dst: &Target, to: &Token) -> Result<Vec<Attribute>> {
    let h = one(from, src)?;
    let mut t = vec![Attribute::Token(true)];
    t.extend(locator_attrs(&dst.on_token.locator)?);
    t.extend(to.policy_template(&dst.spec.attributes)?);
    match src.object.class {
        Class::Certificate => {
            let der = value(from, h)?;
            let cert = x509_cert::Certificate::from_der(&der)
                .map_err(|e| KmError::Conflict(format!("{src}: CKA_VALUE is not an X.509 certificate: {e}")))?;
            let tbs = cert.tbs_certificate();
            let enc = |r: x509_cert::der::Result<Vec<u8>>| r.map_err(|e| KmError::Conflict(format!("{src}: {e}")));
            t.extend([
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Subject(enc(tbs.subject().to_der())?),
                Attribute::Issuer(enc(tbs.issuer().to_der())?),
                Attribute::SerialNumber(enc(tbs.serial_number().to_der())?),
                Attribute::Value(der),
            ]);
        }
        Class::Data => t.extend([Attribute::Class(ObjectClass::DATA), Attribute::Value(value(from, h)?)]),
        Class::PublicKey => {
            t.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
            t.extend(public_key(src, &from.spki(h, &src.on_token.locator)?)?);
        }
        class => {
            return Err(KmError::Validation(format!("{src}: a {class} is not a public object")));
        }
    }
    Ok(t)
}

/// The public key's material from its canonical SPKI, in PKCS#11's encoding: an EC or Edwards
/// point as a DER OCTET STRING beside the curve's parameters, an RSA key as its modulus and
/// exponent.
pub(crate) fn public_key(src: &Target, spki: &[u8]) -> Result<Vec<Attribute>> {
    let bad = |e: &dyn std::fmt::Display| KmError::Conflict(format!("{src}: the locked public key: {e}"));
    if src.object.key_type == Some(cakeys_core::types::KeyType::Rsa) {
        let key = rsa::PublicKey::from_public_key_der(spki).map_err(|e| bad(&e))?;
        return Ok(vec![
            Attribute::KeyType(KeyType::RSA),
            Attribute::Modulus(key.n().to_be_bytes_trimmed_vartime().to_vec()),
            Attribute::PublicExponent(key.e().to_be_bytes_trimmed_vartime().to_vec()),
        ]);
    }
    let curve = curve_of(src.object)?;
    let info = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki).map_err(|e| bad(&e))?;
    let point = info.subject_public_key.as_bytes().ok_or_else(|| bad(&"the key is not whole bytes"))?;
    let point = x509_cert::der::asn1::OctetStringRef::new(point).and_then(|o| o.to_der()).map_err(|e| bad(&e))?;
    Ok(vec![
        Attribute::KeyType(if curve.edwards() { KeyType::EC_EDWARDS } else { KeyType::EC }),
        Attribute::EcParams(curve.params().to_vec()),
        Attribute::EcPoint(point),
    ])
}

/// The one object of `t`'s class under its locator (verified just before).
fn one(tok: &Token, t: &Target) -> Result<ObjectHandle> {
    match tok.find(class_of(t.object), &t.on_token.locator)?.as_slice() {
        [h] => Ok(*h),
        [] => Err(KmError::NotFound(t.to_string())),
        _ => Err(KmError::Ambiguous(format!("{t}: several objects under the locator"))),
    }
}

/// `CKA_VALUE` of `h`.
fn value(tok: &Token, h: ObjectHandle) -> Result<Vec<u8>> {
    let read = tok.raw().get_attributes(h, &[AttributeType::Value]);
    match read.map_err(|e| KmError::Unavailable(format!("C_GetAttributeValue: {e}")))?.as_slice() {
        [Attribute::Value(v)] => Ok(v.clone()),
        _ => Err(KmError::NotFound("the object has no CKA_VALUE".into())),
    }
}
