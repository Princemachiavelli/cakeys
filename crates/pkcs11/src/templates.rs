//! The templates cakeys builds, from what is known before the call: the run sends these, as the
//! provider adjusts them ([`Provider::template`]), and a plan asks the provider about the same
//! ones before anything runs ([`crate::ops::check_import`], [`crate::gate::check`], camigrate's
//! plan), so a refusal comes before anything is made.
//!
//! The object's material is the caller's: a secret value or a private key's components are added
//! after the provider's adjustment, never shown to it; a public object's value and a public key's
//! material are in the template at the run, and absent from a plan's, which has not read them.
//!
//! [`Provider::template`]: crate::Provider::template

use crate::provider::{Declared, SessionKey};
use crate::token::{bool_attr, key_type_of, locator_attrs};
use cakeys_core::config::{AttrValue, Object, ObjectCfg, SpecCfg};
use cakeys_core::id::Commit;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use std::collections::BTreeMap;

/// Template attributes for declared policy values (a spec's `attributes`), each mechanism name
/// mapped by `mechanism(attribute, name)`: the open token's list at the run
/// (`Token::policy_template`), the profile baseline in a plan ([`known_policy`]).
///
/// # Errors
///
/// `Validation` for an attribute cakeys cannot set; whatever `mechanism` refuses.
pub fn policy(
    attrs: &BTreeMap<String, AttrValue>,
    mechanism: &dyn Fn(&str, &str) -> Result<MechanismType>,
) -> Result<Vec<Attribute>> {
    attrs
        .iter()
        .map(|(name, v)| match v {
            AttrValue::Bool(b) => bool_attr(name, *b)
                .ok_or_else(|| KmError::Validation(format!("unsupported policy attribute {name}").into())),
            AttrValue::Mechanisms(names) => {
                names.iter().map(|n| mechanism(name, n)).collect::<Result<Vec<_>>>().map(Attribute::AllowedMechanisms)
            }
        })
        .collect()
}

/// [`policy`] with no token: each mechanism name mapped by the profile baseline's dictionary of
/// the PKCS#11 names. `None` when a name is none it knows (a vendor's, which only the token's own
/// list maps): the plan cannot build what the run will send.
///
/// # Errors
///
/// As [`policy`]; the baseline's parse error (a commit-time bug).
pub fn known_policy(attrs: &BTreeMap<String, AttrValue>) -> Result<Option<Vec<Attribute>>> {
    let baseline =
        cakeys_profile::Set::active().and_then(|s| s.baseline()).map_err(|e| KmError::Validation(e.into()))?;
    // Whether the mapper met a name it does not know: the one failure that means "cannot
    // decide", told apart from any other `policy` refuses by this flag, not by the error's kind.
    let unknown = std::cell::Cell::new(false);
    let by_name = |name: &str, n: &str| {
        baseline.mechanisms.get(n).and_then(|id| MechanismType::try_from(*id).ok()).ok_or_else(|| {
            unknown.set(true);
            KmError::Unsupported(format!("{name}: {n} is no mechanism the baseline names").into())
        })
    };
    match policy(attrs, &by_name) {
        Ok(t) => Ok(Some(t)),
        Err(_) if unknown.get() => Ok(None),
        Err(e) => Err(e),
    }
}

/// `CKA_TOKEN` and the locator: what every token object's template starts with.
fn token_object(on: Declared<'_>) -> Result<Vec<Attribute>> {
    let mut t = vec![Attribute::Token(true)];
    t.extend(locator_attrs(on.locator)?);
    Ok(t)
}

/// A public key's defaults, beside the spec's public `policy`: `CKA_VERIFY`, and public (`CKA_PRIVATE
/// = false`), each unless the public half's template declares it (a template may not carry a
/// type twice; [`public_declares`]).
fn public_defaults(on: Declared<'_>, t: &mut Vec<Attribute>) {
    if !public_declares(on.spec, "CKA_VERIFY") {
        t.push(Attribute::Verify(true));
    }
    if !public_declares(on.spec, "CKA_PRIVATE") {
        t.push(Attribute::Private(false));
    }
}

/// Whether a key pair's public half declares the attribute `name`: its `publicAttributes`, the
/// only ones its template carries. The private key's `attributes` are the private key's: one
/// declaring `CKA_PRIVATE = true` leaves the public half public (templates.rs F1).
#[must_use]
pub fn public_declares(spec: &SpecCfg, name: &str) -> bool {
    spec.public_attributes.contains_key(name)
}

/// The key `on` generates, from cakeys' templates: a pair's private template (`CKA_TOKEN`, the
/// locator, the spec's `policy`), or a secret key's whole one.
///
/// # Errors
///
/// `Validation` for a secret key without its size (`valueLen`); whatever the key type refuses.
pub fn generation_key(on: Declared<'_>, policy: Vec<Attribute>) -> Result<Vec<Attribute>> {
    let mut t = token_object(on)?;
    match key_type_of(on.object)? {
        KeyType::RSA | KeyType::EC | KeyType::EC_EDWARDS => {}
        // The key type fixes the length: a template with CKA_VALUE_LEN is inconsistent.
        KeyType::DES3 => t.extend([Attribute::Class(ObjectClass::SECRET_KEY), Attribute::KeyType(KeyType::DES3)]),
        kt => {
            let len =
                on.object.value_len.ok_or_else(|| KmError::Validation("secret keys need valueLen (bytes)".into()))?;
            t.extend([
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(kt),
                Attribute::ValueLen(len.into()),
            ]);
        }
    }
    t.extend(policy);
    Ok(t)
}

/// A key pair's public template: the size or the curve (`ec_params`, else the curve's OID), the
/// spec's `public_policy`, the public defaults. `None` for a secret key.
///
/// # Errors
///
/// `Validation` for an RSA key without `modulusBits`; whatever the key type or curve refuses.
pub fn generation_public(
    on: Declared<'_>,
    public_policy: Vec<Attribute>,
    ec_params: Option<&[u8]>,
) -> Result<Option<Vec<Attribute>>> {
    let mut t = token_object(on)?;
    match key_type_of(on.object)? {
        KeyType::RSA => {
            let bits = on.object.modulus_bits.ok_or_else(|| KmError::Validation("RSA keys need modulusBits".into()))?;
            t.extend([Attribute::ModulusBits(bits.into()), Attribute::PublicExponent(vec![1, 0, 1])]);
        }
        KeyType::EC | KeyType::EC_EDWARDS => {
            let Some(curve) = on.object.curve() else { return Ok(None) };
            t.push(Attribute::EcParams(ec_params.unwrap_or(curve.params()).to_vec()));
        }
        _ => return Ok(None),
    }
    t.extend(public_policy);
    public_defaults(on, &mut t);
    Ok(Some(t))
}

/// A private or secret key imported under `on` (by `C_CreateObject` or `C_UnwrapKey`): its class
/// and key type, `CKA_TOKEN`, the locator and `policy`. Its value is the caller's, after.
///
/// # Errors
///
/// Whatever the key type or the locator refuses.
pub fn import_key(on: Declared<'_>, policy: Vec<Attribute>) -> Result<Vec<Attribute>> {
    let mut t = vec![
        Attribute::Token(true),
        Attribute::Class(crate::token::class_of(&on.object)),
        Attribute::KeyType(key_type_of(on.object)?),
    ];
    t.extend(locator_attrs(on.locator)?);
    t.extend(policy);
    Ok(t)
}

/// The public key object made beside an imported private key, as a generation makes its public
/// half: the key's `material` (`token::public_key_attrs`; `None` in a plan), the spec's
/// `public_policy`, the public defaults.
///
/// # Errors
///
/// Whatever the locator refuses.
pub fn public_half(
    on: Declared<'_>,
    public_policy: Vec<Attribute>,
    material: Option<Vec<Attribute>>,
) -> Result<Vec<Attribute>> {
    let mut t = vec![Attribute::Token(true), Attribute::Class(ObjectClass::PUBLIC_KEY)];
    t.extend(locator_attrs(on.locator)?);
    t.extend(material.into_iter().flatten());
    t.extend(public_policy);
    public_defaults(on, &mut t);
    Ok(t)
}

/// A certificate, data object or public key object created from its value: `CKA_TOKEN`, the
/// locator, `policy`, then its class and `material` (`token::public_object_attrs`; in a plan,
/// `None`: the class, and a certificate's type). A data object no spec declares private is said
/// public: a token's default may make it private (`SoftHSM` does \[run\]).
///
/// # Errors
///
/// Whatever the locator refuses.
pub fn object(on: Declared<'_>, policy: Vec<Attribute>, material: Option<Vec<Attribute>>) -> Result<Vec<Attribute>> {
    let mut t = token_object(on)?;
    t.extend(policy);
    t.extend(material.unwrap_or_else(|| kind(&on.object)));
    if on.object.class == Class::Data && on.spec.flag("CKA_PRIVATE").is_none() {
        t.push(Attribute::Private(false));
    }
    Ok(t)
}

/// A public object's class, and a certificate's type: what a plan knows of it before its value.
fn kind(object: &ObjectCfg) -> Vec<Attribute> {
    let mut t = vec![Attribute::Class(crate::token::class_of(object))];
    if object.class == Class::Certificate {
        t.push(Attribute::CertificateType(CertificateType::X_509));
    }
    t
}

/// A session key's template, without its value (the host's KEK, the `kw` input) or its public
/// material (the transport key's modulus and exponent), which the caller adds. wrap-rebind's
/// copy is [`rebind_copy`]: this is its part that does not depend on the key.
#[must_use]
pub fn session(key: SessionKey) -> Vec<Attribute> {
    let secret = |kt| vec![Attribute::Class(ObjectClass::SECRET_KEY), Attribute::KeyType(kt), Attribute::Token(false)];
    match key {
        SessionKey::ProofSecret { sealed, .. } => {
            let mut t = secret(KeyType::GENERIC_SECRET);
            t.extend([Attribute::Sensitive(sealed), Attribute::Extractable(!sealed)]);
            if sealed {
                t.push(Attribute::Sign(true));
            }
            t
        }
        SessionKey::RebindKek => vec![
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ],
        SessionKey::RebindCopy => vec![
            Attribute::Token(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ],
        // The fixed key is public, so it is created extractable; the key under commitment only
        // has to allow CKA_WRAP.
        SessionKey::KwInput => {
            let mut t = secret(KeyType::GENERIC_SECRET);
            t.extend([Attribute::Sensitive(false), Attribute::Extractable(true)]);
            t
        }
        SessionKey::HostKek => {
            let mut t = secret(KeyType::AES);
            t.extend([Attribute::Sensitive(true), Attribute::Extractable(false), Attribute::Wrap(true)]);
            t
        }
        SessionKey::TransportKey => vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Token(false),
            Attribute::Wrap(true),
            Attribute::Encrypt(true),
        ],
        // It leaves only wrapped to the transport key: never readable, whatever the module's
        // default.
        SessionKey::ExportKek => {
            let mut t = secret(KeyType::AES);
            t.extend([
                Attribute::ValueLen(32.into()),
                Attribute::Wrap(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(true),
            ]);
            t
        }
        SessionKey::ImportKek => {
            let mut t = secret(KeyType::AES);
            t.extend([Attribute::Unwrap(true), Attribute::Sensitive(true), Attribute::Extractable(false)]);
            t
        }
    }
}

/// wrap-rebind's copy of `object`'s key: a session key of its type that allows each use the
/// `commits` compute with, sealed.
///
/// # Errors
///
/// Whatever the key type refuses.
pub fn rebind_copy(object: Object<'_>, commits: &[Commit]) -> Result<Vec<Attribute>> {
    let mut t = session(SessionKey::RebindCopy);
    t.push(Attribute::KeyType(key_type_of(object)?));
    for c in commits {
        let usage = match c {
            Commit::Hmac(_) | Commit::Cmac => Attribute::Sign(true),
            Commit::KcvEcb(_) => Attribute::Encrypt(true),
            Commit::KcvEcbDecrypt(_) => Attribute::Decrypt(true),
            Commit::Kw => Attribute::Wrap(true),
        };
        // A template may not carry an attribute twice.
        if !t.contains(&usage) {
            t.push(usage);
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::config::{Locator, SpecMigrateCfg};
    use cakeys_core::types::KeyType as Kt;
    use cryptoki::object::AttributeType;

    fn spec(private: &[(&str, bool)], public: &[(&str, bool)]) -> SpecCfg {
        let attrs = |a: &[(&str, bool)]| a.iter().map(|(n, v)| ((*n).to_owned(), AttrValue::Bool(*v))).collect();
        SpecCfg {
            object: "k".into(),
            attributes: attrs(private),
            public_attributes: attrs(public),
            migrate: SpecMigrateCfg::default(),
            tokens: BTreeMap::new(),
        }
    }

    /// The public half's defaults follow its own template's declarations (templates.rs F1): a
    /// private key declared `CKA_PRIVATE = true` leaves its public half public and verifying,
    /// generated or imported; only `publicAttributes` naming the attribute removes the default,
    /// so no type is there twice.
    #[test]
    fn the_public_half_takes_its_defaults_from_its_own_declarations() {
        let object = ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Ec)) };
        let locator = Locator { label: Some("k".into()), id: None };
        let count = |t: &[Attribute], ty: AttributeType| t.iter().filter(|a| a.attribute_type() == ty).count();
        for (private, public, carries) in [
            (&[("CKA_PRIVATE", true), ("CKA_SIGN", true)][..], &[][..], true),
            (&[][..], &[][..], true),
            (&[("CKA_PRIVATE", true)][..], &[("CKA_PRIVATE", true), ("CKA_VERIFY", true)][..], false),
        ] {
            let s = spec(private, public);
            let on = Declared { object: Object::new(&object).unwrap(), spec: &s, locator: &locator };
            for t in [generation_public(on, vec![], None).unwrap().unwrap(), public_half(on, vec![], None).unwrap()] {
                assert_eq!(t.contains(&Attribute::Private(false)), carries, "{private:?} {public:?}: {t:?}");
                assert_eq!(t.contains(&Attribute::Verify(true)), carries, "{private:?} {public:?}: {t:?}");
                assert!(count(&t, AttributeType::Private) <= 1 && count(&t, AttributeType::Verify) <= 1, "{t:?}");
            }
            assert_eq!(public_declares(&s, "CKA_PRIVATE"), !carries);
        }
    }

    /// A plan's policy template: a mechanism name the baseline does not know is "cannot decide"
    /// (`None`), anything else `policy` refuses is the refusal, whatever its kind (templates.rs
    /// F2: no error stands in for the unknown name).
    #[test]
    fn only_an_unknown_mechanism_name_leaves_the_plan_undecided() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let attrs = |a: &[(&str, AttrValue)]| a.iter().map(|(n, v)| ((*n).to_owned(), v.clone())).collect();
        let mechanisms = |names: &[&str]| AttrValue::mechanisms(names.iter().map(|n| (*n).to_owned()));
        let known = known_policy(&attrs(&[("CKA_ALLOWED_MECHANISMS", mechanisms(&["CKM_ECDSA"]))])).unwrap();
        assert_eq!(known, Some(vec![Attribute::AllowedMechanisms(vec![MechanismType::ECDSA])]));
        let vendor = attrs(&[("CKA_ALLOWED_MECHANISMS", mechanisms(&["CKM_VENDOR_THING"]))]);
        assert_eq!(known_policy(&vendor).unwrap(), None);
        for refused in [
            attrs(&[("CKA_NO_SUCH_FLAG", AttrValue::Bool(true))]),
            attrs(&[
                ("CKA_ALLOWED_MECHANISMS", mechanisms(&["CKM_ECDSA"])),
                ("CKA_NO_SUCH_FLAG", AttrValue::Bool(true)),
            ]),
        ] {
            assert!(matches!(known_policy(&refused), Err(KmError::Validation(_))), "{refused:?}");
        }
    }
}
