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
use crate::token::{bool_attr, curve_of, key_type_of, locator_attrs};
use cakeys_core::config::{AttrValue, ObjectCfg};
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
    let unknown = || KmError::NotFound(String::new().into());
    let by_name = |_: &str, n: &str| {
        baseline.mechanisms.get(n).and_then(|id| MechanismType::try_from(*id).ok()).ok_or_else(unknown)
    };
    match policy(attrs, &by_name) {
        Ok(t) => Ok(Some(t)),
        Err(KmError::NotFound(_)) => Ok(None),
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
/// = false`), each unless the spec declares it (a template may not carry a type twice).
fn public_defaults(on: Declared<'_>, t: &mut Vec<Attribute>) {
    let declared = |n| on.spec.attributes.contains_key(n) || on.spec.public_attributes.contains_key(n);
    if !declared("CKA_VERIFY") {
        t.push(Attribute::Verify(true));
    }
    if !declared("CKA_PRIVATE") {
        t.push(Attribute::Private(false));
    }
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
            let curve = curve_of(on.object)?;
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
        Attribute::Class(crate::token::class_of(on.object)),
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
    t.extend(material.unwrap_or_else(|| kind(on.object)));
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
pub fn rebind_copy(object: &ObjectCfg, commits: &[Commit]) -> Result<Vec<Attribute>> {
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
