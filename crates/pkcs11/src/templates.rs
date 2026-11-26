//! The templates that cakeys builds from what is known before the call. The run sends these
//! templates, as the provider adjusts them ([`Provider::template`]). A plan asks the provider
//! about the same templates before anything runs ([`crate::ops::check_import`],
//! [`crate::gate::check`], camigrate's plan), so that a refusal comes before anything is made.
//!
//! The caller supplies the object's material. A secret value or a private key's components are
//! added after the provider's adjustment, and they are never shown to the provider. A public
//! object's value and a public key's material are in the template at the run, but they are absent
//! from a plan's template, because the plan has not read them.
//!
//! [`Provider::template`]: crate::Provider::template

use crate::provider::{Declared, SessionKey};
use crate::token::{bool_attr, key_type_of, locator_attrs};
use cakeys_core::config::{AttrValue, Object, ObjectCfg, SpecCfg};
use cakeys_core::id::Commit;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass};
use std::collections::BTreeMap;

/// Returns the template attributes for declared policy values (a spec's `attributes`). Each
/// mechanism name is mapped by `mechanism(attribute, name)`. At the run, that function uses the
/// open token's list (`Token::policy_template`). In a plan, it uses the profile baseline
/// ([`known_policy`]).
///
/// # Errors
///
/// `Validation` for an attribute that cakeys cannot set. Any error that `mechanism` returns.
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

/// Works as [`policy`] without a token. Each mechanism name is mapped by the profile baseline's
/// dictionary of the PKCS#11 names. Returns `None` when the baseline does not know a name (for
/// example, a vendor's mechanism, which only the token's own list maps), because then the plan
/// cannot build what the run will send.
///
/// # Errors
///
/// The same errors as [`policy`], and the baseline's parse error, which is a bug in the commit.
pub fn known_policy(attrs: &BTreeMap<String, AttrValue>) -> Result<Option<Vec<Attribute>>> {
    let baseline =
        cakeys_profile::Set::active().and_then(|s| s.baseline()).map_err(|e| KmError::Validation(e.into()))?;
    // This flag records whether the mapper found a name that it does not know. That is the only
    // failure that means "cannot decide". The flag, and not the kind of the error, distinguishes
    // it from every other error that `policy` returns.
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

/// Returns `CKA_TOKEN` and the locator attributes, with which every token object's template
/// starts.
fn token_object(on: Declared<'_>) -> Result<Vec<Attribute>> {
    let mut t = vec![Attribute::Token(true)];
    t.extend(locator_attrs(on.locator)?);
    Ok(t)
}

/// Adds a public key's defaults next to the spec's public `policy`: `CKA_VERIFY = true` and
/// `CKA_PRIVATE = false`. Each default is added only when the public half's template does not
/// declare the attribute, because a template may not contain an attribute type twice
/// ([`public_declares`]).
fn public_defaults(on: Declared<'_>, t: &mut Vec<Attribute>) {
    if !public_declares(on.spec, "CKA_VERIFY") {
        t.push(Attribute::Verify(true));
    }
    if !public_declares(on.spec, "CKA_PRIVATE") {
        t.push(Attribute::Private(false));
    }
}

/// Returns whether a key pair's public half declares the attribute `name` in its
/// `publicAttributes`, which are the only declared attributes that its template contains. The
/// spec's `attributes` apply only to the private key, so a private key that declares
/// `CKA_PRIVATE = true` leaves the public half public (templates.rs F1).
#[must_use]
pub fn public_declares(spec: &SpecCfg, name: &str) -> bool {
    spec.public_attributes.contains_key(name)
}

/// Returns cakeys' template for the key that `on` generates. For a key pair, this is the private
/// key's template (`CKA_TOKEN`, the locator and the spec's `policy`). For a secret key, this is
/// the complete template.
///
/// # Errors
///
/// `Validation` for a secret key without its size (`valueLen`). Any error from the key type.
pub fn generation_key(on: Declared<'_>, policy: Vec<Attribute>) -> Result<Vec<Attribute>> {
    let mut t = token_object(on)?;
    match key_type_of(on.object)? {
        KeyType::RSA | KeyType::EC | KeyType::EC_EDWARDS => {}
        // The key type fixes the length, so a template with `CKA_VALUE_LEN` would be
        // inconsistent.
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

/// Returns a key pair's public template: the size or the curve (`ec_params`, or otherwise the
/// curve's OID), the spec's `public_policy`, and the public defaults. Returns `None` for a secret
/// key.
///
/// # Errors
///
/// `Validation` for an RSA key without `modulusBits`. Any error from the key type or the curve.
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

/// Returns the template of a private or secret key that is imported under `on` (by
/// `C_CreateObject` or `C_UnwrapKey`): its class and key type, `CKA_TOKEN`, the locator and
/// `policy`. The caller adds the key's value afterwards.
///
/// # Errors
///
/// Any error from the key type or the locator.
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

/// Returns the template of the public key object that is made next to an imported private key,
/// in the same way as a generation makes its public half. The template contains the key's
/// `material` (`token::public_key_attrs`, or `None` in a plan), the spec's `public_policy`, and
/// the public defaults.
///
/// # Errors
///
/// Any error from the locator.
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

/// Returns the template of a certificate, a data object or a public key object that is created
/// from its value: `CKA_TOKEN`, the locator, `policy`, and then its class and `material`
/// (`token::public_object_attrs`). In a plan, `material` is `None`, and the template contains the
/// class and, for a certificate, its type. A data object whose spec does not declare
/// `CKA_PRIVATE` is declared public, because a token's default may make it private (`SoftHSM`
/// does \[run\]).
///
/// # Errors
///
/// Any error from the locator.
pub fn object(on: Declared<'_>, policy: Vec<Attribute>, material: Option<Vec<Attribute>>) -> Result<Vec<Attribute>> {
    let mut t = token_object(on)?;
    t.extend(policy);
    t.extend(material.unwrap_or_else(|| kind(&on.object)));
    if on.object.class == Class::Data && on.spec.flag("CKA_PRIVATE").is_none() {
        t.push(Attribute::Private(false));
    }
    Ok(t)
}

/// Returns a public object's class and, for a certificate, its type. This is what a plan knows
/// about the object before it reads its value.
fn kind(object: &ObjectCfg) -> Vec<Attribute> {
    let mut t = vec![Attribute::Class(crate::token::class_of(object))];
    if object.class == Class::Certificate {
        t.push(Attribute::CertificateType(CertificateType::X_509));
    }
    t
}

/// A session key's template, which only [`session`] and [`rebind_copy`] build (review 2026-11-24
/// B-8). It holds the key that it is for, and attributes that keep the key off the token
/// (`CKA_TOKEN = false`) and as sealed as its purpose requires. No caller can build it in another
/// way or loosen it afterwards: the provider's adjustment is checked (`Provider::adjusted`), and
/// material is added only through [`Self::with_material`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTemplate {
    key: SessionKey,
    attrs: Vec<Attribute>,
}

impl SessionTemplate {
    /// Returns the session key that the template is for.
    #[must_use]
    pub fn key(&self) -> SessionKey {
        self.key
    }

    /// Returns the template's attributes.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.attrs
    }

    /// Returns the template's `CKA_TOKEN`, `CKA_SENSITIVE` and `CKA_EXTRACTABLE`, when it sets
    /// them. These attributes decide whether the key outlives the session and whether it can be
    /// read from the token.
    #[must_use]
    pub fn sealing(&self) -> [Option<bool>; 3] {
        let flag = |want: AttributeType| {
            self.attrs.iter().find_map(|a| match a {
                Attribute::Token(b) | Attribute::Sensitive(b) | Attribute::Extractable(b)
                    if a.attribute_type() == want =>
                {
                    Some(*b)
                }
                _ => None,
            })
        };
        [flag(AttributeType::Token), flag(AttributeType::Sensitive), flag(AttributeType::Extractable)]
    }

    /// Returns the same template with the key's public material `more` (for example, a
    /// transport key's modulus and exponent) added to its attributes.
    ///
    /// # Errors
    ///
    /// `Validation` for an attribute that the template already has, or for a security attribute
    /// (`provider::SECURITY`), because `more` may only add material and may not change what the
    /// template seals.
    pub fn with_material(mut self, more: impl IntoIterator<Item = Attribute>) -> Result<SessionTemplate> {
        for a in more {
            let t = a.attribute_type();
            if self.attrs.iter().any(|b| b.attribute_type() == t) || crate::provider::SECURITY.iter().any(|s| s.0 == t)
            {
                return Err(KmError::Validation(
                    format!("the session key {:?}'s template takes {t:?} from cakeys alone, not as material", self.key)
                        .into(),
                ));
            }
            self.attrs.push(a);
        }
        Ok(self)
    }
}

impl From<SessionTemplate> for Vec<Attribute> {
    fn from(t: SessionTemplate) -> Self {
        t.attrs
    }
}

/// Returns a session key's template, without its value (for the host's KEK and the `kw` input)
/// and without its public material (the transport key's modulus and exponent), which the caller
/// adds. The template of wrap-rebind's copy comes from [`rebind_copy`], and this function returns
/// only the part of it that does not depend on the key.
#[must_use]
pub fn session(key: SessionKey) -> SessionTemplate {
    SessionTemplate { key, attrs: session_attributes(key) }
}

/// Returns the attributes of the template that [`session`] returns.
fn session_attributes(key: SessionKey) -> Vec<Attribute> {
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
        // The fixed key is public, so it is created extractable. The key under commitment only
        // has to allow `CKA_WRAP`.
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
        // This key leaves the token only when it is wrapped to the transport key. It is never
        // readable, whatever the module's default is.
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

/// Returns the template of wrap-rebind's copy of the key of `object`. The copy is a sealed session
/// key of the same type, and it allows each operation with which the `commits` are computed.
///
/// # Errors
///
/// Any error from the key type.
pub fn rebind_copy(object: Object<'_>, commits: &[Commit]) -> Result<SessionTemplate> {
    let mut t = session_attributes(SessionKey::RebindCopy);
    t.push(Attribute::KeyType(key_type_of(object)?));
    for c in commits {
        let usage = match c {
            Commit::Hmac(_) | Commit::Cmac => Attribute::Sign(true),
            Commit::KcvEcb(_) => Attribute::Encrypt(true),
            Commit::KcvEcbDecrypt(_) => Attribute::Decrypt(true),
            Commit::Kw => Attribute::Wrap(true),
        };
        // A template may not contain an attribute twice.
        if !t.contains(&usage) {
            t.push(usage);
        }
    }
    Ok(SessionTemplate { key: SessionKey::RebindCopy, attrs: t })
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

    /// The public half's defaults follow the declarations of its own template (templates.rs F1).
    /// A private key that declares `CKA_PRIVATE = true` leaves its public half public and able to
    /// verify, whether the key is generated or imported. Only `publicAttributes` that name the
    /// attribute remove the default, so no attribute type is in the template twice.
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

    /// In a plan's policy template, a mechanism name that the baseline does not know means
    /// "cannot decide" (`None`). Every other error from `policy` is the refusal, whatever its kind
    /// (templates.rs F2: no other error is mistaken for the unknown name).
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

    /// The sealing of each session key is fixed by this test (review 2026-11-24 B-8: before it,
    /// flipping any of the flags passed every test). No session key is on the token. A key that
    /// must not leave the token is sensitive and not extractable (a sealed proof secret,
    /// wrap-rebind's KEK and copy, the host's KEK, and the import KEK). The export KEK is
    /// sensitive but extractable, so it leaves only when wrapped to the transport key. A key is
    /// readable only when it is public by design (the `kw` input, and an unsealed proof secret,
    /// which the module refused to seal). A transport public key sets neither flag.
    #[test]
    fn each_session_key_is_sealed_as_its_purpose_says() {
        use cakeys_core::config::Binding;
        let proof = |sealed| SessionKey::ProofSecret { binding: Binding::PopUnwrap, sealed };
        let (sealed, readable, wrappable, public) = (
            [Some(false), Some(true), Some(false)],
            [Some(false), Some(false), Some(true)],
            [Some(false), Some(true), Some(true)],
            [Some(false), None, None],
        );
        let pinned = [
            (proof(true), sealed),
            (proof(false), readable),
            (SessionKey::RebindKek, sealed),
            (SessionKey::RebindCopy, sealed),
            (SessionKey::KwInput, readable),
            (SessionKey::HostKek, sealed),
            (SessionKey::TransportKey, public),
            (SessionKey::ExportKek, wrappable),
            (SessionKey::ImportKek, sealed),
        ];
        for (key, want) in pinned {
            let t = session(key);
            assert_eq!((t.key(), t.sealing()), (key, want), "{key:?} as [CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE]");
        }
        let aes = ObjectCfg { value_len: Some(32), ..ObjectCfg::new(Class::SecretKey, Some(Kt::Aes)) };
        let copy = rebind_copy(Object::new(&aes).unwrap(), &[Commit::Kw]).unwrap();
        assert_eq!((copy.key(), copy.sealing()), (SessionKey::RebindCopy, sealed), "wrap-rebind's copy");
        // Adding material does not unseal the key.
        let loaded = session(SessionKey::HostKek).with_material([Attribute::ValueLen(32.into())]).unwrap();
        assert_eq!(loaded.sealing(), sealed);
        assert!(session(SessionKey::HostKek).with_material([Attribute::Extractable(true)]).is_err());
        assert!(session(SessionKey::TransportKey).with_material([Attribute::Wrap(false)]).is_err(), "already there");
    }
}
