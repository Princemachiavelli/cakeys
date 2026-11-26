//! The object's type and policy. This file checks what the spec declares against what the token
//! reports, reads the observed policy vector and the immutable attributes, and maps the boolean
//! attributes to `cryptoki`.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// Checks the intrinsic type and every policy attribute of the spec against the live object.
    ///
    /// # Errors
    ///
    /// `Conflict` when the token's object is not of the declared type (no `CKA_KEY_TYPE`, or
    /// another curve, modulus size or length), or when it violates a declared policy attribute.
    /// `Unsupported` for an object class that cakeys does not manage, for a private data object
    /// whose spec does not declare `CKA_PRIVATE = true`, and for a key whose `CKA_VALUE_LEN` the
    /// token does not report.
    pub fn check(&self, h: ObjectHandle, object: Object<'_>, spec: &SpecCfg) -> Result<()> {
        let class = class_of(&object);
        if class == ObjectClass::CERTIFICATE {
            return match self.attr(h, AttributeType::CertificateType)? {
                Some(Attribute::CertificateType(CertificateType::X_509)) => self.check_policy(h, spec),
                other => Err(KmError::Conflict(Reason::check(
                    Check::ObjectType,
                    format!("CKA_CERTIFICATE_TYPE is {other:?}, not CKC_X_509"),
                ))),
            };
        }
        if class == ObjectClass::DATA {
            // A data object's identity is a hash of its value. For a private value that can be
            // guessed (a password, a PIN), that hash in the lock lets anyone who reads the lock
            // test guesses offline. So a private data object is identified only when its spec
            // declares `CKA_PRIVATE = true`, which is the spec author's statement, visible in
            // review, that nobody can guess the value.
            return match (self.attr(h, AttributeType::Private)?, spec.flag("CKA_PRIVATE")) {
                (Some(Attribute::Private(false)), _) | (Some(Attribute::Private(true)), Some(true)) => {
                    self.check_policy(h, spec)
                }
                (other, _) => Err(KmError::Unsupported(
                    format!(
                        "data object is CKA_PRIVATE ({other:?}): its value hash would let anyone with \
                     the lock guess the value offline; declare CKA_PRIVATE = true in the spec to \
                     identify it anyway, for a value nobody can guess (a random secret, never a \
                     password or PIN)"
                    )
                    .into(),
                )),
            };
        }
        let Some(kt) = self.key_type(h)? else {
            return Err(KmError::Conflict(Reason::check(Check::ObjectType, "object has no CKA_KEY_TYPE")));
        };
        if kt != key_type_of(object)? {
            return Err(KmError::Conflict(Reason::check(
                Check::ObjectType,
                format!("CKA_KEY_TYPE is {kt}, spec object type says {}", object.key_type.map_or("", Kt::name)),
            )));
        }
        // The key type matched. For an EC or Edwards object, the curve must also match.
        if let Some(want) = object.curve() {
            match self.attr(h, AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) if Curve::from_params(&p) == Some(want) => {}
                other => {
                    return Err(KmError::Conflict(Reason::check(
                        Check::ObjectType,
                        format!("CKA_EC_PARAMS {other:?} is not {want:?}"),
                    )));
                }
            }
        }
        if let Some(bits) = object.modulus_bits {
            // Compare the number of significant bits, because a 2047-bit key is not a 2048-bit
            // key, even when both take the same number of bytes (review 2026-11-24 B-5).
            let size = id::modulus_bits;
            match self.attr(h, AttributeType::Modulus)? {
                Some(Attribute::Modulus(m)) if size(&m) == bits => {}
                other => {
                    let have = other.and_then(|a| match a {
                        Attribute::Modulus(m) => Some(size(&m)),
                        _ => None,
                    });
                    return Err(KmError::Conflict(Reason::check(
                        Check::ObjectType,
                        format!("RSA modulus is {have:?} bits, spec says {bits}"),
                    )));
                }
            }
        }
        // A DES3 key has no `CKA_VALUE_LEN`, because its key type fixes its length, so the check
        // of `CKA_KEY_TYPE` above covers it.
        if let Some(len) = object.value_len.filter(|_| object.key_type.and_then(Kt::fixed_value_len).is_none()) {
            match self.attr(h, AttributeType::ValueLen)? {
                Some(Attribute::ValueLen(v)) if *v == len => {}
                Some(Attribute::ValueLen(v)) => {
                    return Err(KmError::Conflict(Reason::check(
                        Check::ObjectType,
                        format!("CKA_VALUE_LEN is {}, spec says {len}", u64::from(v)),
                    )));
                }
                // PKCS#11 requires the attribute on the key. A module that stores an imported key
                // without it (tpm2-pkcs11's `C_CreateObject`) makes the length impossible to
                // verify, but it does not show a different length, so the result is `Unsupported`
                // and not `Conflict`.
                _ => {
                    return Err(KmError::Unsupported(
                        format!(
                            "token '{}' reports no CKA_VALUE_LEN for the key, so its length (spec: {len}) cannot be \
                         checked",
                            self.name
                        )
                        .into(),
                    ));
                }
            }
        }
        self.check_policy(h, spec)
    }

    /// Returns the observed policy vector: every boolean attribute of the class of `h` (PKCS#11
    /// 3.2 §4, `cakeys_core::attrs::observed`) that the token reports, whether or not the spec
    /// declares it, and `CKA_ALLOWED_MECHANISMS` on key objects when it can be read. Attributes
    /// that the object lacks, or that the module refuses to read, are left out (`if_readable`).
    ///
    /// # Errors
    ///
    /// `Conflict` when the object has no `CKA_CLASS`. `Unsupported` for a class that cakeys does
    /// not manage. `Unavailable` when the device, the token or the session fails a read.
    pub fn policy(&self, h: ObjectHandle) -> Result<BTreeMap<String, AttrValue>> {
        let class = match self.attr(h, AttributeType::Class)? {
            Some(Attribute::Class(c)) => {
                managed_class(c).ok_or_else(|| KmError::Unsupported(format!("object class {c}").into()))?
            }
            _ => return Err(KmError::Conflict(Reason::check(Check::ObjectType, "object has no CKA_CLASS"))),
        };
        let mut policy = BTreeMap::new();
        for name in attrs::observed(class) {
            let Some(t) = bool_attr(name, false).map(|a| a.attribute_type()) else { continue };
            // An attribute that this token does not support, or refuses to read, is not part of
            // the vector.
            if let Some(b) = self.flag_if_readable(h, t)? {
                policy.insert(name.to_owned(), AttrValue::Bool(b));
            }
        }
        if attrs::has_allowed_mechanisms(class) {
            // An empty list is not reported, because it cannot be told apart from an absent list,
            // and both mean that the key is not restricted.
            if let Some(m) = self.allowed_if_readable(h)? {
                policy.insert(
                    "CKA_ALLOWED_MECHANISMS".to_owned(),
                    AttrValue::mechanisms(m.iter().copied().map(mechanism_namer())),
                );
            }
        }
        Ok(policy)
    }

    /// Returns the `CKA_ALLOWED_MECHANISMS` of `h`, or `None` when the object has no list or an
    /// empty list. Modules report an unrestricted key in both ways (`SoftHSM` reports an empty
    /// list), and neither form restricts the key.
    ///
    /// # Errors
    ///
    /// `Unsupported` when the list names a mechanism that this build's cryptoki cannot read back
    /// (a build without the `cryptoki-allowed-mechanisms-unnamed` patch, docs/OPEN.md).
    /// Otherwise, the module's error.
    pub(crate) fn allowed_mechanisms(&self, h: ObjectHandle) -> Result<Option<Vec<MechanismType>>> {
        match self.read_allowed(h) {
            Ok(m) => Ok(m),
            Err(CkError::NotSupported) => Err(KmError::Unsupported(
                format!(
                    "CKA_ALLOWED_MECHANISMS on token '{}' names a mechanism this build's cryptoki cannot read \
                 (a build without the cryptoki-allowed-mechanisms-unnamed patch, docs/OPEN.md)",
                    self.name
                )
                .into(),
            )),
            Err(e) => Err(ck("C_GetAttributeValue")(e)),
        }
    }

    /// Works as [`Self::allowed_mechanisms`], but returns `None` when the attribute cannot be read
    /// ([`if_readable`]). It also returns `None` when this build's cryptoki cannot name a
    /// mechanism in the list.
    pub(crate) fn allowed_if_readable(&self, h: ObjectHandle) -> Result<Option<Vec<MechanismType>>> {
        if_readable(self.read_allowed(h))
    }

    fn read_allowed(&self, h: ObjectHandle) -> std::result::Result<Option<Vec<MechanismType>>, CkError> {
        Ok(self.session.get_attributes(h, &[AttributeType::AllowedMechanisms])?.into_iter().find_map(|a| match a {
            Attribute::AllowedMechanisms(m) if !m.is_empty() => Some(m),
            _ => None,
        }))
    }

    /// Returns `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` and
    /// `CKA_KEY_GEN_MECHANISM` of a key (all empty for other classes). Attributes that the object
    /// lacks, or that the module refuses to read, are left out.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the device, the token or the session fails a read (`if_readable`).
    pub fn immutables(&self, h: ObjectHandle) -> Result<Immutables> {
        let flag = |t| Ok::<_, KmError>(self.attr_if_readable(h, t)?.as_ref().and_then(attr_bool));
        Ok(Immutables {
            local: flag(AttributeType::Local)?,
            never_extractable: flag(AttributeType::NeverExtractable)?,
            always_sensitive: flag(AttributeType::AlwaysSensitive)?,
            key_gen_mechanism: match self.attr_if_readable(h, AttributeType::KeyGenMechanism)? {
                // `CK_UNAVAILABLE_INFORMATION` means that there is no generation mechanism,
                // because the key was imported.
                Some(Attribute::KeyGenMechanism(m)) if *m != CK_UNAVAILABLE_INFORMATION => Some(m.to_string()),
                _ => None,
            },
        })
    }
    /// Checks that every declared policy attribute of the spec matches the live object.
    fn check_policy(&self, h: ObjectHandle, spec: &SpecCfg) -> Result<()> {
        self.check_attrs(h, &spec.attributes, "")
    }

    fn check_attrs(&self, h: ObjectHandle, attrs: &BTreeMap<String, AttrValue>, what: &str) -> Result<()> {
        for (name, want) in attrs {
            let have = self.attr_value(h, name)?;
            if have.as_ref() != Some(want) {
                return Err(KmError::Conflict(Reason::check(
                    Check::PolicyAttribute,
                    format!(
                        "{what}{name} is {} on token '{}', spec wants {want}",
                        have.map_or("unreadable".into(), |v| v.to_string()),
                        self.name
                    ),
                )));
            }
        }
        Ok(())
    }

    /// Reads a policy attribute of `h` in the form in which the spec writes it.
    fn attr_value(&self, h: ObjectHandle, name: &str) -> Result<Option<AttrValue>> {
        if name == "CKA_ALLOWED_MECHANISMS" {
            return Ok(self
                .allowed_mechanisms(h)?
                .map(|m| AttrValue::mechanisms(m.into_iter().map(mechanism_namer()))));
        }
        let t = bool_attr(name, false).ok_or_else(|| unsupported_attr(name))?.attribute_type();
        Ok(self.flag(h, t)?.map(AttrValue::Bool))
    }

    /// Reads a boolean policy attribute as the module reports it, corrected by the provider when
    /// the module reports it wrongly (`Provider::policy_flag`).
    fn flag(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<bool>> {
        self.repaired(h, t, self.attr(h, t)?.as_ref())
    }

    /// Works as [`Self::flag`], but returns `None` when the module refuses to read the attribute
    /// ([`if_readable`]).
    fn flag_if_readable(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<bool>> {
        self.repaired(h, t, self.attr_if_readable(h, t)?.as_ref())
    }

    /// Returns `read` as the provider corrects it. The provider corrects the value only when it
    /// declares a repair of `t` for the key type of the private key `h` (`Provider::repairs`), so
    /// that no repair widens a permission that the provider does not declare (review 2026-11-24
    /// B-3). The key's type is read only for an attribute that some repair names. A failure of
    /// the device, the token or the session during that read is returned as an error, and it is
    /// not treated as a missing key type.
    fn repaired(&self, h: ObjectHandle, t: AttributeType, read: Option<&Attribute>) -> Result<Option<bool>> {
        let Some(reported) = read.and_then(attr_bool) else { return Ok(None) };
        let repairs = self.provider.repairs();
        if !repairs.iter().any(|(a, _)| *a == t) {
            return Ok(Some(reported));
        }
        let key_type = match self.attr_if_readable(h, AttributeType::Class)? {
            Some(Attribute::Class(ObjectClass::PRIVATE_KEY)) => self.key_type_if_readable(h)?,
            _ => None,
        };
        Ok(Some(match key_type {
            Some(kt) if repairs.contains(&(t, kt)) => self.provider.policy_flag(t, reported, &|| Some(kt)),
            _ => reported,
        }))
    }

    /// Checks `publicAttributes` on the public key object of the pair. That object is `h` itself
    /// for an object adopted with `publicOnly`. Otherwise, it is the single public key object
    /// under the locator, which must hold the same public key as `h`.
    ///
    /// # Errors
    ///
    /// `NotFound` when the pair's public half is not under the locator. `Ambiguous` when several
    /// public key objects share the locator. `Conflict` when the public key object holds another
    /// key or cannot be read. Every rejection of `check_attrs` on the public key object itself.
    pub fn check_public_half(&self, h: ObjectHandle, spec: &SpecCfg, loc: &Locator, public_only: bool) -> Result<()> {
        if spec.public_attributes.is_empty() {
            return Ok(());
        }
        let p = if public_only {
            h
        } else {
            let p = match self.find(ObjectClass::PUBLIC_KEY, loc)?.as_slice() {
                [p] => *p,
                [] => {
                    return Err(KmError::NotFound(
                        "publicAttributes are declared, but there is no public key object under the locator".into(),
                    ));
                }
                _ => {
                    return Err(KmError::Ambiguous(Reason::check(
                        Check::LocatorUnique,
                        "several public key objects share the locator",
                    )));
                }
            };
            same_public_key(self.held_spki(p)?.as_deref(), self.material_spki(h)?.as_deref())?;
            p
        };
        self.check_attrs(p, &spec.public_attributes, "public key object: ")
    }

    /// Returns the template attributes for declared policy values (a spec's `attributes`), as a
    /// creation or an import puts them on the object. Each mechanism name must be a mechanism
    /// that the token offers.
    ///
    /// # Errors
    ///
    /// `Validation` for an attribute that cakeys cannot set. `Unsupported` for a mechanism that the
    /// token does not offer.
    pub fn policy_template(&self, attrs: &BTreeMap<String, AttrValue>) -> Result<Vec<Attribute>> {
        // The token's mechanisms are named once per template, and not once per declared name
        // (policy.rs F3).
        let named = || {
            let name = mechanism_namer();
            self.mechanisms.iter().map(|m| (name(*m), *m)).collect::<BTreeMap<String, MechanismType>>()
        };
        let offered = std::cell::OnceCell::new();
        crate::templates::policy(attrs, &|name, n| {
            offered.get_or_init(named).get(n).copied().ok_or_else(|| {
                self.unsupported_for(Topic::Mechanism, format!("{name}: token '{}' does not offer {n}", self.name))
            })
        })
    }
}

/// The "same key" check of [`Token::check_public_half`]. The public key of the public key object
/// (`held`) must be readable, and the private key's own material (`own`), when the private key
/// has any, must equal it. A private key without its point (`SoftHSM`'s EC keys) takes its SPKI
/// from that same public key object ([`Token::spki`], which cross-checks it), so in that case the
/// two are the same by construction.
///
/// # Errors
///
/// `Conflict` for a public key object that cannot be read (it never counts as a match: policy.rs
/// F2), or for a public key object that holds another key.
fn same_public_key(held: Option<&[u8]>, own: Option<&[u8]>) -> Result<()> {
    match (held, own) {
        (None, _) => Err(KmError::Conflict(Reason::check(
            Check::PublicSameKey,
            "the public key object under the locator exposes no key material, so it cannot be told apart from \
             another key's",
        ))),
        (Some(held), Some(own)) if held != own => Err(KmError::Conflict(Reason::check(
            Check::PublicSameKey,
            "the public key object under the locator holds another key",
        ))),
        _ => Ok(()),
    }
}

/// Returns a function that names a mechanism by its `CKM_` name. It uses cryptoki's name when
/// cryptoki has one. Otherwise, it uses the name that the specification baseline gives for the
/// mechanism's value (cryptoki names about 350 of the mechanisms of PKCS#11 3.2). Otherwise, it
/// uses cryptoki's `unknown …` text, which is the case for a vendor's mechanism. keys.toml, the
/// lock and the token's lists are all compared in this one spelling. The baseline is indexed by
/// value once, when the first mechanism that cryptoki does not name needs it, and it is never
/// scanned for each mechanism (policy.rs F3).
pub(crate) fn mechanism_namer() -> impl Fn(MechanismType) -> String {
    let by_value = std::cell::OnceCell::new();
    move |m| {
        let name = m.to_string();
        if name.starts_with("CKM_") {
            return name;
        }
        let by_value: &std::collections::HashMap<u64, &'static str> = by_value.get_or_init(|| {
            cakeys_profile::Set::active()
                .ok()
                .and_then(|set| set.baseline().ok())
                .map(|b| b.mechanisms.iter().map(|(n, id)| (*id, n.as_str())).collect())
                .unwrap_or_default()
        });
        by_value.get(&*m).map_or(name, |n| (*n).to_owned())
    }
}

/// Every boolean attribute that cakeys reads or sets, by its PKCS#11 name. `cakeys_core::attrs`
/// says which class carries which attribute, and this macro defines only the mapping to
/// `cryptoki`.
macro_rules! bool_attrs {
    ($($name:literal => $variant:ident),* $(,)?) => {
        /// Returns the boolean attribute `name` with the value `v`, or `None` for a name that is
        /// not a boolean attribute.
        pub fn bool_attr(name: &str, v: bool) -> Option<Attribute> {
            match name {
                $($name => Some(Attribute::$variant(v)),)*
                _ => None,
            }
        }

        /// Returns the value of a boolean attribute, or `None` for an attribute that is not
        /// boolean.
        pub(super) fn attr_bool(a: &Attribute) -> Option<bool> {
            match a {
                $(Attribute::$variant(b))|* => Some(*b),
                _ => None,
            }
        }
    };
}

bool_attrs! {
    "CKA_TOKEN" => Token,
    "CKA_PRIVATE" => Private,
    "CKA_MODIFIABLE" => Modifiable,
    "CKA_COPYABLE" => Copyable,
    "CKA_DESTROYABLE" => Destroyable,
    "CKA_SIGN" => Sign,
    "CKA_SIGN_RECOVER" => SignRecover,
    "CKA_VERIFY" => Verify,
    "CKA_VERIFY_RECOVER" => VerifyRecover,
    "CKA_ENCRYPT" => Encrypt,
    "CKA_DECRYPT" => Decrypt,
    "CKA_WRAP" => Wrap,
    "CKA_UNWRAP" => Unwrap,
    "CKA_DERIVE" => Derive,
    "CKA_SENSITIVE" => Sensitive,
    "CKA_EXTRACTABLE" => Extractable,
    "CKA_WRAP_WITH_TRUSTED" => WrapWithTrusted,
    "CKA_ALWAYS_AUTHENTICATE" => AlwaysAuthenticate,
    "CKA_TRUSTED" => Trusted,
    "CKA_LOCAL" => Local,
    "CKA_NEVER_EXTRACTABLE" => NeverExtractable,
    "CKA_ALWAYS_SENSITIVE" => AlwaysSensitive,
}

fn unsupported_attr(name: &str) -> KmError {
    KmError::Validation(format!("unsupported policy attribute {name}").into())
}

/// `CK_UNAVAILABLE_INFORMATION`: the value that a token reports for an attribute that it cannot
/// give.
const CK_UNAVAILABLE_INFORMATION: std::os::raw::c_ulong = !0;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every boolean attribute that the core table names maps to a `cryptoki` attribute, and back.
    #[test]
    fn every_tabled_boolean_maps_to_cryptoki() {
        for &class in Class::ALL {
            for name in attrs::observed(class) {
                assert_eq!(bool_attr(name, true).as_ref().and_then(attr_bool), Some(true), "{name}");
            }
        }
        for name in
            ["CKA_SIGN_RECOVER", "CKA_VERIFY_RECOVER", "CKA_LOCAL", "CKA_NEVER_EXTRACTABLE", "CKA_ALWAYS_SENSITIVE"]
        {
            assert_eq!(bool_attr(name, false).as_ref().and_then(attr_bool), Some(false), "{name}");
        }
        assert!(bool_attr("CKA_ALLOWED_MECHANISMS", true).is_none());
    }

    /// The public half of a pair is the same key only when its public key can be read and the
    /// private key's own material, when it has any, equals that key (policy.rs F2). A public key
    /// object that cannot be read is not a match, and it never passes.
    #[test]
    fn an_unreadable_public_half_is_no_match() {
        let (a, b) = (&b"spki a"[..], &b"spki b"[..]);
        assert!(same_public_key(Some(a), Some(a)).is_ok());
        assert!(same_public_key(Some(a), None).is_ok(), "a private key without its point takes the public half's");
        for (held, own, why) in [(None, Some(a), "exposes no key material"), (None, None, "exposes no key material")] {
            let e = same_public_key(held, own).unwrap_err();
            assert!(matches!(&e, KmError::Conflict(m) if m.contains(why)), "{e}");
        }
        let e = same_public_key(Some(a), Some(b)).unwrap_err();
        assert!(matches!(&e, KmError::Conflict(m) if m.contains("holds another key")), "{e}");
    }

    /// A mechanism is named by its `CKM_` constant, which is the only spelling that keys.toml and
    /// the lock use.
    #[test]
    fn mechanisms_are_named_by_their_constants() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let name = mechanism_namer();
        for (m, n) in [(MechanismType::ECDSA, "CKM_ECDSA"), (MechanismType::SHA256_HMAC, "CKM_SHA256_HMAC")] {
            assert_eq!(name(m), n);
        }
    }
}
