//! The object's type and policy: what the spec declares, checked against what the token reports; the observed policy vector and immutables; and the mapping of boolean attributes to `cryptoki`.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// Check the intrinsic type and every policy attribute of the spec against the live object.
    ///
    /// # Errors
    ///
    /// `Conflict` whenever the token's object is not the declared type (missing
    /// `CKA_KEY_TYPE`, another curve, modulus or length) or violates a declared policy
    /// attribute; `Unsupported` for an object class cakeys does not manage.
    pub fn check(&self, h: ObjectHandle, object: &ObjectCfg, spec: &SpecCfg) -> Result<()> {
        let class = class_of(object);
        if class == ObjectClass::CERTIFICATE {
            return match self.attr(h, AttributeType::CertificateType)? {
                Some(Attribute::CertificateType(CertificateType::X_509)) => self.check_policy(h, spec),
                other => Err(KmError::Conflict(format!("CKA_CERTIFICATE_TYPE is {other:?}, not CKC_X_509").into())),
            };
        }
        if class == ObjectClass::DATA {
            // Its identity is a hash of the value: for a guessable private value (a password, a
            // PIN) that hash in the lock is an offline guessing oracle. So a private data object
            // is identified only when its spec declares CKA_PRIVATE = true: the spec's author
            // says, in review, that nobody can guess the value.
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
            return Err(KmError::Conflict("object has no CKA_KEY_TYPE".into()));
        };
        if kt != key_type_of(object)? {
            return Err(KmError::Conflict(
                format!("CKA_KEY_TYPE is {kt}, spec object type says {}", object.key_type.map_or("", Kt::name)).into(),
            ));
        }
        if kt == KeyType::EC || kt == KeyType::EC_EDWARDS {
            let want = curve_of(object)?;
            match self.attr(h, AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) if Curve::from_params(&p) == Some(want) => {}
                other => return Err(KmError::Conflict(format!("CKA_EC_PARAMS {other:?} is not {want:?}").into())),
            }
        }
        if let Some(bits) = object.modulus_bits {
            // A big integer may come with leading zero bytes: they are not part of its size.
            let size = |m: &[u8]| m.iter().skip_while(|b| **b == 0).count() as u64 * 8;
            match self.attr(h, AttributeType::Modulus)? {
                Some(Attribute::Modulus(m)) if size(&m) == bits => {}
                other => {
                    let have = other.and_then(|a| match a {
                        Attribute::Modulus(m) => Some(size(&m)),
                        _ => None,
                    });
                    return Err(KmError::Conflict(format!("RSA modulus is {have:?} bits, spec says {bits}").into()));
                }
            }
        }
        // A DES3 key's length is its key type's (no CKA_VALUE_LEN): checked as CKA_KEY_TYPE above.
        if let Some(len) = object.value_len.filter(|_| object.key_type.and_then(Kt::fixed_value_len).is_none()) {
            match self.attr(h, AttributeType::ValueLen)? {
                Some(Attribute::ValueLen(v)) if *v == len => {}
                Some(Attribute::ValueLen(v)) => {
                    return Err(KmError::Conflict(
                        format!("CKA_VALUE_LEN is {}, spec says {len}", u64::from(v)).into(),
                    ));
                }
                // PKCS#11 requires it of the key; a module that stores an imported key without it
                // (tpm2-pkcs11's C_CreateObject) leaves the type unverifiable, not different.
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

    /// The observed policy vector: every boolean attribute of `h`'s class (PKCS#11 3.2 §4,
    /// `cakeys_core::attrs::observed`) the token reports, declared in the spec or not, plus
    /// `CKA_ALLOWED_MECHANISMS` on key objects when readable. Those the object lacks or the module
    /// refuses are left out (`if_readable`).
    ///
    /// # Errors
    ///
    /// `Conflict` when the object exposes no `CKA_CLASS`; `Unsupported` for a class cakeys
    /// does not manage; `Unavailable` when the device, token or session fails a read.
    pub fn policy(&self, h: ObjectHandle) -> Result<BTreeMap<String, AttrValue>> {
        let class = match self.attr(h, AttributeType::Class)? {
            Some(Attribute::Class(c)) => {
                managed_class(c).ok_or_else(|| KmError::Unsupported(format!("object class {c}").into()))?
            }
            _ => return Err(KmError::Conflict("object has no CKA_CLASS".into())),
        };
        let mut policy = BTreeMap::new();
        for name in attrs::observed(class) {
            let Some(t) = bool_attr(name, false).map(|a| a.attribute_type()) else { continue };
            // Unsupported or refused on this token: not part of what it can show.
            if let Some(b) = self.flag_if_readable(h, t)? {
                policy.insert(name.to_owned(), AttrValue::Bool(b));
            }
        }
        if attrs::has_allowed_mechanisms(class) {
            // An empty list is not reported: it is indistinguishable from absent and means none.
            if let Some(m) = self.allowed_if_readable(h)? {
                policy.insert(
                    "CKA_ALLOWED_MECHANISMS".to_owned(),
                    AttrValue::mechanisms(m.iter().copied().map(mechanism_namer())),
                );
            }
        }
        Ok(policy)
    }

    /// `h`'s `CKA_ALLOWED_MECHANISMS`, `None` where the object has none or an empty one: modules
    /// report an unrestricted key both ways (`SoftHSM` empty), and neither restricts it.
    ///
    /// # Errors
    ///
    /// `Unsupported` where the list names a mechanism this build's cryptoki cannot read back
    /// (one without the `cryptoki-allowed-mechanisms-unnamed` patch, docs/OPEN.md), else the
    /// module's error.
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

    /// [`Self::allowed_mechanisms`] where it can be read ([`if_readable`]): `None` too where this
    /// build's cryptoki cannot name a mechanism in it.
    pub(crate) fn allowed_if_readable(&self, h: ObjectHandle) -> Result<Option<Vec<MechanismType>>> {
        if_readable(self.read_allowed(h))
    }

    fn read_allowed(&self, h: ObjectHandle) -> std::result::Result<Option<Vec<MechanismType>>, CkError> {
        Ok(self.session.get_attributes(h, &[AttributeType::AllowedMechanisms])?.into_iter().find_map(|a| match a {
            Attribute::AllowedMechanisms(m) if !m.is_empty() => Some(m),
            _ => None,
        }))
    }

    /// `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` and `CKA_KEY_GEN_MECHANISM` of a
    /// key (empty for other classes). Those the object lacks or the module refuses are left out.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the device, token or session fails a read (`if_readable`).
    pub fn immutables(&self, h: ObjectHandle) -> Result<Immutables> {
        let flag = |t| Ok::<_, KmError>(self.attr_if_readable(h, t)?.as_ref().and_then(attr_bool));
        Ok(Immutables {
            local: flag(AttributeType::Local)?,
            never_extractable: flag(AttributeType::NeverExtractable)?,
            always_sensitive: flag(AttributeType::AlwaysSensitive)?,
            key_gen_mechanism: match self.attr_if_readable(h, AttributeType::KeyGenMechanism)? {
                // CK_UNAVAILABLE_INFORMATION: no generation mechanism (imported).
                Some(Attribute::KeyGenMechanism(m)) if *m != CK_UNAVAILABLE_INFORMATION => Some(m.to_string()),
                _ => None,
            },
        })
    }
    /// Every declared policy attribute of the spec must match the live object.
    fn check_policy(&self, h: ObjectHandle, spec: &SpecCfg) -> Result<()> {
        self.check_attrs(h, &spec.attributes, "")
    }

    fn check_attrs(&self, h: ObjectHandle, attrs: &BTreeMap<String, AttrValue>, what: &str) -> Result<()> {
        for (name, want) in attrs {
            let have = self.attr_value(h, name)?;
            if have.as_ref() != Some(want) {
                return Err(KmError::Conflict(
                    format!(
                        "{what}{name} is {} on token '{}', spec wants {want}",
                        have.map_or("unreadable".into(), |v| v.to_string()),
                        self.name
                    )
                    .into(),
                ));
            }
        }
        Ok(())
    }

    /// A policy attribute as the spec writes it.
    fn attr_value(&self, h: ObjectHandle, name: &str) -> Result<Option<AttrValue>> {
        if name == "CKA_ALLOWED_MECHANISMS" {
            return Ok(self.allowed_mechanisms(h)?.map(|m| AttrValue::mechanisms(m.into_iter().map(mechanism_namer()))));
        }
        let t = bool_attr(name, false).ok_or_else(|| unsupported_attr(name))?.attribute_type();
        Ok(self.flag(h, t)?.map(AttrValue::Bool))
    }

    /// A boolean policy attribute as the module reports it, repaired by the provider where the
    /// module misreports it (`Provider::policy_flag`).
    fn flag(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<bool>> {
        self.repaired(h, t, self.attr(h, t)?.as_ref())
    }

    /// [`Self::flag`] where it can be read ([`if_readable`]).
    fn flag_if_readable(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<bool>> {
        self.repaired(h, t, self.attr_if_readable(h, t)?.as_ref())
    }

    fn repaired(&self, h: ObjectHandle, t: AttributeType, read: Option<&Attribute>) -> Result<Option<bool>> {
        let Some(reported) = read.and_then(attr_bool) else { return Ok(None) };
        // The key's type, for a provider whose repair needs it: read only then, and a failed
        // device, token or session is the read's error, not "no type".
        let failed = std::cell::Cell::new(None);
        let private_key_type = || {
            let read = || match self.attr_if_readable(h, AttributeType::Class)? {
                Some(Attribute::Class(ObjectClass::PRIVATE_KEY)) => self.key_type_if_readable(h),
                _ => Ok(None),
            };
            read().unwrap_or_else(|e| {
                failed.set(Some(e));
                None
            })
        };
        let flag = self.provider.policy_flag(t, reported, &private_key_type);
        failed.into_inner().map_or(Ok(Some(flag)), Err)
    }

    /// `publicAttributes`, checked on the public key object of the pair: `h` itself when adopting
    /// publicOnly, else the single public key object under the locator, which must hold the
    /// same public key as `h`.
    ///
    /// # Errors
    ///
    /// `NotFound` when the pair's public half is absent under the locator, `Ambiguous` when
    /// several share it, `Conflict` when it holds another key, and whatever `check_attrs`
    /// rejects on the public object itself.
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
                _ => return Err(KmError::Ambiguous("several public key objects share the locator".into())),
            };
            same_public_key(self.held_spki(p)?.as_deref(), self.material_spki(h)?.as_deref())?;
            p
        };
        self.check_attrs(p, &spec.public_attributes, "public key object: ")
    }

    /// Template attributes for declared policy values (a spec's `attributes`), as creation and
    /// import put them on the object. Mechanism names must be ones the token offers.
    ///
    /// # Errors
    ///
    /// `Validation` for an attribute cakeys cannot set; `Unsupported` for a mechanism the token
    /// does not offer.
    pub fn policy_template(&self, attrs: &BTreeMap<String, AttrValue>) -> Result<Vec<Attribute>> {
        // Named once per template, not once per declared name (policy.rs F3).
        let named = || {
            let name = mechanism_namer();
            self.mechanisms.iter().map(|m| (name(*m), *m)).collect::<BTreeMap<String, MechanismType>>()
        };
        let offered = std::cell::OnceCell::new();
        crate::templates::policy(attrs, &|name, n| {
            offered
                .get_or_init(named)
                .get(n)
                .copied()
                .ok_or_else(|| self.unsupported(format!("{name}: token '{}' does not offer {n}", self.name)))
        })
    }
}

/// [`Token::check_public_half`]'s "same key": the public key object's public key (`held`) must be
/// readable, and the private key's own material (`own`), where it has any, must be it. A private
/// key without its point (`SoftHSM`'s EC keys) takes its SPKI from that very public key object
/// ([`Token::spki`], which cross-checks it), so there it is the same by construction.
///
/// # Errors
///
/// `Conflict` for an unreadable public key object (never a match: policy.rs F2) or another key.
fn same_public_key(held: Option<&[u8]>, own: Option<&[u8]>) -> Result<()> {
    match (held, own) {
        (None, _) => Err(KmError::Conflict(
            "the public key object under the locator exposes no key material, so it cannot be told apart from \
             another key's"
                .into(),
        )),
        (Some(held), Some(own)) if held != own => {
            Err(KmError::Conflict("the public key object under the locator holds another key".into()))
        }
        _ => Ok(()),
    }
}

/// What names mechanisms by their `CKM_` name: cryptoki's where it has one, else the spec
/// baseline's for its value (cryptoki names about 350 of the 3.2 mechanisms), else cryptoki's
/// `unknown …` (a vendor's). The one spelling keys.toml, the lock and the token's lists are
/// compared in. The baseline is indexed by value once, when the first mechanism cryptoki does
/// not name needs it, never scanned per mechanism (policy.rs F3).
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

/// Every boolean attribute cakeys reads or sets, by its PKCS#11 name: which class carries which
/// is `cakeys_core::attrs`; this is only the mapping to `cryptoki`.
macro_rules! bool_attrs {
    ($($name:literal => $variant:ident),* $(,)?) => {
        /// The boolean attribute `name` with value `v`; `None` for any other name.
        pub fn bool_attr(name: &str, v: bool) -> Option<Attribute> {
            match name {
                $($name => Some(Attribute::$variant(v)),)*
                _ => None,
            }
        }

        /// The value of a boolean attribute; `None` for any other attribute.
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

/// `CK_UNAVAILABLE_INFORMATION`: the value a token reports for an attribute it cannot give.
const CK_UNAVAILABLE_INFORMATION: std::os::raw::c_ulong = !0;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every boolean the core table names maps to a `cryptoki` attribute, and back.
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
    /// private key's own material, where it has any, is that key (policy.rs F2): an unreadable
    /// public key object is no match, never a pass.
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

    /// A mechanism is named by its `CKM_` constant, the one spelling of keys.toml and the lock.
    #[test]
    fn mechanisms_are_named_by_their_constants() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let name = mechanism_namer();
        for (m, n) in [(MechanismType::ECDSA, "CKM_ECDSA"), (MechanismType::SHA256_HMAC, "CKM_SHA256_HMAC")] {
            assert_eq!(name(m), n);
        }
    }
}
