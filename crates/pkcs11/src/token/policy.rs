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
                Some(Attribute::CertificateType(CertificateType::X_509)) => Ok(()),
                other => Err(KmError::Conflict(format!("CKA_CERTIFICATE_TYPE is {other:?}, not CKC_X_509"))),
            };
        }
        if class == ObjectClass::DATA {
            // Its identity is a hash of the value: for a private value (a password, a PIN) that
            // hash in the lock would be an offline guessing oracle.
            return match self.attr(h, AttributeType::Private)? {
                Some(Attribute::Private(false)) => self.check_policy(h, spec),
                other => Err(KmError::Unsupported(format!(
                    "data object is CKA_PRIVATE ({other:?}): its value hash would let anyone with \
                     the lock guess the value offline; only public data objects are supported"
                ))),
            };
        }
        let Some(Attribute::KeyType(kt)) = self.attr(h, AttributeType::KeyType)? else {
            return Err(KmError::Conflict("object has no CKA_KEY_TYPE".into()));
        };
        if kt != key_type_of(object)? {
            return Err(KmError::Conflict(format!(
                "CKA_KEY_TYPE is {kt}, spec object type says {}",
                object.key_type.map_or("", Kt::name)
            )));
        }
        if kt == KeyType::EC || kt == KeyType::EC_EDWARDS {
            let want = curve_of(object)?;
            match self.attr(h, AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) if Curve::from_params(&p) == Some(want) => {}
                other => return Err(KmError::Conflict(format!("CKA_EC_PARAMS {other:?} is not {want:?}"))),
            }
        }
        if let Some(bits) = object.modulus_bits {
            match self.attr(h, AttributeType::Modulus)? {
                Some(Attribute::Modulus(m)) if m.len() as u64 * 8 == bits => {}
                other => {
                    let have = other.and_then(|a| match a {
                        Attribute::Modulus(m) => Some(m.len() * 8),
                        _ => None,
                    });
                    return Err(KmError::Conflict(format!("RSA modulus is {have:?} bits, spec says {bits}")));
                }
            }
        }
        if let Some(len) = object.value_len {
            match self.attr(h, AttributeType::ValueLen)? {
                Some(Attribute::ValueLen(v)) if *v == len => {}
                other => return Err(KmError::Conflict(format!("CKA_VALUE_LEN mismatch: {other:?}"))),
            }
        }
        self.check_policy(h, spec)
    }

    /// The observed policy vector: every boolean attribute of `h`'s class (PKCS#11 3.2 §4,
    /// `cakeys_core::attrs::observed`) the token reports, declared in the spec or not, plus
    /// `CKA_ALLOWED_MECHANISMS` on key objects when readable. Unreadable ones are left out.
    ///
    /// # Errors
    ///
    /// `Conflict` when the object exposes no `CKA_CLASS`; `Unsupported` for a class cakeys
    /// does not manage.
    pub fn policy(&self, h: ObjectHandle) -> Result<BTreeMap<String, AttrValue>> {
        let class = match self.attr(h, AttributeType::Class)? {
            Some(Attribute::Class(c)) => {
                managed_class(c).ok_or_else(|| KmError::Unsupported(format!("object class {c}")))?
            }
            _ => return Err(KmError::Conflict("object has no CKA_CLASS".into())),
        };
        let mut policy = BTreeMap::new();
        for name in attrs::observed(class) {
            let Some(t) = bool_attr(name, false).map(|a| a.attribute_type()) else { continue };
            // Unsupported or unreadable on this token: not part of what it can show.
            if let Ok(Some(a)) = self.attr(h, t)
                && let Some(b) = attr_bool(&a)
            {
                policy.insert(name.to_owned(), AttrValue::Bool(b));
            }
        }
        if attrs::has_allowed_mechanisms(class) {
            // An empty list is not reported: it is indistinguishable from absent and means none.
            if let Ok(Some(Attribute::AllowedMechanisms(m))) = self.attr(h, AttributeType::AllowedMechanisms)
                && !m.is_empty()
            {
                policy.insert(
                    "CKA_ALLOWED_MECHANISMS".to_owned(),
                    AttrValue::mechanisms(m.iter().map(std::string::ToString::to_string)),
                );
            }
        }
        Ok(policy)
    }

    /// `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` and `CKA_KEY_GEN_MECHANISM` of a
    /// key (empty for other classes). Unreadable values are left out.
    pub fn immutables(&self, h: ObjectHandle) -> Immutables {
        let flag = |t| match self.attr(h, t) {
            Ok(Some(a)) => attr_bool(&a),
            _ => None,
        };
        Immutables {
            local: flag(AttributeType::Local),
            never_extractable: flag(AttributeType::NeverExtractable),
            always_sensitive: flag(AttributeType::AlwaysSensitive),
            key_gen_mechanism: match self.attr(h, AttributeType::KeyGenMechanism) {
                // CK_UNAVAILABLE_INFORMATION: no generation mechanism (imported).
                Ok(Some(Attribute::KeyGenMechanism(m))) if *m != CK_UNAVAILABLE_INFORMATION => Some(m.to_string()),
                _ => None,
            },
        }
    }
    /// Every declared policy attribute of the spec must match the live object.
    fn check_policy(&self, h: ObjectHandle, spec: &SpecCfg) -> Result<()> {
        self.check_attrs(h, &spec.attributes, "")
    }

    fn check_attrs(&self, h: ObjectHandle, attrs: &BTreeMap<String, AttrValue>, what: &str) -> Result<()> {
        for (name, want) in attrs {
            let have = self.attr_value(h, name)?;
            if have.as_ref() != Some(want) {
                return Err(KmError::Conflict(format!(
                    "{what}{name} is {} on token '{}', spec wants {want}",
                    have.map_or("unreadable".into(), |v| v.to_string()),
                    self.name
                )));
            }
        }
        Ok(())
    }

    /// A policy attribute as the spec writes it.
    fn attr_value(&self, h: ObjectHandle, name: &str) -> Result<Option<AttrValue>> {
        if name == "CKA_ALLOWED_MECHANISMS" {
            return Ok(match self.attr(h, AttributeType::AllowedMechanisms)? {
                Some(Attribute::AllowedMechanisms(m)) => {
                    Some(AttrValue::mechanisms(m.iter().map(std::string::ToString::to_string)))
                }
                _ => None,
            });
        }
        let t = bool_attr(name, false).ok_or_else(|| unsupported_attr(name))?.attribute_type();
        Ok(self.attr(h, t)?.as_ref().and_then(attr_bool).map(AttrValue::Bool))
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
            if let (Some(a), Some(b)) = (self.material_spki(p)?, self.material_spki(h)?)
                && a != b
            {
                return Err(KmError::Conflict("the public key object under the locator holds another key".into()));
            }
            p
        };
        self.check_attrs(p, &spec.public_attributes, "public key object: ")
    }

    /// Template attributes for declared policy values. Mechanism names must be ones the token
    /// offers.
    pub(super) fn policy_template(&self, attrs: &BTreeMap<String, AttrValue>) -> Result<Vec<Attribute>> {
        attrs
            .iter()
            .map(|(name, v)| match v {
                AttrValue::Bool(b) => bool_attr(name, *b).ok_or_else(|| unsupported_attr(name)),
                AttrValue::Mechanisms(names) => names
                    .iter()
                    .map(|n| {
                        self.mechanisms.iter().copied().find(|m| m.to_string() == *n).ok_or_else(|| {
                            self.unsupported(format!("{name}: token '{}' does not offer {n}", self.name))
                        })
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(Attribute::AllowedMechanisms),
            })
            .collect()
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
    KmError::Validation(format!("unsupported policy attribute {name}"))
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
}
