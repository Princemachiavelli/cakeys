//! Creating and destroying objects (in an SO session where the module needs one).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// Create `object` on the token under `loc`, as `spec` declares it. The provider checks the
    /// generation first, and a module that creates only in a Security Officer session runs it
    /// that way (the admin credential of keys.toml, the user PIN restored afterwards).
    ///
    /// # Errors
    ///
    /// `Validation` for a class cakeys adopts rather than creates, or a key type missing its
    /// size (`modulusBits`, `valueLen`); a generation the module refuses is `Unsupported`,
    /// naming the token and the `C_*` failure. `Some(note)` says how the key was made other than
    /// asked (a public key the module made private). `binding` is how a private key will be
    /// proven: a module that generates from its own template ([`Provider::generation`]) refuses
    /// here a key it could not prove.
    ///
    /// [`Provider::generation`]: crate::Provider::generation
    pub fn create(
        &self,
        object: &ObjectCfg,
        spec: &SpecCfg,
        loc: &Locator,
        binding: Option<Binding>,
    ) -> Result<Option<String>> {
        self.provider.check_create(object, loc)?;
        let own = self.provider.generation(object, spec, loc, binding)?;
        let run = || match &own {
            Some(g) => self.generate_own(g),
            None => self.generate(object, spec, loc),
        };
        if self.provider.manages_as_so() { self.as_so("generating a key", run) } else { run() }
    }

    /// The module's own generation: its template alone, no public template.
    fn generate_own(&self, g: &Generation) -> Result<Option<String>> {
        let (mech, pair) = keygen_mechanism(g.keygen)
            .ok_or_else(|| self.unsupported(format!("generating key on '{}' with {}", self.name, g.keygen)))?;
        let made = if pair {
            self.session.generate_key_pair(&mech, &[], &g.template).map(drop)
        } else {
            self.session.generate_key(&mech, &g.template).map(drop)
        };
        made.map(|()| None).map_err(|e| self.unsupported(format!("generating key on '{}': {e}", self.name)))
    }

    fn generate(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<Option<String>> {
        let mut common = vec![Attribute::Token(true)];
        common.extend(locator_attrs(loc)?);
        let policy = self.policy_template(&spec.attributes)?;
        let refused = |e: CkError| self.unsupported(format!("generating key on '{}': {e}", self.name));
        let private_declared =
            spec.attributes.contains_key("CKA_PRIVATE") || spec.public_attributes.contains_key("CKA_PRIVATE");
        // A key pair, once more without the public half's default `CKA_PRIVATE = false` when the
        // module refuses it ([`retry_without_public_private`]).
        let pair = |mech: &Mechanism, public: &[Attribute], private: &[Attribute]| match self
            .session
            .generate_key_pair(mech, public, private)
        {
            Ok(_) => Ok(None),
            Err(e) if retry_without_public_private(&e, private_declared) => {
                let without: Vec<_> = public.iter().filter(|a| **a != Attribute::Private(false)).cloned().collect();
                self.session.generate_key_pair(mech, &without, private).map_err(|_| e).map(|_| {
                    Some(format!(
                        "{}: the module refuses a public key with CKA_PRIVATE = false; generated \
                         without it, so its public key is private (reading it needs a login)",
                        self.name
                    ))
                })
            }
            Err(e) => Err(e),
        };
        // Defaults for the public half of a pair, left out when the declared attributes set the
        // same type (the template may not carry a type twice).
        let public_half = |public: &mut Vec<Attribute>| -> Result<()> {
            public.extend(self.policy_template(&spec.public_attributes)?);
            let declared = |n| spec.attributes.contains_key(n) || spec.public_attributes.contains_key(n);
            if !declared("CKA_VERIFY") {
                public.push(Attribute::Verify(true));
            }
            if !declared("CKA_PRIVATE") {
                public.push(Attribute::Private(false));
            }
            Ok(())
        };
        match key_type_of(object)? {
            KeyType::RSA => {
                let bits =
                    object.modulus_bits.ok_or_else(|| KmError::Validation("RSA keys need modulusBits".into()))?;
                let mut public = common.clone();
                public.extend([Attribute::ModulusBits(bits.into()), Attribute::PublicExponent(vec![1, 0, 1])]);
                public_half(&mut public)?;
                let mut private = common;
                private.extend(policy);
                pair(&Mechanism::RsaPkcsKeyPairGen, &public, &private).map_err(refused)
            }
            KeyType::EC | KeyType::EC_EDWARDS => {
                let curve = curve_of(object)?;
                let mech = self.runnable(if curve.edwards() {
                    Mechanism::EccEdwardsKeyPairGen
                } else {
                    Mechanism::EccKeyPairGen
                });
                let public_with = |params: &[u8]| -> Result<Vec<Attribute>> {
                    let mut public = common.clone();
                    public.push(Attribute::EcParams(params.to_vec()));
                    public_half(&mut public)?;
                    Ok(public)
                };
                let mut private = common.clone();
                private.extend(policy);
                // The OID first; a module that takes the curve only by name (ykcs11's
                // edwards25519, a profile's `by-name` row [src]) gets PKCS#11 3.0's
                // PrintableString form. The identity is the same: the SPKI, not the params.
                let by_oid = pair(&mech, &public_with(curve.params())?, &private);
                match (by_oid, curve.params_by_name()) {
                    (Err(e), Some(name)) => pair(&mech, &public_with(name)?, &private).map_err(|_| e),
                    (other, _) => other,
                }
                .map_err(refused)
            }
            KeyType::DES3 => {
                // The key type fixes the length: a template with CKA_VALUE_LEN is inconsistent.
                let mut t = common;
                t.extend([Attribute::Class(ObjectClass::SECRET_KEY), Attribute::KeyType(KeyType::DES3)]);
                t.extend(policy);
                self.session.generate_key(&Mechanism::Des3KeyGen, &t).map(|_| None).map_err(refused)
            }
            kt => {
                let len =
                    object.value_len.ok_or_else(|| KmError::Validation("secret keys need valueLen (bytes)".into()))?;
                let mech = match object.key_type.and_then(hmac_key_gen) {
                    Some(m) => m,
                    None if kt == KeyType::AES => Mechanism::AesKeyGen,
                    None => Mechanism::GenericSecretKeyGen,
                };
                let mut t = common;
                t.extend([
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(kt),
                    Attribute::ValueLen(len.into()),
                ]);
                t.extend(policy);
                self.session.generate_key(&mech, &t).map(|_| None).map_err(refused)
            }
        }
    }

    /// Destroy every object of the key's class under its locator, and any public half there: only
    /// for what a creation just put under a locator that was empty before (`realise` cleaning up
    /// after itself). `delete` removes what it identified, through [`Self::destroy_identified`].
    ///
    /// # Errors
    ///
    /// As [`Self::destroy_identified`]. An empty locator destroys nothing, not an error.
    pub fn destroy(&self, object: &ObjectCfg, loc: &Locator) -> Result<usize> {
        let class = class_of(object);
        let mut handles = self.find(class, loc)?;
        if class == ObjectClass::PRIVATE_KEY {
            handles.extend(self.find(ObjectClass::PUBLIC_KEY, loc)?);
        }
        self.destroy_handles(object, loc, &handles)
    }

    /// Destroy the object `h`, identified by the caller, and — for a private key — the public key
    /// objects under its locator that hold its public key. A public key object holding another
    /// key (or none cakeys can read) is left alone. Returns (destroyed, left).
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) when the provider cannot actually erase keys (ykcs11); a failure to
    /// destroy is `Unavailable`, naming the token.
    pub fn destroy_identified(&self, h: ObjectHandle, object: &ObjectCfg, loc: &Locator) -> Result<(usize, usize)> {
        let mut handles = vec![h];
        let mut left = 0;
        if class_of(object) == ObjectClass::PRIVATE_KEY {
            let spki = self.spki(h, loc)?;
            for p in self.find(ObjectClass::PUBLIC_KEY, loc)? {
                if self.held_spki(p).as_ref() == Some(&spki) {
                    handles.push(p);
                } else {
                    left += 1;
                }
            }
        }
        Ok((self.destroy_handles(object, loc, &handles)?, left))
    }

    /// Destroy exactly `handles` (what a failed import created), as `object` under `loc` would be.
    ///
    /// # Errors
    ///
    /// As [`Self::destroy`].
    pub fn destroy_handles(&self, object: &ObjectCfg, loc: &Locator, handles: &[ObjectHandle]) -> Result<usize> {
        let class = class_of(object);
        if handles.is_empty() {
            return Ok(0);
        }
        if matches!(class, ObjectClass::PRIVATE_KEY | ObjectClass::PUBLIC_KEY | ObjectClass::SECRET_KEY)
            && let Some(advice) = self.provider.keeps_destroyed_keys(loc)
        {
            return Err(KmError::Unsupported(format!("deleting {} on '{}': {advice}", object.class, self.name)));
        }
        let run = || {
            for (i, h) in handles.iter().enumerate() {
                match self.session.destroy_object(*h) {
                    Ok(()) => {}
                    // Gone with an object destroyed before it: libkmsp11 removes a key's public
                    // half with its private one (one Cloud KMS version) [run]. Deleting what is
                    // already gone is success.
                    Err(CkError::Pkcs11(RvError::ObjectHandleInvalid, _)) if i > 0 => {}
                    Err(e) => return Err(ck("C_DestroyObject")(e)),
                }
            }
            Ok(handles.len())
        };
        if self.provider.manages_as_so() { self.as_so("deleting", run) } else { run() }
    }
}

/// Whether a refused key pair is generated once more without the public half's
/// `CKA_PRIVATE = false`: only cakeys' own default (the spec did not declare `CKA_PRIVATE`), and
/// only when the module called a value invalid. AWS `CloudHSM` makes every public key private
/// \[run\] (docs/CAPROBE.md); a spec that asks for `CKA_PRIVATE = false` keeps the refusal.
#[must_use]
pub fn retry_without_public_private(refusal: &CkError, declared: bool) -> bool {
    !declared && matches!(refusal, CkError::Pkcs11(RvError::AttributeValueInvalid, _))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    #[test]
    fn only_the_default_is_dropped_and_only_for_an_invalid_value() {
        let invalid = CkError::Pkcs11(RvError::AttributeValueInvalid, Function::GenerateKeyPair);
        let other = CkError::Pkcs11(RvError::TemplateInconsistent, Function::GenerateKeyPair);
        assert!(retry_without_public_private(&invalid, false));
        assert!(!retry_without_public_private(&invalid, true), "a declared CKA_PRIVATE is the spec's");
        assert!(!retry_without_public_private(&other, false));
    }
}
