//! Creating and destroying objects (in an SO session where the module needs one).

#[allow(clippy::wildcard_imports)] // the token/ split files work on the parent module's imports (R9)
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
    /// naming the token and the `C_*` failure.
    pub fn create(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<()> {
        self.provider.check_create(object, loc)?;
        if self.provider.manages_as_so() {
            self.as_so("generating a key", || self.generate(object, spec, loc))
        } else {
            self.generate(object, spec, loc)
        }
    }

    fn generate(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<()> {
        let mut common = vec![Attribute::Token(true)];
        common.extend(locator_attrs(loc)?);
        let policy = self.policy_template(&spec.attributes)?;
        let refused = |e: CkError| self.unsupported(format!("generating key on '{}': {e}", self.name));
        let class = class_of(object);
        if class != ObjectClass::PRIVATE_KEY && class != ObjectClass::SECRET_KEY {
            return Err(KmError::Validation(format!("{} objects are adopted, not created", object.class)));
        }
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
                self.session
                    .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &private)
                    .map(drop)
                    .map_err(refused)
            }
            KeyType::EC | KeyType::EC_EDWARDS => {
                let curve = curve_of(object)?;
                let mech = if curve.edwards() { Mechanism::EccEdwardsKeyPairGen } else { Mechanism::EccKeyPairGen };
                let mut public = common.clone();
                public.extend([Attribute::EcParams(curve.params().to_vec())]);
                public_half(&mut public)?;
                let mut private = common;
                private.extend(policy);
                self.session.generate_key_pair(&mech, &public, &private).map(drop).map_err(refused)
            }
            kt => {
                let len =
                    object.value_len.ok_or_else(|| KmError::Validation("secret keys need valueLen (bytes)".into()))?;
                let mech = if kt == KeyType::AES { Mechanism::AesKeyGen } else { Mechanism::GenericSecretKeyGen };
                let mut t = common;
                t.extend([
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(kt),
                    Attribute::ValueLen(len.into()),
                ]);
                t.extend(policy);
                self.session.generate_key(&mech, &t).map(drop).map_err(refused)
            }
        }
    }

    /// Destroy the key and any public half sharing its locator.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) when the provider cannot actually erase keys (ykcs11); a failure to
    /// destroy is `Unavailable`, naming the token. An empty locator destroys nothing, not an
    /// error.
    pub fn destroy(&self, object: &ObjectCfg, loc: &Locator) -> Result<usize> {
        let class = class_of(object);
        let mut handles = self.find(class, loc)?;
        if class == ObjectClass::PRIVATE_KEY {
            handles.extend(self.find(ObjectClass::PUBLIC_KEY, loc)?);
        }
        if handles.is_empty() {
            return Ok(0);
        }
        if matches!(class, ObjectClass::PRIVATE_KEY | ObjectClass::PUBLIC_KEY | ObjectClass::SECRET_KEY)
            && let Some(advice) = self.provider.keeps_destroyed_keys(loc)
        {
            return Err(KmError::Unsupported(format!("deleting {} on '{}': {advice}", object.class, self.name)));
        }
        let run = || {
            for h in &handles {
                self.session.destroy_object(*h).map_err(ck("C_DestroyObject"))?;
            }
            Ok(handles.len())
        };
        if self.provider.manages_as_so() { self.as_so("deleting", run) } else { run() }
    }
}
