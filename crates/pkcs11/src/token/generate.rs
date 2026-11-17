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
        self.provider.create(self, &Create { object, spec, locator: loc, binding })
    }

    /// [`Provider::create`]'s default, for an override to wrap: the module's own template where
    /// [`Provider::generation`] chooses one, else cakeys' templates, in an SO session where the
    /// module needs one ([`Self::managing`]).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    ///
    /// [`Provider::create`]: crate::Provider::create
    pub fn create_declared(&self, req: &Create<'_>) -> Result<Option<String>> {
        let own = self.provider.generation(req.object, req.spec, req.locator, req.binding)?;
        self.managing("generating a key", || match &own {
            Some(g) => self.generate_own(g),
            None => self.generate(req.object, req.spec, req.locator),
        })
    }

    /// Run `step`, which creates or destroys token objects, in a Security Officer session where
    /// the module does that only as SO ([`Provider::manages_as_so`]), else as it is.
    ///
    /// # Errors
    ///
    /// `step`'s, and [`Self::as_so`]'s where it runs as SO.
    ///
    /// [`Provider::manages_as_so`]: crate::Provider::manages_as_so
    pub fn managing<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.provider.manages_as_so() { self.as_so(what, step) } else { step() }
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
        made.map(|()| None)
            .map_err(|e| self.unsupported(format!("generating key on '{}': {} ({e})", self.name, rv_name(&e))))
    }

    /// cakeys' template for the key `on` generates (a pair's private one), as the provider
    /// adjusts it.
    ///
    /// # Errors
    ///
    /// As [`templates::generation_key`]; the provider's refusal.
    pub(crate) fn generation_key(&self, on: Declared<'_>) -> Result<Vec<Attribute>> {
        let t = templates::generation_key(on, self.policy_template(&on.spec.attributes)?)?;
        self.provider.adjusted(&Template::Generate(on, Half::Key), t)
    }

    /// cakeys' public template for the pair `on` generates, the curve by `ec_params` (else its
    /// OID), as the provider adjusts it; `None` for a secret key.
    ///
    /// # Errors
    ///
    /// As [`templates::generation_public`]; the provider's refusal.
    pub(crate) fn generation_public(
        &self,
        on: Declared<'_>,
        ec_params: Option<&[u8]>,
    ) -> Result<Option<Vec<Attribute>>> {
        if !matches!(key_type_of(on.object)?, KeyType::RSA | KeyType::EC | KeyType::EC_EDWARDS) {
            return Ok(None);
        }
        let public_policy = self.policy_template(&on.spec.public_attributes)?;
        templates::generation_public(on, public_policy, ec_params)?
            .map(|t| self.provider.adjusted(&Template::Generate(on, Half::Public), t))
            .transpose()
    }

    fn generate(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<Option<String>> {
        // Each template as the provider adjusts it, before anything is generated.
        let on = Declared { object, spec, locator: loc };
        let key = self.generation_key(on)?;
        let public = self.generation_public(on, None)?;
        let refused =
            |e: CkError| self.unsupported(format!("generating key on '{}': {} ({e})", self.name, rv_name(&e)));
        let private_declared =
            spec.attributes.contains_key("CKA_PRIVATE") || spec.public_attributes.contains_key("CKA_PRIVATE");
        // A key pair, once more without the public half's default `CKA_PRIVATE = false` when the
        // module refuses it ([`with_public_default_dropped`]).
        let pair = |mech: &Mechanism, public: &[Attribute], private: &[Attribute]| {
            with_public_default_dropped(public, private_declared, |p| self.session.generate_key_pair(mech, p, private))
                .map(|(_, dropped)| {
                    dropped.then(|| {
                        format!(
                            "{}: the module refuses a public key with CKA_PRIVATE = false; generated \
                             without it, so its public key is private (reading it needs a login)",
                            self.name
                        )
                    })
                })
        };
        match (key_type_of(object)?, public) {
            (KeyType::RSA, Some(public)) => pair(&Mechanism::RsaPkcsKeyPairGen, &public, &key).map_err(refused),
            (KeyType::EC | KeyType::EC_EDWARDS, Some(by_oid_public)) => {
                let curve = curve_of(object)?;
                let mech = self.runnable(if curve.edwards() {
                    Mechanism::EccEdwardsKeyPairGen
                } else {
                    Mechanism::EccKeyPairGen
                });
                // The OID first; a module that takes the curve only by name (ykcs11's
                // edwards25519, a profile's `by-name` row [src]) gets PKCS#11 3.0's
                // PrintableString form. The identity is the same: the SPKI, not the params.
                let by_oid = pair(&mech, &by_oid_public, &key);
                match (by_oid, curve.params_by_name()) {
                    (Err(e), Some(name)) => {
                        let by_name = self.generation_public(on, Some(name))?.unwrap_or_default();
                        pair(&mech, &by_name, &key).map_err(|_| e).map(|note| {
                            let said = format!("{}: {BY_NAME} ({})", self.name, curve.name());
                            Some(note.map_or_else(|| said.clone(), |n| format!("{n}; {said}")))
                        })
                    }
                    (other, _) => other,
                }
                .map_err(refused)
            }
            (KeyType::DES3, _) => {
                self.session.generate_key(&Mechanism::Des3KeyGen, &key).map(|_| None).map_err(refused)
            }
            (kt, _) => {
                let mech = match object.key_type.and_then(hmac_key_gen) {
                    Some(m) => m,
                    None if kt == KeyType::AES => Mechanism::AesKeyGen,
                    None => Mechanism::GenericSecretKeyGen,
                };
                self.session.generate_key(&mech, &key).map(|_| None).map_err(refused)
            }
        }
    }

    /// Destroy every object of the key's class under its locator, and any public half there: only
    /// for what a creation just put under a locator that was empty before (`lock` cleaning up
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
        if handles.is_empty() {
            return Ok(0);
        }
        self.provider.destroy(self, &Destroy { object, locator: loc, handles })
    }

    /// [`Provider::destroy`]'s default, for an override to wrap: `C_DestroyObject` on each of
    /// `req.handles`, in an SO session where the module needs one ([`Self::managing`]).
    ///
    /// # Errors
    ///
    /// A failure to destroy is `Unavailable`, naming the token.
    ///
    /// [`Provider::destroy`]: crate::Provider::destroy
    pub fn destroy_plain(&self, req: &Destroy<'_>) -> Result<usize> {
        let handles = req.handles;
        self.managing("deleting", || {
            for (i, h) in handles.iter().enumerate() {
                match self.session.destroy_object(*h) {
                    Ok(()) => {}
                    // Gone with an object destroyed before it in this call: deleting what is
                    // already gone is success, on any module (libkmsp11 removes a key's public
                    // half with its private one, one Cloud KMS version [run]). The first handle
                    // was just identified, so its refusal is never taken for gone.
                    Err(CkError::Pkcs11(RvError::ObjectHandleInvalid, _)) if i > 0 => {}
                    Err(e) => return Err(ck("C_DestroyObject")(e)),
                }
            }
            Ok(handles.len())
        })
    }
}

/// What [`Token::create`]'s note says when the module generated the curve only from its name
/// (PKCS#11 3.0's `PrintableString` `CKA_EC_PARAMS`), never by OID: ykcs11's edwards25519.
pub const BY_NAME: &str = "the module takes the curve only by name, as a PrintableString CKA_EC_PARAMS";

/// Make a public key object, alone or as a pair's half, from the template `public`; where the
/// module calls a value invalid and the spec did not declare `CKA_PRIVATE` (`declared`), once
/// more without cakeys' own `CKA_PRIVATE = false` default. A fallback for every module, not one
/// module's quirk: the strong form first, then the one the module takes (AWS `CloudHSM` makes
/// every public key private \[run\], docs/CAPROBE.md). A spec that asks for
/// `CKA_PRIVATE = false` keeps the refusal, and so does a second refusal: the first is the error.
/// Returns what `make` made and whether the default was dropped.
///
/// # Errors
///
/// `make`'s first refusal.
pub fn with_public_default_dropped<T>(
    public: &[Attribute],
    declared: bool,
    make: impl Fn(&[Attribute]) -> std::result::Result<T, CkError>,
) -> std::result::Result<(T, bool), CkError> {
    match make(public) {
        Ok(object) => Ok((object, false)),
        Err(e) if retry_without_public_private(&e, declared) => {
            let without: Vec<_> = public.iter().filter(|a| **a != Attribute::Private(false)).cloned().collect();
            make(&without).map(|object| (object, true)).map_err(|_| e)
        }
        Err(e) => Err(e),
    }
}

/// Whether a refusal is retried without the public default ([`with_public_default_dropped`]):
/// only cakeys' own default, and only when the module called a value invalid.
fn retry_without_public_private(refusal: &CkError, declared: bool) -> bool {
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

    /// The default is dropped once, only on the refusal it answers; a second refusal reports
    /// the first.
    #[test]
    fn the_public_default_is_dropped_once_and_only_when_refused() {
        let public = [Attribute::Verify(true), Attribute::Private(false)];
        let invalid = || CkError::Pkcs11(RvError::AttributeValueInvalid, Function::CreateObject);
        let refuses_default =
            |t: &[Attribute]| if t.contains(&Attribute::Private(false)) { Err(invalid()) } else { Ok(t.len()) };
        assert_eq!(with_public_default_dropped(&public, false, refuses_default).unwrap(), (1, true));
        assert!(with_public_default_dropped(&public, true, refuses_default).is_err(), "declared: kept");
        assert_eq!(with_public_default_dropped(&public, false, |t: &[Attribute]| Ok(t.len())).unwrap(), (2, false));
        let calls = std::cell::Cell::new(0);
        let always = |_: &[Attribute]| -> std::result::Result<usize, CkError> {
            calls.set(calls.get() + 1);
            Err(if calls.get() == 1 {
                invalid()
            } else {
                CkError::Pkcs11(RvError::DeviceError, Function::CreateObject)
            })
        };
        let e = with_public_default_dropped(&public, false, always).unwrap_err();
        assert!(matches!(e, CkError::Pkcs11(RvError::AttributeValueInvalid, _)), "the first refusal: {e}");
        assert_eq!(calls.get(), 2);
    }
}
