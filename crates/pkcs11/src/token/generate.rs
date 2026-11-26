//! The creation and the destruction of objects, in an SO session when the module needs one.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::rv::refused_unless_device;
use super::{
    Attribute, Binding, Checked, CkError, Create, Declared, Destroy, Generation, Half, KeyType, KmError, Locator,
    Mechanism, Msg, Object, ObjectCfg, ObjectClass, ObjectHandle, Result, RvError, SpecCfg, Template, Token, Topic, ck,
    class_of, key_type_of, keygen_mechanism, rv_name, rv_of, secret_key_gen, templates,
};
use cakeys_profile::{Capability, On};

impl Token {
    /// Creates `object` on the token under `loc`, as `spec` declares it. The function first
    /// refuses a key that the provider does not place under `loc` ([`Provider::placement`]). For
    /// a module that creates objects only in a Security Officer session, the provider's creation
    /// runs in such a session, with the admin credential from keys.toml, and the user PIN is
    /// restored afterwards. The provider then checks the generation. `binding` says how a private
    /// key will be proven, and a module that generates from its own template
    /// ([`Provider::generation`]) refuses here a key that it could not prove. Returns
    /// `Some(note)` when the key was made differently from how it was asked, for example a public
    /// key that the module made private.
    ///
    /// # Errors
    ///
    /// - `Validation` (exit 17) for a locator under which the provider places no key. The error
    ///   names the `placement` rule.
    /// - `Validation` for a class that cakeys adopts instead of creating, or for a key type
    ///   without its size (`modulusBits`, `valueLen`).
    /// - `Unsupported` for a generation that the module refuses. The error names the token and
    ///   the failed `C_*` call.
    ///
    /// [`Provider::generation`]: crate::Provider::generation
    /// [`Provider::placement`]: crate::Provider::placement
    pub fn create(
        &self,
        object: Object<'_>,
        spec: &SpecCfg,
        loc: &Locator,
        binding: Option<Binding>,
    ) -> Result<Option<CreateNote>> {
        // This order belongs to the core code, and no provider override can skip it (review
        // 2026-11-24 B-2): first the check of where the key may go, then the session in which the
        // module writes, then the provider.
        crate::ops::placement(self.provider.as_ref(), object.class, loc)?;
        let req = Checked::new(Create { object, spec, locator: loc, binding });
        self.managing("generating a key", || self.provider.create(self, &req))
    }

    /// The default implementation of [`Provider::create`], which an override can wrap. It
    /// generates from the module's own template when [`Provider::generation`] chooses one, and
    /// from cakeys' templates otherwise. [`Self::create`] has already checked the placement and
    /// entered the session in which the module writes.
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::create`].
    ///
    /// [`Provider::create`]: crate::Provider::create
    /// [`Provider::generation`]: crate::Provider::generation
    pub fn create_declared(&self, req: &Checked<Create<'_>>) -> Result<Option<CreateNote>> {
        match self.provider.generation(req.object, req.spec, req.locator, req.binding)? {
            Some(g) => self.generate_own(&g),
            None => self.generate(req.object, req.spec, req.locator),
        }
    }

    /// Runs `step`, which creates or destroys token objects. When the module does that only as
    /// the SO ([`Provider::manages_as_so`]), the step runs in a Security Officer session.
    /// Otherwise, it runs in the current session.
    ///
    /// # Errors
    ///
    /// The errors of `step`, and the errors of [`Self::as_so`] when the step runs as the SO.
    ///
    /// [`Provider::manages_as_so`]: crate::Provider::manages_as_so
    pub fn managing<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.provider.manages_as_so() { self.as_so(what, step) } else { step() }
    }

    /// Returns whether, and why, a curve that the module refused by OID is generated once more by
    /// its name (ISSUES.md B18). It applies [`by_name_retry`] to the token's module profile.
    fn retries_by_name(&self, key_type: &str, curve: &str) -> Option<ByName> {
        by_name_retry(self.profiles.module.as_ref(), key_type, curve)
    }

    /// Returns the error for a refused generation. A failure of the device, the token or the
    /// session is a failure of the token and not of the key, so it is unavailable (exit 16), as
    /// for an attribute read ([`Self::refused_for`]). A refusal of the key itself is unsupported
    /// (exit 15), with the provider's hint.
    fn refused_generation(&self, e: &CkError) -> KmError {
        self.refused_for(Topic::Generate, e, format!("generating key on '{}': {} ({e})", self.name, rv_name(e)))
    }

    /// Generates with the module's own template only, without a public template.
    fn generate_own(&self, g: &Generation) -> Result<Option<CreateNote>> {
        let (mech, pair) = keygen_mechanism(g.keygen).ok_or_else(|| {
            self.unsupported_for(Topic::Generate, format!("generating key on '{}' with {}", self.name, g.keygen))
        })?;
        let made = if pair {
            self.session.generate_key_pair(&mech, &[], &g.template).map(drop)
        } else {
            self.session.generate_key(&mech, &g.template).map(drop)
        };
        made.map(|()| None).map_err(|e| self.refused_generation(&e))
    }

    /// Returns cakeys' template for the key that `on` generates (for a key pair, the private
    /// key's template), as the provider adjusts it.
    ///
    /// # Errors
    ///
    /// The errors of [`templates::generation_key`], and the provider's refusal.
    pub(crate) fn generation_key(&self, on: Declared<'_>) -> Result<Vec<Attribute>> {
        let t = templates::generation_key(on, self.policy_template(&on.spec.attributes)?)?;
        self.provider.adjusted(&Template::Generate(on, Half::Key), t)
    }

    /// Returns cakeys' public template for the key pair that `on` generates, as the provider
    /// adjusts it. The template names the curve by `ec_params`, or by its OID when `ec_params` is
    /// `None`. Returns `None` for a secret key.
    ///
    /// # Errors
    ///
    /// The errors of [`templates::generation_public`], and the provider's refusal.
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

    fn generate(&self, object: Object<'_>, spec: &SpecCfg, loc: &Locator) -> Result<Option<CreateNote>> {
        // Build each template, as the provider adjusts it, before anything is generated.
        let on = Declared { object, spec, locator: loc };
        let key = self.generation_key(on)?;
        let public = self.generation_public(on, None)?;
        let refused = |e: CkError| self.refused_generation(&e);
        let private_declared = templates::public_declares(spec, "CKA_PRIVATE");
        // Generates a key pair, and generates it once more without the public half's default
        // `CKA_PRIVATE = false` when the module refuses that default
        // ([`with_public_default_dropped`]). The result says whether the default was dropped.
        let pair = |mech: &Mechanism, public: &[Attribute], private: &[Attribute]| {
            with_public_default_dropped(public, private_declared, |p| self.session.generate_key_pair(mech, p, private))
                .map(|(_, dropped)| dropped)
        };
        let note = |dropped, by_name| CreateNote::of(&self.name, dropped, by_name);
        match (key_type_of(object)?, object.curve(), public) {
            (KeyType::RSA, _, Some(public)) => {
                pair(&Mechanism::RsaPkcsKeyPairGen, &public, &key).map(|d| note(d, None)).map_err(refused)
            }
            (kt @ (KeyType::EC | KeyType::EC_EDWARDS), Some(curve), Some(by_oid_public)) => {
                let mech = self.runnable(if curve.edwards() {
                    Mechanism::EccEdwardsKeyPairGen
                } else {
                    Mechanism::EccKeyPairGen
                });
                // Try the OID first. A module that takes the curve only by its name (ykcs11's
                // edwards25519, or a profile's `by-name` row [src]) then gets the PrintableString
                // form of PKCS#11 3.0. The identity does not change, because it is computed from
                // the SPKI and not from the parameters.
                let by_oid = pair(&mech, &by_oid_public, &key);
                let retry = curve.params_by_name().zip(self.retries_by_name(&kt.to_string(), curve.name()));
                match (by_oid, retry) {
                    (Err(by_oid), Some((name, why))) => {
                        let by_name = self.generation_public(on, Some(name))?.unwrap_or_default();
                        pair(&mech, &by_name, &key).map(|d| note(d, Some(curve.name().to_owned()))).map_err(|by_name| {
                            refused_unless_device(by_name_refused(&self.name, why, &by_oid, &by_name), |m| {
                                self.unsupported_for(Topic::Generate, m)
                            })
                        })
                    }
                    (other, _) => other.map(|d| note(d, None)).map_err(refused),
                }
            }
            // A secret key is generated with the mechanism that its key type names.
            _ => {
                let mech = object.key_type.map_or(Mechanism::GenericSecretKeyGen, secret_key_gen);
                self.session.generate_key(&mech, &key).map(|_| None).map_err(refused)
            }
        }
    }

    /// Destroys every object of the key's class under its locator, and, for a private key, every
    /// public key object there. Use it only for what a creation or an import just put under a
    /// locator that was empty before. `create` uses it to undo a creation that failed or whose
    /// identity could not be established, and camigrate uses it to undo a `tpm2_ptool` import
    /// that `lock_import` refused. `delete` removes only what it identified, through
    /// [`Self::destroy_identified`].
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::destroy_identified`]. An empty locator destroys nothing, and
    /// that is not an error.
    pub fn destroy(&self, object: &ObjectCfg, loc: &Locator) -> Result<usize> {
        let class = class_of(object);
        let mut handles = self.find(class, loc)?;
        if class == ObjectClass::PRIVATE_KEY {
            handles.extend(self.find(ObjectClass::PUBLIC_KEY, loc)?);
        }
        self.destroy_handles(object, loc, &handles)
    }

    /// Destroys the object `h`, which the caller identified, and, for a private key, the public key
    /// objects under its locator that hold its public key. A public key object that holds another
    /// key (or a key that cakeys cannot read) is left alone. Returns the number of destroyed
    /// objects and the number of public key objects that were left. `spki` is the private key's
    /// SPKI ([`Self::spki`]) when the caller has already read it.
    ///
    /// # Errors
    ///
    /// `Unsupported` (exit 15) when the provider cannot actually erase keys (ykcs11).
    /// `Unavailable`, which names the token, when a destroy fails.
    pub fn destroy_identified(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        loc: &Locator,
        spki: Option<&[u8]>,
    ) -> Result<(usize, usize)> {
        let mut handles = vec![h];
        let mut left = 0;
        if class_of(object) == ObjectClass::PRIVATE_KEY {
            let spki = spki.map_or_else(|| self.spki(h, loc), |s| Ok(s.to_vec()))?;
            for p in self.find(ObjectClass::PUBLIC_KEY, loc)? {
                if self.held_spki(p)?.as_ref() == Some(&spki) {
                    handles.push(p);
                } else {
                    left += 1;
                }
            }
        }
        Ok((self.destroy_handles(object, loc, &handles)?, left))
    }

    /// Destroys exactly `handles` (for example, what a failed import created) in the way that
    /// `object` under `loc` would be destroyed. The steps are the provider's check
    /// [`Provider::deletion`](crate::provider::Provider::deletion), the session in which the module
    /// writes, the provider's `destroy`, and then a lookup under `loc` for any of `handles` that
    /// is still there (`delete-kept`).
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::destroy`], and `Unavailable` (exit 16, `delete-kept`) when any
    /// of `handles` is still under `loc` after the provider reported it destroyed.
    pub fn destroy_handles(&self, object: &ObjectCfg, loc: &Locator, handles: &[ObjectHandle]) -> Result<usize> {
        if handles.is_empty() {
            return Ok(0);
        }
        // This order belongs to the core code, as for a creation: first the check of whether the
        // module removes the object, then the session in which the module writes, then the
        // provider.
        crate::ops::deletion(self.provider.as_ref(), object.class, loc)
            .map_err(|e| e.prefixed(format_args!("deleting {} on '{}'", object.class, self.name)))?;
        let req = Checked::new(Destroy { object, locator: loc, handles });
        let n = self.managing("deleting", || self.provider.destroy(self, &req))?;
        // The count is only what the provider reports (review 2026-11-24 B-13). A handle that is
        // still found under the locator is an object that the module kept.
        let kept = self.find_any(loc)?.into_iter().filter(|h| handles.contains(h)).count();
        if kept > 0 {
            let why = format!(
                "{kept} of the {} object(s) of {} deleted on '{}' are still under its locator {loc}: the module \
                 said it destroyed them",
                handles.len(),
                object.class,
                self.name
            );
            return Err(crate::ops::Refusal::new(crate::ops::Rule::DeleteKept, KmError::Unavailable(why.into())).into());
        }
        Ok(n)
    }

    /// The default implementation of [`Provider::destroy`], which an override can wrap. It calls
    /// `C_DestroyObject` on each of `req.handles`, in the session that the token entered for the
    /// module's destroys.
    ///
    /// # Errors
    ///
    /// `Unavailable`, which names the token, when a destroy fails.
    ///
    /// [`Provider::destroy`]: crate::Provider::destroy
    pub fn destroy_plain(&self, req: &Checked<Destroy<'_>>) -> Result<usize> {
        let handles = req.handles;
        for (i, h) in handles.iter().enumerate() {
            match self.session.destroy_object(*h) {
                Ok(()) => {}
                // The object was removed together with an object that was destroyed before it in
                // this call. Deleting an object that is already gone counts as success on any
                // module (libkmsp11 removes a key's public half together with its private half,
                // because both are one Cloud KMS version [run]). The first handle was just
                // identified, so its refusal is never treated as an object that is already gone.
                Err(CkError::Pkcs11(RvError::ObjectHandleInvalid, _)) if i > 0 => {}
                Err(e) => return Err(ck("C_DestroyObject")(e)),
            }
        }
        Ok(handles.len())
    }
}

/// The text of the note of [`Token::create`] when the module generated the curve only from its
/// name (the `PrintableString` form of `CKA_EC_PARAMS` in PKCS#11 3.0) and not by its OID, as
/// ykcs11 does for edwards25519.
pub const BY_NAME: &str = "the module takes the curve only by name, as a PrintableString CKA_EC_PARAMS";

/// The text of the note of [`Token::create`] when the module refused the public half's default
/// `CKA_PRIVATE = false` and the pair was generated without it (AWS `CloudHSM`).
pub const PUBLIC_MADE_PRIVATE: &str = "the module refuses a public key with CKA_PRIVATE = false";

/// How [`Token::create`] made a key differently from how it was asked (ISSUES.md Q3). The probe
/// reads it as data, and the run prints it through its `Display` implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateNote {
    /// The token's name in keys.toml. Each part of the note starts with it.
    token: String,
    /// Whether the public half was generated without `CKA_PRIVATE = false`
    /// ([`PUBLIC_MADE_PRIVATE`]).
    pub public_made_private: bool,
    /// The curve that the module accepted only by its name ([`BY_NAME`]).
    pub by_name: Option<String>,
}

impl CreateNote {
    /// Returns `Some` when at least one part of the note applies.
    fn of(token: &str, public_made_private: bool, by_name: Option<String>) -> Option<Self> {
        (public_made_private || by_name.is_some()).then(|| CreateNote {
            token: token.to_owned(),
            public_made_private,
            by_name,
        })
    }
}

impl std::fmt::Display for CreateNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = &self.token;
        if self.public_made_private {
            write!(
                f,
                "{token}: {PUBLIC_MADE_PRIVATE}; generated without it, so its public key is private (reading it \
                 needs a login)"
            )?;
            if self.by_name.is_some() {
                f.write_str("; ")?;
            }
        }
        if let Some(curve) = &self.by_name {
            write!(f, "{token}: {BY_NAME} ({curve})")?;
        }
        Ok(())
    }
}

/// Makes a public key object, alone or as the half of a key pair, from the template `public`.
/// When the module calls a value invalid and the spec did not declare `CKA_PRIVATE` (`declared`
/// is false), the function tries once more without cakeys' own default `CKA_PRIVATE = false`.
/// This fallback applies to every module and is not a workaround for one module: the stricter
/// form is tried first, and then the form that the module accepts (AWS `CloudHSM` makes every
/// public key private \[run\], docs/CAPROBE.md). When the spec asks for `CKA_PRIVATE = false`,
/// the refusal stands. When the second try is also refused, the first refusal is the error.
/// Returns what `make` made and whether the default was dropped.
///
/// # Errors
///
/// The first refusal of `make`.
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

/// Returns whether a refusal is retried without the public default
/// ([`with_public_default_dropped`]). Only cakeys' own default is dropped (the spec did not
/// declare `CKA_PRIVATE`), and only when the module called a value invalid.
fn retry_without_public_private(refusal: &CkError, declared: bool) -> bool {
    !declared && matches!(refusal, CkError::Pkcs11(RvError::AttributeValueInvalid, _))
}

/// The reason why a curve that the module refused by OID is generated once more by its name
/// ([`by_name_retry`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByName {
    /// The module profile says that only the curve's name generates it (`via = "by-name"`). The
    /// refusal by OID was expected, and the result of the attempt by name is the module's answer.
    Profiled,
    /// No profile answers for the curve. The refusal by OID is the module's own answer, and the
    /// attempt by name is only a try.
    Unprofiled,
}

/// Returns whether, and why, a curve that the module refused by OID is generated once more by
/// its name (ISSUES.md B18). That happens when the token's `module` profile says that only the
/// curve's name generates it, or when no profile answers for the curve. With any other row, the
/// refusal is the module's answer, which is reported unchanged, and no second generation is
/// tried on the token.
fn by_name_retry(module: Option<&cakeys_profile::Profile>, key_type: &str, curve: &str) -> Option<ByName> {
    let row = Capability::Generate { key_type: key_type.into(), on: On::Item(curve.to_owned()) };
    match module.and_then(|p| p.capabilities.get(&row)) {
        None => Some(ByName::Unprofiled),
        Some(r) if r.via.as_deref() == Some("by-name") => Some(ByName::Profiled),
        Some(_) => None,
    }
}

/// Returns the message for a generation that `token` refused by OID (`by_oid`) and then by name
/// (`by_name`). The message names both refusals. It starts with the refusal that counts as the
/// module's answer, which `why` decides, and it keeps that refusal's return value
/// (token/generate.rs F3).
fn by_name_refused(token: &str, why: ByName, by_oid: &CkError, by_name: &CkError) -> Msg {
    let (answer, other, other_was) = match why {
        ByName::Profiled => (by_name, by_oid, "by OID, as the profile expects"),
        ByName::Unprofiled => (by_oid, by_name, "by name, tried after"),
    };
    Msg::from(format!("generating key on '{token}': {} ({answer}); {other_was}: {}", rv_name(answer), rv_name(other)))
        .with_rv(rv_of(answer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    /// A curve that was refused by OID is retried by name when its profile row says so or when
    /// no row answers. The refusal message starts with the attempt that counts as the answer,
    /// keeps that attempt's return value, and still names the other attempt (token/generate.rs
    /// F3). With `via = "by-name"`, the answer is the attempt by name, and not the refusal by OID,
    /// which the profile expects.
    #[test]
    fn the_by_name_retry_reports_the_attempt_that_answers() {
        use cakeys_profile::{Answer, Mode, Profile, Row};
        let row = |via: Option<&str>| {
            let mut p = Profile::new("ykcs11/2.7".into(), Mode::Observed);
            let generate =
                Capability::Generate { key_type: "CKK_EC_EDWARDS".into(), on: On::Item("edwards25519".into()) };
            p.capabilities
                .insert(generate, Row { answer: Answer::Yes, by: None, evidence: None, via: via.map(Into::into) });
            p
        };
        let retry = |p: Option<&Profile>| by_name_retry(p, "CKK_EC_EDWARDS", "edwards25519");
        assert_eq!(retry(Some(&row(Some("by-name")))), Some(ByName::Profiled));
        assert_eq!(retry(None), Some(ByName::Unprofiled));
        assert_eq!(retry(Some(&Profile::new("m".into(), Mode::Observed))), Some(ByName::Unprofiled));
        assert_eq!(retry(Some(&row(None))), None);
        let oid = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::GenerateKeyPair);
        let name = CkError::Pkcs11(RvError::VendorDefined(0x8000_0002), Function::GenerateKeyPair);
        let profiled = by_name_refused("yk", ByName::Profiled, &oid, &name);
        assert_eq!(profiled.rv(), Some(0x8000_0002));
        assert!(profiled.starts_with("generating key on 'yk': CKR 0x80000002 ("), "{profiled}");
        assert!(profiled.ends_with("by OID, as the profile expects: CKR 0x80000001"), "{profiled}");
        let unprofiled = by_name_refused("yk", ByName::Unprofiled, &oid, &name);
        assert_eq!(unprofiled.rv(), Some(0x8000_0001));
        assert!(unprofiled.ends_with("by name, tried after: CKR 0x80000002"), "{unprofiled}");
    }

    /// The note prints the same text that it printed before it became a typed value: each part
    /// is its own sentence after the token's name, and two parts are joined by `; `.
    #[test]
    fn a_create_note_says_what_it_said_as_text() {
        assert_eq!(CreateNote::of("t", false, None), None);
        let public = "t: the module refuses a public key with CKA_PRIVATE = false; generated without it, so its \
                      public key is private (reading it needs a login)";
        let by_name = "t: the module takes the curve only by name, as a PrintableString CKA_EC_PARAMS (edwards25519)";
        let note = |p, n: Option<&str>| CreateNote::of("t", p, n.map(str::to_owned)).unwrap().to_string();
        assert_eq!(note(true, None), public);
        assert_eq!(note(false, Some("edwards25519")), by_name);
        assert_eq!(note(true, Some("edwards25519")), format!("{public}; {by_name}"));
    }

    #[test]
    fn only_the_default_is_dropped_and_only_for_an_invalid_value() {
        let invalid = CkError::Pkcs11(RvError::AttributeValueInvalid, Function::GenerateKeyPair);
        let other = CkError::Pkcs11(RvError::TemplateInconsistent, Function::GenerateKeyPair);
        assert!(retry_without_public_private(&invalid, false));
        assert!(!retry_without_public_private(&invalid, true), "a declared CKA_PRIVATE is the spec's");
        assert!(!retry_without_public_private(&other, false));
    }

    /// The default is dropped once, and only after the refusal that dropping it can fix. When
    /// the second try is also refused, the error is the first refusal.
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
