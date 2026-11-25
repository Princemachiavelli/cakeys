//! Creating and destroying objects (in an SO session where the module needs one).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::rv::device_failed;
use super::{
    Attribute, Binding, Checked, CkError, Create, Declared, Destroy, Generation, Half, KeyType, KmError, Locator,
    Mechanism, Msg, Object, ObjectCfg, ObjectClass, ObjectHandle, Result, RvError, SpecCfg, Template, Token, Topic, ck,
    class_of, key_type_of, keygen_mechanism, rv_name, rv_of, secret_key_gen, templates,
};
use cakeys_profile::{Capability, On};

impl Token {
    /// Create `object` on the token under `loc`, as `spec` declares it. A key the provider
    /// places nowhere under `loc` is refused first ([`Provider::placement`]); a module that
    /// creates only in a Security Officer session runs the provider's creation that way (the
    /// admin credential of keys.toml, the user PIN restored afterwards); then the provider
    /// checks the generation.
    ///
    /// # Errors
    ///
    /// `Validation` (17) for a locator the provider places no key under, naming the rule
    /// (`placement`); `Validation` for a class cakeys adopts rather than creates, or a key type missing its
    /// size (`modulusBits`, `valueLen`); a generation the module refuses is `Unsupported`,
    /// naming the token and the `C_*` failure. `Some(note)` says how the key was made other than
    /// asked (a public key the module made private). `binding` is how a private key will be
    /// proven: a module that generates from its own template ([`Provider::generation`]) refuses
    /// here a key it could not prove.
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
        // Core's order, which no override can skip (review 2026-11-24 B-2): where the key may go,
        // then the session the module writes in, then the provider.
        crate::ops::placement(self.provider.as_ref(), object.class, loc)?;
        let req = Checked::new(Create { object, spec, locator: loc, binding });
        self.managing("generating a key", || self.provider.create(self, &req))
    }

    /// [`Provider::create`]'s default, for an override to wrap: the module's own template where
    /// [`Provider::generation`] chooses one, else cakeys' templates. [`Self::create`] has asked
    /// placement and entered the session the module writes in.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    ///
    /// [`Provider::create`]: crate::Provider::create
    /// [`Provider::generation`]: crate::Provider::generation
    pub fn create_declared(&self, req: &Checked<Create<'_>>) -> Result<Option<CreateNote>> {
        match self.provider.generation(req.object, req.spec, req.locator, req.binding)? {
            Some(g) => self.generate_own(&g),
            None => self.generate(req.object, req.spec, req.locator),
        }
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

    /// Whether a curve the module refused by OID is generated once more by name (ISSUES.md
    /// B18), [`by_name_retry`] by the token's module profile.
    fn retries_by_name(&self, key_type: &str, curve: &str) -> Option<ByName> {
        by_name_retry(self.profiles.module.as_ref(), key_type, curve)
    }

    /// A refused generation. A failure of the device, token or session is the token's, not the
    /// key's: unavailable (16), as an attribute read's is ([`device_failed`]). What the module
    /// says of the key is unsupported (15), with the provider's hint.
    fn refused_generation(&self, e: &CkError, msg: String) -> KmError {
        let rv = rv_of(e);
        if device_failed(e) {
            KmError::Unavailable(msg.into()).with_rv(rv)
        } else {
            self.unsupported_for(Topic::Generate, msg).with_rv(rv)
        }
    }

    /// The module's own generation: its template alone, no public template.
    fn generate_own(&self, g: &Generation) -> Result<Option<CreateNote>> {
        let (mech, pair) = keygen_mechanism(g.keygen).ok_or_else(|| {
            self.unsupported_for(Topic::Generate, format!("generating key on '{}' with {}", self.name, g.keygen))
        })?;
        let made = if pair {
            self.session.generate_key_pair(&mech, &[], &g.template).map(drop)
        } else {
            self.session.generate_key(&mech, &g.template).map(drop)
        };
        made.map(|()| None).map_err(|e| {
            self.refused_generation(&e, format!("generating key on '{}': {} ({e})", self.name, rv_name(&e)))
        })
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

    fn generate(&self, object: Object<'_>, spec: &SpecCfg, loc: &Locator) -> Result<Option<CreateNote>> {
        // Each template as the provider adjusts it, before anything is generated.
        let on = Declared { object, spec, locator: loc };
        let key = self.generation_key(on)?;
        let public = self.generation_public(on, None)?;
        let refused = |e: CkError| {
            self.refused_generation(&e, format!("generating key on '{}': {} ({e})", self.name, rv_name(&e)))
        };
        let private_declared = templates::public_declares(spec, "CKA_PRIVATE");
        // A key pair, once more without the public half's default `CKA_PRIVATE = false` when the
        // module refuses it ([`with_public_default_dropped`]): whether it did.
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
                // The OID first; a module that takes the curve only by name (ykcs11's
                // edwards25519, a profile's `by-name` row [src]) gets PKCS#11 3.0's
                // PrintableString form. The identity is the same: the SPKI, not the params.
                let by_oid = pair(&mech, &by_oid_public, &key);
                let retry = curve.params_by_name().zip(self.retries_by_name(&kt.to_string(), curve.name()));
                match (by_oid, retry) {
                    (Err(by_oid), Some((name, why))) => {
                        let by_name = self.generation_public(on, Some(name))?.unwrap_or_default();
                        pair(&mech, &by_name, &key).map(|d| note(d, Some(curve.name().to_owned()))).map_err(|by_name| {
                            self.unsupported_for(Topic::Generate, by_name_refused(&self.name, why, &by_oid, &by_name))
                        })
                    }
                    (other, _) => other.map(|d| note(d, None)).map_err(refused),
                }
            }
            // A secret key: the mechanism its key type names.
            _ => {
                let mech = object.key_type.map_or(Mechanism::GenericSecretKeyGen, secret_key_gen);
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
    /// key (or none cakeys can read) is left alone. Returns (destroyed, left). `spki` is the
    /// private key's ([`Self::spki`]) where the caller has read it already.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) when the provider cannot actually erase keys (ykcs11); a failure to
    /// destroy is `Unavailable`, naming the token.
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

    /// Destroy exactly `handles` (what a failed import created), as `object` under `loc` would be.
    ///
    /// # Errors
    ///
    /// As [`Self::destroy`].
    pub fn destroy_handles(&self, object: &ObjectCfg, loc: &Locator, handles: &[ObjectHandle]) -> Result<usize> {
        if handles.is_empty() {
            return Ok(0);
        }
        let req = Checked::new(Destroy { object, locator: loc, handles });
        self.managing("deleting", || self.provider.destroy(self, &req))
    }

    /// [`Provider::destroy`]'s default, for an override to wrap: `C_DestroyObject` on each of
    /// `req.handles`, in the session the token's destroys entered for the module.
    ///
    /// # Errors
    ///
    /// A failure to destroy is `Unavailable`, naming the token.
    ///
    /// [`Provider::destroy`]: crate::Provider::destroy
    pub fn destroy_plain(&self, req: &Checked<Destroy<'_>>) -> Result<usize> {
        let handles = req.handles;
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
    }
}

/// What [`Token::create`]'s note says when the module generated the curve only from its name
/// (PKCS#11 3.0's `PrintableString` `CKA_EC_PARAMS`), never by OID: ykcs11's edwards25519.
pub const BY_NAME: &str = "the module takes the curve only by name, as a PrintableString CKA_EC_PARAMS";

/// What [`Token::create`]'s note says when the module refused the public half's
/// `CKA_PRIVATE = false` default and the pair was generated without it (AWS `CloudHSM`).
pub const PUBLIC_MADE_PRIVATE: &str = "the module refuses a public key with CKA_PRIVATE = false";

/// How [`Token::create`] made a key other than it was asked (ISSUES.md Q3): read as data by
/// the probe, said on the run as its `Display`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateNote {
    /// The token's keys.toml name, which each part of the note starts with.
    token: String,
    /// The public half was generated without `CKA_PRIVATE = false` ([`PUBLIC_MADE_PRIVATE`]).
    pub public_made_private: bool,
    /// The curve the module took only by name ([`BY_NAME`]).
    pub by_name: Option<String>,
}

impl CreateNote {
    /// `Some` when either part says something.
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

/// Why a curve the module refused by OID is generated once more by name ([`by_name_retry`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByName {
    /// The module profile says only the curve's name generates it (`via = "by-name"`): the OID
    /// refusal was expected, the by-name attempt's answer is the module's.
    Profiled,
    /// No profile answers for the curve: the OID refusal is the module's own answer, the by-name
    /// attempt a try.
    Unprofiled,
}

/// Whether, and why, a curve the module refused by OID is generated once more by name
/// (ISSUES.md B18): when the token's `module` profile says only its name generates it, or no
/// profile answers for it. Any other row is the module's answer, reported as given, and no
/// second generation is tried on the token.
fn by_name_retry(module: Option<&cakeys_profile::Profile>, key_type: &str, curve: &str) -> Option<ByName> {
    let row = Capability::Generate { key_type: key_type.into(), on: On::Item(curve.to_owned()) };
    match module.and_then(|p| p.capabilities.get(&row)) {
        None => Some(ByName::Unprofiled),
        Some(r) if r.via.as_deref() == Some("by-name") => Some(ByName::Profiled),
        Some(_) => None,
    }
}

/// A generation `token` refused by OID (`by_oid`) and then by name (`by_name`): both said, led by
/// the one that answers (`why`), whose return value it keeps (token/generate.rs F3).
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

    /// A curve refused by OID is retried by name where its profile row says so or no row
    /// answers; the refusal leads with the attempt that answers, keeps its return value and
    /// still says the other (token/generate.rs F3): with `via = "by-name"`, the by-name
    /// attempt's, not the OID refusal the profile expects.
    #[test]
    fn the_by_name_retry_reports_the_attempt_that_answers() {
        use cakeys_profile::{Answer, Mode, Profile, Row};
        let row = |via: Option<&str>| {
            let mut p = Profile::new("ykcs11/2.7".into(), Mode::Observed);
            let generate =
                Capability::Generate { key_type: "CKK_EC_EDWARDS".into(), on: On::Item("edwards25519".into()) };
            p.capabilities.insert(generate, Row { answer: Answer::Yes, evidence: None, via: via.map(Into::into) });
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

    /// The note says on the run what it said as text before it was typed: each part as its own
    /// sentence after the token's name, both joined by `; `.
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
