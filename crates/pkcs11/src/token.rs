//! PKCS#11 token layer over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.
//! Module-specific behaviour goes through the selected [`Provider`].

use crate::provider::{AttestationCap, AttestCtx, Attested, Provider, Registry};
pub use cakeys_core::config::{Immutables, ModuleInfo, TokenInfo};
use cakeys_core::attrs;
use cakeys_core::config::{AttrValue, Binding, Locator, Mode, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::id::{self, Commit, Curve, HmacHash};
use cakeys_core::pop;
use cakeys_core::{KmError, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct Token {
    pub name: String,
    pub label: String,
    pub module: ModuleInfo,
    pub token: TokenInfo,
    /// Usable mechanisms: advertised ones, filtered by the provider.
    pub mechanisms: Vec<MechanismType>,
    /// Their names, sorted: what the lock records and `caps` prints.
    mechanism_names: Vec<String>,
    pub provider: Arc<dyn Provider>,
    session: Session,
    /// Logged in as the user: private objects are visible. Otherwise a public session.
    pub logged_in: bool,
    /// The token's config, for provider hooks that need more than the module (the native TPM
    /// attestation path's `tcti`, `tpm2Store` and `akHandle`).
    pub cfg: TokenCfg,
    /// The user credential, already read for login, kept only when the provider can attest
    /// (the TPM attestation path unseals the token's wrapping key with it) or an SO step must
    /// log the user back in afterwards (`mgmKeyFile`/`mgmKeyEnv`). Zeroized on drop.
    pin: Option<Zeroizing<String>>,
}

fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}"))
}

impl Token {
    pub fn open(
        name: &str,
        cfg: &TokenCfg,
        module_override: Option<&str>,
        registry: &Registry,
    ) -> Result<Token> {
        let module = module_override
            .map(str::to_owned)
            .or_else(|| cfg.module.clone())
            .ok_or_else(|| KmError::Validation(format!("token '{name}' has no module")))?;
        let ctx = Pkcs11::new(&module).map_err(ck(&format!("loading {module}")))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map_err(ck("C_Initialize"))?;
        let lib = ctx.get_library_info().map_err(ck("C_GetInfo"))?;
        let module = ModuleInfo {
            path: module,
            description: lib.library_description().trim().to_owned(),
            manufacturer: lib.manufacturer_id().trim().to_owned(),
            version: lib.library_version().to_string(),
            cryptoki: lib.cryptoki_version().to_string(),
        };
        let provider = registry.select(cfg.provider.as_deref(), &module)?;
        if has_admin(cfg) && !provider.manages_as_so() {
            return Err(KmError::Validation(format!(
                "token '{name}': mgmKeyFile/mgmKeyEnv is only for modules that create keys as \
                 Security Officer (ykcs11); provider {} creates them as the user",
                provider.name()
            )));
        }
        let mut slot = None;
        for s in ctx.get_slots_with_token().map_err(ck("C_GetSlotList"))? {
            let info = ctx.get_token_info(s).map_err(ck("C_GetTokenInfo"))?;
            if info.label() == cfg.token_label {
                if slot.is_some() {
                    return Err(KmError::Ambiguous(format!(
                        "several tokens labelled '{}'",
                        cfg.token_label
                    )));
                }
                slot = Some((
                    s,
                    TokenInfo {
                        model: info.model().trim().to_owned(),
                        serial: info.serial_number().trim().to_owned(),
                        firmware: info.firmware_version().to_string(),
                    },
                ));
            }
        }
        let (slot, token) = slot.ok_or_else(|| {
            KmError::Unavailable(format!("token '{}' not present in {}", cfg.token_label, module.path))
        })?;
        let mechanisms = provider.mechanisms(ctx.get_mechanism_list(slot).map_err(ck("C_GetMechanismList"))?);
        let mut mechanism_names: Vec<String> = mechanisms.iter().map(|m| m.to_string()).collect();
        mechanism_names.sort();
        let session = ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?;
        let pin = read_pin(cfg)?;
        if let Some(pin) = pin.as_deref() {
            match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(KmError::Unavailable(format!("C_Login: {e}"))),
            }
        }
        Ok(Token {
            name: name.to_owned(),
            label: cfg.token_label.clone(),
            module,
            token,
            mechanisms,
            mechanism_names,
            session,
            logged_in: pin.is_some(),
            cfg: cfg.clone(),
            pin: pin.filter(|_| provider.attestation().is_some() || has_admin(cfg)),
            provider,
        })
    }

    /// An `Unsupported` error carrying the provider's advice, if it has any.
    pub fn unsupported(&self, msg: String) -> KmError {
        match self.provider.hint() {
            Some(h) => KmError::Unsupported(format!("{msg} (hint for {}: {h})", self.provider.name())),
            None => KmError::Unsupported(msg),
        }
    }

    pub fn has(&self, m: MechanismType) -> bool {
        self.mechanisms.contains(&m)
    }

    pub fn mechanism_names(&self) -> &[String] {
        &self.mechanism_names
    }

    /// The provider's attestation capability for `object`'s class, when the spec opted in:
    /// `None` when this module attests nothing (or not this class).
    pub fn attestation_cap(&self, object: &ObjectCfg) -> Option<AttestationCap> {
        self.provider
            .attestation()
            .filter(|cap| cap.classes.contains(&object.class.as_str()))
    }

    /// Compute the attestation commitment for `key` (§3.7 of docs/DESIGN.md) through the
    /// provider: the module-exposed attestation certificate (PIV) or the native TPM2_Certify
    /// path (tpm2-pkcs11), verified on the host. `spki` is the material SPKI the attestation
    /// must name (`None` for secret keys); `provision` lets the provider create the device
    /// state it attests with (only `realise` sets it).
    pub fn attest(&self, key: ObjectHandle, object: &ObjectCfg, spki: Option<&[u8]>, provision: bool) -> Result<Attested> {
        let ctx = AttestCtx {
            session: &self.session,
            cfg: &self.cfg,
            token_name: &self.name,
            key,
            object,
            spki,
            pin: self.pin.as_ref().map(|p| p.as_str()),
            provision,
        };
        self.provider.attest(&ctx)
    }

    pub fn find(&self, class: ObjectClass, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        let mut template = vec![Attribute::Class(class)];
        template.extend(locator_attrs(loc)?);
        self.session
            .find_objects(&template)
            .map_err(ck("C_FindObjects"))
    }

    /// Every object under the locator, whatever its class (If-None-Match before creating).
    pub fn find_any(&self, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        self.session
            .find_objects(&locator_attrs(loc)?)
            .map_err(ck("C_FindObjects"))
    }

    /// Exactly-one lookup of the object named by the locator: the key (private or secret) or
    /// certificate, or the public key object when adopting public-only.
    pub fn find_key(
        &self,
        object: &ObjectCfg,
        loc: &Locator,
        public_only: bool,
    ) -> Result<Option<ObjectHandle>> {
        let class = if public_only { ObjectClass::PUBLIC_KEY } else { class_of(object)? };
        let found = self.find(class, loc)?;
        match found.len() {
            0 => Ok(None),
            1 => Ok(Some(found[0])),
            n => Err(KmError::Ambiguous(format!(
                "{n} objects match locator {loc} on token '{}'",
                self.name
            ))),
        }
    }

    /// Consumers that select a key by `CKA_ID` (OpenSSH takes the first private key with the
    /// certificate's or public key's ID) must find exactly this one: refuse when another private
    /// key shares `h`'s `CKA_ID`. Only a logged-in session can see private keys; a public session
    /// checks nothing (the lock records which it was).
    pub fn check_unique_private_id(&self, h: ObjectHandle) -> Result<()> {
        if !self.logged_in {
            return Ok(());
        }
        let id = match self.attr(h, AttributeType::Id)? {
            Some(Attribute::Id(id)) if !id.is_empty() => id,
            _ => return Ok(()),
        };
        let keys = self
            .session
            .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(id.clone())])
            .map_err(ck("C_FindObjects"))?;
        if keys.len() > 1 {
            return Err(KmError::Ambiguous(format!(
                "{} private keys on token '{}' share CKA_ID {}; a consumer selecting by ID may use another key",
                keys.len(),
                self.name,
                pct_all(&id)
            )));
        }
        Ok(())
    }

    fn attr(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<Attribute>> {
        Ok(self
            .session
            .get_attributes(h, &[t])
            .map_err(ck("C_GetAttributeValue"))?
            .into_iter()
            .next())
    }

    /// Check the intrinsic type and every policy attribute of the spec against the live object.
    pub fn check(&self, h: ObjectHandle, object: &ObjectCfg, spec: &SpecCfg) -> Result<()> {
        let class = class_of(object)?;
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
        let kt = match self.attr(h, AttributeType::KeyType)? {
            Some(Attribute::KeyType(k)) => k,
            _ => return Err(KmError::Conflict("object has no CKA_KEY_TYPE".into())),
        };
        if kt != key_type_of(object)? {
            return Err(KmError::Conflict(format!(
                "CKA_KEY_TYPE is {kt}, spec object type says {}",
                object.key_type
            )));
        }
        if kt == KeyType::EC || kt == KeyType::EC_EDWARDS {
            let want = curve_of(object)?;
            match self.attr(h, AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) if Curve::from_params(&p) == Some(want) => {}
                other => {
                    return Err(KmError::Conflict(format!(
                        "CKA_EC_PARAMS {other:?} is not {want:?}"
                    )))
                }
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
                other => {
                    return Err(KmError::Conflict(format!("CKA_VALUE_LEN mismatch: {other:?}")))
                }
            }
        }
        self.check_policy(h, spec)
    }


    /// The observed policy vector: every boolean attribute of `h`'s class (PKCS#11 3.2 §4,
    /// `cakeys_core::attrs::observed`) the token reports, declared in the spec or not, plus
    /// `CKA_ALLOWED_MECHANISMS` on key objects when readable. Unreadable ones are left out.
    pub fn policy(&self, h: ObjectHandle) -> Result<BTreeMap<String, AttrValue>> {
        let class = match self.attr(h, AttributeType::Class)? {
            Some(Attribute::Class(c)) => c.to_string(),
            _ => return Err(KmError::Conflict("object has no CKA_CLASS".into())),
        };
        let mut policy = BTreeMap::new();
        for name in attrs::observed(&class) {
            let Some(t) = bool_attr(name, false).map(|a| a.attribute_type()) else { continue };
            // Unsupported or unreadable on this token: not part of what it can show.
            if let Ok(Some(a)) = self.attr(h, t) {
                if let Some(b) = attr_bool(&a) {
                    policy.insert(name.to_owned(), AttrValue::Bool(b));
                }
            }
        }
        if attrs::has_allowed_mechanisms(&class) {
            // An empty list is not reported: it is indistinguishable from absent and means none.
            if let Ok(Some(Attribute::AllowedMechanisms(m))) = self.attr(h, AttributeType::AllowedMechanisms) {
                if !m.is_empty() {
                    policy.insert(
                        "CKA_ALLOWED_MECHANISMS".to_owned(),
                        AttrValue::mechanisms(m.iter().map(|m| m.to_string())),
                    );
                }
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
                Some(Attribute::AllowedMechanisms(m)) => Some(AttrValue::mechanisms(m.iter().map(|m| m.to_string()))),
                _ => None,
            });
        }
        let t = bool_attr(name, false).ok_or_else(|| unsupported_attr(name))?.attribute_type();
        Ok(self.attr(h, t)?.as_ref().and_then(attr_bool).map(AttrValue::Bool))
    }

    /// `publicAttributes`, checked on the public key object of the pair: `h` itself when adopting
    /// publicOnly, else the single public key object under the locator, which must hold the
    /// same public key as `h`.
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
                    ))
                }
                _ => return Err(KmError::Ambiguous("several public key objects share the locator".into())),
            };
            if let (Some(a), Some(b)) = (self.material_spki(p)?, self.material_spki(h)?) {
                if a != b {
                    return Err(KmError::Conflict("the public key object under the locator holds another key".into()));
                }
            }
            p
        };
        self.check_attrs(p, &spec.public_attributes, "public key object: ")
    }

    /// Template attributes for declared policy values. Mechanism names must be ones the token
    /// offers.
    fn policy_template(&self, attrs: &BTreeMap<String, AttrValue>) -> Result<Vec<Attribute>> {
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

    pub fn create(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<()> {
        self.provider.check_create(object, loc)?;
        if self.provider.manages_as_so() {
            self.as_so("generating a key", || self.generate(object, spec, loc))
        } else {
            self.generate(object, spec, loc)
        }
    }

    /// Run `step` in a Security Officer session (`mgmKeyFile`/`mgmKeyEnv`), for modules that
    /// create and destroy objects only as SO, then return to the user session. Login state is
    /// per token, so the user is logged out first. The admin credential is read here, never at
    /// open, and zeroized when the step ends.
    fn as_so<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        let so = read_mgm(&self.cfg)?.ok_or_else(|| {
            self.unsupported(format!(
                "{what} on '{}' needs a Security Officer session: set tokens.{}.mgmKeyFile or mgmKeyEnv",
                self.name, self.name
            ))
        })?;
        if self.logged_in {
            self.session.logout().map_err(ck("C_Logout"))?;
        }
        let out = match self.session.login(UserType::So, Some(&AuthPin::new(so.as_str().to_owned().into()))) {
            Ok(()) => {
                let out = step();
                let logout = self.session.logout().map_err(ck("C_Logout (SO)"));
                out.and_then(|v| logout.map(|()| v))
            }
            Err(e) => Err(KmError::Unavailable(format!(
                "C_Login (SO) with mgmKeyFile/mgmKeyEnv: {e}; it must hold the module's admin \
                 credential (ykcs11: the PIV management key in hex, or the PIN on a device whose \
                 management key is PIN-protected)"
            ))),
        };
        drop(so);
        if self.logged_in {
            let pin = self.pin.as_deref().ok_or_else(|| KmError::Unavailable("no user PIN to log back in with".into()))?;
            match self.session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(KmError::Unavailable(format!("C_Login (back to the user): {e}"))),
            }
        }
        out
    }

    fn generate(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<()> {
        let mut common = vec![Attribute::Token(true)];
        common.extend(locator_attrs(loc)?);
        let policy = self.policy_template(&spec.attributes)?;
        let gen = |e: CkError| self.unsupported(format!("generating key on '{}': {e}", self.name));
        let class = class_of(object)?;
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
                let bits = object.modulus_bits.ok_or_else(|| {
                    KmError::Validation("RSA keys need modulusBits".into())
                })?;
                let mut public = common.clone();
                public.extend([
                    Attribute::ModulusBits(bits.into()),
                    Attribute::PublicExponent(vec![1, 0, 1]),
                ]);
                public_half(&mut public)?;
                let mut private = common;
                private.extend(policy);
                self.session
                    .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &private)
                    .map(drop)
                    .map_err(gen)
            }
            KeyType::EC | KeyType::EC_EDWARDS => {
                let curve = curve_of(object)?;
                let mech = if curve.edwards() {
                    Mechanism::EccEdwardsKeyPairGen
                } else {
                    Mechanism::EccKeyPairGen
                };
                let mut public = common.clone();
                public.extend([Attribute::EcParams(curve.params().to_vec())]);
                public_half(&mut public)?;
                let mut private = common;
                private.extend(policy);
                self.session
                    .generate_key_pair(&mech, &public, &private)
                    .map(drop)
                    .map_err(gen)
            }
            kt => {
                let len = object.value_len.ok_or_else(|| {
                    KmError::Validation("secret keys need valueLen (bytes)".into())
                })?;
                let mech = if kt == KeyType::AES {
                    Mechanism::AesKeyGen
                } else {
                    Mechanism::GenericSecretKeyGen
                };
                let mut t = common;
                t.extend([
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(kt),
                    Attribute::ValueLen(len.into()),
                ]);
                t.extend(policy);
                self.session.generate_key(&mech, &t).map(drop).map_err(gen)
            }
        }
    }

    /// Destroy the key and any public half sharing its locator.
    pub fn destroy(&self, object: &ObjectCfg, loc: &Locator) -> Result<usize> {
        let class = class_of(object)?;
        let mut handles = self.find(class, loc)?;
        if class == ObjectClass::PRIVATE_KEY {
            handles.extend(self.find(ObjectClass::PUBLIC_KEY, loc)?);
        }
        if handles.is_empty() {
            return Ok(0);
        }
        if matches!(class, ObjectClass::PRIVATE_KEY | ObjectClass::PUBLIC_KEY | ObjectClass::SECRET_KEY) {
            if let Some(advice) = self.provider.keeps_destroyed_keys(loc) {
                return Err(KmError::Unsupported(format!(
                    "deleting {} on '{}': {advice}",
                    object.class, self.name
                )));
            }
        }
        let run = || {
            for h in &handles {
                self.session.destroy_object(*h).map_err(ck("C_DestroyObject"))?;
            }
            Ok(handles.len())
        };
        if self.provider.manages_as_so() {
            self.as_so("deleting", run)
        } else {
            run()
        }
    }

    /// Compute the material CA-IDs of the object using `mode`; secret keys use `commits`. With
    /// `binding`, `h` is a private key whose possession of the public key hashed is proven
    /// (`None`, or `TokenAsserted`, proves nothing).
    #[allow(clippy::too_many_arguments)] // two callers (resolve, delete), each passing all of them
    pub fn ids(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        loc: &Locator,
        mode: Mode,
        commits: &[Commit],
        commitment_label: &str,
        binding: Option<Binding>,
    ) -> Result<BTreeMap<String, String>> {
        let mut ids = BTreeMap::new();
        match mode {
            Mode::Direct if class_of(object)? == ObjectClass::CERTIFICATE => {
                let der = match self.attr(h, AttributeType::Value)? {
                    Some(Attribute::Value(v)) => v,
                    _ => return Err(KmError::Unsupported("certificate has no readable CKA_VALUE".into())),
                };
                ids.insert("certhash".into(), id::sri(&der));
                ids.insert("rfc7093m4".into(), id::sri(&id::cert_spki(&der)?));
            }
            Mode::Direct if class_of(object)? == ObjectClass::DATA => {
                // SHA-256 of the content: the same SRI hash as a flat Nix fixed-output hash.
                let value = match self.attr(h, AttributeType::Value)? {
                    Some(Attribute::Value(v)) => v,
                    _ => return Err(KmError::Unsupported("data object has no readable CKA_VALUE".into())),
                };
                ids.insert("valuehash".into(), id::sri(&value));
            }
            Mode::Direct => {
                let spki = self.spki(h, loc)?;
                if let Some(b) = binding.filter(|b| b != &Binding::TokenAsserted) {
                    self.prove_binding(h, object, &spki, b)?;
                }
                ids.insert("rfc7093m4".into(), id::sri(&spki));
            }
            Mode::Commitment => {
                for c in commits {
                    ids.insert(c.scheme().into(), id::sri(&self.commit(h, object, *c, commitment_label)?));
                }
            }
            Mode::WrapRebind => {
                for (c, out) in self.wrap_rebind(h, object, commits, commitment_label)? {
                    ids.insert(c.scheme().into(), id::sri(&out));
                }
            }
            m => {
                return Err(KmError::Unsupported(format!(
                    "identity mode '{m}' is not implemented in this POC"
                )))
            }
        }
        Ok(ids)
    }

    /// Canonical SPKI of a key, from key material rather than from what the module asserts:
    /// 1. the object's own material (RSA modulus/exponent, EC params and point);
    /// 2. else the single public key object under the locator (EC/Edwards private keys expose no
    ///    point; possession of the private half is proven separately);
    /// 3. else `CKA_PUBLIC_KEY_INFO`.
    ///
    /// Whenever `CKA_PUBLIC_KEY_INFO` is present it must agree with the material: modules may let
    /// it be set without checking (SoftHSM, kryoptic), so it is never trusted on its own.
    pub(crate) fn spki(&self, h: ObjectHandle, loc: &Locator) -> Result<Vec<u8>> {
        let spki = match self.material_spki(h)? {
            Some(spki) => spki,
            None => match self.find(ObjectClass::PUBLIC_KEY, loc)?.as_slice() {
                [p] => {
                    let spki = match self.material_spki(*p)? {
                        Some(spki) => spki,
                        None => self.public_key_info(*p).ok_or_else(|| {
                            KmError::NotFound("the public key object exposes no key material".into())
                        })??,
                    };
                    self.cross_check(*p, &spki)?;
                    spki
                }
                [] => match self.public_key_info(h) {
                    Some(spki) => spki?,
                    None => return Err(KmError::NotFound("no public key object under the locator".into())),
                },
                _ => return Err(KmError::Ambiguous("several public key objects share the locator".into())),
            },
        };
        self.cross_check(h, &spki)?;
        Ok(spki)
    }

    /// `CKA_PUBLIC_KEY_INFO`, canonicalized; `None` when absent, empty or unreadable (ykcs11
    /// reports length 0 and then fails the fetch with CKR_ARGUMENTS_BAD).
    fn public_key_info(&self, h: ObjectHandle) -> Option<Result<Vec<u8>>> {
        match self.attr(h, AttributeType::PublicKeyInfo) {
            Ok(Some(Attribute::PublicKeyInfo(der))) if !der.is_empty() => Some(id::spki_canonical(&der)),
            _ => None,
        }
    }

    /// Fail when the object's `CKA_PUBLIC_KEY_INFO` names a different key than its material.
    fn cross_check(&self, h: ObjectHandle, spki: &[u8]) -> Result<()> {
        match self.public_key_info(h) {
            Some(Ok(asserted)) if asserted != spki => Err(KmError::Conflict(format!(
                "token '{}' reports a CKA_PUBLIC_KEY_INFO ({}) that disagrees with the key material ({})",
                self.name,
                id::sri(&asserted),
                id::sri(spki)
            ))),
            _ => Ok(()),
        }
    }


    /// Proof of possession (`cakeys_core::pop`, docs/DESIGN.md §3.6), by the spec's `binding`:
    /// the private key `h` proves, by whichever capability it has, that it holds the private
    /// half of `spki`, the public key its identity hashes. A proof that does not verify is a
    /// `Conflict`; a token that cannot prove is `Unsupported` or `Unavailable`, never a pass.
    fn prove_binding(&self, h: ObjectHandle, object: &ObjectCfg, spki: &[u8], binding: Binding) -> Result<()> {
        // A context-specific login per proof (PIV signing slot) would spend PIN retries.
        if let Some(Attribute::AlwaysAuthenticate(true)) = self.attr(h, AttributeType::AlwaysAuthenticate)? {
            return Err(KmError::Unavailable(format!(
                "the private key on token '{}' is CKA_ALWAYS_AUTHENTICATE; proving possession would need a \
                 PIN entry per run; adopt it publicOnly, or opt in with binding = \"token-asserted\"",
                self.name
            )));
        }
        let msg = pop::challenge(spki)?;
        match binding {
            Binding::PopSign => self.prove_sign(h, object, spki, &msg),
            Binding::PopEcdh => self.prove_ecdh(h, spki, &msg),
            Binding::PopDecrypt => self.prove_decrypt(h, spki, &msg),
            Binding::TokenAsserted => Ok(()),
        }
    }

    /// `pop-sign`: the token signs the challenge; the host verifies the signature.
    fn prove_sign(&self, h: ObjectHandle, object: &ObjectCfg, spki: &[u8], msg: &[u8]) -> Result<()> {
        let (mech, data) = match key_type_of(object)? {
            KeyType::EC => {
                let hash = pop::EcdsaHash::for_curve(curve_of(object)?)
                    .ok_or_else(|| KmError::Unsupported(format!("ECDSA on {}", object.curve.as_deref().unwrap_or("?"))))?;
                let hashed = match hash {
                    pop::EcdsaHash::Sha256 => (Mechanism::EcdsaSha256, MechanismType::ECDSA_SHA256),
                    pop::EcdsaHash::Sha384 => (Mechanism::EcdsaSha384, MechanismType::ECDSA_SHA384),
                    pop::EcdsaHash::Sha512 => (Mechanism::EcdsaSha512, MechanismType::ECDSA_SHA512),
                };
                if self.has(hashed.1) {
                    (hashed.0, msg.to_vec())
                } else {
                    (Mechanism::Ecdsa, hash.digest(msg))
                }
            }
            KeyType::EC_EDWARDS => (Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)), msg.to_vec()),
            KeyType::RSA => (Mechanism::Sha256RsaPkcs, msg.to_vec()),
            kt => return Err(KmError::Unsupported(format!("proof of possession for {kt}"))),
        };
        if !self.has(mech.mechanism_type()) {
            return Err(self.unsupported(format!(
                "token '{}' lacks {} to prove possession of the private key; opt in with binding = \"token-asserted\"",
                self.name,
                mech.mechanism_type()
            )));
        }
        let sig = self.session.sign(&mech, h, &data).map_err(|e| match e {
            CkError::Pkcs11(RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent, _) => {
                self.unsupported(format!(
                    "token '{}' refused to sign with the private key ({e}); proving possession needs CKA_SIGN, \
                     or opt in with binding = \"token-asserted\"",
                    self.name
                ))
            }
            e => KmError::Unavailable(format!("C_Sign (proof of possession) on token '{}': {e}", self.name)),
        })?;
        pop::verify(spki, msg, &sig)
    }

    /// `pop-ecdh`: the host holds an ephemeral key and the MAC of the challenge under the shared
    /// secret; the token derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable
    /// session key and MACs the challenge with it. The MACs agree only if the token's private key
    /// is the one `spki` names.
    fn prove_ecdh(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        let ch = pop::ecdh_challenge(spki, msg)?;
        fn lacking(t: &Token, what: &str) -> KmError {
            t.unsupported(format!(
                "token '{}' lacks {what} to prove possession of the private key; opt in with binding = \"token-asserted\"",
                t.name
            ))
        }
        if !self.has(MechanismType::ECDH1_DERIVE) {
            return Err(lacking(self, "CKM_ECDH1_DERIVE"));
        }
        if !self.has(MechanismType::SHA256_HMAC) {
            return Err(lacking(self, "CKM_SHA256_HMAC"));
        }
        let derived = self.session
            .derive_key(
                &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &ch.peer)),
                h,
                &[
                    Attribute::Token(false),
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Sign(true),
                ],
            )
            .map_err(|e| match e {
                CkError::Pkcs11(RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent, _) => {
                    self.unsupported(format!(
                        "token '{}' refused to derive with the private key ({e}); proving possession needs CKA_DERIVE, \
                         or opt in with binding = \"token-asserted\"",
                        self.name
                    ))
                }
                e => KmError::Unavailable(format!("C_DeriveKey (proof of possession) on token '{}': {e}", self.name)),
            })?;
        // A session object: dropped with the session even if destroying it fails here.
        let tag = self
            .session
            .sign(&Mechanism::Sha256Hmac, derived, msg)
            .inspect_err(|_| {
                let _ = self.session.destroy_object(derived);
            })
            .map_err(|e| KmError::Unavailable(format!("C_Sign (ECDH proof of possession) on token '{}': {e}", self.name)))?;
        let _ = self.session.destroy_object(derived);
        if !pop::ct_eq(&ch.mac, &tag) {
            return Err(KmError::Conflict(format!(
                "proof of possession failed: the private key did not derive for the public key {}",
                id::sri(spki)
            )));
        }
        Ok(())
    }

    /// `pop-decrypt`: the host encrypts the challenge to the public key with RSA-OAEP; the token
    /// decrypts it with the private key. The plaintext matches only if the token's private key is
    /// the one `spki` names.
    fn prove_decrypt(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        if !self.has(MechanismType::RSA_PKCS_OAEP) {
            return Err(self.unsupported(format!(
                "token '{}' lacks CKM_RSA_PKCS_OAEP to prove possession of the private key; opt in with binding = \"token-asserted\"",
                self.name
            )));
        }
        let cipher = pop::oaep_challenge(spki, msg)?;
        let plain = self.session
            .decrypt(
                &Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                    MechanismType::SHA1,
                    PkcsMgfType::MGF1_SHA1,
                    PkcsOaepSource::empty(),
                )),
                h,
                &cipher,
            )
            .map_err(|e| match e {
                CkError::Pkcs11(RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent, _) => {
                    self.unsupported(format!(
                        "token '{}' refused to decrypt with the private key ({e}); proving possession needs CKA_DECRYPT, \
                         or opt in with binding = \"token-asserted\"",
                        self.name
                    ))
                }
                e => KmError::Unavailable(format!("C_Decrypt (proof of possession) on token '{}': {e}", self.name)),
            })?;
        if !pop::ct_eq(msg, &plain) {
            return Err(KmError::Conflict(format!(
                "proof of possession failed: the private key did not decrypt for the public key {}",
                id::sri(spki)
            )));
        }
        Ok(())
    }
    /// SPKI from the key material attributes of `h`; `None` when it carries none (e.g. an EC
    /// private key without `CKA_EC_POINT`).
    fn material_spki(&self, h: ObjectHandle) -> Result<Option<Vec<u8>>> {
        match self.attr(h, AttributeType::KeyType)? {
            Some(Attribute::KeyType(KeyType::EC | KeyType::EC_EDWARDS)) => {
                let a = self
                    .session
                    .get_attributes(h, &[AttributeType::EcParams, AttributeType::EcPoint])
                    .map_err(ck("C_GetAttributeValue"))?;
                match a.as_slice() {
                    [Attribute::EcParams(params), Attribute::EcPoint(p)] => Curve::from_params(params)
                        .ok_or_else(|| KmError::Unsupported(format!("CKA_EC_PARAMS {params:02x?}")))?
                        .spki_from_point(&self.provider.ec_point(p))
                        .map(Some),
                    _ => Ok(None),
                }
            }
            Some(Attribute::KeyType(KeyType::RSA)) => {
                let a = self
                    .session
                    .get_attributes(h, &[AttributeType::Modulus, AttributeType::PublicExponent])
                    .map_err(ck("C_GetAttributeValue"))?;
                match a.as_slice() {
                    [Attribute::Modulus(n), Attribute::PublicExponent(e)] => id::rsa_spki(n, e).map(Some),
                    _ => Ok(None),
                }
            }
            kt => Err(KmError::Unsupported(format!("public key of type {kt:?}"))),
        }
    }

    /// One commitment (`id::Commit`) on the key `h`.
    fn commit(&self, h: ObjectHandle, object: &ObjectCfg, c: Commit, commitment_label: &str) -> Result<Vec<u8>> {
        let s = &self.session;
        let input = c.input(commitment_label, object);
        let fail = |e: CkError| KmError::Unsupported(format!("{} commitment ({}): {e}", c.scheme(), commit_mechanism(c)));
        match c {
            Commit::Hmac(hash) => {
                let m = match hash {
                    HmacHash::Sha1 => Mechanism::Sha1Hmac,
                    HmacHash::Sha224 => Mechanism::Sha224Hmac,
                    HmacHash::Sha256 => Mechanism::Sha256Hmac,
                    HmacHash::Sha384 => Mechanism::Sha384Hmac,
                    HmacHash::Sha512 => Mechanism::Sha512Hmac,
                };
                s.sign(&m, h, &input).map_err(fail)
            }
            Commit::Cmac => s.sign(&Mechanism::AesCMac, h, &input).map_err(fail),
            Commit::KcvEcb => s.encrypt(&Mechanism::AesEcb, h, &input).map_err(fail),
            Commit::KcvEcbDecrypt => s.decrypt(&Mechanism::AesEcb, h, &input).map_err(fail),
            Commit::Kw => {
                // The fixed key is public, so it is created extractable; the key under test only
                // has to allow CKA_WRAP.
                let fixed = s
                    .create_object(&[
                        Attribute::Token(false),
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::GENERIC_SECRET),
                        Attribute::Value(input),
                        Attribute::Sensitive(false),
                        Attribute::Extractable(true),
                    ])
                    .map_err(fail)?;
                let out = s.wrap_key(&Mechanism::AesKeyWrap, h, fixed).map_err(fail);
                let _ = s.destroy_object(fixed);
                out
            }
        }
    }

    /// Commit through a temporary session copy (PLAN.md, "Wrap-and-rebind"): generate a session
    /// wrapping key on the token, wrap, unwrap as a key of the same type that allows every
    /// operation `commits` need, commit, destroy.
    fn wrap_rebind(
        &self,
        target: ObjectHandle,
        object: &ObjectCfg,
        commits: &[Commit],
        commitment_label: &str,
    ) -> Result<Vec<(Commit, Vec<u8>)>> {
        let s = &self.session;
        let fail = |what: &'static str| move |e: CkError| KmError::Unsupported(format!("wrap-rebind {what}: {e}"));
        let kek = s
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Token(false),
                    Attribute::ValueLen(32.into()),
                    Attribute::Wrap(true),
                    Attribute::Unwrap(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                ],
            )
            .map_err(fail("generating session KEK"))?;
        let result = (|| {
            let wrap = if self.has(MechanismType::AES_KEY_WRAP_PAD) {
                Mechanism::AesKeyWrapPad
            } else {
                Mechanism::AesKeyWrap
            };
            let blob = s.wrap_key(&wrap, kek, target).map_err(fail("C_WrapKey"))?;
            let mut template = vec![
                Attribute::Token(false),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(key_type_of(object)?),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ];
            for c in commits {
                template.push(match c {
                    Commit::Hmac(_) | Commit::Cmac => Attribute::Sign(true),
                    Commit::KcvEcb => Attribute::Encrypt(true),
                    Commit::KcvEcbDecrypt => Attribute::Decrypt(true),
                    Commit::Kw => Attribute::Wrap(true),
                });
            }
            template.dedup();
            let copy = s
                .unwrap_key(&wrap, kek, &blob, &template)
                .map_err(fail("C_UnwrapKey"))?;
            let out = commits
                .iter()
                .map(|c| Ok((*c, self.commit(copy, object, *c, commitment_label)?)))
                .collect::<Result<Vec<_>>>();
            let _ = s.destroy_object(copy);
            out
        })();
        let _ = s.destroy_object(kek);
        result
    }

    /// RFC 7512 URI of the object consumers use: for a key adopted public-only this is still
    /// the private key (only its verification went through the public half).
    pub fn uri(&self, object: &ObjectCfg, loc: &Locator) -> Result<String> {
        // The serial tells apart tokens that share a label (RFC 7512 `serial`).
        let mut parts = vec![format!("token={}", pct(self.label.as_bytes()))];
        if !self.token.serial.is_empty() {
            parts.push(format!("serial={}", pct(self.token.serial.as_bytes())));
        }
        if let Some(l) = &loc.label {
            parts.push(format!("object={}", pct(l.as_bytes())));
        }
        if let Some(i) = &loc.id {
            parts.push(format!("id={}", pct_all(&hex_decode(i)?)));
        }
        let kind = match class_of(object)? {
            c if c == ObjectClass::PRIVATE_KEY => "private",
            c if c == ObjectClass::PUBLIC_KEY => "public",
            c if c == ObjectClass::CERTIFICATE => "cert",
            c if c == ObjectClass::DATA => "data",
            _ => "secret-key",
        };
        parts.push(format!("type={kind}"));
        // A pure locator: which module realised it is recorded separately (ModuleInfo).
        Ok(format!("pkcs11:{}", parts.join(";")))
    }
}

fn read_pin(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = &cfg.pin_env {
        return std::env::var(var)
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| KmError::Unavailable(format!("PIN env var {var} not set")));
    }
    if let Some(path) = &cfg.pin_file {
        return std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .map(|s| Some(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned())))
            .map_err(|e| KmError::Unavailable(format!("PIN file {}: {e}", path.display())));
    }
    Ok(None)
}

fn has_admin(cfg: &TokenCfg) -> bool {
    cfg.mgm_key_file.is_some() || cfg.mgm_key_env.is_some()
}

/// The admin credential (`mgmKeyEnv`, else `mgmKeyFile`), read only for an SO step. The format
/// is the module's: ykcs11 takes the PIV management key in hex, or the PIN on devices whose
/// management key is PIN-protected.
fn read_mgm(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = &cfg.mgm_key_env {
        return std::env::var(var)
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| KmError::Unavailable(format!("management-key env var {var} not set")));
    }
    if let Some(path) = &cfg.mgm_key_file {
        return std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .map(|s| Some(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned())))
            .map_err(|e| KmError::Unavailable(format!("management-key file {}: {e}", path.display())));
    }
    Ok(None)
}

pub fn class_of(object: &ObjectCfg) -> Result<ObjectClass> {
    match object.class.as_str() {
        "CKO_PRIVATE_KEY" => Ok(ObjectClass::PRIVATE_KEY),
        "CKO_SECRET_KEY" => Ok(ObjectClass::SECRET_KEY),
        "CKO_PUBLIC_KEY" => Ok(ObjectClass::PUBLIC_KEY),
        "CKO_CERTIFICATE" => Ok(ObjectClass::CERTIFICATE),
        "CKO_DATA" => Ok(ObjectClass::DATA),
        c => Err(KmError::Unsupported(format!(
            "object class {c} (supported: CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, \
             CKO_CERTIFICATE, CKO_DATA)"
        ))),
    }
}

/// Mechanism a commitment runs on the token.
pub fn commit_mechanism(c: Commit) -> MechanismType {
    match c {
        Commit::Hmac(HmacHash::Sha1) => MechanismType::SHA1_HMAC,
        Commit::Hmac(HmacHash::Sha224) => MechanismType::SHA224_HMAC,
        Commit::Hmac(HmacHash::Sha256) => MechanismType::SHA256_HMAC,
        Commit::Hmac(HmacHash::Sha384) => MechanismType::SHA384_HMAC,
        Commit::Hmac(HmacHash::Sha512) => MechanismType::SHA512_HMAC,
        Commit::Cmac => MechanismType::AES_CMAC,
        Commit::KcvEcb | Commit::KcvEcbDecrypt => MechanismType::AES_ECB,
        Commit::Kw => MechanismType::AES_KEY_WRAP,
    }
}

pub fn curve_of(object: &ObjectCfg) -> Result<Curve> {
    let name = object.curve.as_deref().ok_or_else(|| {
        KmError::Validation(format!("{} keys need a curve", object.key_type))
    })?;
    Curve::from_cfg(&object.key_type, name).ok_or_else(|| {
        if id::CURVES_WITHOUT_CRATE.contains(&name) {
            return KmError::Unsupported(format!(
                "curve {name:?}: no RustCrypto crate validates and encodes it yet"
            ));
        }
        KmError::Unsupported(format!(
            "curve {name:?} for {} (supported: secp256r1, secp384r1, secp521r1, secp256k1, \
             brainpoolP256r1, brainpoolP384r1 for CKK_EC; edwards25519, edwards448 for \
             CKK_EC_EDWARDS)",
            object.key_type
        ))
    })
}

pub fn key_type_of(object: &ObjectCfg) -> Result<KeyType> {
    match (object.class.as_str(), object.key_type.as_str()) {
        ("CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY", "CKK_EC") => curve_of(object).map(|_| KeyType::EC),
        ("CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY", "CKK_EC_EDWARDS") => {
            curve_of(object).map(|_| KeyType::EC_EDWARDS)
        }
        ("CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY", "CKK_RSA") => Ok(KeyType::RSA),
        ("CKO_SECRET_KEY", "CKK_GENERIC_SECRET") => Ok(KeyType::GENERIC_SECRET),
        ("CKO_SECRET_KEY", "CKK_AES") => Ok(KeyType::AES),
        ("CKO_SECRET_KEY", "CKK_SHA_1_HMAC") => Ok(KeyType::SHA_1_HMAC),
        ("CKO_SECRET_KEY", "CKK_SHA224_HMAC") => hmac_key_type(KeyType::SHA224_HMAC, 0x2e),
        ("CKO_SECRET_KEY", "CKK_SHA256_HMAC") => Ok(KeyType::SHA256_HMAC),
        ("CKO_SECRET_KEY", "CKK_SHA384_HMAC") => hmac_key_type(KeyType::SHA384_HMAC, 0x2c),
        ("CKO_SECRET_KEY", "CKK_SHA512_HMAC") => hmac_key_type(KeyType::SHA512_HMAC, 0x2d),
        (c, k) => Err(KmError::Unsupported(format!("{c}/{k}"))),
    }
}

/// cryptoki 0.12.1 (and main) gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC` (0x2b), so such
/// keys could be neither created nor told apart. The Nix build patches it
/// (nix/patches/cryptoki-hmac-key-types.patch); refuse rather than misidentify without the patch.
fn hmac_key_type(kt: KeyType, raw: std::os::raw::c_ulong) -> Result<KeyType> {
    if std::os::raw::c_ulong::from(kt) == raw {
        Ok(kt)
    } else {
        Err(KmError::Unsupported(format!(
            "{kt}: this build's cryptoki maps it to CKK_SHA256_HMAC; build with \
             nix/patches/cryptoki-hmac-key-types.patch applied"
        )))
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
        fn attr_bool(a: &Attribute) -> Option<bool> {
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

fn locator_attrs(loc: &Locator) -> Result<Vec<Attribute>> {
    let mut v = Vec::new();
    if let Some(l) = &loc.label {
        v.push(Attribute::Label(l.as_bytes().to_vec()));
    }
    if let Some(i) = &loc.id {
        v.push(Attribute::Id(hex_decode(i)?));
    }
    if v.is_empty() {
        return Err(KmError::Validation("locator needs CKA_LABEL and/or CKA_ID".into()));
    }
    Ok(v)
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    // ASCII only: byte slicing below would panic inside a multi-byte character.
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err(KmError::Validation(format!("CKA_ID '{s}' is not hex")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| KmError::Validation(format!("CKA_ID '{s}' is not hex")))
}

fn pct(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn pct_all(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("%{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers for the parts of each scheme's definition that live here: which HMAC hash a
    /// key type commits with, and which mechanism each commitment runs (docs/DESIGN.md §10).
    #[test]
    fn commitment_mechanisms_are_pinned() {
        for (key_type, hash, mech) in [
            ("CKK_GENERIC_SECRET", HmacHash::Sha256, MechanismType::SHA256_HMAC),
            ("CKK_SHA_1_HMAC", HmacHash::Sha1, MechanismType::SHA1_HMAC),
            ("CKK_SHA224_HMAC", HmacHash::Sha224, MechanismType::SHA224_HMAC),
            ("CKK_SHA256_HMAC", HmacHash::Sha256, MechanismType::SHA256_HMAC),
            ("CKK_SHA384_HMAC", HmacHash::Sha384, MechanismType::SHA384_HMAC),
            ("CKK_SHA512_HMAC", HmacHash::Sha512, MechanismType::SHA512_HMAC),
        ] {
            assert_eq!(HmacHash::for_key_type(key_type), Some(hash), "{key_type}");
            assert_eq!(commit_mechanism(Commit::Hmac(hash)), mech, "{key_type}");
        }
        assert_eq!(HmacHash::for_key_type("CKK_AES"), None);
        assert_eq!(commit_mechanism(Commit::Cmac), MechanismType::AES_CMAC);
        assert_eq!(commit_mechanism(Commit::KcvEcb), MechanismType::AES_ECB);
        assert_eq!(commit_mechanism(Commit::KcvEcbDecrypt), MechanismType::AES_ECB);
        assert_eq!(commit_mechanism(Commit::Kw), MechanismType::AES_KEY_WRAP);
    }

    /// Every boolean the core table names maps to a `cryptoki` attribute, and back.
    #[test]
    fn every_tabled_boolean_maps_to_cryptoki() {
        for class in ["CKO_PRIVATE_KEY", "CKO_PUBLIC_KEY", "CKO_SECRET_KEY", "CKO_CERTIFICATE", "CKO_DATA"] {
            for name in attrs::observed(class) {
                assert_eq!(bool_attr(name, true).as_ref().and_then(attr_bool), Some(true), "{name}");
            }
        }
        for name in ["CKA_SIGN_RECOVER", "CKA_VERIFY_RECOVER", "CKA_LOCAL", "CKA_NEVER_EXTRACTABLE", "CKA_ALWAYS_SENSITIVE"] {
            assert_eq!(bool_attr(name, false).as_ref().and_then(attr_bool), Some(false), "{name}");
        }
        assert!(bool_attr("CKA_ALLOWED_MECHANISMS", true).is_none());
    }

    #[test]
    fn hex_decode_rejects_non_hex_without_panicking() {
        assert_eq!(hex_decode("0aFF").unwrap(), [0x0a, 0xff]);
        for bad in ["0", "zz", "aéb", "éé", "0x12"] {
            assert!(matches!(hex_decode(bad), Err(KmError::Validation(_))), "{bad}");
        }
    }
}
