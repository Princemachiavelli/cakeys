//! PKCS#11 token layer over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.
//! Module-specific behaviour goes through the selected [`Provider`].

use crate::provider::{Provider, Registry};
pub use cakeys_core::config::{ModuleInfo, TokenInfo};
use cakeys_core::config::{Locator, Mode, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::id::{self, Commit, Curve, HmacHash};
use cakeys_core::pop;
use cakeys_core::{KmError, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct Token {
    pub name: String,
    pub label: String,
    pub module: ModuleInfo,
    pub token: TokenInfo,
    /// Usable mechanisms: advertised ones, filtered by the provider.
    pub mechanisms: Vec<MechanismType>,
    pub provider: Arc<dyn Provider>,
    session: Session,
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
        let session = ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?;
        if let Some(pin) = read_pin(cfg)? {
            match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
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
            provider,
            session,
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

    pub fn mechanism_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.mechanisms.iter().map(|m| m.to_string()).collect();
        v.sort();
        v
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
                "{n} objects match locator {loc:?} on token '{}'",
                self.name
            ))),
        }
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

    /// Every boolean policy attribute of the spec must match the live object.
    fn check_policy(&self, h: ObjectHandle, spec: &SpecCfg) -> Result<()> {
        for (name, want) in &spec.attributes {
            let (t, _) = bool_attr(name, *want)?;
            match self.attr(h, t)?.as_ref().and_then(attr_bool) {
                Some(have) if have == *want => {}
                have => {
                    return Err(KmError::Conflict(format!(
                        "{name} is {have:?} on token '{}', spec wants {want}",
                        self.name
                    )))
                }
            }
        }
        Ok(())
    }

    pub fn create(&self, object: &ObjectCfg, spec: &SpecCfg, loc: &Locator) -> Result<()> {
        let mut common = vec![Attribute::Token(true)];
        common.extend(locator_attrs(loc)?);
        let mut policy = Vec::new();
        for (name, v) in &spec.attributes {
            policy.push(bool_attr(name, *v)?.1);
        }
        let gen = |e: CkError| self.unsupported(format!("generating key on '{}': {e}", self.name));
        let class = class_of(object)?;
        if class != ObjectClass::PRIVATE_KEY && class != ObjectClass::SECRET_KEY {
            return Err(KmError::Validation(format!("{} objects are adopted, not created", object.class)));
        }
        match key_type_of(object)? {
            KeyType::RSA => {
                let bits = object.modulus_bits.ok_or_else(|| {
                    KmError::Validation("RSA keys need modulusBits".into())
                })?;
                let mut public = common.clone();
                public.extend([
                    Attribute::ModulusBits(bits.into()),
                    Attribute::PublicExponent(vec![1, 0, 1]),
                    Attribute::Verify(true),
                    Attribute::Private(false),
                ]);
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
                public.extend([
                    Attribute::EcParams(curve.params().to_vec()),
                    Attribute::Verify(true),
                    Attribute::Private(false),
                ]);
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
        let mut handles = self.find(class_of(object)?, loc)?;
        if class_of(object)? == ObjectClass::PRIVATE_KEY {
            handles.extend(self.find(ObjectClass::PUBLIC_KEY, loc)?);
        }
        for h in &handles {
            self.session
                .destroy_object(*h)
                .map_err(ck("C_DestroyObject"))?;
        }
        Ok(handles.len())
    }

    /// Compute the material CA-IDs of the object using `mode`; secret keys use `commits`. With
    /// `prove`, `h` is a private key whose possession is proven against the public key hashed.
    #[allow(clippy::too_many_arguments)] // two callers (resolve, delete), each passing all of them
    pub fn ids(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        loc: &Locator,
        mode: Mode,
        commits: &[Commit],
        commitment_label: &str,
        prove: bool,
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
                if prove {
                    self.prove_possession(h, object, &spki)?;
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
    fn spki(&self, h: ObjectHandle, loc: &Locator) -> Result<Vec<u8>> {
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


    /// Proof of possession (`cakeys_core::pop`): sign a fresh challenge with the private key `h`
    /// and verify it on the host against `spki`, the public key its identity hashes. A signature
    /// that does not verify is a `Conflict`; a token that cannot sign is `Unsupported` or
    /// `Unavailable`, never a pass.
    fn prove_possession(&self, h: ObjectHandle, object: &ObjectCfg, spki: &[u8]) -> Result<()> {
        // A context-specific login per signature (PIV signing slot) would spend PIN retries.
        if let Some(Attribute::AlwaysAuthenticate(true)) = self.attr(h, AttributeType::AlwaysAuthenticate)? {
            return Err(KmError::Unavailable(format!(
                "the private key on token '{}' is CKA_ALWAYS_AUTHENTICATE; proving possession would need a \
                 PIN entry per run; adopt it publicOnly, or opt in with binding = \"token-asserted\"",
                self.name
            )));
        }
        let msg = pop::challenge(spki)?;
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
                    (hashed.0, msg.clone())
                } else {
                    (Mechanism::Ecdsa, hash.digest(&msg))
                }
            }
            KeyType::EC_EDWARDS => (Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)), msg.clone()),
            KeyType::RSA => (Mechanism::Sha256RsaPkcs, msg.clone()),
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
        pop::verify(spki, &msg, &sig)
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
        let mut parts = vec![format!("token={}", pct(self.label.as_bytes()))];
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

fn read_pin(cfg: &TokenCfg) -> Result<Option<String>> {
    if let Some(var) = &cfg.pin_env {
        return std::env::var(var)
            .map(Some)
            .map_err(|_| KmError::Unavailable(format!("PIN env var {var} not set")));
    }
    if let Some(path) = &cfg.pin_file {
        return std::fs::read_to_string(path)
            .map(|s| Some(s.trim_end_matches(['\n', '\r']).to_owned()))
            .map_err(|e| KmError::Unavailable(format!("PIN file {}: {e}", path.display())));
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

/// Boolean policy attributes the spec may set.
pub fn bool_attr(name: &str, v: bool) -> Result<(AttributeType, Attribute)> {
    let a = match name {
        "CKA_SIGN" => Attribute::Sign(v),
        "CKA_VERIFY" => Attribute::Verify(v),
        "CKA_ENCRYPT" => Attribute::Encrypt(v),
        "CKA_DECRYPT" => Attribute::Decrypt(v),
        "CKA_WRAP" => Attribute::Wrap(v),
        "CKA_UNWRAP" => Attribute::Unwrap(v),
        "CKA_DERIVE" => Attribute::Derive(v),
        "CKA_SENSITIVE" => Attribute::Sensitive(v),
        "CKA_EXTRACTABLE" => Attribute::Extractable(v),
        "CKA_MODIFIABLE" => Attribute::Modifiable(v),
        "CKA_PRIVATE" => Attribute::Private(v),
        n => return Err(KmError::Validation(format!("unsupported policy attribute {n}"))),
    };
    Ok((a.attribute_type(), a))
}

fn attr_bool(a: &Attribute) -> Option<bool> {
    match a {
        Attribute::Sign(b)
        | Attribute::Verify(b)
        | Attribute::Encrypt(b)
        | Attribute::Decrypt(b)
        | Attribute::Wrap(b)
        | Attribute::Unwrap(b)
        | Attribute::Derive(b)
        | Attribute::Sensitive(b)
        | Attribute::Extractable(b)
        | Attribute::Modifiable(b)
        | Attribute::Private(b) => Some(*b),
        _ => None,
    }
}

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

    #[test]
    fn hex_decode_rejects_non_hex_without_panicking() {
        assert_eq!(hex_decode("0aFF").unwrap(), [0x0a, 0xff]);
        for bad in ["0", "zz", "aéb", "éé", "0x12"] {
            assert!(matches!(hex_decode(bad), Err(KmError::Validation(_))), "{bad}");
        }
    }
}
