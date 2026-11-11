//! PKCS#11 backend over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.

use crate::config::{Locator, Mode, ObjectCfg, SpecCfg, TokenCfg};
use crate::error::{KmError, Result};
use crate::id;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::collections::BTreeMap;

pub struct Token {
    pub name: String,
    pub label: String,
    pub module: String,
    pub mechanisms: Vec<MechanismType>,
    session: Session,
}

fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}"))
}

impl Token {
    pub fn open(name: &str, cfg: &TokenCfg, module_override: Option<&str>) -> Result<Token> {
        let module = module_override
            .map(str::to_owned)
            .or_else(|| cfg.module.clone())
            .ok_or_else(|| KmError::Validation(format!("token '{name}' has no module")))?;
        let ctx = Pkcs11::new(&module).map_err(ck(&format!("loading {module}")))?;
        ctx.initialize(CInitializeArgs::OsThreads).map_err(ck("C_Initialize"))?;
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
                slot = Some(s);
            }
        }
        let slot = slot.ok_or_else(|| {
            KmError::Unavailable(format!("token '{}' not present in {module}", cfg.token_label))
        })?;
        let mechanisms = ctx.get_mechanism_list(slot).map_err(ck("C_GetMechanismList"))?;
        let session = ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?;
        if let Some(pin) = read_pin(cfg)? {
            match session.login(UserType::User, Some(&AuthPin::new(pin))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(KmError::Unavailable(format!("C_Login: {e}"))),
            }
        }
        Ok(Token {
            name: name.to_owned(),
            label: cfg.token_label.clone(),
            module,
            mechanisms,
            session,
        })
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
        if class_of(object)? == ObjectClass::CERTIFICATE {
            return match self.attr(h, AttributeType::CertificateType)? {
                Some(Attribute::CertificateType(CertificateType::X_509)) => Ok(()),
                other => Err(KmError::Conflict(format!("CKA_CERTIFICATE_TYPE is {other:?}, not CKC_X_509"))),
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
        if kt == KeyType::EC {
            match self.attr(h, AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) if p == id::SECP256R1_PARAMS => {}
                other => {
                    return Err(KmError::Conflict(format!("CKA_EC_PARAMS mismatch: {other:?}")))
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
        let gen = |e: CkError| KmError::Unsupported(format!("generating key on '{}': {e}", self.name));
        if class_of(object)? == ObjectClass::CERTIFICATE {
            return Err(KmError::Validation("certificates are adopted, not created".into()));
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
            KeyType::EC => {
                let mut public = common.clone();
                public.extend([
                    Attribute::EcParams(id::SECP256R1_PARAMS.to_vec()),
                    Attribute::Verify(true),
                    Attribute::Private(false),
                ]);
                let mut private = common;
                private.extend(policy);
                self.session
                    .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
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

    /// Compute the material CA-IDs of the object using `mode`.
    pub fn ids(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        loc: &Locator,
        mode: Mode,
    ) -> Result<BTreeMap<String, String>> {
        let mut ids = BTreeMap::new();
        match mode {
            Mode::Direct if class_of(object)? == ObjectClass::CERTIFICATE => {
                let der = match self.attr(h, AttributeType::Value)? {
                    Some(Attribute::Value(v)) => v,
                    _ => return Err(KmError::Unsupported("certificate has no readable CKA_VALUE".into())),
                };
                ids.insert("certhash".into(), id::sri(&der));
                ids.insert("pubkeyhash".into(), id::sri(&id::cert_spki(&der)?));
            }
            Mode::Direct => {
                ids.insert("pubkeyhash".into(), id::sri(&self.spki(h, loc)?));
            }
            Mode::Commitment => {
                let mac = self
                    .session
                    .sign(&Mechanism::Sha256Hmac, h, &id::commitment_label(object))
                    .map_err(|e| KmError::Unsupported(format!("CKM_SHA256_HMAC: {e}")))?;
                ids.insert("commitment".into(), id::sri(&mac));
            }
            Mode::WrapRebind => {
                ids.insert("commitment".into(), id::sri(&self.wrap_rebind(h, object)?));
            }
            m => {
                return Err(KmError::Unsupported(format!(
                    "identity mode '{m}' is not implemented in this POC"
                )))
            }
        }
        Ok(ids)
    }

    /// SPKI of a key: from the object itself (`CKA_PUBLIC_KEY_INFO`, RSA modulus/exponent,
    /// EC point), else from the single public key object under the same locator.
    fn spki(&self, h: ObjectHandle, loc: &Locator) -> Result<Vec<u8>> {
        if let Ok(spki) = self.public_spki(h) {
            return Ok(spki);
        }
        let public = self.find(ObjectClass::PUBLIC_KEY, loc)?;
        match public.as_slice() {
            [p] => self.public_spki(*p),
            [] => Err(KmError::NotFound("no public key object under the locator".into())),
            _ => Err(KmError::Ambiguous("several public key objects share the locator".into())),
        }
    }

    fn public_spki(&self, h: ObjectHandle) -> Result<Vec<u8>> {
        // Optional shortcut. Some providers (ykcs11) report it with length 0 and then reject the
        // fetch with CKR_ARGUMENTS_BAD, so any error here just means "absent".
        if let Ok(Some(Attribute::PublicKeyInfo(der))) = self.attr(h, AttributeType::PublicKeyInfo) {
            if !der.is_empty() {
                return id::spki_canonical(&der);
            }
        }
        match self.attr(h, AttributeType::KeyType)? {
            Some(Attribute::KeyType(KeyType::EC)) => match self.attr(h, AttributeType::EcPoint)? {
                Some(Attribute::EcPoint(p)) => id::p256_spki_from_ec_point(&p),
                _ => Err(KmError::NotFound("no CKA_EC_POINT on this object".into())),
            },
            Some(Attribute::KeyType(KeyType::RSA)) => {
                let a = self
                    .session
                    .get_attributes(h, &[AttributeType::Modulus, AttributeType::PublicExponent])
                    .map_err(ck("C_GetAttributeValue"))?;
                match a.as_slice() {
                    [Attribute::Modulus(n), Attribute::PublicExponent(e)] => id::rsa_spki(n, e),
                    _ => Err(KmError::NotFound("no CKA_MODULUS/CKA_PUBLIC_EXPONENT".into())),
                }
            }
            kt => Err(KmError::Unsupported(format!("public key of type {kt:?}"))),
        }
    }

    /// Commit through a temporary session copy (PLAN.md, "Wrap-and-rebind"): generate a session
    /// wrapping key on the token, wrap, unwrap as a sign-capable generic secret, HMAC, destroy.
    fn wrap_rebind(&self, target: ObjectHandle, object: &ObjectCfg) -> Result<Vec<u8>> {
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
            let copy = s
                .unwrap_key(
                    &wrap,
                    kek,
                    &blob,
                    &[
                        Attribute::Token(false),
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::GENERIC_SECRET),
                        Attribute::Sign(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                    ],
                )
                .map_err(fail("C_UnwrapKey"))?;
            let mac = s
                .sign(&Mechanism::Sha256Hmac, copy, &id::commitment_label(object))
                .map_err(fail("CKM_SHA256_HMAC"));
            let _ = s.destroy_object(copy);
            mac
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
            c if c == ObjectClass::CERTIFICATE => "cert",
            _ => "secret-key",
        };
        parts.push(format!("type={kind}"));
        Ok(format!(
            "pkcs11:{}?module-path={}",
            parts.join(";"),
            pct(self.module.as_bytes())
        ))
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
        "CKO_CERTIFICATE" => Ok(ObjectClass::CERTIFICATE),
        c => Err(KmError::Unsupported(format!(
            "object class {c} (POC supports CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_CERTIFICATE)"
        ))),
    }
}

pub fn key_type_of(object: &ObjectCfg) -> Result<KeyType> {
    match (object.class.as_str(), object.key_type.as_str()) {
        ("CKO_PRIVATE_KEY", "CKK_EC") => match object.curve.as_deref() {
            Some("secp256r1" | "prime256v1" | "P-256") => Ok(KeyType::EC),
            c => Err(KmError::Unsupported(format!("curve {c:?} (POC supports secp256r1)"))),
        },
        ("CKO_PRIVATE_KEY", "CKK_RSA") => Ok(KeyType::RSA),
        ("CKO_SECRET_KEY", "CKK_GENERIC_SECRET") => Ok(KeyType::GENERIC_SECRET),
        ("CKO_SECRET_KEY", "CKK_AES") => Ok(KeyType::AES),
        (c, k) => Err(KmError::Unsupported(format!("{c}/{k}"))),
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
    if !s.len().is_multiple_of(2) {
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
