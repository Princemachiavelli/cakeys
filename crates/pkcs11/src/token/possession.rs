//! Proof of possession on the token (`cakeys_core::pop`, docs/DESIGN.md §3.6): sign, derive or decrypt a fresh challenge the host checks.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use cakeys_core::pop;

impl Token {
    /// The binding the private key `h` is proven and recorded with, from the `planned` one
    /// (`cakeys_core::plan::binding`): `pop-sign` becomes `pop-sign-pin` when the token reports
    /// the key `CKA_ALWAYS_AUTHENTICATE` — the observed attribute, declared or not
    /// (docs/DESIGN.md §3.6).
    ///
    /// # Errors
    ///
    /// `Unavailable` for `pop-ecdh`/`pop-decrypt`/`pop-unwrap` on a `CKA_ALWAYS_AUTHENTICATE` key: only the
    /// sign path does the per-use login.
    pub fn recorded_binding(&self, h: ObjectHandle, planned: Option<Binding>) -> Result<Option<Binding>> {
        let Some(b) = planned.filter(|b| b != &Binding::TokenAsserted) else { return Ok(planned) };
        let always =
            matches!(self.attr(h, AttributeType::AlwaysAuthenticate)?, Some(Attribute::AlwaysAuthenticate(true)));
        Ok(Some(match b {
            _ if !always => b,
            Binding::PopSign | Binding::PopSignPin => Binding::PopSignPin,
            _ => {
                return Err(KmError::Unavailable(format!(
                    "the private key on token '{}' is CKA_ALWAYS_AUTHENTICATE; only binding = \"pop-sign\" \
                     proves possession with its per-use PIN; adopt it publicOnly, or opt in with binding = \
                     \"token-asserted\"",
                    self.name
                )));
            }
        }))
    }

    /// Proof of possession (`cakeys_core::pop`, docs/DESIGN.md §3.6), by the [recorded
    /// binding](Self::recorded_binding): the private key `h` proves, by whichever capability it
    /// has, that it holds the private half of `spki`, the public key its identity hashes. A proof
    /// that does not verify is a `Conflict`; a token that cannot prove is `Unsupported` or
    /// `Unavailable`, never a pass. `token-asserted` proves nothing.
    pub(super) fn prove_binding(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        spki: &[u8],
        binding: Binding,
    ) -> Result<()> {
        self.check_proof(object, binding)?;
        let msg = pop::challenge(spki)?;
        match binding {
            Binding::PopSign => self.prove_sign(h, object, spki, &msg, false),
            Binding::PopSignPin => self.prove_sign(h, object, spki, &msg, true),
            Binding::PopEcdh => self.prove_ecdh(h, spki, &msg),
            Binding::PopDecrypt => self.prove_decrypt(h, spki, &msg),
            Binding::PopUnwrap => self.prove_unwrap(h, spki, &msg),
            Binding::TokenAsserted => Ok(()),
        }
    }

    /// `pop-sign`: the token signs the challenge; the host verifies the signature. With
    /// `per_use_pin` (`pop-sign-pin`), the signature is authorized by a context-specific login.
    fn prove_sign(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        spki: &[u8],
        msg: &[u8],
        per_use_pin: bool,
    ) -> Result<()> {
        let (mech, data) = match key_type_of(object)? {
            KeyType::EC => {
                let hash = ecdsa_hash(object)?;
                let hashed = match hash {
                    pop::EcdsaHash::Sha256 => Mechanism::EcdsaSha256,
                    pop::EcdsaHash::Sha384 => Mechanism::EcdsaSha384,
                    pop::EcdsaHash::Sha512 => Mechanism::EcdsaSha512,
                };
                if self.has(hashed.mechanism_type()) {
                    (hashed, msg.to_vec())
                } else {
                    (Mechanism::Ecdsa, hash.digest(msg))
                }
            }
            KeyType::EC_EDWARDS => {
                (self.runnable(Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))), msg.to_vec())
            }
            KeyType::RSA => (Mechanism::Sha256RsaPkcs, msg.to_vec()),
            kt => return Err(KmError::Unsupported(format!("proof of possession for {kt}"))),
        };
        let refused = self.proof_failed("C_Sign", "sign", "CKA_SIGN");
        let sig = if per_use_pin {
            self.sign_with_pin(&mech, h, &data, refused)?
        } else {
            self.session.sign(&mech, h, &data).map_err(refused)?
        };
        pop::verify(spki, msg, &sig)
    }

    /// Sign under a `CKA_ALWAYS_AUTHENTICATE` key's per-use policy: `C_SignInit`, then the
    /// context-specific login, then a single-part `C_Sign` (PKCS#11 3.2 §5.1), which every
    /// signing mechanism offers. The login happens exactly once, never retried: the PIN is the one
    /// that opened the session, so it cannot be wrong and a successful login spends no retry; a
    /// failure (another actor locked the PIN meanwhile) is `Unavailable`. The sign after
    /// `C_SignInit` is the patched cryptoki's (`sign-after-init`); without it, [`proof_refusal`]
    /// refuses the proof before it gets here.
    #[cfg(feature = "sign-after-init")]
    fn sign_with_pin(
        &self,
        mech: &Mechanism,
        h: ObjectHandle,
        data: &[u8],
        refused: impl Fn(CkError) -> KmError,
    ) -> Result<Vec<u8>> {
        let pin = self.pin.as_deref().ok_or_else(|| {
            KmError::Unavailable(format!(
                "token '{}': the private key is CKA_ALWAYS_AUTHENTICATE and needs the user PIN per use; \
                 configure pinFile or pinEnv",
                self.name
            ))
        })?;
        self.session.sign_init(mech, h).map_err(&refused)?;
        if let Err(e) = self.session.login(UserType::ContextSpecific, Some(&AuthPin::new(pin.to_owned().into()))) {
            // C_SignFinal always ends the operation: the session stays usable for the next proof.
            let _ = self.session.sign_final();
            return Err(KmError::Unavailable(format!(
                "C_Login(CKU_CONTEXT_SPECIFIC) for the CKA_ALWAYS_AUTHENTICATE key on token '{}': {e}; \
                 not retried",
                self.name
            )));
        }
        self.session.sign_initialized(data).map_err(refused)
    }

    /// Without the patched cryptoki there is no sign after the login: [`proof_refusal`] refuses
    /// a `pop-sign-pin` proof before it signs.
    #[cfg(not(feature = "sign-after-init"))]
    #[expect(clippy::unused_self, reason = "the signature of the patched build's per-use sign")]
    fn sign_with_pin(
        &self,
        _: &Mechanism,
        _: ObjectHandle,
        _: &[u8],
        _: impl Fn(CkError) -> KmError,
    ) -> Result<Vec<u8>> {
        Err(KmError::Unsupported(NO_SIGN_AFTER_INIT.into()))
    }

    /// `pop-ecdh`: the host holds an ephemeral key and the MAC of the challenge under the shared
    /// secret; the token derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable
    /// session key and MACs the challenge with it. The MACs agree only if the token's private key
    /// is the one `spki` names. A token without HMAC, or whose profile says it derives only into
    /// an extractable secret (`derive.sealed = false`: ykcs11 \[src\]), proves by
    /// [`Self::prove_ecdh_extractable`] instead.
    fn prove_ecdh(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        let ch = pop::ecdh_challenge(spki, msg)?;
        let sealed = self.profiles.module.as_ref().and_then(|p| p.derive.sealed) != Some(false);
        if !sealed || !self.has(MechanismType::SHA256_HMAC) {
            return self.prove_ecdh_extractable(h, spki, &ch);
        }
        let (derived, rw) = self.derive_for_proof(
            h,
            &ch.peer,
            &[
                Attribute::Token(false),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
            ],
            ch.secret.len(),
        )?;
        let session = rw.as_ref().unwrap_or(&self.session);
        // A session object: dropped with the session even if destroying it fails here.
        let tag = session
            .sign(&Mechanism::Sha256Hmac, derived, msg)
            .inspect_err(|_| {
                let _ = session.destroy_object(derived);
            })
            .map_err(|e| {
                KmError::Unavailable(format!("C_Sign (ECDH proof of possession) on token '{}': {e}", self.name))
            })?;
        let _ = session.destroy_object(derived);
        if !pop::ct_eq(&ch.mac, &tag) {
            return Err(KmError::Conflict(format!(
                "proof of possession failed: the private key did not derive for the public key {}",
                id::sri(spki)
            )));
        }
        Ok(())
    }

    /// `pop-ecdh` on a token that derives only into an extractable secret: the token derives
    /// into a session object, the host reads its `CKA_VALUE` and compares it with the shared
    /// secret it computed itself. The secret belongs to a single-use ephemeral key the host
    /// generated, so reading it reveals nothing the host did not already hold.
    fn prove_ecdh_extractable(&self, h: ObjectHandle, spki: &[u8], ch: &pop::EcdhChallenge) -> Result<()> {
        let (derived, rw) = self.derive_for_proof(
            h,
            &ch.peer,
            &[
                Attribute::Token(false),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
            ],
            ch.secret.len(),
        )?;
        let session = rw.as_ref().unwrap_or(&self.session);
        let value = session.get_attributes(derived, &[AttributeType::Value]);
        // A session object: dropped with the session even if destroying it fails here.
        let _ = session.destroy_object(derived);
        let value = match value.map(|v| v.into_iter().next()) {
            Ok(Some(Attribute::Value(v))) => v,
            Ok(_) => {
                return Err(KmError::Unavailable(format!(
                    "token '{}': the derived secret has no CKA_VALUE",
                    self.name
                )));
            }
            Err(e) => {
                return Err(KmError::Unavailable(format!(
                    "C_GetAttributeValue (ECDH proof of possession) on token '{}': {e}",
                    self.name
                )));
            }
        };
        if !pop::ct_eq(&ch.secret, &value) {
            return Err(KmError::Conflict(format!(
                "proof of possession failed: the private key did not derive for the public key {}",
                id::sri(spki)
            )));
        }
        Ok(())
    }

    /// `C_DeriveKey` for a proof, against the ephemeral `peer`: in the verb's session, else —
    /// refused there as read-only (tpm2-pkcs11 keeps derived secrets as store rows, so it
    /// derives only in a read-write session, `derive.read-only = false` \[run\]) — in a read-write
    /// session opened for it, returned so the secret is used and destroyed where it lives.
    fn derive_for_proof(
        &self,
        h: ObjectHandle,
        peer: &[u8],
        template: &[Attribute],
        len: usize,
    ) -> Result<(ObjectHandle, Option<Session>)> {
        let mech = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        let failed = self.proof_failed("C_DeriveKey", "derive", "CKA_DERIVE");
        // A module refusing the template's own policy defaults derives without them
        // (`derive_any`): the proof needs only the shared secret.
        match derive_any(&self.session, &mech, h, template, len) {
            Ok((derived, ..)) => Ok((derived, None)),
            Err(CkError::Pkcs11(RvError::SessionReadOnly, _)) => {
                let rw = self.extra_session(Access::Write)?;
                let (derived, ..) = derive_any(&rw, &mech, h, template, len).map_err(failed)?;
                Ok((derived, Some(rw)))
            }
            Err(e) => Err(failed(e)),
        }
    }

    /// `pop-decrypt`: the host encrypts the challenge to the public key with RSA-OAEP; the token
    /// decrypts it with the private key. The plaintext matches only if the token's private key is
    /// the one `spki` names.
    fn prove_decrypt(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        let cipher = pop::oaep_challenge(spki, msg)?;
        let plain = self
            .session
            .decrypt(
                &Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                    MechanismType::SHA1,
                    PkcsMgfType::MGF1_SHA1,
                    PkcsOaepSource::empty(),
                )),
                h,
                &cipher,
            )
            .map_err(self.proof_failed("C_Decrypt", "decrypt", "CKA_DECRYPT"))?;
        if !pop::ct_eq(msg, &plain) {
            return Err(KmError::Conflict(format!(
                "proof of possession failed: the private key did not decrypt for the public key {}",
                id::sri(spki)
            )));
        }
        Ok(())
    }

    /// `pop-unwrap`: the host wraps a fresh secret to the public key with RSA-OAEP; the token
    /// unwraps it into a non-extractable session key and MACs the challenge with it. The MACs
    /// agree only if the token's private key is the one `spki` names; no plaintext leaves the
    /// token, so a transport key proves possession without `CKA_DECRYPT`.
    fn prove_unwrap(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        let ch = pop::unwrap_challenge(spki, msg)?;
        let mech = Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
            MechanismType::SHA1,
            PkcsMgfType::MGF1_SHA1,
            PkcsOaepSource::empty(),
        ));
        let template = [
            Attribute::Token(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
        ];
        let failed = self.proof_failed("C_UnwrapKey", "unwrap", "CKA_UNWRAP");
        // Like a derive: a module that keeps session keys as store rows unwraps only read-write.
        let (key, rw) = match self.session.unwrap_key(&mech, h, &ch.wrapped, &template) {
            Ok(k) => (k, None),
            Err(CkError::Pkcs11(RvError::SessionReadOnly, _)) => {
                let rw = self.extra_session(Access::Write)?;
                let k = rw.unwrap_key(&mech, h, &ch.wrapped, &template).map_err(failed)?;
                (k, Some(rw))
            }
            Err(e) => return Err(failed(e)),
        };
        let session = rw.as_ref().unwrap_or(&self.session);
        // A session object: dropped with the session even if destroying it fails here.
        let tag = session.sign(&Mechanism::Sha256Hmac, key, msg);
        let _ = session.destroy_object(key);
        let tag = tag.map_err(|e| {
            KmError::Unavailable(format!("C_Sign (unwrap proof of possession) on token '{}': {e}", self.name))
        })?;
        if !pop::ct_eq(&ch.mac, &tag) {
            return Err(KmError::Conflict(format!(
                "proof of possession failed: the private key did not unwrap for the public key {}",
                id::sri(spki)
            )));
        }
        Ok(())
    }

    /// What this token offers a proof of possession ([`proof_refusal`]): its usable mechanisms,
    /// and whether it unwraps at all (its profile's `[migration] unwraps`).
    pub fn proof_side(&self) -> ProofSide<'_> {
        let profile = self.profiles.module.as_ref();
        ProofSide {
            token: &self.name,
            profile: profile.map(|p| p.profile.as_str()),
            has: Box::new(|m| self.has(m)),
            unwraps: profile.and_then(|p| p.migration.as_ref()).and_then(|m| m.unwraps) != Some(false),
        }
    }

    /// Whether this token can give a proof of possession by `binding` of a private key of
    /// `object` ([`proof_refusal`]), checked before anything is generated or proven.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15), with the provider's hint, when it cannot; `Unsupported` for a key type
    /// no proof is defined for.
    pub fn check_proof(&self, object: &ObjectCfg, binding: Binding) -> Result<()> {
        match proof_refusal(object, binding, &self.proof_side())? {
            Some(why) => Err(self.unsupported(why)),
            None => Ok(()),
        }
    }

    /// How a proof's `call` failing maps: a key the token will not `op` with is `Unsupported` (the
    /// spec needs `attr`, or the opt-out); a challenge the token finds invalid was made for another
    /// key than the one it holds, a `Conflict` (the host encrypted or wrapped it to the public key
    /// the identity names); any other failure is `Unavailable`.
    fn proof_failed(&self, call: &'static str, op: &'static str, attr: &'static str) -> impl Fn(CkError) -> KmError {
        move |e| match e {
            CkError::Pkcs11(
                RvError::KeyFunctionNotPermitted
                | RvError::MechanismInvalid
                | RvError::KeyTypeInconsistent
                | RvError::FunctionNotSupported,
                _,
            ) => self.unsupported(format!(
                "token '{}' refused to {op} with the private key ({e}); proving possession needs {attr}, or opt \
                 in with binding = \"token-asserted\"",
                self.name
            )),
            CkError::Pkcs11(
                RvError::EncryptedDataInvalid
                | RvError::EncryptedDataLenRange
                | RvError::WrappedKeyInvalid
                | RvError::WrappedKeyLenRange,
                _,
            ) => KmError::Conflict(format!(
                "proof of possession failed: the private key on token '{}' did not {op} what was made for its \
                 public key ({call}: {e})",
                self.name
            )),
            e => KmError::Unavailable(format!("{call} (proof of possession) on token '{}': {e}", self.name)),
        }
    }
}

/// What a token offers a proof of possession, as a live token ([`Token::proof_side`]) or as
/// camigrate's plan knows a target from its profile: the one input [`proof_refusal`] takes.
pub struct ProofSide<'a> {
    pub token: &'a str,
    /// The module profile, named in a refusal.
    pub profile: Option<&'a str>,
    /// Whether the token offers a mechanism.
    pub has: Box<dyn Fn(MechanismType) -> bool + 'a>,
    /// Whether the module unwraps at all.
    pub unwraps: bool,
}

/// The refusal of a per-use PIN proof in a build without the patched cryptoki.
#[cfg(not(feature = "sign-after-init"))]
const NO_SIGN_AFTER_INIT: &str = "this build's cryptoki has no sign after C_SignInit, where the per-use login of a \
     CKA_ALWAYS_AUTHENTICATE key goes (nix/patches/cryptoki-sign-after-init.patch, the Nix build's), so the key \
     cannot prove possession; build with it, or opt in with binding = \"token-asserted\"";

/// Why a proof of possession by `binding` of a private key of `object` cannot run on `side`:
/// `None` when it can. The one check the proof itself (`Token::prove_binding`), `cakeys`
/// before it creates a key, and camigrate's plan for a move's target all make, so none promises
/// a proof another then refuses.
///
/// # Errors
///
/// `Unsupported` for a key type or curve no proof is defined for.
pub fn proof_refusal(object: &ObjectCfg, binding: Binding, side: &ProofSide<'_>) -> Result<Option<String>> {
    #[cfg(not(feature = "sign-after-init"))]
    if binding == Binding::PopSignPin {
        return Ok(Some(NO_SIGN_AFTER_INIT.into()));
    }
    if binding == Binding::PopUnwrap && !side.unwraps {
        return Ok(Some(format!(
            "token '{}' never unwraps (C_UnwrapKey{}), so binding = \"pop-unwrap\" cannot prove \
             possession there: use pop-decrypt or pop-sign, or opt in with binding = \"token-asserted\"",
            side.token,
            side.profile.map_or(String::new(), |p| format!("; profile {p}"))
        )));
    }
    Ok(proof_mechanisms(object, binding)?.into_iter().find(|g| !g.iter().any(|m| (side.has)(*m))).map(|group| {
        format!(
            "token '{}' lacks {} to prove possession of the private key; opt in with binding = \"token-asserted\"",
            side.token,
            group.iter().map(ToString::to_string).collect::<Vec<_>>().join(" or ")
        )
    }))
}

/// The hash ECDSA signs a proof with on `object`'s curve.
fn ecdsa_hash(object: &ObjectCfg) -> Result<pop::EcdsaHash> {
    pop::EcdsaHash::for_curve(curve_of(object)?)
        .ok_or_else(|| KmError::Unsupported(format!("ECDSA on {}", object.curve.as_deref().unwrap_or("?"))))
}

/// The mechanisms a proof of possession by `binding` uses on a private key of `object`'s type:
/// the token must offer at least one of each group. The one list both the proof itself
/// ([`Token::prove_binding`]) and camigrate's planner check, so a plan never promises a proof the
/// target then refuses. An ECDSA proof prefers the curve's hashed mechanism and falls back to
/// raw `CKM_ECDSA` over a host-side digest.
///
/// # Errors
///
/// `Unsupported` for a key type or curve no proof is defined for.
fn proof_mechanisms(object: &ObjectCfg, binding: Binding) -> Result<Vec<Vec<MechanismType>>> {
    Ok(match binding {
        Binding::TokenAsserted => vec![],
        Binding::PopSign | Binding::PopSignPin => match key_type_of(object)? {
            KeyType::EC => {
                let hashed = match ecdsa_hash(object)? {
                    pop::EcdsaHash::Sha256 => MechanismType::ECDSA_SHA256,
                    pop::EcdsaHash::Sha384 => MechanismType::ECDSA_SHA384,
                    pop::EcdsaHash::Sha512 => MechanismType::ECDSA_SHA512,
                };
                vec![vec![hashed, MechanismType::ECDSA]]
            }
            KeyType::EC_EDWARDS => vec![vec![MechanismType::EDDSA]],
            KeyType::RSA => vec![vec![MechanismType::SHA256_RSA_PKCS]],
            kt => return Err(KmError::Unsupported(format!("proof of possession for {kt}"))),
        },
        Binding::PopEcdh => vec![vec![MechanismType::ECDH1_DERIVE]],
        Binding::PopDecrypt => vec![vec![MechanismType::RSA_PKCS_OAEP]],
        Binding::PopUnwrap => vec![vec![MechanismType::RSA_PKCS_OAEP], vec![MechanismType::SHA256_HMAC]],
    })
}

/// A refusal of the template, not of the operation: what dropping one of a template's own
/// policy defaults may cure ([`is_policy_default`]).
#[must_use]
pub fn template_refusal(e: &CkError) -> bool {
    matches!(
        e,
        CkError::Pkcs11(
            RvError::AttributeValueInvalid
                | RvError::AttributeTypeInvalid
                | RvError::TemplateInconsistent
                | RvError::TemplateIncomplete,
            _
        )
    )
}

/// The attributes a template carries as policy defaults, which a module may refuse and still
/// make the object: never what defines the object (class, key type, curve, size) or what it is
/// then used for (`CKA_SIGN`, `CKA_DERIVE`, ...).
#[must_use]
pub fn is_policy_default(a: &Attribute) -> bool {
    matches!(a, Attribute::Private(_) | Attribute::Sensitive(_) | Attribute::Extractable(_))
}

/// `CKA_PRIVATE = false`, for notes.
#[must_use]
pub fn show(a: &Attribute) -> String {
    match a {
        Attribute::Private(b) | Attribute::Sensitive(b) | Attribute::Extractable(b) => {
            format!("{} = {b}", a.attribute_type())
        }
        other => other.attribute_type().to_string(),
    }
}

/// What [`derive_any`] derived: the handle, the template that took, and, when that is not the
/// one asked, what was changed and the refusal of the one asked.
pub type Derived = (ObjectHandle, Vec<Attribute>, Option<(String, CkError)>);

/// `C_DeriveKey` with `template` as asked; on a template refusal only, once more with
/// `CKA_VALUE_LEN` of the secret's `len` and without one policy default at a time (AWS
/// `CloudHSM` refuses `CKA_EXTRACTABLE = false` on a derived secret \[run\]). The derived handle,
/// the template that took, and, when that is not the one asked, what was changed and the refusal
/// of the one asked; that first refusal is the error when nothing takes. `caprobe` records the
/// change; a proof of possession only needs a secret.
///
/// # Errors
///
/// The module's refusal of the template as asked; or, when a changed template passes and the
/// module refuses it for another reason (a read-only session), that refusal.
pub fn derive_any(
    s: &Session,
    mech: &Mechanism,
    key: ObjectHandle,
    template: &[Attribute],
    len: usize,
) -> std::result::Result<Derived, CkError> {
    let first = match s.derive_key(mech, key, template) {
        Ok(h) => return Ok((h, template.to_vec(), None)),
        Err(e) if template_refusal(&e) => e,
        Err(e) => return Err(e),
    };
    let with_len = [template, &[Attribute::ValueLen((len as u64).into())]].concat();
    let mut tries = vec![(with_len.clone(), format!("CKA_VALUE_LEN = {len} added"))];
    for base in [template, &with_len[..]] {
        for default in template.iter().filter(|a| is_policy_default(a)) {
            let without: Vec<_> = base.iter().filter(|a| *a != default).cloned().collect();
            let added =
                if base.len() > template.len() { format!("CKA_VALUE_LEN = {len} added, ") } else { String::new() };
            tries.push((without, format!("{added}{} dropped", show(default))));
        }
    }
    for (t, what) in tries {
        match s.derive_key(mech, key, &t) {
            Ok(h) => return Ok((h, t, Some((what, first)))),
            // Past the template, refused for something else: the caller's to answer (AWS
            // CloudHSM checks the template before the session, then refuses a read-only one
            // [run]; `derive_for_proof` derives again read-write).
            Err(e) if !template_refusal(&e) => return Err(e),
            Err(_) => {}
        }
    }
    Err(first)
}
