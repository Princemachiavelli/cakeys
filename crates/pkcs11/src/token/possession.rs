//! Proof of possession on the token (`cakeys_core::pop`, docs/DESIGN.md §3.6): sign, derive or decrypt a fresh challenge the host checks.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use cakeys_core::pop;
use cakeys_profile::{Capability, Profile};
use cryptoki::context::Function;
use cryptoki::mechanism::rsa::PkcsPssParams;

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
                return Err(KmError::Unavailable(
                    format!(
                        "the private key on token '{}' is CKA_ALWAYS_AUTHENTICATE; only binding = \"pop-sign\" \
                     proves possession with its per-use PIN; adopt it publicOnly, or opt in with binding = \
                     \"token-asserted\"",
                        self.name
                    )
                    .into(),
                ));
            }
        }))
    }

    /// Proof of possession (`cakeys_core::pop`, docs/DESIGN.md §3.6), by the [recorded
    /// binding](Self::recorded_binding): the private key `h` proves, by whichever capability it
    /// has, that it holds the private half of `spki`, the public key its identity hashes. A proof
    /// that does not verify is a `Conflict`; a token that cannot prove is `Unsupported` or
    /// `Unavailable`, never a pass. `token-asserted` proves nothing. `caprobe` measures a token's
    /// `prove.*` capabilities with it, on keys it generated: the verbs' own proof.
    ///
    /// # Errors
    ///
    /// As [`Self::check_proof`]; `Conflict` for a proof that does not verify; `Unsupported` or
    /// `Unavailable` for one the token cannot give.
    pub fn prove_binding(&self, h: ObjectHandle, object: &ObjectCfg, spki: &[u8], binding: Binding) -> Result<()> {
        self.check_proof(object, binding)?;
        let msg = pop::challenge(spki)?;
        match binding {
            Binding::PopSign | Binding::PopSignPin => self.prove_sign(h, object, spki, &msg, binding),
            Binding::PopEcdh => self.prove_ecdh(h, spki, &msg),
            Binding::PopDecrypt => self.prove_decrypt(h, spki),
            Binding::PopUnwrap => self.prove_unwrap(h, spki, &msg),
            Binding::TokenAsserted => Ok(()),
        }
    }

    /// `pop-sign`: the token signs the challenge; the host verifies the signature. With
    /// `binding` `pop-sign-pin`, the signature is authorized by a context-specific login.
    /// An RSA key signs as [`rsa_signature`] chooses for it.
    fn prove_sign(&self, h: ObjectHandle, object: &ObjectCfg, spki: &[u8], msg: &[u8], binding: Binding) -> Result<()> {
        // Read once: it narrows the mechanism here and chooses the RSA signature below.
        let allowed = self.allowed_if_readable(h)?;
        let permits = |m| permitted(allowed.as_deref(), m);
        let usable = |m: MechanismType| self.has(m) && permits(m);
        let none_allowed = |ms: &[MechanismType]| self.none_allowed(ms);
        let mut rsa = pop::RsaSignature::Pkcs1v15(pop::HashAlg::Sha256);
        let (mech, data) = match key_type_of(object)? {
            KeyType::EC => {
                let hash = ecdsa_hash(object)?;
                let hashed = match hash {
                    pop::HashAlg::Sha256 => Mechanism::EcdsaSha256,
                    pop::HashAlg::Sha384 => Mechanism::EcdsaSha384,
                    pop::HashAlg::Sha512 => Mechanism::EcdsaSha512,
                };
                let raw = MechanismType::ECDSA;
                if usable(hashed.mechanism_type()) {
                    (hashed, msg.to_vec())
                } else if permits(raw) {
                    (Mechanism::Ecdsa, hash.digest(msg))
                } else {
                    return Err(none_allowed(&[hashed.mechanism_type(), raw]));
                }
            }
            KeyType::EC_EDWARDS => {
                if !permits(MechanismType::EDDSA) {
                    return Err(none_allowed(&[MechanismType::EDDSA]));
                }
                (self.runnable(Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))), msg.to_vec())
            }
            KeyType::RSA => {
                let Some((m, scheme)) = rsa_signature(allowed.as_deref(), |m| self.has(m)) else {
                    return Err(none_allowed(&RSA_SIGN.map(|(m, _)| m)));
                };
                rsa = scheme;
                rsa_sign(m, scheme, msg)
            }
            kt => return Err(KmError::Unsupported(format!("proof of possession for {kt}").into())),
        };
        let refused = self.proof_failed("C_Sign", "sign", "CKA_SIGN");
        let sig = if binding == Binding::PopSignPin {
            self.sign_with_pin(&mech, h, &data, refused)?
        } else {
            self.session.sign(&mech, h, &data).map_err(refused)?
        };
        pop::verify_with(spki, msg, &sig, rsa)
    }

    /// Sign under a `CKA_ALWAYS_AUTHENTICATE` key's per-use policy: `C_SignInit`, then the
    /// context-specific login, then a single-part `C_Sign` (PKCS#11 3.2 §5.1), which every
    /// signing mechanism offers. The login happens exactly once, never retried: the PIN is the one
    /// that opened the session, so it cannot be wrong and a successful login spends no retry; a
    /// failure (another actor locked the PIN meanwhile) is `Unavailable`. The sign after
    /// `C_SignInit` is cryptoki's `Session::sign_single`.
    fn sign_with_pin(
        &self,
        mech: &Mechanism,
        h: ObjectHandle,
        data: &[u8],
        refused: impl Fn(CkError) -> KmError,
    ) -> Result<Vec<u8>> {
        let pin = self.pin.as_deref().ok_or_else(|| {
            KmError::Unavailable(
                format!(
                    "token '{}': the private key is CKA_ALWAYS_AUTHENTICATE and needs the user PIN per use; \
                 configure pinFile or pinEnv",
                    self.name
                )
                .into(),
            )
        })?;
        self.session.sign_init(mech, h).map_err(&refused)?;
        if let Err(e) = self.session.login(UserType::ContextSpecific, Some(&AuthPin::new(pin.to_owned().into()))) {
            // C_SignFinal always ends the operation: the session stays usable for the next proof.
            let _ = self.session.sign_final();
            return Err(KmError::Unavailable(
                format!(
                    "C_Login(CKU_CONTEXT_SPECIFIC) for the CKA_ALWAYS_AUTHENTICATE key on token '{}': {}; \
                 not retried",
                    self.name,
                    rv_name(&e)
                )
                .into(),
            )
            .with_rv(rv_of(&e)));
        }
        self.session.sign_single(data).map_err(refused)
    }

    /// `pop-ecdh`: the host holds an ephemeral key and the MAC of the challenge under the shared
    /// secret; the token derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable
    /// session key and MACs the challenge with it. The MACs agree only if the token's private key
    /// is the one `spki` names. A token without HMAC, or whose profile says it derives only into
    /// an extractable secret (`derive.ecdh.sealed` no: ykcs11 \[src\]), proves by
    /// [`Self::prove_ecdh_extractable`] instead, and so does one that refuses the sealed form
    /// when its profile does not say.
    fn prove_ecdh(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        if !self.proof_permits(h)?(MechanismType::ECDH1_DERIVE) {
            return Err(self.none_allowed(&[MechanismType::ECDH1_DERIVE]));
        }
        let ch = pop::ecdh_challenge(spki, msg)?;
        if !self.ecdh_seals() {
            return self.prove_ecdh_extractable(h, spki, &ch);
        }
        // The extractable form after the sealed one failed for `why`, which its own failure names.
        let extractable_after =
            |why: String| self.prove_ecdh_extractable(h, spki, &ch).map_err(|e| after_sealed(e, &why));
        // Unknown means try (review 2026-11-15 §4): where the module refuses to derive into a
        // sealed secret, the extractable one. Only that refusal, of the template: a key that may
        // not derive or a derivation that failed is the proof's answer, never derived again
        // (review 2026-11-23 B-8).
        let failed = self.proof_failed("C_DeriveKey", "derive", "CKA_DERIVE");
        let sealed = self.proof_secret(Binding::PopEcdh, true)?;
        let (derived, rw) = match self.derive_for_proof(h, &ch.peer, &sealed, ch.secret.len())? {
            Ok(derived) => derived,
            Err(e) if template_refusal(&e) => return extractable_after(failed(e).to_string()),
            Err(e) => return Err(failed(e)),
        };
        let session = rw.as_ref().unwrap_or(&self.session);
        let derived = SessionObject::new(session, derived);
        let tag = match session.sign(&Mechanism::Sha256Hmac, derived.handle(), msg) {
            Ok(tag) => tag,
            // A sealed secret the module will not MAC with (tpm2-pkcs11 [run]): no operation
            // began, so the extractable form is tried as for a refused derivation.
            Err(e @ CkError::Pkcs11(_, cryptoki::context::Function::SignInit)) => {
                drop(derived);
                return extractable_after(format!("C_SignInit with the sealed secret: {e}"));
            }
            Err(e) => {
                return Err(KmError::Unavailable(
                    format!("C_Sign (ECDH proof of possession) on token '{}': {e}", self.name).into(),
                )
                .with_rv(rv_of(&e)));
            }
        };
        drop(derived);
        if !pop::ct_eq(&ch.mac, &tag) {
            return Err(KmError::Conflict(
                format!(
                    "proof of possession failed: the private key did not derive for the public key {}",
                    id::sri(spki)
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// `pop-ecdh` on a token that derives only into an extractable secret: the token derives
    /// into a session object, the host reads its `CKA_VALUE` and compares it with the shared
    /// secret it computed itself. The secret belongs to a single-use ephemeral key the host
    /// generated, so reading it reveals nothing the host did not already hold.
    fn prove_ecdh_extractable(&self, h: ObjectHandle, spki: &[u8], ch: &pop::EcdhChallenge) -> Result<()> {
        let failed = self.proof_failed("C_DeriveKey", "derive", "CKA_DERIVE");
        let (derived, rw) = self
            .derive_for_proof(h, &ch.peer, &self.proof_secret(Binding::PopEcdh, false)?, ch.secret.len())?
            .map_err(failed)?;
        let session = rw.as_ref().unwrap_or(&self.session);
        let derived = SessionObject::new(session, derived);
        let value = session.get_attributes(derived.handle(), &[AttributeType::Value]);
        drop(derived);
        // Wiped as the host's copy of the same secret is (B16), though it reveals nothing.
        let value = match value.map(|v| v.into_iter().next()) {
            Ok(Some(Attribute::Value(v))) => Zeroizing::new(v),
            Ok(_) => {
                return Err(KmError::Unavailable(
                    format!("token '{}': the derived secret has no CKA_VALUE", self.name).into(),
                ));
            }
            Err(e) => {
                return Err(KmError::Unavailable(
                    format!("C_GetAttributeValue (ECDH proof of possession) on token '{}': {e}", self.name).into(),
                )
                .with_rv(rv_of(&e)));
            }
        };
        if !pop::ct_eq(&ch.secret, &value) {
            return Err(KmError::Conflict(
                format!(
                    "proof of possession failed: the private key did not derive for the public key {}",
                    id::sri(spki)
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// `C_DeriveKey` for a proof, against the ephemeral `peer`: in the verb's session, else —
    /// refused there as read-only (tpm2-pkcs11 keeps derived secrets as store rows, so it
    /// derives only in a read-write session, `derive.read-only = false` \[run\]) — in a read-write
    /// session opened for it, returned so the secret is used and destroyed where it lives. The
    /// module's refusal is returned as it is (the inner error), for the caller to tell a refused
    /// template from a failed derivation.
    fn derive_for_proof(
        &self,
        h: ObjectHandle,
        peer: &[u8],
        template: &[Attribute],
        len: usize,
    ) -> Result<std::result::Result<(ObjectHandle, Option<Session>), CkError>> {
        let mech = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        // A module refusing the template's own policy defaults derives without them
        // (`derive_any`): the proof needs only the shared secret.
        Ok(match derive_any(&self.session, &mech, h, template, len) {
            Ok((derived, ..)) => Ok((derived, None)),
            Err(CkError::Pkcs11(RvError::SessionReadOnly, _)) => {
                let rw = self.extra_session(Access::Write)?;
                derive_any(&rw, &mech, h, template, len).map(|(derived, ..)| (derived, Some(rw)))
            }
            Err(e) => Err(e),
        })
    }

    /// `pop-decrypt`: the host encrypts a fresh secret ([`pop::secret`]) to the public key with
    /// RSA-OAEP, or with PKCS #1 v1.5 where the token or the key's allowed mechanisms offer only
    /// `CKM_RSA_PKCS`; the token decrypts it with the private key. The plaintext matches only if
    /// the token's private key is the one `spki` names. OAEP takes the first of [`OAEP`]'s hashes
    /// the token does not refuse before decrypting.
    fn prove_decrypt(&self, h: ObjectHandle, spki: &[u8]) -> Result<()> {
        // 32 bytes, not the 78-byte challenge, which OAEP-SHA-256 cannot carry in a 1024-bit key
        // (review 2026-11-23 B-7).
        let secret = pop::secret()?;
        let msg = secret.as_slice();
        let permits = self.proof_permits(h)?;
        let usable = |m: MechanismType| self.has(m) && permits(m);
        let (oaep, v15) = (MechanismType::RSA_PKCS_OAEP, MechanismType::RSA_PKCS);
        let failed = self.proof_failed("C_Decrypt", "decrypt", "CKA_DECRYPT");
        let plain = if usable(oaep) || (permits(oaep) && !usable(v15)) {
            // Each hash in turn; the last one's refusal is the proof's.
            let mut plain = None;
            for (i, padding) in OAEP.into_iter().enumerate() {
                let Some((params, _)) = oaep_params(padding) else { continue };
                let cipher = pop::rsa_encrypt(spki, padding, msg)?;
                match self.session.decrypt(&Mechanism::RsaPkcsOaep(params), h, &cipher) {
                    Ok(p) => {
                        plain = Some(p);
                        break;
                    }
                    Err(e) if i + 1 < OAEP.len() && oaep_hash_refused(&e, Function::DecryptInit) => {}
                    Err(e) => return Err(failed(e)),
                }
            }
            plain.ok_or_else(|| {
                KmError::Unavailable(format!("token '{}': no OAEP hash to decrypt with", self.name).into())
            })?
        } else if permits(v15) {
            let cipher = pop::rsa_encrypt(spki, pop::RsaPadding::Pkcs1v15, msg)?;
            self.session.decrypt(&Mechanism::RsaPkcs, h, &cipher).map_err(failed)?
        } else {
            return Err(self.none_allowed(&[oaep, v15]));
        };
        let plain = Zeroizing::new(plain);
        if !pop::ct_eq(msg, &plain) {
            return Err(KmError::Conflict(
                format!(
                    "proof of possession failed: the private key did not decrypt for the public key {}",
                    id::sri(spki)
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// `pop-unwrap`: the host wraps a fresh secret to the public key with RSA-OAEP; the token
    /// unwraps it into a non-extractable session key and MACs the challenge with it. The MACs
    /// agree only if the token's private key is the one `spki` names; no plaintext leaves the
    /// token, so a transport key proves possession without `CKA_DECRYPT`. OAEP takes the first of
    /// [`OAEP`]'s hashes the token does not refuse.
    fn prove_unwrap(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        if !self.proof_permits(h)?(MechanismType::RSA_PKCS_OAEP) {
            return Err(self.none_allowed(&[MechanismType::RSA_PKCS_OAEP]));
        }
        let template = self.proof_secret(Binding::PopUnwrap, true)?;
        let failed = self.proof_failed("C_UnwrapKey", "unwrap", "CKA_UNWRAP");
        // Like a derive: a module that keeps session keys as store rows unwraps only read-write.
        // C_UnwrapKey is one call: a hash it refuses began nothing the next try meets.
        let mut rw: Option<Session> = None;
        // Each hash in turn, from the first again once a read-write session is open; the last
        // one's refusal is the proof's.
        let mut next = 0;
        let (key, ch) = loop {
            let Some((padding, params)) = OAEP.get(next).and_then(|p| Some((*p, oaep_params(*p)?.0))) else {
                return Err(KmError::Unavailable(format!("token '{}': no OAEP hash to unwrap with", self.name).into()));
            };
            let ch = pop::unwrap_challenge_with(spki, msg, padding)?;
            let session = rw.as_ref().unwrap_or(&self.session);
            match session.unwrap_key(&Mechanism::RsaPkcsOaep(params), h, &ch.wrapped, &template) {
                Ok(k) => break (k, ch),
                Err(CkError::Pkcs11(RvError::SessionReadOnly, _)) if rw.is_none() => {
                    rw = Some(self.extra_session(Access::Write)?);
                    next = 0;
                }
                Err(e) if next + 1 < OAEP.len() && oaep_hash_refused(&e, Function::UnwrapKey) => next += 1,
                Err(e) => return Err(failed(e)),
            }
        };
        let session = rw.as_ref().unwrap_or(&self.session);
        let key = SessionObject::new(session, key);
        let tag = session.sign(&Mechanism::Sha256Hmac, key.handle(), msg);
        drop(key);
        let tag = tag.map_err(|e| {
            KmError::Unavailable(format!("C_Sign (unwrap proof of possession) on token '{}': {e}", self.name).into())
                .with_rv(rv_of(&e))
        })?;
        if !pop::ct_eq(&ch.mac, &tag) {
            return Err(KmError::Conflict(
                format!(
                    "proof of possession failed: the private key did not unwrap for the public key {}",
                    id::sri(spki)
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// Whether the private key's own `CKA_ALLOWED_MECHANISMS` lets a proof use a mechanism. It
    /// narrows the choice where it can be read (absent or refused, it does not). A proof records
    /// only its binding, never the mechanism, so choosing per run changes nothing the lock pins.
    fn proof_permits(&self, h: ObjectHandle) -> Result<impl Fn(MechanismType) -> bool> {
        let allowed = self.allowed_if_readable(h)?;
        Ok(move |m| permitted(allowed.as_deref(), m))
    }

    /// A proof refused because the key's `CKA_ALLOWED_MECHANISMS` allows none of `ms`.
    fn none_allowed(&self, ms: &[MechanismType]) -> KmError {
        KmError::Unsupported(
            format!(
                "token '{}': the key's CKA_ALLOWED_MECHANISMS allows none of {} for a proof of possession",
                self.name,
                ms.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            )
            .into(),
        )
    }

    /// What this token offers a proof of possession ([`proof_refusal`]): its usable mechanisms,
    /// and whether it unwraps at all (its profile's `[migration] unwraps`).
    pub fn proof_side(&self) -> ProofSide<'_> {
        let profile = self.profiles.module.as_ref();
        ProofSide {
            token: &self.name,
            profile: profile.map(|p| p.profile.as_str()),
            has: Box::new(|m| self.has(m)),
            unwraps: profile.and_then(Profile::unwraps) != Some(false),
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
        move |e| {
            let rv = rv_of(&e);
            self.proof_failure(call, op, attr, e).with_rv(rv)
        }
    }

    /// [`Self::proof_failed`]'s mapping, before the return value is attached.
    fn proof_failure(&self, call: &'static str, op: &'static str, attr: &'static str, e: CkError) -> KmError {
        match e {
            CkError::Pkcs11(
                RvError::KeyFunctionNotPermitted
                | RvError::MechanismInvalid
                | RvError::KeyTypeInconsistent
                | RvError::FunctionNotSupported,
                _,
            ) => self.unsupported(format!(
                "token '{}' refused to {op} with the private key ({}: {e}); proving possession needs {attr}, or opt \
                 in with binding = \"token-asserted\"",
                self.name,
                rv_name(&e)
            )),
            CkError::Pkcs11(
                RvError::EncryptedDataInvalid
                | RvError::EncryptedDataLenRange
                | RvError::WrappedKeyInvalid
                | RvError::WrappedKeyLenRange,
                _,
            ) => KmError::Conflict(
                format!(
                    "proof of possession failed: the private key on token '{}' did not {op} what was made for its \
                 public key ({call}: {}: {e})",
                    self.name,
                    rv_name(&e)
                )
                .into(),
            ),
            e => KmError::Unavailable(
                format!("{call} (proof of possession) on token '{}': {}: {e}", self.name, rv_name(&e)).into(),
            ),
        }
    }

    /// Whether a `pop-ecdh` proof derives into a sealed secret first ([`Self::prove_ecdh`]), by
    /// [`crate::ops::ecdh_seals`], which a plan asks without the token.
    pub(crate) fn ecdh_seals(&self) -> bool {
        let derive_sealed = self.profiles.module.as_ref().and_then(|p| p.answer(&Capability::DeriveSealed));
        crate::ops::ecdh_seals(derive_sealed, Some(self.has(MechanismType::SHA256_HMAC))) == Some(true)
    }

    /// The session secret a proof makes on the token (`pop-ecdh` derives it, `pop-unwrap`
    /// unwraps it), as the provider adjusts it: `sealed`, sensitive, never extractable and only
    /// for signing, to MAC with; else the readable secret of
    /// [`Self::prove_ecdh_extractable`].
    fn proof_secret(&self, binding: Binding, sealed: bool) -> Result<Vec<Attribute>> {
        self.session_template(SessionKey::ProofSecret { binding, sealed })
    }
}

/// What a token offers a proof of possession, as a live token ([`Token::proof_side`]) or as
/// camigrate's plan knows a target from its profile: the one input [`proof_refusal`] takes.
pub struct ProofSide<'a> {
    /// The token's name in keys.toml.
    pub token: &'a str,
    /// The module profile, named in a refusal.
    pub profile: Option<&'a str>,
    /// Whether the token offers a mechanism.
    pub has: Box<dyn Fn(MechanismType) -> bool + 'a>,
    /// Whether the module unwraps at all.
    pub unwraps: bool,
}

/// Why a proof of possession by `binding` of a private key of `object` cannot run on `side`:
/// `None` when it can. The one check the proof itself (`Token::prove_binding`), `cakeys`
/// before it creates a key, and camigrate's plan for a move's target all make, so none promises
/// a proof another then refuses.
///
/// # Errors
///
/// `Unsupported` for a key type or curve no proof is defined for.
pub fn proof_refusal(object: &ObjectCfg, binding: Binding, side: &ProofSide<'_>) -> Result<Option<String>> {
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

/// The RSA signatures a `pop-sign` proof can ask for, in order of preference: PKCS #1 v1.5 over
/// SHA-256, hashed by the token or by the host into the `DigestInfo` raw `CKM_RSA_PKCS` signs (the
/// same signature either way); the other v1.5 hashes; then PSS, hashed by the token or over the
/// host's digest. A raw mechanism's hash here is its default ([`rsa_signature`]).
const RSA_SIGN: [(MechanismType, pop::RsaSignature); 8] = {
    use pop::HashAlg::{Sha256, Sha384, Sha512};
    use pop::RsaSignature::{Pkcs1v15, Pss};
    [
        (MechanismType::SHA256_RSA_PKCS, Pkcs1v15(Sha256)),
        (MechanismType::RSA_PKCS, Pkcs1v15(Sha256)),
        (MechanismType::SHA384_RSA_PKCS, Pkcs1v15(Sha384)),
        (MechanismType::SHA512_RSA_PKCS, Pkcs1v15(Sha512)),
        (MechanismType::SHA256_RSA_PKCS_PSS, Pss(Sha256)),
        (MechanismType::SHA384_RSA_PKCS_PSS, Pss(Sha384)),
        (MechanismType::SHA512_RSA_PKCS_PSS, Pss(Sha512)),
        (MechanismType::RSA_PKCS_PSS, Pss(Sha256)),
    ]
};

/// The RSA signature a `pop-sign` proof asks for, under the key's `allowed` mechanisms (`None`:
/// any) on a token offering what `has` says: the first of [`RSA_SIGN`] both allow, else the first
/// the key allows (tried, though the token does not list it), else none. A raw mechanism signs
/// over the hash of a hashed mechanism of its padding the key allows, if any, else SHA-256: a key
/// bound to SHA-512 checks the `DigestInfo` it signs (Cloud KMS, `CKR_DATA_INVALID` \[run\]).
/// With no allowed list this is what the proof always did: v1.5 over SHA-256, hashed or raw.
fn rsa_signature(
    allowed: Option<&[MechanismType]>,
    has: impl Fn(MechanismType) -> bool,
) -> Option<(MechanismType, pop::RsaSignature)> {
    let permits = |m: MechanismType| allowed.is_none_or(|a| a.contains(&m));
    let &(m, scheme) =
        RSA_SIGN.iter().find(|(m, _)| has(*m) && permits(*m)).or_else(|| RSA_SIGN.iter().find(|(m, _)| permits(*m)))?;
    let raw = |m: MechanismType| m == MechanismType::RSA_PKCS || m == MechanismType::RSA_PKCS_PSS;
    let scheme = match allowed {
        Some(a) if raw(m) => RSA_SIGN
            .iter()
            .find(|(h, s)| !raw(*h) && a.contains(h) && std::mem::discriminant(s) == std::mem::discriminant(&scheme))
            .map_or(scheme, |&(_, s)| s),
        _ => scheme,
    };
    Some((m, scheme))
}

/// The mechanism and the data a `pop-sign` proof signs `msg` with by `m`, as `scheme`: the
/// message itself for a hashed mechanism, the host's digest (in its `DigestInfo` for v1.5) for a
/// raw one. PSS asks a salt as long as the hash, which the host's verifier expects.
fn rsa_sign(m: MechanismType, scheme: pop::RsaSignature, msg: &[u8]) -> (Mechanism<'static>, Vec<u8>) {
    use pop::HashAlg::{Sha256, Sha384, Sha512};
    match scheme {
        pop::RsaSignature::Pkcs1v15(h) if m == MechanismType::RSA_PKCS => {
            (Mechanism::RsaPkcs, [digest_info(h), h.digest(msg).as_slice()].concat())
        }
        pop::RsaSignature::Pkcs1v15(h) => (
            match h {
                Sha256 => Mechanism::Sha256RsaPkcs,
                Sha384 => Mechanism::Sha384RsaPkcs,
                Sha512 => Mechanism::Sha512RsaPkcs,
            },
            msg.to_vec(),
        ),
        pop::RsaSignature::Pss(h) => {
            let (hash_alg, mgf, len) = match h {
                Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32_u64),
                Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48),
                Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64),
            };
            let params = PkcsPssParams { hash_alg, mgf, s_len: len.into() };
            match (m == MechanismType::RSA_PKCS_PSS, h) {
                (true, _) => (Mechanism::RsaPkcsPss(params), h.digest(msg)),
                (false, Sha256) => (Mechanism::Sha256RsaPkcsPss(params), msg.to_vec()),
                (false, Sha384) => (Mechanism::Sha384RsaPkcsPss(params), msg.to_vec()),
                (false, Sha512) => (Mechanism::Sha512RsaPkcsPss(params), msg.to_vec()),
            }
        }
    }
}

/// The DER `DigestInfo` prefix of a digest by `h` (RFC 8017 §9.2, note 1): what
/// `CKM_SHA*_RSA_PKCS` puts before the hash it computes, so raw `CKM_RSA_PKCS` over it and the
/// host's hash signs the same PKCS #1 v1.5 signature.
#[must_use]
pub fn digest_info(h: pop::HashAlg) -> &'static [u8] {
    const SHA256: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
        0x20,
    ];
    const SHA384: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
        0x30,
    ];
    const SHA512: [u8; 19] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
        0x40,
    ];
    match h {
        pop::HashAlg::Sha256 => &SHA256,
        pop::HashAlg::Sha384 => &SHA384,
        pop::HashAlg::Sha512 => &SHA512,
    }
}

/// The OAEP hashes a decryption or unwrap proof tries, in order: SHA-1, the PKCS#11 baseline
/// (all `SoftHSM` implements), then SHA-256 and SHA-512 for a key bound to one (Cloud KMS
/// \[run\]): the host's padding and the token's parameters. `CKA_ALLOWED_MECHANISMS` cannot say
/// which: it names `CKM_RSA_PKCS_OAEP`, never its hash.
pub const OAEP: [pop::RsaPadding; 3] = [
    pop::RsaPadding::Oaep(pop::OaepHash::Sha1),
    pop::RsaPadding::Oaep(pop::OaepHash::Sha256),
    pop::RsaPadding::OaepSha512,
];

/// RSA-OAEP as a token runs the host's `padding`: the hash, MGF1 of the same hash and an empty
/// label, with the hash's name as a capability row writes it (`SHA-256`). `None` for PKCS #1
/// v1.5, which has none. The one table the proofs, the probe and camigrate's wraps read.
#[must_use]
pub fn oaep_params(padding: pop::RsaPadding) -> Option<(PkcsOaepParams<'static>, &'static str)> {
    match padding {
        pop::RsaPadding::Pkcs1v15 => None,
        pop::RsaPadding::Oaep(hash) => Some(oaep_of(hash)),
        pop::RsaPadding::OaepSha512 => Some((
            PkcsOaepParams::new(MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, PkcsOaepSource::empty()),
            "SHA-512",
        )),
    }
}

/// [`oaep_params`] of a transport wrap's hash (`OaepHash`), which always has them.
#[must_use]
pub fn oaep_of(hash: pop::OaepHash) -> (PkcsOaepParams<'static>, &'static str) {
    let (h, mgf, name) = match hash {
        pop::OaepHash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, "SHA-1"),
        pop::OaepHash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, "SHA-256"),
    };
    (PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty()), name)
}

/// Whether `e` refuses an OAEP hash before the operation began (`init`: the call that starts it),
/// so the next of [`OAEP`] may be tried. Never a failure after it began: a module may leave that
/// operation active (tpm2-pkcs11 \[run\]), and the session would refuse the next.
fn oaep_hash_refused(e: &CkError, init: Function) -> bool {
    match e {
        CkError::Pkcs11(RvError::MechanismParamInvalid | RvError::ArgumentsBad, f) => {
            std::mem::discriminant(f) == std::mem::discriminant(&init)
        }
        _ => false,
    }
}

/// The hash ECDSA signs a proof with on `object`'s curve.
fn ecdsa_hash(object: &ObjectCfg) -> Result<pop::HashAlg> {
    pop::HashAlg::for_curve(curve_of(object)?)
        .ok_or_else(|| KmError::Unsupported(format!("ECDSA on {}", object.curve.as_deref().unwrap_or("?")).into()))
}

/// The mechanisms a proof of possession by `binding` uses on a private key of `object`'s type:
/// the token must offer at least one of each group. The one list both the proof itself
/// ([`Token::prove_binding`]) and camigrate's planner check, so a plan never promises a proof the
/// target then refuses. An ECDSA proof prefers the curve's hashed mechanism and falls back to
/// raw `CKM_ECDSA` over a host-side digest; an RSA proof signs by any of [`RSA_SIGN`], as
/// [`rsa_signature`] chooses; a decryption proof prefers OAEP and falls back to PKCS #1 v1.5.
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
                    pop::HashAlg::Sha256 => MechanismType::ECDSA_SHA256,
                    pop::HashAlg::Sha384 => MechanismType::ECDSA_SHA384,
                    pop::HashAlg::Sha512 => MechanismType::ECDSA_SHA512,
                };
                vec![vec![hashed, MechanismType::ECDSA]]
            }
            KeyType::EC_EDWARDS => vec![vec![MechanismType::EDDSA]],
            KeyType::RSA => vec![RSA_SIGN.map(|(m, _)| m).to_vec()],
            kt => return Err(KmError::Unsupported(format!("proof of possession for {kt}").into())),
        },
        Binding::PopEcdh => vec![vec![MechanismType::ECDH1_DERIVE]],
        Binding::PopDecrypt => vec![vec![MechanismType::RSA_PKCS_OAEP, MechanismType::RSA_PKCS]],
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

/// Whether a key whose `CKA_ALLOWED_MECHANISMS` reads `allowed` (`None`: absent or unreadable,
/// which does not narrow) lets a proof use `m`.
fn permitted(allowed: Option<&[MechanismType]>, m: MechanismType) -> bool {
    allowed.is_none_or(|a| a.contains(&m))
}

/// The extractable `pop-ecdh` proof's failure `e`, after the sealed one failed for `why`: a
/// refusal names both, and keeps the return value of the module call that failed (Q3).
fn after_sealed(e: KmError, why: &str) -> KmError {
    match e {
        KmError::Unavailable(m) => {
            let rv = m.rv();
            KmError::Unavailable(Msg::from(format!("{m} (sealed: {why})")).with_rv(rv))
        }
        KmError::Unsupported(m) => {
            let rv = m.rv();
            KmError::Unsupported(Msg::from(format!("{m} (sealed: {why})")).with_rv(rv))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pop::HashAlg::{Sha256, Sha512};
    use pop::RsaSignature::{Pkcs1v15, Pss};

    /// The mechanisms a proof runs on the private key are the ones core's load check names
    /// (review 2026-11-23 A-10): an allowed list load accepts is one some proof mechanism fits.
    #[test]
    fn the_proofs_mechanisms_are_the_ones_load_checks() {
        let ec =
            |curve: &str| ObjectCfg { curve: Some(curve.into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Ec)) };
        let objects = [
            ec("secp256r1"),
            ec("secp384r1"),
            ec("secp521r1"),
            ObjectCfg { curve: Some("edwards25519".into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::EcEdwards)) },
            ObjectCfg::new(Class::PrivateKey, Some(Kt::Rsa)),
        ];
        let bindings = [
            Binding::PopSign,
            Binding::PopSignPin,
            Binding::PopEcdh,
            Binding::PopDecrypt,
            Binding::PopUnwrap,
            Binding::TokenAsserted,
        ];
        for object in &objects {
            let kind = object.kind().unwrap();
            for binding in bindings {
                let groups = proof_mechanisms(object, binding).unwrap();
                let ours: Vec<String> =
                    groups.first().map(|g| g.iter().map(ToString::to_string).collect()).unwrap_or_default();
                assert_eq!(ours, cakeys_core::plan::proof_mechanisms(binding, kind), "{object:?} {binding}");
            }
        }
    }

    /// The extractable ECDH proof's refusal after the sealed one names both and keeps the
    /// module's return value (possession.rs F1); a failed proof is the proof's answer, as given.
    #[test]
    fn the_extractable_proofs_refusal_keeps_its_return_value() {
        let rv = Some(0x8000_0001);
        let said = |e: KmError| (e.exit_code(), e.rv(), e.to_string());
        let unavailable = after_sealed(KmError::Unavailable(Msg::from("C_DeriveKey").with_rv(rv)), "refused");
        assert_eq!(said(unavailable), (16, rv, "unavailable: C_DeriveKey (sealed: refused)".into()));
        let unsupported = after_sealed(KmError::Unsupported(Msg::from("C_DeriveKey").with_rv(rv)), "refused");
        assert_eq!(said(unsupported), (15, rv, "unsupported: C_DeriveKey (sealed: refused)".into()));
        let conflict = after_sealed(KmError::Conflict(Msg::from("did not derive").with_rv(rv)), "refused");
        assert_eq!(said(conflict), (13, rv, "conflict: did not derive".into()));
    }

    /// A key's allowed list narrows a proof's mechanism only where it was read.
    #[test]
    fn only_a_read_allowed_list_narrows_the_proof() {
        assert!(permitted(None, MechanismType::ECDSA));
        assert!(permitted(Some(&[MechanismType::ECDSA]), MechanismType::ECDSA));
        assert!(!permitted(Some(&[MechanismType::ECDSA_SHA256]), MechanismType::ECDSA));
    }

    /// The RSA signature a proof asks for: with no allowed list what it always did (v1.5 over
    /// SHA-256, hashed where the token offers it, else raw); within a key's list, the first of
    /// `RSA_SIGN` it names, a raw one over the hash of the hashed one beside it (Cloud KMS's
    /// SHA-512 and PSS keys \[run\]); none when the list names no RSA signature.
    #[test]
    fn an_rsa_proof_signs_as_the_key_is_bound() {
        let all = |_| true;
        let (sha256, raw, sha512) =
            (MechanismType::SHA256_RSA_PKCS, MechanismType::RSA_PKCS, MechanismType::SHA512_RSA_PKCS);
        let (pss256, raw_pss) = (MechanismType::SHA256_RSA_PKCS_PSS, MechanismType::RSA_PKCS_PSS);
        assert_eq!(rsa_signature(None, all), Some((sha256, Pkcs1v15(Sha256))));
        assert_eq!(rsa_signature(None, |m| m == raw), Some((raw, Pkcs1v15(Sha256))));
        assert_eq!(rsa_signature(None, |_| false), Some((sha256, Pkcs1v15(Sha256))), "tried though unlisted");
        assert_eq!(rsa_signature(Some(&[raw, sha512]), all), Some((raw, Pkcs1v15(Sha512))));
        assert_eq!(rsa_signature(Some(&[raw, sha512]), |m| m == sha512), Some((sha512, Pkcs1v15(Sha512))));
        assert_eq!(rsa_signature(Some(&[raw_pss, pss256]), all), Some((pss256, Pss(Sha256))));
        assert_eq!(rsa_signature(Some(&[raw_pss, pss256]), |m| m == raw_pss), Some((raw_pss, Pss(Sha256))));
        assert_eq!(rsa_signature(Some(&[raw_pss]), all), Some((raw_pss, Pss(Sha256))));
        assert_eq!(rsa_signature(Some(&[MechanismType::ECDSA]), all), None);
        // The data each signs: the message for a hashed mechanism, the digest (in its
        // DigestInfo for v1.5) for a raw one.
        let (_, data) = rsa_sign(raw, Pkcs1v15(Sha512), b"m");
        assert_eq!(data, [digest_info(Sha512), Sha512.digest(b"m").as_slice()].concat());
        assert_eq!(rsa_sign(raw_pss, Pss(Sha256), b"m").1, Sha256.digest(b"m"));
        assert_eq!(rsa_sign(pss256, Pss(Sha256), b"m").1, b"m");
    }

    /// The next OAEP hash is tried only on a refusal of its parameters before the operation
    /// began: never after `C_Decrypt` itself failed, nor for any other refusal.
    #[test]
    fn only_a_refused_oaep_hash_is_tried_again() {
        let e = |rv, f| CkError::Pkcs11(rv, f);
        assert!(oaep_hash_refused(&e(RvError::MechanismParamInvalid, Function::DecryptInit), Function::DecryptInit));
        assert!(oaep_hash_refused(&e(RvError::ArgumentsBad, Function::DecryptInit), Function::DecryptInit));
        assert!(!oaep_hash_refused(&e(RvError::MechanismParamInvalid, Function::Decrypt), Function::DecryptInit));
        assert!(!oaep_hash_refused(&e(RvError::GeneralError, Function::DecryptInit), Function::DecryptInit));
        assert!(oaep_hash_refused(&e(RvError::MechanismParamInvalid, Function::UnwrapKey), Function::UnwrapKey));
    }
}
