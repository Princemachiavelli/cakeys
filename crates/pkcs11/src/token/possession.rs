//! The proof of possession on the token (`cakeys_core::pop`, docs/DESIGN.md §3.6). The token
//! signs, derives with, decrypts or unwraps a fresh challenge, and the host checks the result.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use cakeys_core::pop;
use cakeys_core::sig::digest;
use cakeys_profile::{Capability, Profile};
use cryptoki::context::Function;
use cryptoki::mechanism::rsa::PkcsPssParams;

impl Token {
    /// Returns the binding with which the private key `h` is proven and recorded, starting from
    /// the `planned` binding (`cakeys_core::plan::binding`). `pop-sign` becomes `pop-sign-pin`
    /// when the token reports the key as `CKA_ALWAYS_AUTHENTICATE`. The function uses the
    /// attribute that it observes on the token, whether or not the spec declares it
    /// (docs/DESIGN.md §3.6).
    ///
    /// # Errors
    ///
    /// `Unavailable` for `pop-ecdh`, `pop-decrypt` or `pop-unwrap` on a `CKA_ALWAYS_AUTHENTICATE`
    /// key, because only the sign path performs the login for each use.
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

    /// Runs the proof of possession (`cakeys_core::pop`, docs/DESIGN.md §3.6) with the [recorded
    /// binding](Self::recorded_binding). The proof shows that the private key `h` holds the
    /// private half of `spki`, which is the public key that the identity hashes, and it uses the
    /// capability that the binding names. A proof that does not verify is a `Conflict`. A token
    /// that cannot give the proof returns `Unsupported` or `Unavailable`, and the proof never
    /// passes in that case. `token-asserted` proves nothing. `caprobe` uses this function to
    /// measure a token's `prove.*` capabilities on keys that it generated, so the probe measures
    /// the same proof that the verbs run.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::check_proof`]. `Conflict` for a proof that does not verify.
    /// `Unsupported` or `Unavailable` for a proof that the token cannot give.
    pub fn prove_binding(&self, h: ObjectHandle, object: Object<'_>, spki: &[u8], binding: Binding) -> Result<()> {
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

    /// `pop-sign`: the token signs the challenge, and the host verifies the signature. When
    /// `binding` is `pop-sign-pin`, a context-specific login authorizes the signature. An RSA key
    /// signs with the mechanism and the scheme that [`rsa_signature`] chooses for it.
    fn prove_sign(&self, h: ObjectHandle, object: Object<'_>, spki: &[u8], msg: &[u8], binding: Binding) -> Result<()> {
        // The allowed mechanisms are read once. They narrow the mechanism here, and they choose
        // the RSA signature below.
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
                    (Mechanism::Ecdsa, digest(hash, msg))
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
        let refused = self.proof_failed(Check::PopSign, "C_Sign", "sign", "CKA_SIGN");
        let sig = if binding == Binding::PopSignPin {
            self.sign_with_pin(&mech, h, &data, refused)?
        } else {
            self.session.sign(&mech, h, &data).map_err(refused)?
        };
        pop::verify(spki, msg, &sig, rsa)
    }

    /// Signs with a `CKA_ALWAYS_AUTHENTICATE` key, which needs a login for each use. The sequence
    /// is `C_SignInit`, then the context-specific login, then a single-part `C_Sign` (PKCS#11 3.2
    /// §5.1), which every signing mechanism offers. The login happens exactly once and is never
    /// retried. The PIN is the one that opened the session, so it cannot be wrong, and a
    /// successful login uses up no retry. A failure (for example, because another process locked
    /// the PIN in the meantime) is `Unavailable`. The sign after `C_SignInit` is cryptoki's
    /// `Session::sign_single`.
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
            // `C_SignFinal` always ends the operation, so the session stays usable for the next
            // proof.
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
    /// secret. The token derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable
    /// session key and computes the MAC of the challenge with it. The two MACs are equal only if
    /// the token's private key is the one that `spki` names. A token without HMAC, or a token
    /// whose profile says that it derives only into an extractable secret
    /// (`derive.ecdh.sealed` is no, as for ykcs11 \[src\]), uses [`Self::prove_ecdh_extractable`]
    /// instead. A token that refuses the sealed form, when its profile does not decide
    /// `derive.ecdh.sealed`, also falls back to [`Self::prove_ecdh_extractable`].
    fn prove_ecdh(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        if !self.proof_permits(h)?(MechanismType::ECDH1_DERIVE) {
            return Err(self.none_allowed(&[MechanismType::ECDH1_DERIVE]));
        }
        let ch = pop::ecdh_challenge(spki, msg)?;
        if !self.ecdh_seals() {
            return self.prove_ecdh_extractable(h, spki, &ch);
        }
        // Run the extractable form after the sealed form failed for the reason `why`. A failure of
        // the extractable form also names `why`.
        let extractable_after =
            |why: String| self.prove_ecdh_extractable(h, spki, &ch).map_err(|e| after_sealed(e, &why));
        // An unknown answer means that the run tries (review 2026-11-15 §4). When the module
        // refuses to derive into a sealed secret, the proof uses the extractable secret. Only a
        // refusal of the template causes this fallback. A key that may not derive, or a
        // derivation that failed, is the result of the proof, and the proof does not derive again
        // (review 2026-11-23 B-8).
        let failed = self.proof_failed(Check::PopEcdh, "C_DeriveKey", "derive", "CKA_DERIVE");
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
            // The module does not compute a MAC with a sealed secret (tpm2-pkcs11 [run]). No
            // operation began, so the extractable form is tried, as for a refused derivation.
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
            return Err(KmError::Conflict(Reason::check(
                Check::PopEcdh,
                format!(
                    "proof of possession failed: the private key did not derive for the public key {}",
                    id::sri(spki)
                ),
            )));
        }
        Ok(())
    }

    /// `pop-ecdh` on a token that derives only into an extractable secret. The token derives the
    /// secret into a session object, and the host reads the object's `CKA_VALUE` and compares it
    /// with the shared secret that the host computed itself. The secret comes from a single-use
    /// ephemeral key that the host generated, so reading it reveals nothing that the host did not
    /// already hold.
    fn prove_ecdh_extractable(&self, h: ObjectHandle, spki: &[u8], ch: &pop::EcdhChallenge) -> Result<()> {
        let failed = self.proof_failed(Check::PopEcdh, "C_DeriveKey", "derive", "CKA_DERIVE");
        let (derived, rw) = self
            .derive_for_proof(h, &ch.peer, &self.proof_secret(Binding::PopEcdh, false)?, ch.secret.len())?
            .map_err(failed)?;
        let session = rw.as_ref().unwrap_or(&self.session);
        let derived = SessionObject::new(session, derived);
        let value = session.get_attributes(derived.handle(), &[AttributeType::Value]);
        drop(derived);
        // The value is zeroized, as the host's copy of the same secret is (B16), although it
        // reveals nothing.
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
            return Err(KmError::Conflict(Reason::check(
                Check::PopEcdh,
                format!(
                    "proof of possession failed: the private key did not derive for the public key {}",
                    id::sri(spki)
                ),
            )));
        }
        Ok(())
    }

    /// Calls `C_DeriveKey` for a proof, with the ephemeral public key `peer`. The derivation runs
    /// in the verb's session. When that session refuses it as read-only, the derivation runs in a
    /// read-write session that is opened for it. tpm2-pkcs11 needs this, because it stores derived
    /// secrets as rows in its store and therefore derives only in a read-write session
    /// (`derive.read-only = false` \[run\]). The read-write session is returned, so that the
    /// caller uses and destroys the secret in the session where it exists. The module's refusal is
    /// returned unchanged as the inner error, so that the caller can tell a refused template from
    /// a failed derivation.
    fn derive_for_proof(
        &self,
        h: ObjectHandle,
        peer: &[u8],
        template: &[Attribute],
        len: usize,
    ) -> Result<std::result::Result<(ObjectHandle, Option<Session>), CkError>> {
        let mech = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        // When a module refuses the policy defaults in the template, `derive_any` derives
        // without them, because the proof needs only the shared secret.
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
    /// RSA-OAEP, or with PKCS #1 v1.5 when the token or the key's allowed mechanisms offer only
    /// `CKM_RSA_PKCS`. The token decrypts it with the private key. The plaintext matches only if
    /// the token's private key is the one that `spki` names. OAEP uses the first hash in [`OAEP`]
    /// that the token does not refuse before it decrypts.
    fn prove_decrypt(&self, h: ObjectHandle, spki: &[u8]) -> Result<()> {
        // The secret is 32 bytes and not the 78-byte challenge, because OAEP with SHA-256 cannot
        // carry 78 bytes in a 1024-bit key (review 2026-11-23 B-7).
        let secret = pop::secret()?;
        let msg = secret.as_slice();
        let permits = self.proof_permits(h)?;
        let usable = |m: MechanismType| self.has(m) && permits(m);
        let (oaep, v15) = (MechanismType::RSA_PKCS_OAEP, MechanismType::RSA_PKCS);
        let failed = self.proof_failed(Check::PopDecrypt, "C_Decrypt", "decrypt", "CKA_DECRYPT");
        let plain = if usable(oaep) || (permits(oaep) && !usable(v15)) {
            // Try each hash in turn. The refusal of the last hash is the result of the proof.
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
            return Err(KmError::Conflict(Reason::check(
                Check::PopDecrypt,
                format!(
                    "proof of possession failed: the private key did not decrypt for the public key {}",
                    id::sri(spki)
                ),
            )));
        }
        Ok(())
    }

    /// `pop-unwrap`: the host wraps a fresh secret to the public key with RSA-OAEP. The token
    /// unwraps it into a non-extractable session key and computes the MAC of the challenge with
    /// it. The two MACs are equal only if the token's private key is the one that `spki` names.
    /// No plaintext leaves the token, so a transport key can prove possession without
    /// `CKA_DECRYPT`. OAEP uses the first hash in [`OAEP`] that the token does not refuse.
    fn prove_unwrap(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        if !self.proof_permits(h)?(MechanismType::RSA_PKCS_OAEP) {
            return Err(self.none_allowed(&[MechanismType::RSA_PKCS_OAEP]));
        }
        let template = self.proof_secret(Binding::PopUnwrap, true)?;
        let failed = self.proof_failed(Check::PopUnwrap, "C_UnwrapKey", "unwrap", "CKA_UNWRAP");
        // As for a derivation, a module that stores session keys as rows in its store unwraps
        // only in a read-write session. `C_UnwrapKey` is a single call, so a refused hash leaves
        // no active operation that would affect the next try.
        let mut rw: Option<Session> = None;
        // Try each hash in turn, and start again from the first hash once a read-write session
        // is open. The refusal of the last hash is the result of the proof.
        let mut next = 0;
        let (key, ch) = loop {
            let Some((padding, params)) = OAEP.get(next).and_then(|p| Some((*p, oaep_params(*p)?.0))) else {
                return Err(KmError::Unavailable(format!("token '{}': no OAEP hash to unwrap with", self.name).into()));
            };
            let ch = pop::unwrap_challenge(spki, msg, padding)?;
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
            return Err(KmError::Conflict(Reason::check(
                Check::PopUnwrap,
                format!(
                    "proof of possession failed: the private key did not unwrap for the public key {}",
                    id::sri(spki)
                ),
            )));
        }
        Ok(())
    }

    /// Returns a function that says whether the private key's own `CKA_ALLOWED_MECHANISMS` allows
    /// a proof to use a mechanism. The list narrows the choice only when it can be read. When the
    /// attribute is absent or the module refuses to read it, every mechanism is allowed. A proof
    /// records only its binding and never the mechanism, so a choice that differs between runs
    /// changes nothing that the lock records.
    fn proof_permits(&self, h: ObjectHandle) -> Result<impl Fn(MechanismType) -> bool> {
        let allowed = self.allowed_if_readable(h)?;
        Ok(move |m| permitted(allowed.as_deref(), m))
    }

    /// Returns the refusal of a proof because the key's `CKA_ALLOWED_MECHANISMS` allows none of
    /// `ms`.
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

    /// Returns what this token offers a proof of possession ([`proof_refusal`]): its usable
    /// mechanisms, and whether it unwraps at all (the `[migration] unwraps` row of its profile).
    pub fn proof_side(&self) -> ProofSide<'_> {
        let profile = self.profiles.module.as_ref();
        ProofSide {
            token: &self.name,
            profile: profile.map(|p| p.profile.as_str()),
            has: Box::new(|m| self.has(m)),
            unwraps: profile.and_then(Profile::unwraps) != Some(false),
        }
    }

    /// Checks whether this token can give a proof of possession by `binding` of a private key of
    /// `object` ([`proof_refusal`]). The check runs before anything is generated or proven.
    ///
    /// # Errors
    ///
    /// `Unsupported` (exit 15), with the provider's hint, when the token cannot give the proof.
    /// `Unsupported` for a key type for which no proof is defined.
    pub fn check_proof(&self, object: Object<'_>, binding: Binding) -> Result<()> {
        match proof_refusal(object, binding, &self.proof_side())? {
            Some(why) => Err(self.unsupported_for(Topic::Mechanism, why)),
            None => Ok(()),
        }
    }

    /// Returns the function that maps a failure of the proof's module call `call` to an error.
    /// When the token refuses to `op` with the key, the error is `Unsupported`, and the message
    /// says that the spec needs `attr` or the opt-out. When the token finds the challenge invalid,
    /// the challenge was made for a key other than the one that the token holds, so the error is
    /// a `Conflict`; the host encrypted or wrapped the challenge to the public key that the
    /// identity names. Every other failure is `Unavailable`.
    fn proof_failed(
        &self,
        check: Check,
        call: &'static str,
        op: &'static str,
        attr: &'static str,
    ) -> impl Fn(CkError) -> KmError {
        move |e| {
            let rv = rv_of(&e);
            self.proof_failure(check, call, op, attr, e).with_rv(rv)
        }
    }

    /// The mapping of [`Self::proof_failed`], before the return value is attached.
    fn proof_failure(
        &self,
        check: Check,
        call: &'static str,
        op: &'static str,
        attr: &'static str,
        e: CkError,
    ) -> KmError {
        match e {
            CkError::Pkcs11(
                RvError::KeyFunctionNotPermitted
                | RvError::MechanismInvalid
                | RvError::KeyTypeInconsistent
                | RvError::FunctionNotSupported,
                _,
            ) => self.unsupported_for(Topic::Mechanism, format!(
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
            ) => KmError::Conflict(Reason::check(check, format!(
                    "proof of possession failed: the private key on token '{}' did not {op} what was made for its \
                 public key ({call}: {}: {e})",
                    self.name,
                    rv_name(&e)
                ))),
            e => KmError::Unavailable(
                format!("{call} (proof of possession) on token '{}': {}: {e}", self.name, rv_name(&e)).into(),
            ),
        }
    }

    /// Returns whether a `pop-ecdh` proof first derives into a sealed secret
    /// ([`Self::prove_ecdh`]). It uses [`crate::ops::ecdh_seals`], which a plan also calls without
    /// the token.
    pub(crate) fn ecdh_seals(&self) -> bool {
        let derive_sealed = self.profiles.module.as_ref().and_then(|p| p.answer(&Capability::DeriveSealed));
        crate::ops::ecdh_seals(derive_sealed, Some(self.has(MechanismType::SHA256_HMAC))) == Some(true)
    }

    /// Returns the template of the session secret that a proof makes on the token (`pop-ecdh`
    /// derives it, and `pop-unwrap` unwraps it), as the provider adjusts it. When `sealed` is
    /// true, the secret is sensitive, never extractable, and usable only for signing, so that the
    /// token computes the MAC with it. Otherwise, it is the readable secret of
    /// [`Self::prove_ecdh_extractable`].
    fn proof_secret(&self, binding: Binding, sealed: bool) -> Result<Vec<Attribute>> {
        self.session_template(SessionKey::ProofSecret { binding, sealed })
    }
}

/// What a token offers a proof of possession, either from a live token ([`Token::proof_side`])
/// or from the profile of a target in camigrate's plan. It is the only input about the token that
/// [`proof_refusal`] takes.
pub struct ProofSide<'a> {
    /// The token's name in keys.toml.
    pub token: &'a str,
    /// The name of the module profile, which a refusal names.
    pub profile: Option<&'a str>,
    /// Whether the token offers a mechanism.
    pub has: Box<dyn Fn(MechanismType) -> bool + 'a>,
    /// Whether the module unwraps at all.
    pub unwraps: bool,
}

/// Returns the reason why a proof of possession by `binding` of a private key of `object` cannot
/// run on `side`, or `None` when it can. The proof itself (`Token::prove_binding`), `cakeys`
/// before it creates a key, and camigrate's plan for the target of a move all use this one check.
/// So none of them accepts a proof that another one then refuses.
///
/// # Errors
///
/// `Unsupported` for a key type or a curve for which no proof is defined.
pub fn proof_refusal(object: Object<'_>, binding: Binding, side: &ProofSide<'_>) -> Result<Option<String>> {
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

/// The RSA signatures that a `pop-sign` proof can request, in order of preference. First comes
/// PKCS #1 v1.5 over SHA-256, either hashed by the token or hashed by the host into the
/// `DigestInfo` that raw `CKM_RSA_PKCS` signs; both give the same signature. Next come the other
/// v1.5 hashes, and then PSS, either hashed by the token or over the host's digest. The hash
/// listed for a raw mechanism is only its default, which [`rsa_signature`] may replace.
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

/// Returns the RSA signature that a `pop-sign` proof requests, given the key's `allowed`
/// mechanisms (`None` means any mechanism) and the token's mechanisms (`has`). The result is the
/// first entry of [`RSA_SIGN`] that both the key and the token allow. Otherwise, it is the first
/// entry that the key allows, which is tried although the token does not list it. Otherwise, the
/// result is `None`. A raw mechanism signs over the hash of a hashed mechanism with the same
/// padding that the key allows, if there is one, and otherwise over SHA-256. This matters because
/// a key bound to SHA-512 checks the `DigestInfo` that it signs (Cloud KMS returns
/// `CKR_DATA_INVALID` \[run\]). With no allowed list, the result is what the proof always did:
/// v1.5 over SHA-256, hashed or raw.
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

/// Returns the mechanism and the data with which a `pop-sign` proof signs `msg` by `m` with
/// `scheme`. The data is the message itself for a hashed mechanism, and the host's digest (inside
/// its `DigestInfo` for v1.5) for a raw mechanism. PSS requests a salt as long as the hash,
/// because the host's verifier expects that length.
fn rsa_sign(m: MechanismType, scheme: pop::RsaSignature, msg: &[u8]) -> (Mechanism<'static>, Vec<u8>) {
    use pop::HashAlg::{Sha256, Sha384, Sha512};
    match scheme {
        pop::RsaSignature::Pkcs1v15(h) if m == MechanismType::RSA_PKCS => {
            (Mechanism::RsaPkcs, [digest_info(h), digest(h, msg).as_slice()].concat())
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
                (true, _) => (Mechanism::RsaPkcsPss(params), digest(h, msg)),
                (false, Sha256) => (Mechanism::Sha256RsaPkcsPss(params), msg.to_vec()),
                (false, Sha384) => (Mechanism::Sha384RsaPkcsPss(params), msg.to_vec()),
                (false, Sha512) => (Mechanism::Sha512RsaPkcsPss(params), msg.to_vec()),
            }
        }
    }
}

/// Returns the DER `DigestInfo` prefix of a digest by `h` (RFC 8017 §9.2, note 1).
/// `CKM_SHA*_RSA_PKCS` puts this prefix before the hash that it computes. So raw `CKM_RSA_PKCS`
/// over this prefix followed by the host's hash produces the same PKCS #1 v1.5 signature.
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

/// The OAEP hashes that a decryption proof or an unwrap proof tries, in order. SHA-1 comes first,
/// because it is the PKCS#11 baseline and the only hash that `SoftHSM` implements. SHA-256 and
/// SHA-512 follow, for a key that is bound to one of them (Cloud KMS \[run\]). Each entry sets both
/// the host's padding and the token's parameters. `CKA_ALLOWED_MECHANISMS` cannot say which hash a
/// key needs, because it names `CKM_RSA_PKCS_OAEP` and never its hash.
pub const OAEP: [pop::RsaPadding; 3] = [
    pop::RsaPadding::Oaep(cakeys_core::migrate::OaepHash::Sha1),
    pop::RsaPadding::Oaep(cakeys_core::migrate::OaepHash::Sha256),
    pop::RsaPadding::OaepSha512,
];

/// Returns the RSA-OAEP parameters with which a token runs the host's `padding`: the hash, MGF1
/// with the same hash, and an empty label. It also returns the hash's name as a capability row
/// writes it (`SHA-256`). Returns `None` for PKCS #1 v1.5, which has no OAEP parameters. The
/// proofs, the probe and camigrate's wraps all read this one table.
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

/// Returns the [`oaep_params`] of a transport wrap's hash (`OaepHash`), which always has OAEP
/// parameters.
#[must_use]
pub fn oaep_of(hash: cakeys_core::migrate::OaepHash) -> (PkcsOaepParams<'static>, &'static str) {
    let (h, mgf, name) = match hash {
        cakeys_core::migrate::OaepHash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, "SHA-1"),
        cakeys_core::migrate::OaepHash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, "SHA-256"),
    };
    (PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty()), name)
}

/// Returns whether `e` refuses an OAEP hash before the operation began (`init` is the call that
/// starts the operation), so that the next hash in [`OAEP`] may be tried. A failure after the
/// operation began never counts, because a module may leave that operation active (tpm2-pkcs11
/// \[run\]), and the session would then refuse the next operation.
fn oaep_hash_refused(e: &CkError, init: Function) -> bool {
    match e {
        CkError::Pkcs11(RvError::MechanismParamInvalid | RvError::ArgumentsBad, f) => {
            std::mem::discriminant(f) == std::mem::discriminant(&init)
        }
        _ => false,
    }
}

/// Returns the hash with which ECDSA signs a proof on the curve of `object`.
fn ecdsa_hash(object: Object<'_>) -> Result<pop::HashAlg> {
    let curve = object.curve();
    curve.and_then(pop::HashAlg::for_curve).ok_or_else(|| {
        KmError::Unsupported(
            format!("ECDSA on {}", curve.map_or_else(|| object.class.to_string(), |c| c.name().into())).into(),
        )
    })
}

/// Returns the mechanisms that a proof of possession by `binding` uses on a private key of the
/// type of `object`. The token must offer at least one mechanism of each group. Both the proof
/// itself ([`Token::prove_binding`]) and camigrate's planner check this one list, so a plan never
/// accepts a proof that the target then refuses. An ECDSA proof prefers the curve's hashed
/// mechanism and falls back to raw `CKM_ECDSA` over a digest computed on the host. An RSA proof
/// signs with any entry of [`RSA_SIGN`], as [`rsa_signature`] chooses. A decryption proof prefers
/// OAEP and falls back to PKCS #1 v1.5.
///
/// # Errors
///
/// `Unsupported` for a key type or a curve for which no proof is defined.
fn proof_mechanisms(object: Object<'_>, binding: Binding) -> Result<Vec<Vec<MechanismType>>> {
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

/// Returns whether `e` is a refusal of the template and not of the operation. Such a refusal may
/// go away when one of the template's policy defaults is dropped ([`is_policy_default`]).
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

/// Returns whether `a` is an attribute that a template carries as a policy default. A module may
/// refuse such an attribute and still make the object. A policy default is never an attribute
/// that defines the object (class, key type, curve, size) or what the object is then used for
/// (`CKA_SIGN`, `CKA_DERIVE`, and so on).
#[must_use]
pub fn is_policy_default(a: &Attribute) -> bool {
    matches!(a, Attribute::Private(_) | Attribute::Sensitive(_) | Attribute::Extractable(_))
}

/// Formats an attribute for a note, for example as `CKA_PRIVATE = false`. An attribute that is
/// not a policy default is shown by its type only.
#[must_use]
pub fn show(a: &Attribute) -> String {
    match a {
        Attribute::Private(b) | Attribute::Sensitive(b) | Attribute::Extractable(b) => {
            format!("{} = {b}", a.attribute_type())
        }
        other => other.attribute_type().to_string(),
    }
}

/// What [`derive_any`] derived: the handle and the template that the module accepted. When that
/// template is not the requested one, the third element holds what was changed and the module's
/// refusal of the requested template.
pub type Derived = (ObjectHandle, Vec<Attribute>, Option<(String, CkError)>);

/// Calls `C_DeriveKey` with `template` as requested. Only when the module refuses the template
/// does the function try again: with `CKA_VALUE_LEN` set to the secret's `len`, and without one
/// policy default at a time (AWS `CloudHSM` refuses `CKA_EXTRACTABLE = false` on a derived secret
/// \[run\]). Returns the derived handle and the template that the module accepted. When that
/// template is not the requested one, it also returns what was changed and the refusal of the
/// requested template. When the module accepts no template, that first refusal is the error.
/// `caprobe` records the change, and a proof of possession needs only a secret.
///
/// # Errors
///
/// The module's refusal of the template as requested. When a changed template passes the
/// template checks and the module refuses it for another reason (for example, a read-only
/// session), that other refusal.
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
            // The template passed, and the module refused for another reason, which the caller
            // handles. AWS CloudHSM checks the template before the session and then refuses a
            // read-only session [run], and `derive_for_proof` then derives again in a read-write
            // session.
            Err(e) if !template_refusal(&e) => return Err(e),
            Err(_) => {}
        }
    }
    Err(first)
}

/// Returns whether a key whose `CKA_ALLOWED_MECHANISMS` is `allowed` allows a proof to use `m`.
/// `None` means that the attribute is absent or cannot be read, and then every mechanism is
/// allowed.
fn permitted(allowed: Option<&[MechanismType]>, m: MechanismType) -> bool {
    allowed.is_none_or(|a| a.contains(&m))
}

/// Adds `why`, the reason why the sealed `pop-ecdh` proof failed, to the failure `e` of the
/// extractable proof that ran after it. An `Unavailable` or `Unsupported` error then names both
/// failures and keeps the return value of the module call that failed (Q3). Every other error is
/// returned unchanged.
fn after_sealed(e: KmError, why: &str) -> KmError {
    match e {
        KmError::Unavailable(m) => {
            let text = format!("{m} (sealed: {why})");
            KmError::Unavailable(m.with_text(text))
        }
        KmError::Unsupported(m) => {
            let text = format!("{m} (sealed: {why})");
            KmError::Unsupported(m.with_text(text))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pop::HashAlg::{Sha256, Sha512};
    use pop::RsaSignature::{Pkcs1v15, Pss};

    /// The mechanisms that a proof runs on the private key are the ones that core's load check
    /// names (review 2026-11-23 A-10). So every allowed list that the load accepts fits at least
    /// one proof mechanism.
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
                let groups = proof_mechanisms(Object::new(object).unwrap(), binding).unwrap();
                let ours: Vec<String> =
                    groups.first().map(|g| g.iter().map(ToString::to_string).collect()).unwrap_or_default();
                assert_eq!(ours, cakeys_core::plan::proof_mechanisms(binding, kind), "{object:?} {binding}");
            }
        }
    }

    /// The refusal of the extractable ECDH proof after the sealed proof names both failures and
    /// keeps the module's return value (possession.rs F1). A failed proof (a conflict) is
    /// returned unchanged.
    #[test]
    fn the_extractable_proofs_refusal_keeps_its_return_value() {
        let rv = Some(0x8000_0001);
        let said = |e: KmError| (e.exit_code(), e.rv(), e.to_string());
        let unavailable = after_sealed(KmError::Unavailable(Msg::from("C_DeriveKey").with_rv(rv)), "refused");
        assert_eq!(said(unavailable), (16, rv, "unavailable: C_DeriveKey (sealed: refused)".into()));
        let unsupported = after_sealed(KmError::Unsupported(Msg::from("C_DeriveKey").with_rv(rv)), "refused");
        assert_eq!(said(unsupported), (15, rv, "unsupported: C_DeriveKey (sealed: refused)".into()));
        let conflict =
            after_sealed(KmError::Conflict(Reason::check(Check::PopEcdh, "did not derive")).with_rv(rv), "refused");
        assert_eq!(said(conflict), (13, rv, "conflict: did not derive".into()));
    }

    /// A key's allowed list narrows a proof's mechanism only when the list was read.
    #[test]
    fn only_a_read_allowed_list_narrows_the_proof() {
        assert!(permitted(None, MechanismType::ECDSA));
        assert!(permitted(Some(&[MechanismType::ECDSA]), MechanismType::ECDSA));
        assert!(!permitted(Some(&[MechanismType::ECDSA_SHA256]), MechanismType::ECDSA));
    }

    /// The RSA signature that a proof requests. With no allowed list, it is what the proof always
    /// did: v1.5 over SHA-256, hashed where the token offers that, and raw otherwise. With a key's
    /// allowed list, it is the first entry of `RSA_SIGN` that the list names, and a raw mechanism
    /// signs over the hash of the hashed mechanism that the list also names (Cloud KMS's SHA-512
    /// and PSS keys \[run\]). It is `None` when the list names no RSA signature.
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
        // The data that each mechanism signs: the message for a hashed mechanism, and the digest
        // (inside its `DigestInfo` for v1.5) for a raw mechanism.
        let (_, data) = rsa_sign(raw, Pkcs1v15(Sha512), b"m");
        assert_eq!(data, [digest_info(Sha512), digest(Sha512, b"m").as_slice()].concat());
        assert_eq!(rsa_sign(raw_pss, Pss(Sha256), b"m").1, digest(Sha256, b"m"));
        assert_eq!(rsa_sign(pss256, Pss(Sha256), b"m").1, b"m");
    }

    /// The next OAEP hash is tried only after a refusal of the parameters before the operation
    /// began. It is never tried after `C_Decrypt` itself failed, or after any other refusal.
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
