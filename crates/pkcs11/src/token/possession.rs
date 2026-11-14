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
    /// (`docs/CKA_ALWAYS_AUTHENTICATE.md`).
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
    /// `Unavailable`, never a pass.
    pub(super) fn prove_binding(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        spki: &[u8],
        binding: Binding,
    ) -> Result<()> {
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
                let hash = pop::EcdsaHash::for_curve(curve_of(object)?).ok_or_else(|| {
                    KmError::Unsupported(format!("ECDSA on {}", object.curve.as_deref().unwrap_or("?")))
                })?;
                let hashed = match hash {
                    pop::EcdsaHash::Sha256 => (Mechanism::EcdsaSha256, MechanismType::ECDSA_SHA256),
                    pop::EcdsaHash::Sha384 => (Mechanism::EcdsaSha384, MechanismType::ECDSA_SHA384),
                    pop::EcdsaHash::Sha512 => (Mechanism::EcdsaSha512, MechanismType::ECDSA_SHA512),
                };
                if self.has(hashed.1) { (hashed.0, msg.to_vec()) } else { (Mechanism::Ecdsa, hash.digest(msg)) }
            }
            KeyType::EC_EDWARDS => (Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)), msg.to_vec()),
            KeyType::RSA => (Mechanism::Sha256RsaPkcs, msg.to_vec()),
            kt => return Err(KmError::Unsupported(format!("proof of possession for {kt}"))),
        };
        if !self.has(mech.mechanism_type()) {
            return Err(self.lacks_for_proof(mech.mechanism_type()));
        }
        let refused = self.proof_failed("C_Sign", "sign", "CKA_SIGN");
        let sig = if per_use_pin {
            self.sign_with_pin(&mech, h, &data, refused)?
        } else {
            self.session.sign(&mech, h, &data).map_err(refused)?
        };
        pop::verify(spki, msg, &sig)
    }

    /// Sign under a `CKA_ALWAYS_AUTHENTICATE` key's per-use policy: the context-specific login
    /// must come after `C_SignInit` and before the signature (PKCS#11 3.2 §5.1). Exactly once, never
    /// retried: the PIN is the one that opened the session, so it cannot be wrong and a successful
    /// login spends no retry; a failure (another actor locked the PIN meanwhile) is `Unavailable`.
    ///
    /// cryptoki 0.12's single-part `Session::sign` issues `C_SignInit` and `C_Sign` in one call,
    /// leaving no point for the login, so this uses the multi-part `C_SignUpdate`/`C_SignFinal`
    /// and refuses the single-part-only mechanisms (`CKM_EDDSA`, raw `CKM_ECDSA`) — and whatever
    /// a module will not sign in parts (`SoftHSM`: every `CKM_ECDSA_SHA*`) — as `Unsupported`.
    // TODO(cryptoki): patch cryptoki with a public single-part `C_Sign` after `sign_init` (like
    // the patches in nix/patches/, PR draft in upstream/rust-cryptoki/) and upstream it, then
    // sign single-part here: every key type then proves possession under its per-use PIN
    // (Ed25519, raw ECDSA, and ECDSA on modules without multi-part ECDSA, like SoftHSM).
    fn sign_with_pin(
        &self,
        mech: &Mechanism,
        h: ObjectHandle,
        data: &[u8],
        refused: impl Fn(CkError) -> KmError,
    ) -> Result<Vec<u8>> {
        if matches!(mech, Mechanism::Ecdsa | Mechanism::Eddsa(_)) {
            return Err(self.unsupported(format!(
                "token '{}' would prove possession of a CKA_ALWAYS_AUTHENTICATE key with {}, which signs \
                 in one part only and leaves cakeys no point for the per-use login; opt in with \
                 binding = \"token-asserted\"",
                self.name,
                mech.mechanism_type()
            )));
        }
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
        self.session.sign_update(data).map_err(|e| match e {
            // The operation was started and authorized: the module only refuses it in parts.
            CkError::Pkcs11(RvError::OperationNotInitialized | RvError::FunctionNotSupported, _) => {
                self.unsupported(format!(
                    "token '{}' does not sign with {} in parts ({e}), the only way cakeys can log in per \
                     use for a CKA_ALWAYS_AUTHENTICATE key; opt in with binding = \"token-asserted\"",
                    self.name,
                    mech.mechanism_type()
                ))
            }
            e => refused(e),
        })?;
        self.session.sign_final().map_err(refused)
    }

    /// `pop-ecdh`: the host holds an ephemeral key and the MAC of the challenge under the shared
    /// secret; the token derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable
    /// session key and MACs the challenge with it. The MACs agree only if the token's private key
    /// is the one `spki` names. A token without HMAC, or whose profile says it derives only into
    /// an extractable secret (`derive.sealed = false`: ykcs11 [src]), proves by
    /// [`Self::prove_ecdh_extractable`] instead.
    fn prove_ecdh(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        let ch = pop::ecdh_challenge(spki, msg)?;
        if !self.has(MechanismType::ECDH1_DERIVE) {
            return Err(self.lacks_for_proof(MechanismType::ECDH1_DERIVE));
        }
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
    /// derives only in a read-write session, `derive.read-only = false` [run]) — in a read-write
    /// session opened for it, returned so the secret is used and destroyed where it lives.
    fn derive_for_proof(
        &self,
        h: ObjectHandle,
        peer: &[u8],
        template: &[Attribute],
    ) -> Result<(ObjectHandle, Option<Session>)> {
        let mech = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        let failed = self.proof_failed("C_DeriveKey", "derive", "CKA_DERIVE");
        match self.session.derive_key(&mech, h, template) {
            Ok(derived) => Ok((derived, None)),
            Err(CkError::Pkcs11(RvError::SessionReadOnly, _)) => {
                let rw = self.extra_session(Access::Write)?;
                let derived = rw.derive_key(&mech, h, template).map_err(failed)?;
                Ok((derived, Some(rw)))
            }
            Err(e) => Err(failed(e)),
        }
    }

    /// `pop-decrypt`: the host encrypts the challenge to the public key with RSA-OAEP; the token
    /// decrypts it with the private key. The plaintext matches only if the token's private key is
    /// the one `spki` names.
    fn prove_decrypt(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        if !self.has(MechanismType::RSA_PKCS_OAEP) {
            return Err(self.lacks_for_proof(MechanismType::RSA_PKCS_OAEP));
        }
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
        for m in [MechanismType::RSA_PKCS_OAEP, MechanismType::SHA256_HMAC] {
            if !self.has(m) {
                return Err(self.lacks_for_proof(m));
            }
        }
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

    /// The token lacks the mechanism `m` a proof needs: `Unsupported`, with the opt-out.
    fn lacks_for_proof(&self, m: MechanismType) -> KmError {
        self.unsupported(format!(
            "token '{}' lacks {m} to prove possession of the private key; opt in with binding = \"token-asserted\"",
            self.name
        ))
    }

    /// How a proof's `call` failing maps: a key the token will not `op` with is `Unsupported` (the
    /// spec needs `attr`, or the opt-out); any other failure is `Unavailable`.
    fn proof_failed(&self, call: &'static str, op: &'static str, attr: &'static str) -> impl Fn(CkError) -> KmError {
        move |e| match e {
            CkError::Pkcs11(
                RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent,
                _,
            ) => self.unsupported(format!(
                "token '{}' refused to {op} with the private key ({e}); proving possession needs {attr}, or opt \
                 in with binding = \"token-asserted\"",
                self.name
            )),
            e => KmError::Unavailable(format!("{call} (proof of possession) on token '{}': {e}", self.name)),
        }
    }
}
