//! Proof of possession on the token (`cakeys_core::pop`, docs/DESIGN.md §3.6): sign, derive or decrypt a fresh challenge the host checks.

#[allow(clippy::wildcard_imports)] // the token/ split files work on the parent module's imports (R9)
use super::*;
use cakeys_core::pop;

impl Token {
    /// Proof of possession (`cakeys_core::pop`, docs/DESIGN.md §3.6), by the spec's `binding`:
    /// the private key `h` proves, by whichever capability it has, that it holds the private
    /// half of `spki`, the public key its identity hashes. A proof that does not verify is a
    /// `Conflict`; a token that cannot prove is `Unsupported` or `Unavailable`, never a pass.
    pub(super) fn prove_binding(
        &self,
        h: ObjectHandle,
        object: &ObjectCfg,
        spki: &[u8],
        binding: Binding,
    ) -> Result<()> {
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
            return Err(self.unsupported(format!(
                "token '{}' lacks {} to prove possession of the private key; opt in with binding = \"token-asserted\"",
                self.name,
                mech.mechanism_type()
            )));
        }
        let sig = self.session.sign(&mech, h, &data).map_err(|e| match e {
            CkError::Pkcs11(
                RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent,
                _,
            ) => self.unsupported(format!(
                "token '{}' refused to sign with the private key ({e}); proving possession needs CKA_SIGN, \
                     or opt in with binding = \"token-asserted\"",
                self.name
            )),
            e => KmError::Unavailable(format!("C_Sign (proof of possession) on token '{}': {e}", self.name)),
        })?;
        pop::verify(spki, msg, &sig)
    }

    /// `pop-ecdh`: the host holds an ephemeral key and the MAC of the challenge under the shared
    /// secret; the token derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable
    /// session key and MACs the challenge with it. The MACs agree only if the token's private key
    /// is the one `spki` names.
    fn prove_ecdh(&self, h: ObjectHandle, spki: &[u8], msg: &[u8]) -> Result<()> {
        fn lacking(t: &Token, what: &str) -> KmError {
            t.unsupported(format!(
                "token '{}' lacks {what} to prove possession of the private key; opt in with binding = \"token-asserted\"",
                t.name
            ))
        }
        let ch = pop::ecdh_challenge(spki, msg)?;
        if !self.has(MechanismType::ECDH1_DERIVE) {
            return Err(lacking(self, "CKM_ECDH1_DERIVE"));
        }
        if !self.has(MechanismType::SHA256_HMAC) {
            return Err(lacking(self, "CKM_SHA256_HMAC"));
        }
        let derived = self
            .session
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
                CkError::Pkcs11(
                    RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent,
                    _,
                ) => self.unsupported(format!(
                    "token '{}' refused to derive with the private key ({e}); proving possession needs CKA_DERIVE, \
                         or opt in with binding = \"token-asserted\"",
                    self.name
                )),
                e => KmError::Unavailable(format!("C_DeriveKey (proof of possession) on token '{}': {e}", self.name)),
            })?;
        // A session object: dropped with the session even if destroying it fails here.
        let tag = self
            .session
            .sign(&Mechanism::Sha256Hmac, derived, msg)
            .inspect_err(|_| {
                let _ = self.session.destroy_object(derived);
            })
            .map_err(|e| {
                KmError::Unavailable(format!("C_Sign (ECDH proof of possession) on token '{}': {e}", self.name))
            })?;
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
            .map_err(|e| match e {
                CkError::Pkcs11(
                    RvError::KeyFunctionNotPermitted | RvError::MechanismInvalid | RvError::KeyTypeInconsistent,
                    _,
                ) => self.unsupported(format!(
                    "token '{}' refused to decrypt with the private key ({e}); proving possession needs CKA_DECRYPT, \
                         or opt in with binding = \"token-asserted\"",
                    self.name
                )),
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
}
