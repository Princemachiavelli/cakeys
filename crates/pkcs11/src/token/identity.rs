//! The material CA-IDs: the canonical SPKI of a key, and the secret-key commitments (directly or through a wrap-and-rebind copy).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// Compute the material CA-IDs of the object using `mode`; secret keys use `commits`. With
    /// `binding`, `h` is a private key whose possession of the public key hashed is proven
    /// (`None`, or `TokenAsserted`, proves nothing).
    ///
    /// # Errors
    ///
    /// `Conflict` when the token's own cross-checks disagree (a `CKA_PUBLIC_KEY_INFO` that is
    /// not the object's material, a wrong `CKA_KEY_TYPE`); `NotFound`/`Ambiguous` when the
    /// public half the object's identity needs is absent or duplicated under the locator;
    /// `Unsupported` for an unimplemented mode, unreadable material or a curve/mechanism the
    /// token exposes but cakeys cannot use.
    #[expect(clippy::too_many_arguments, reason = "one caller (`ops::compute_ids`), the one place they meet")]
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
            Mode::Direct if class_of(object) == ObjectClass::CERTIFICATE => {
                let Some(Attribute::Value(der)) = self.attr(h, AttributeType::Value)? else {
                    return Err(KmError::Unsupported("certificate has no readable CKA_VALUE".into()));
                };
                ids.insert(Scheme::Certhash.name().into(), id::sri(&der));
                ids.insert(Scheme::Rfc7093m4.name().into(), id::sri(&id::cert_spki(&der)?));
            }
            Mode::Direct if class_of(object) == ObjectClass::DATA => {
                // SHA-256 of the content: the same SRI hash as a flat Nix fixed-output hash.
                let Some(Attribute::Value(value)) = self.attr(h, AttributeType::Value)? else {
                    return Err(KmError::Unsupported("data object has no readable CKA_VALUE".into()));
                };
                ids.insert(Scheme::Valuehash.name().into(), id::sri(&value));
            }
            Mode::Direct => {
                let spki = self.spki(h, loc)?;
                if let Some(b) = binding.filter(|b| b != &Binding::TokenAsserted) {
                    self.prove_binding(h, object, &spki, b)?;
                }
                ids.insert(Scheme::Rfc7093m4.name().into(), id::sri(&spki));
            }
            Mode::Commitment => {
                for c in commits {
                    ids.insert(c.scheme().name().into(), id::sri(&self.commit(h, object, *c, commitment_label)?));
                }
            }
            Mode::WrapRebind => {
                for (c, out) in self.wrap_rebind(h, object, commits, commitment_label)? {
                    ids.insert(c.scheme().name().into(), id::sri(&out));
                }
            }
            m => return Err(KmError::Unsupported(format!("identity mode '{m}' is not implemented in this POC"))),
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
    /// it be set without checking (`SoftHSM`, kryoptic), so it is never trusted on its own.
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

    /// Consumers may select a key's public half by the locator alone (`pkcs11:object=…;type=public`):
    /// every public key object under the locator of the private key `h` must hold `h`'s own
    /// public key. Checked on every resolve, declared `publicAttributes` or not.
    ///
    /// # Errors
    ///
    /// `Conflict` (13) for a public key object holding another key, or exposing no key material
    /// to compare; whatever [`Self::spki`] refuses for `h`.
    pub fn check_public_objects(&self, h: ObjectHandle, loc: &Locator) -> Result<()> {
        let spki = self.spki(h, loc)?;
        for p in self.find(ObjectClass::PUBLIC_KEY, loc)? {
            match self.held_spki(p) {
                Some(held) if held == spki => {}
                Some(held) => {
                    return Err(KmError::Conflict(format!(
                        "a public key object under locator {loc} on token '{}' holds another key ({}) than the \
                         private key ({}); a consumer selecting the public half by the locator would get it",
                        self.name,
                        id::sri(&held),
                        id::sri(&spki)
                    )));
                }
                None => {
                    return Err(KmError::Conflict(format!(
                        "a public key object under locator {loc} on token '{}' exposes no key material, so it \
                         cannot be told apart from another key's",
                        self.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// The public key a public key object holds: its material, else its `CKA_PUBLIC_KEY_INFO`;
    /// `None` when it exposes neither in a form cakeys reads.
    pub(super) fn held_spki(&self, p: ObjectHandle) -> Option<Vec<u8>> {
        match self.material_spki(p) {
            Ok(Some(s)) => Some(s),
            Ok(None) => self.public_key_info(p).and_then(Result::ok),
            Err(_) => None,
        }
    }

    /// `CKA_PUBLIC_KEY_INFO`, canonicalized; `None` when absent, empty or unreadable (ykcs11
    /// reports length 0 and then fails the fetch with `CKR_ARGUMENTS_BAD`).
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

    /// SPKI from the key material attributes of `h`; `None` when it carries none (e.g. an EC
    /// private key without `CKA_EC_POINT`).
    pub(super) fn material_spki(&self, h: ObjectHandle) -> Result<Option<Vec<u8>>> {
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
        let fail =
            |e: CkError| KmError::Unsupported(format!("{} commitment ({}): {e}", c.scheme(), commit_mechanism(c)));
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
            let copy = s.unwrap_key(&wrap, kek, &blob, &template).map_err(fail("C_UnwrapKey"))?;
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
}

/// Mechanism a commitment runs on the token.
#[must_use]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers for the parts of each scheme's definition that live here: which HMAC hash a
    /// key type commits with, and which mechanism each commitment runs (docs/DESIGN.md §10).
    #[test]
    fn commitment_mechanisms_are_pinned() {
        for (key_type, hash, mech) in [
            ("CKK_GENERIC_SECRET".parse::<Kt>().unwrap(), HmacHash::Sha256, MechanismType::SHA256_HMAC),
            ("CKK_SHA_1_HMAC".parse::<Kt>().unwrap(), HmacHash::Sha1, MechanismType::SHA1_HMAC),
            ("CKK_SHA224_HMAC".parse::<Kt>().unwrap(), HmacHash::Sha224, MechanismType::SHA224_HMAC),
            ("CKK_SHA256_HMAC".parse::<Kt>().unwrap(), HmacHash::Sha256, MechanismType::SHA256_HMAC),
            ("CKK_SHA384_HMAC".parse::<Kt>().unwrap(), HmacHash::Sha384, MechanismType::SHA384_HMAC),
            ("CKK_SHA512_HMAC".parse::<Kt>().unwrap(), HmacHash::Sha512, MechanismType::SHA512_HMAC),
        ] {
            assert_eq!(HmacHash::for_key_type(key_type), Some(hash), "{key_type}");
            assert_eq!(commit_mechanism(Commit::Hmac(hash)), mech, "{key_type}");
        }
        assert_eq!(HmacHash::for_key_type(Kt::Aes), None);
        assert_eq!(commit_mechanism(Commit::Cmac), MechanismType::AES_CMAC);
        assert_eq!(commit_mechanism(Commit::KcvEcb), MechanismType::AES_ECB);
        assert_eq!(commit_mechanism(Commit::KcvEcbDecrypt), MechanismType::AES_ECB);
        assert_eq!(commit_mechanism(Commit::Kw), MechanismType::AES_KEY_WRAP);
    }
}
