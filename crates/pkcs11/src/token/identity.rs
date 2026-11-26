//! The material CA-IDs. This file computes the canonical SPKI of a key, and the commitments of a
//! secret key, either directly or through a wrap-and-rebind copy.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// Computes the material CA-IDs of the object with `mode`. Secret keys use the commitments
    /// `commits`. With `binding`, `h` is a private key, and the function proves that it possesses
    /// the public key that is hashed (`None` or `TokenAsserted` proves nothing). `spki` is the
    /// key's own SPKI ([`Self::spki`]) when the caller has already read it.
    ///
    /// # Errors
    ///
    /// - `Conflict` when the token's own cross-checks disagree (a `CKA_PUBLIC_KEY_INFO` that is
    ///   not the object's material, or a wrong `CKA_KEY_TYPE`).
    /// - `NotFound` or `Ambiguous` when the public half that the object's identity needs is
    ///   absent or duplicated under the locator.
    /// - `Unsupported` for an unimplemented mode, for material that cannot be read, or for a curve
    ///   or a mechanism that the token exposes but cakeys cannot use.
    #[expect(clippy::too_many_arguments, reason = "one caller (`ops::compute_ids`), the one place they meet")]
    pub fn ids(
        &self,
        h: ObjectHandle,
        object: Object<'_>,
        loc: &Locator,
        mode: Mode,
        commits: &[Commit],
        commitment_label: &str,
        binding: Option<Binding>,
        spki: Option<&[u8]>,
    ) -> Result<BTreeMap<String, String>> {
        let mut ids = BTreeMap::new();
        match mode {
            Mode::Direct if class_of(&object) == ObjectClass::CERTIFICATE => {
                let Some(Attribute::Value(der)) = self.attr(h, AttributeType::Value)? else {
                    return Err(KmError::Unsupported("certificate has no readable CKA_VALUE".into()));
                };
                ids.insert(Scheme::Certhash.name().into(), id::sri(&der));
                ids.insert(Scheme::Rfc7093m4.name().into(), id::sri(&id::cert_spki(&der)?));
            }
            Mode::Direct if class_of(&object) == ObjectClass::DATA => {
                // The ID is the SHA-256 hash of the content, which is the same SRI hash as a
                // flat Nix fixed-output hash.
                let Some(Attribute::Value(value)) = self.attr(h, AttributeType::Value)? else {
                    return Err(KmError::Unsupported("data object has no readable CKA_VALUE".into()));
                };
                ids.insert(Scheme::Valuehash.name().into(), id::sri(&value));
            }
            Mode::Direct => {
                let spki = spki.map_or_else(|| self.spki(h, loc), |s| Ok(s.to_vec()))?;
                if let Some(b) = binding {
                    self.prove_binding(h, object, &spki, b)?;
                }
                ids.insert(Scheme::Rfc7093m4.name().into(), id::sri(&spki));
            }
            Mode::Commitment => {
                for c in commits {
                    ids.insert(c.scheme().name().into(), id::sri(&self.commit(h, &object, *c, commitment_label)?));
                }
            }
            Mode::WrapRebind => {
                for (c, out) in self.wrap_rebind(h, object, commits, commitment_label)? {
                    ids.insert(c.scheme().name().into(), id::sri(&out));
                }
            }
        }
        Ok(ids)
    }

    /// Returns the canonical SPKI of a key, computed from key material and not from what the
    /// module asserts. The sources are tried in this order:
    /// 1. the object's own material (the RSA modulus and exponent, or the EC parameters and
    ///    point);
    /// 2. otherwise, the single public key object under the locator (EC and Edwards private keys
    ///    expose no point, and possession of the private half is proven separately);
    /// 3. otherwise, `CKA_PUBLIC_KEY_INFO`;
    /// 4. otherwise, the single certificate under the locator. This covers an imported key whose
    ///    importer wrote only the certificate beside it, as in a PIV-style slot or a PKCS #12
    ///    import. The certificate is used in the same way as a public key object and is not
    ///    trusted more: a binding proves that the private key belongs to it.
    ///
    /// When `CKA_PUBLIC_KEY_INFO` is present, it must agree with the material. Some modules let it
    /// be set without a check (`SoftHSM`, kryoptic), so it is never trusted on its own.
    ///
    /// # Errors
    ///
    /// `NotFound` or `Ambiguous` when no single public key object or certificate can replace
    /// the missing material. `Conflict` when `CKA_PUBLIC_KEY_INFO` disagrees with the material,
    /// or when the public key that was found has another key type or curve than the key. Any
    /// error from reading or re-encoding the key.
    pub fn spki(&self, h: ObjectHandle, loc: &Locator) -> Result<Vec<u8>> {
        let spki = match self.material_spki(h)? {
            Some(spki) => spki,
            None => match self.find(ObjectClass::PUBLIC_KEY, loc)?.as_slice() {
                [p] => {
                    let spki = match self.material_spki(*p)? {
                        Some(spki) => spki,
                        None => self.public_key_info(*p)?.ok_or_else(|| {
                            KmError::NotFound("the public key object exposes no key material".into())
                        })??,
                    };
                    self.cross_check(*p, &spki)?;
                    spki
                }
                [] => match self.public_key_info(h)? {
                    Some(spki) => spki?,
                    None => self.certificate_spki(loc)?,
                },
                _ => {
                    return Err(KmError::Ambiguous(Reason::check(
                        Check::LocatorUnique,
                        "several public key objects share the locator",
                    )));
                }
            },
        };
        self.cross_check(h, &spki)?;
        self.check_kind(h, &spki)?;
        Ok(spki)
    }

    /// Checks that the public key that [`Self::spki`] found has the key's own type and curve. The
    /// key's own material always has them. A substitute (a public key object or a certificate)
    /// might not, and under `token-asserted` no other check would stop the public key of another
    /// key from being used as this key's identity.
    fn check_kind(&self, h: ObjectHandle, spki: &[u8]) -> Result<()> {
        let own = match self.attr(h, AttributeType::KeyType)? {
            Some(Attribute::KeyType(KeyType::RSA)) => Some(None),
            Some(Attribute::KeyType(KeyType::EC | KeyType::EC_EDWARDS)) => {
                match self.attr(h, AttributeType::EcParams)? {
                    Some(Attribute::EcParams(p)) => Curve::from_params(&p).map(Some),
                    _ => None,
                }
            }
            _ => None,
        };
        // The key has nothing of its own to compare (its type cannot be read, or its curve is
        // unknown). In that case, the read of the substitute's key has already refused any key
        // that cakeys cannot use.
        let Some(own) = own else { return Ok(()) };
        let found = id::KeyAlg::of_spki(spki)?.curve();
        if found == own {
            return Ok(());
        }
        let name = |c: Option<Curve>| c.map_or("RSA", Curve::name);
        Err(KmError::Conflict(Reason::check(
            Check::PublicKeyType,
            format!(
                "token '{}': the public key found for the private key is {} ({}), but the private key is {}",
                self.name,
                name(found),
                id::sri(spki),
                name(own)
            ),
        )))
    }

    /// Returns the public key of the single certificate under the locator. This certificate is
    /// the last substitute that [`Self::spki`] uses for a private key that exposes no public key.
    fn certificate_spki(&self, loc: &Locator) -> Result<Vec<u8>> {
        match self.find(ObjectClass::CERTIFICATE, loc)?.as_slice() {
            [c] => match self.attr(*c, AttributeType::Value)? {
                Some(Attribute::Value(der)) => id::cert_spki(&der),
                _ => Err(KmError::NotFound("the certificate under the locator has no readable CKA_VALUE".into())),
            },
            [] => Err(KmError::NotFound(
                "the private key exposes no public key, and no public key object, CKA_PUBLIC_KEY_INFO or \
                 certificate under the locator holds it; write its public key object or certificate beside it"
                    .into(),
            )),
            _ => Err(KmError::Ambiguous(Reason::check(
                Check::LocatorUnique,
                "no public key object, and several certificates share the locator: which holds the key's public \
                 half is unclear",
            ))),
        }
    }

    /// Checks that every public key object under the locator of a private key holds its public
    /// key, `spki` ([`Self::spki`]). The check is needed because consumers may select a key's
    /// public half by the locator alone (`pkcs11:object=…;type=public`). It runs on every
    /// resolve, whether or not the spec declares `publicAttributes`.
    ///
    /// # Errors
    ///
    /// `Conflict` (exit 13) for a public key object that holds another key, or that exposes no
    /// key material to compare. `Unavailable` when a read fails.
    pub fn check_public_objects(&self, spki: &[u8], loc: &Locator) -> Result<()> {
        for p in self.find(ObjectClass::PUBLIC_KEY, loc)? {
            match self.held_spki(p)? {
                Some(held) if held == spki => {}
                Some(held) => {
                    return Err(KmError::Conflict(Reason::check(
                        Check::PublicSameKey,
                        format!(
                            "a public key object under locator {loc} on token '{}' holds another key ({}) than the \
                         private key ({}); a consumer selecting the public half by the locator would get it",
                            self.name,
                            id::sri(&held),
                            id::sri(spki)
                        ),
                    )));
                }
                None => {
                    return Err(KmError::Conflict(Reason::check(
                        Check::PublicSameKey,
                        format!(
                            "a public key object under locator {loc} on token '{}' exposes no key material, so it \
                         cannot be told apart from another key's",
                            self.name
                        ),
                    )));
                }
            }
        }
        Ok(())
    }

    /// Returns the public key that a public key object holds: its material, or otherwise its
    /// `CKA_PUBLIC_KEY_INFO`. Returns `None` when the object exposes neither in a form that cakeys
    /// reads.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the device, the token or the session fails a read ([`if_readable`]).
    /// Such a failure never becomes `None`, because every caller treats `None` as the object of
    /// another key.
    pub(super) fn held_spki(&self, p: ObjectHandle) -> Result<Option<Vec<u8>>> {
        let read = |types: &[AttributeType]| if_readable(self.session.get_attributes(p, types).map(Some));
        match self.material_spki_by(read) {
            Ok(Some(s)) => Ok(Some(s)),
            Ok(None) => Ok(self.public_key_info(p)?.and_then(Result::ok)),
            // The attributes are read leniently. Only a failed device, token or session is
            // `Unavailable`, and any other error means a key that cakeys does not read.
            Err(e @ KmError::Unavailable(_)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    /// Returns `CKA_PUBLIC_KEY_INFO` in canonical form, or `None` when it is absent, empty or
    /// refused (ykcs11 reports a length of 0 and then fails the fetch with `CKR_ARGUMENTS_BAD`).
    ///
    /// # Errors
    ///
    /// `Unavailable` when the device, token or session fails the read ([`if_readable`]).
    fn public_key_info(&self, h: ObjectHandle) -> Result<Option<Result<Vec<u8>>>> {
        Ok(match self.attr_if_readable(h, AttributeType::PublicKeyInfo)? {
            Some(Attribute::PublicKeyInfo(der)) if !der.is_empty() => Some(id::spki_canonical(&der)),
            _ => None,
        })
    }

    /// Fails with `Conflict` when the object's `CKA_PUBLIC_KEY_INFO` names a different key than
    /// its material.
    fn cross_check(&self, h: ObjectHandle, spki: &[u8]) -> Result<()> {
        match self.public_key_info(h)? {
            Some(Ok(asserted)) if asserted != spki => Err(KmError::Conflict(Reason::check(
                Check::PublicKeyInfo,
                format!(
                    "token '{}' reports a CKA_PUBLIC_KEY_INFO ({}) that disagrees with the key material ({})",
                    self.name,
                    id::sri(&asserted),
                    id::sri(spki)
                ),
            ))),
            _ => Ok(()),
        }
    }

    /// Returns the SPKI built from the key material attributes of `h`, or `None` when `h` has no
    /// such attributes (for example, an EC private key without `CKA_EC_POINT`).
    ///
    /// # Errors
    ///
    /// `Unavailable` when the module refuses `C_GetAttributeValue`. `Unsupported` for a curve
    /// that cakeys does not know, or for a key type that is not RSA, EC or Edwards. Any error
    /// from re-encoding the point or the RSA key.
    pub fn material_spki(&self, h: ObjectHandle) -> Result<Option<Vec<u8>>> {
        self.material_spki_by(|types| {
            self.session.get_attributes(h, types).map(Some).map_err(ck("C_GetAttributeValue"))
        })
    }

    /// Works as [`Self::material_spki`], but reads the attributes with `read`. When `read` returns
    /// `None`, the attributes were not read.
    fn material_spki_by(
        &self,
        read: impl Fn(&[AttributeType]) -> Result<Option<Vec<Attribute>>>,
    ) -> Result<Option<Vec<u8>>> {
        match read(&[AttributeType::KeyType])?.and_then(|a| a.into_iter().next()) {
            Some(Attribute::KeyType(KeyType::EC | KeyType::EC_EDWARDS)) => {
                match read(&[AttributeType::EcParams, AttributeType::EcPoint])?.as_deref() {
                    Some([Attribute::EcParams(params), Attribute::EcPoint(p)]) => Curve::from_params(params)
                        .ok_or_else(|| KmError::Unsupported(format!("CKA_EC_PARAMS {params:02x?}").into()))?
                        .spki_from_point(&self.provider.ec_point(p))
                        .map(Some),
                    _ => Ok(None),
                }
            }
            Some(Attribute::KeyType(KeyType::RSA)) => {
                match read(&[AttributeType::Modulus, AttributeType::PublicExponent])?.as_deref() {
                    Some([Attribute::Modulus(n), Attribute::PublicExponent(e)]) => id::rsa_spki(n, e).map(Some),
                    _ => Ok(None),
                }
            }
            kt => Err(KmError::Unsupported(format!("public key of type {kt:?}").into())),
        }
    }

    /// Computes one commitment (`id::Commit`) on the key `h`. The verbs compute this value, and
    /// the `commit.*` rows of caprobe measure it.
    ///
    /// # Errors
    ///
    /// `Unsupported`, with the module's `CK_RV`, when the module refuses the operation.
    /// `Unavailable` when the device, the token or the session failed
    /// ([`refused_unless_device`]).
    pub fn commit(&self, h: ObjectHandle, object: &ObjectCfg, c: Commit, commitment_label: &str) -> Result<Vec<u8>> {
        let s = &self.session;
        let input = c.input(commitment_label, object);
        let fail = |e: CkError| {
            let msg = Msg::from(format!("{} commitment ({}): {e}", c.scheme(), commit_mechanism(c)));
            refused_unless_device(msg.with_rv(rv_of(&e)), KmError::Unsupported)
        };
        let m = operation(c);
        match c {
            Commit::Hmac(_) | Commit::Cmac => s.sign(&m, h, &input).map_err(fail),
            Commit::KcvEcb(_) => s.encrypt(&m, h, &input).map_err(fail),
            Commit::KcvEcbDecrypt(_) => s.decrypt(&m, h, &input).map_err(fail),
            Commit::Kw => {
                let mut template = self.session_template(SessionKey::KwInput)?;
                template.push(Attribute::Value(input));
                let fixed = s.create_object(&template).map_err(fail)?;
                let fixed = SessionObject::new(s, fixed);
                s.wrap_key(&m, h, fixed.handle()).map_err(fail)
            }
        }
    }

    /// Computes the commitments through a temporary session copy of the key (docs/DESIGN.md
    /// §3.4; docs/archive/PRIOR-ART.md, "Wrap-and-rebind", gives the reasoning). The function
    /// generates a session wrapping key on the token, wraps the key, unwraps it as a key of the
    /// same type that allows every operation that `commits` needs, computes the commitments, and
    /// destroys the session objects.
    fn wrap_rebind(
        &self,
        target: ObjectHandle,
        object: Object<'_>,
        commits: &[Commit],
        commitment_label: &str,
    ) -> Result<Vec<(Commit, Vec<u8>)>> {
        let s = &self.session;
        let fail = |what: &'static str| {
            move |e: CkError| {
                refused_unless_device(
                    Msg::from(format!("wrap-rebind {what}: {e}")).with_rv(rv_of(&e)),
                    KmError::Unsupported,
                )
            }
        };
        // Build both templates before any object is made.
        let kek_template = self.session_template(SessionKey::RebindKek)?;
        let template = self.rebind_copy_template(object, commits)?;
        let kek = s.generate_key(&Mechanism::AesKeyGen, &kek_template).map_err(fail("generating session KEK"))?;
        // Both session objects are destroyed when this function returns, whether it succeeds or
        // fails.
        let kek = SessionObject::new(s, kek);
        let wrap =
            if self.has(MechanismType::AES_KEY_WRAP_PAD) { Mechanism::AesKeyWrapPad } else { Mechanism::AesKeyWrap };
        let blob = s.wrap_key(&wrap, kek.handle(), target).map_err(fail("C_WrapKey"))?;
        let copy = s.unwrap_key(&wrap, kek.handle(), &blob, &template).map_err(fail("C_UnwrapKey"))?;
        let copy = SessionObject::new(s, copy);
        commits.iter().map(|c| Ok((*c, self.commit(copy.handle(), &object, *c, commitment_label)?))).collect()
    }

    /// Returns the template of the wrap-rebind copy of the key of `object` for `commits`
    /// ([`templates::rebind_copy`]), as the provider adjusts it.
    ///
    /// # Errors
    ///
    /// The errors of [`templates::rebind_copy`], and the provider's refusal.
    pub(crate) fn rebind_copy_template(&self, object: Object<'_>, commits: &[Commit]) -> Result<Vec<Attribute>> {
        self.provider.adjusted_session(templates::rebind_copy(object, commits)?)
    }
}

/// Returns the mechanism with which a commitment is computed, as a cryptoki value. It is the
/// mechanism that [`Commit::mechanism`] names, which comes from the names table
/// (`cakeys_names::CommitKind::mechanism`).
#[must_use]
pub fn commit_mechanism(c: Commit) -> MechanismType {
    operation(c).mechanism_type()
}

/// Returns the operation that [`Token::commit`] runs for a commitment, as cryptoki names it. This
/// is the only place on the token side that spells a commitment's mechanism, and the test
/// `commitment_mechanisms_are_pinned` checks it against the names table.
fn operation(c: Commit) -> Mechanism<'static> {
    match c {
        Commit::Hmac(HmacHash::Sha1) => Mechanism::Sha1Hmac,
        Commit::Hmac(HmacHash::Sha224) => Mechanism::Sha224Hmac,
        Commit::Hmac(HmacHash::Sha256) => Mechanism::Sha256Hmac,
        Commit::Hmac(HmacHash::Sha384) => Mechanism::Sha384Hmac,
        Commit::Hmac(HmacHash::Sha512) => Mechanism::Sha512Hmac,
        Commit::Cmac => Mechanism::AesCMac,
        Commit::KcvEcb(BlockCipher::Aes) | Commit::KcvEcbDecrypt(BlockCipher::Aes) => Mechanism::AesEcb,
        Commit::KcvEcb(BlockCipher::Des3) | Commit::KcvEcbDecrypt(BlockCipher::Des3) => Mechanism::Des3Ecb,
        Commit::Kw => Mechanism::AesKeyWrap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers for the parts of each scheme's definition that are in this file: the HMAC
    /// hash with which each key type commits, and the mechanism that each commitment runs
    /// (docs/DESIGN.md §10).
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
        assert_eq!(commit_mechanism(Commit::KcvEcb(BlockCipher::Aes)), MechanismType::AES_ECB);
        assert_eq!(commit_mechanism(Commit::KcvEcbDecrypt(BlockCipher::Aes)), MechanismType::AES_ECB);
        assert_eq!(commit_mechanism(Commit::KcvEcb(BlockCipher::Des3)), MechanismType::DES3_ECB);
        assert_eq!(commit_mechanism(Commit::KcvEcbDecrypt(BlockCipher::Des3)), MechanismType::DES3_ECB);
        assert_eq!(commit_mechanism(Commit::Kw), MechanismType::AES_KEY_WRAP);
        // The mechanism name from the names table is the name by which the core code filters a
        // declared `CKA_ALLOWED_MECHANISMS`, and with which a profile's `commit.*` row was
        // measured. It must be the mechanism that the token runs.
        let all = [
            Commit::Cmac,
            Commit::KcvEcb(BlockCipher::Aes),
            Commit::KcvEcbDecrypt(BlockCipher::Aes),
            Commit::KcvEcb(BlockCipher::Des3),
            Commit::KcvEcbDecrypt(BlockCipher::Des3),
            Commit::Kw,
        ]
        .into_iter()
        .chain(
            [HmacHash::Sha1, HmacHash::Sha224, HmacHash::Sha256, HmacHash::Sha384, HmacHash::Sha512].map(Commit::Hmac),
        );
        for c in all {
            assert_eq!(commit_mechanism(c).to_string(), c.mechanism(), "{}", c.scheme());
        }
    }
}
