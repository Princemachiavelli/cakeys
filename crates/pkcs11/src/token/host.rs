//! The `host` path on a token (docs/CAMIGRATE.md D2, phase 4). This file hands a key to this
//! process in plaintext, and it creates a key from the host's plaintext. Only `camigrate` calls
//! these functions, and only with `--allow-host-plaintext`. Every plaintext buffer is zeroized
//! when it is dropped, including the copies inside creation templates. No plaintext buffer is
//! formatted, logged or put in an error.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use aes_kw::cipher::KeyInit as _;
use cakeys_core::plaintext::PrivateParts;
use zeroize::{Zeroize as _, Zeroizing};

impl Token {
    /// Hands the key `h` to this process. The host draws a fresh AES-256 key and creates it on
    /// the token as a session key. The token wraps `h` under that session key with `kwp`
    /// (RFC 5649), and the host unwraps the result in memory. A private key unwraps to its PKCS#8
    /// `PrivateKeyInfo`, and a secret key unwraps to its value. The session key is destroyed in
    /// every case. No caller may write the returned key anywhere before
    /// [`check_identity`](crate::ops::check_identity) confirms that it is the key that the lock
    /// pins, because a module may hand over a different key (review 2026-11-24 D-5).
    ///
    /// # Errors
    ///
    /// `Unavailable` when the random number generator or the device fails. `Unsupported` when the
    /// module will not make the session key or will not wrap the key with it (because of
    /// `CKA_EXTRACTABLE` or the mechanism). `Conflict` when the wrapped key does not unwrap.
    pub fn extract(&self, h: ObjectHandle, kwp: &Mechanism) -> Result<crate::ops::Extracted> {
        let mut kek = Zeroizing::new([0u8; 32]);
        getrandom::fill(kek.as_mut_slice())
            .map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
        let mut template = Secret(self.session_template(SessionKey::HostKek)?);
        template.0.push(Attribute::Value(kek.to_vec()));
        let refused =
            |what: &str, e: CkError| self.refused_for(Topic::Mechanism, &e, format!("{what} on '{}': {e}", self.name));
        let session_kek =
            self.session.create_object(&template.0).map_err(|e| refused("making the host's session key", e))?;
        drop(template);
        let session_kek = SessionObject::new(&self.session, session_kek);
        let blob = self.session.wrap_key(kwp, session_kek.handle(), h);
        drop(session_kek);
        let blob = blob.map_err(|e| refused("wrapping the key for the host", e))?;
        let mut out = Zeroizing::new(vec![0u8; blob.len()]);
        let n = aes_kw::KwpAes256::new_from_slice(kek.as_slice())
            .map_err(|_| KmError::Unavailable("AES-256 key schedule".into()))?
            .unwrap_key(&blob, &mut out)
            .map_err(|_| {
                KmError::Conflict(Reason::check(
                    Check::HostUnwraps,
                    format!("'{}': the key wrapped for the host does not unwrap", self.name),
                ))
            })?
            .len();
        out.truncate(n);
        Ok(crate::ops::Extracted::new(out))
    }

    /// Creates a private key from its `parts`, under the template `base` (the class, the key
    /// type, `CKA_TOKEN`, the locator and the spec's policy attributes). The provider has already
    /// adjusted `base` as a [`Template::Import`] by [`Via::CreateObject`]. The caller makes that
    /// adjustment, so that a refusal by the provider comes before the public half is made. The
    /// plaintext copies in the template are zeroized after the call.
    ///
    /// [`Via::CreateObject`]: crate::provider::Via::CreateObject
    ///
    /// # Errors
    ///
    /// `Conflict` for EC or Edwards parts when `object` names no curve. `Unsupported` when the
    /// module will not create the key (`C_CreateObject`).
    pub fn create_private(
        &self,
        object: Object<'_>,
        mut base: Vec<Attribute>,
        parts: &PrivateParts,
    ) -> Result<ObjectHandle> {
        match parts {
            PrivateParts::Ec(scalar) | PrivateParts::Edwards(scalar) => {
                let curve = object.curve().ok_or_else(|| {
                    KmError::Conflict(Reason::check(
                        Check::HostKeyType,
                        format!("an EC private key's parts for {}", object.cfg()),
                    ))
                })?;
                base.push(Attribute::EcParams(curve.params().to_vec()));
                base.push(Attribute::Value(scalar.to_vec()));
            }
            PrivateParts::Rsa(p) => base.extend([
                Attribute::Modulus(p.modulus.clone()),
                Attribute::PublicExponent(p.public_exponent.clone()),
                Attribute::PrivateExponent(p.private_exponent.to_vec()),
                Attribute::Prime1(p.prime_1.to_vec()),
                Attribute::Prime2(p.prime_2.to_vec()),
                Attribute::Exponent1(p.exponent_1.to_vec()),
                Attribute::Exponent2(p.exponent_2.to_vec()),
                Attribute::Coefficient(p.coefficient.to_vec()),
            ]),
        }
        self.create_secret_template(&Secret(base))
    }

    /// Creates a secret key with the value `value` under the template `base`, which the provider
    /// has adjusted in the same way as for [`Self::create_private`].
    ///
    /// # Errors
    ///
    /// `Unsupported` when the module will not create the key.
    pub fn create_secret(&self, mut base: Vec<Attribute>, value: &[u8]) -> Result<ObjectHandle> {
        base.push(Attribute::Value(value.to_vec()));
        self.create_secret_template(&Secret(base))
    }

    /// Imports a key from the host's plaintext in the provider's own way (`PlaintextVia::Tool`,
    /// which is `tpm2_ptool import` for tpm2-pkcs11), with the type of `object` and under `loc`.
    /// Afterwards the key is in the module's store, but this open token does not see it. The
    /// caller must open the token again to see the key.
    ///
    /// # Errors
    ///
    /// `Unsupported` when the provider imports through `C_CreateObject`. Otherwise, any error
    /// that the tool returns.
    pub fn import_plaintext(&self, object: &ObjectCfg, loc: &Locator, key: &[u8]) -> Result<()> {
        let crate::provider::PlaintextVia::Tool(_, import) = self.provider.plaintext_import() else {
            return Err(KmError::Unsupported(
                format!("{} imports no plaintext outside PKCS#11", self.provider.name()).into(),
            ));
        };
        import(&crate::provider::ImportCtx {
            cfg: &self.cfg,
            token_name: &self.name,
            pin: self.pin.as_ref().map(|p| p.as_str()),
            object,
            locator: loc,
            key,
        })
    }

    /// Returns whether the module creates public key objects (`C_CreateObject`). The answer comes
    /// from the probed `create.CKO_PUBLIC_KEY.*` rows of the module's profile. When there are no
    /// such rows, it comes from the profile's public accept rows, if there are any (ykcs11 accepts
    /// only certificates). Otherwise, the answer is yes, as the specification says.
    #[must_use]
    pub fn accepts_public_key_objects(&self) -> bool {
        accepts_public_keys(self.profiles.module.as_ref())
    }

    fn create_secret_template(&self, template: &Secret) -> Result<ObjectHandle> {
        let create = || {
            self.session.create_object(&template.0).map_err(|e| {
                self.refused_for(
                    Topic::Create,
                    &e,
                    format!("creating the key on '{}': C_CreateObject: {} ({e})", self.name, rv_name(&e)),
                )
            })
        };
        self.managing("importing a key", create)
    }
}

/// Computes [`Token::accepts_public_key_objects`] from a module profile, for a plan that has no
/// open token.
#[must_use]
pub fn accepts_public_keys(module: Option<&cakeys_profile::Profile>) -> bool {
    if let Some(probed) = module.and_then(cakeys_profile::Profile::creates_public_keys) {
        return probed;
    }
    let rows = module.and_then(|p| p.migration.as_ref()).map(|m| &m.public_accepts);
    rows.is_none_or(|r| r.is_empty() || r.iter().any(|a| a.class == "CKO_PUBLIC_KEY"))
}

/// A creation template that holds plaintext. Its secret attributes are zeroized when it is
/// dropped. It must never implement `Debug`, because `Debug` would print the secret attributes.
struct Secret(Vec<Attribute>);

impl Drop for Secret {
    fn drop(&mut self) {
        for a in &mut self.0 {
            if let Attribute::Value(v)
            | Attribute::PrivateExponent(v)
            | Attribute::Prime1(v)
            | Attribute::Prime2(v)
            | Attribute::Exponent1(v)
            | Attribute::Exponent2(v)
            | Attribute::Coefficient(v) = a
            {
                v.zeroize();
            }
        }
    }
}
