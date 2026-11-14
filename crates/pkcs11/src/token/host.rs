//! The `host` path on a token (docs/CAMIGRATE.md D2, phase 4): a key handed to this process in
//! plaintext, and a key created from the host's plaintext. Only `camigrate` calls these, behind
//! `--allow-host-plaintext`. Every plaintext buffer is zeroized when dropped, the copies inside
//! creation templates included; none is formatted, logged or put in an error.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use aes_kw::cipher::KeyInit as _;
use cakeys_core::plaintext::PrivateParts;
use zeroize::{Zeroize as _, Zeroizing};

impl Token {
    /// Hand the key `h` to this process: wrapped by `kwp` (RFC 5649) under a fresh AES-256 key the
    /// host drew and created here as a session key, then unwrapped in memory. What a private key
    /// unwraps to is its PKCS#8 `PrivateKeyInfo`; a secret key's, its value. The session key is
    /// destroyed whatever happens.
    ///
    /// # Errors
    ///
    /// `Unavailable` if the random number generator fails; `Unsupported` when the module will not
    /// make the session key or wrap the key with it (`CKA_EXTRACTABLE`, the mechanism);
    /// `Conflict` when the blob does not unwrap.
    pub fn extract(&self, h: ObjectHandle, kwp: &Mechanism) -> Result<Zeroizing<Vec<u8>>> {
        let mut kek = Zeroizing::new([0u8; 32]);
        getrandom::fill(kek.as_mut_slice())
            .map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}")))?;
        let template = Secret(vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Wrap(true),
            Attribute::Value(kek.to_vec()),
        ]);
        let refused = |what: &str, e: CkError| self.unsupported(format!("{what} on '{}': {e}", self.name));
        let session_kek =
            self.session.create_object(&template.0).map_err(|e| refused("making the host's session key", e))?;
        drop(template);
        let blob = self.session.wrap_key(kwp, session_kek, h);
        let _ = self.session.destroy_object(session_kek);
        let blob = blob.map_err(|e| refused("wrapping the key for the host", e))?;
        let mut out = Zeroizing::new(vec![0u8; blob.len()]);
        let n = aes_kw::KwpAes256::new_from_slice(kek.as_slice())
            .map_err(|_| KmError::Unavailable("AES-256 key schedule".into()))?
            .unwrap_key(&blob, &mut out)
            .map_err(|_| KmError::Conflict(format!("'{}': the key wrapped for the host does not unwrap", self.name)))?
            .len();
        out.truncate(n);
        Ok(out)
    }

    /// Create a private key from its `parts`, under `base` (class, key type, `CKA_TOKEN`, the
    /// locator and the spec's policy attributes). The plaintext copies in the template are
    /// zeroized after the call.
    ///
    /// # Errors
    ///
    /// `Unsupported` when the module will not create it (`C_CreateObject`).
    pub fn create_private(
        &self,
        object: &ObjectCfg,
        mut base: Vec<Attribute>,
        parts: &PrivateParts,
    ) -> Result<ObjectHandle> {
        match parts {
            PrivateParts::Ec(scalar) | PrivateParts::Edwards(scalar) => {
                base.push(Attribute::EcParams(curve_of(object)?.params().to_vec()));
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

    /// Create a secret key of `value` under `base` (as [`Self::create_private`]).
    ///
    /// # Errors
    ///
    /// `Unsupported` when the module will not create it.
    pub fn create_secret(&self, mut base: Vec<Attribute>, value: &[u8]) -> Result<ObjectHandle> {
        base.push(Attribute::Value(value.to_vec()));
        self.create_secret_template(&Secret(base))
    }

    /// Import a key from the host's plaintext the provider's own way (`Provider::import_plaintext`:
    /// `tpm2_ptool import` for tpm2-pkcs11), under `object`'s type and `loc`. The key is in the
    /// module's store afterwards, but this open token does not see it: open the token again.
    ///
    /// # Errors
    ///
    /// Whatever the provider refuses.
    pub fn import_plaintext(&self, object: &ObjectCfg, loc: &Locator, key: &[u8]) -> Result<()> {
        self.provider.import_plaintext(&crate::provider::ImportCtx {
            cfg: &self.cfg,
            token_name: &self.name,
            pin: self.pin.as_ref().map(|p| p.as_str()),
            object,
            locator: loc,
            key,
        })
    }

    /// Whether the module creates public key objects (`C_CreateObject`): its profile's public
    /// accept rows, when it has any (ykcs11 takes certificates only), else the spec's yes.
    #[must_use]
    pub fn accepts_public_key_objects(&self) -> bool {
        let rows = self.profiles.module.as_ref().and_then(|p| p.migration.as_ref()).map(|m| &m.public_accepts);
        rows.is_none_or(|r| r.is_empty() || r.iter().any(|a| a.class == "CKO_PUBLIC_KEY"))
    }

    fn create_secret_template(&self, template: &Secret) -> Result<ObjectHandle> {
        let create = || {
            self.session
                .create_object(&template.0)
                .map_err(|e| self.unsupported(format!("creating the key on '{}': C_CreateObject: {e}", self.name)))
        };
        if self.provider.manages_as_so() { self.as_so("importing a key", create) } else { create() }
    }
}

/// A creation template holding plaintext: its secret attributes are zeroized when it is dropped.
/// Never `Debug`: it would print them.
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
