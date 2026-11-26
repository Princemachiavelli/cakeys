//! What a (spec, token) pair requires, decided from keys.toml alone: the identity mode, the
//! schemes that it computes, how a private key is bound to its identity, and the checks that a
//! spec must pass before any token is opened (exit 17).

use crate::attrs;
use crate::config::{AsymmetricKey, AttrValue, Binding, Config, Mode, Object, ObjectKind, SpecCfg, SpecTokenCfg};
use crate::id::{BlockCipher, Commit, Curve, HmacHash, Scheme};
use crate::known::{Known, Permission, Restriction, Why};
use crate::types::{KeyType as Kt, ObjectClass as Class};
use crate::{KmError, Result};
use std::collections::BTreeMap;

/// One (spec, token) pair with everything it refers to.
pub struct Target<'a> {
    /// The spec's name.
    pub spec_name: &'a str,
    /// The spec.
    pub spec: &'a SpecCfg,
    /// The name of the object that the spec realises.
    pub object_name: &'a str,
    /// The parsed object.
    pub object: Object<'a>,
    /// The token's name.
    pub token_name: &'a str,
    /// The spec's settings for this token.
    pub on_token: &'a SpecTokenCfg,
    /// True when this spec is the transport key of its token (`transportWith`). The lock then
    /// records its public key.
    pub transport: bool,
}

impl<'a> Target<'a> {
    /// Returns the named spec, the object that it realises, and the spec's settings for
    /// `token_name`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if keys.toml has no such spec, or if the spec has no entry for that
    /// token. Returns `Validation` if the spec refers to an unknown object, or if `[tokens]` has
    /// no entry named `token_name`. Returns the errors of [`Object::new`] for a `Config` that was
    /// not made by loading a file.
    pub fn new(cfg: &'a Config, spec_name: &'a str, token_name: &'a str) -> Result<Self> {
        let spec = cfg.specs.get(spec_name).ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}'").into()))?;
        let (object_name, object) = cfg.objects.get_key_value(&spec.object).ok_or_else(|| {
            KmError::Validation(format!("spec '{spec_name}' references unknown object '{}'", spec.object).into())
        })?;
        let on_token = spec
            .tokens
            .get(token_name)
            .ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}' has no token '{token_name}'").into()))?;
        if !cfg.tokens.contains_key(token_name) {
            return Err(KmError::Validation(format!("unknown token '{token_name}'").into()));
        }
        let transport = cfg.tokens.get(token_name).and_then(|t| t.migrate.transport_with.as_deref()) == Some(spec_name);
        // The load already parsed the object, so this refuses only a `Config` that was not made
        // by loading a file. The error names the pair, as every other error of the pair does.
        let object = Object::new(object)
            .map_err(|e| e.prefixed(format_args!("'{object_name}' (spec '{spec_name}') on token '{token_name}'")))?;
        Ok(Target { spec_name, spec, object_name, object, token_name, on_token, transport })
    }

    /// Returns the identity schemes that this spec can compute, from the spec alone, in order of
    /// preference. The first scheme that a realisation computes is its primary scheme. A token
    /// that lacks a mechanism may compute fewer schemes.
    #[must_use]
    pub fn schemes(&self) -> Vec<Scheme> {
        match (self.object.class, self.object.key_type) {
            (Class::PrivateKey | Class::PublicKey, _) => vec![Scheme::Rfc7093m4],
            (Class::Certificate, _) => vec![Scheme::Certhash, Scheme::Rfc7093m4],
            (Class::Data, _) => vec![Scheme::Valuehash],
            (_, kt) => match (kt.and_then(block_commits), declared_commits(self)) {
                // No usage attribute enables a commitment, so wrap-rebind (if the key is
                // extractable) computes all of them.
                (Some(all), d) if d.is_empty() => all.iter().map(|c| c.scheme()).collect(),
                (Some(_), d) => d.iter().map(|c| c.scheme()).collect(),
                (None, _) => vec![Scheme::Commitment],
            },
        }
    }
}

impl Target<'_> {
    /// Returns whether the object is visible only after a login (review 2026-11-24 B-4). Every
    /// verb that looks for the object asks this before it reports that the object is not there.
    /// The answer comes first from the lock's record of what the token reported (the
    /// `CKA_PRIVATE` of this realisation), then from what the spec declares, and then from the
    /// class. A public key or a certificate is public, and every other class is private,
    /// including a data object (§9.2: an unknown value is treated as the more restrictive one).
    /// A `publicOnly` adoption is looked for through its public key, so it needs no login.
    #[must_use]
    pub fn needs_login(&self, lock: &crate::config::Lock) -> bool {
        if self.on_token.public_only {
            return false;
        }
        let recorded = lock
            .realisation(self.spec_name, self.token_name)
            .map_or(Known::Unknown(Why::Unrecorded), |r| r.observed(Restriction::Private.attr()));
        match recorded.or_else(|| self.spec.known(Restriction::Private.attr())) {
            Known::Is(private) => private,
            Known::Unknown(_) => !matches!(self.object.class, Class::PublicKey | Class::Certificate),
        }
    }
}

/// Formats the target as messages name it: `'<object>' (spec '<spec>') on token '<token>'`.
impl std::fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}' (spec '{}') on token '{}'", self.object_name, self.spec_name, self.token_name)
    }
}

/// Returns how the private key of `t` is bound to its identity: by a proof with signing,
/// deriving or decrypting (`pop-*`), unless the spec opts out (or adopts the key with
/// `publicOnly`). Returns `None` for every other class. This is the planned method. The proof
/// records `pop-sign-pin` instead of `pop-sign` when the token reports that the key has
/// `CKA_ALWAYS_AUTHENTICATE` (docs/DESIGN.md §3.6).
#[must_use]
pub fn binding(t: &Target) -> Option<Binding> {
    if t.object.class != Class::PrivateKey {
        return None;
    }
    if t.on_token.public_only {
        return Some(Binding::TokenAsserted);
    }
    Some(t.on_token.binding.unwrap_or(Binding::PopSign))
}

/// Returns the binding that a realisation of `t` will record, as far as the spec can tell. It is
/// the result of [`binding`], except that `pop-sign` becomes `pop-sign-pin` on a key for which
/// the spec declares `CKA_ALWAYS_AUTHENTICATE`. A check that runs before anything is created or
/// moved asks for a proof of this binding. When the token reports the attribute and the spec does
/// not declare it, only the realisation itself sees that.
#[must_use]
pub fn expected_binding(t: &Target) -> Option<Binding> {
    match binding(t) {
        Some(Binding::PopSign) if t.spec.flag("CKA_ALWAYS_AUTHENTICATE") == Some(true) => Some(Binding::PopSignPin),
        b => b,
    }
}

/// What the check of a realisation establishes when the module or the token may return false data
/// (the replay analysis in docs/archive/REVIEW-2026-11-13.md). It is derived from the class, the
/// recorded binding and the attestation kind, and it is never stored, because the lock already
/// holds all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Assurance {
    /// Possession is proven with a fresh challenge that the host verifies: a `pop-*` binding, or
    /// an attestation bound to a nonce (`tpm-certify`). A replay of an earlier answer fails.
    Proof,
    /// A secret key's commitment: the token's deterministic output over a fixed input. It shows
    /// that the material is the locked material, but any party that saw the output once can
    /// replay it, because the host holds no key with which to check a fresh challenge.
    Fingerprint,
    /// A hash of public bytes (public keys, certificates, data objects, and private keys adopted
    /// with `token-asserted` or `publicOnly`). Any party that has the bytes passes. The same is
    /// true of a private data object's value, because a module that saw the value once can answer
    /// with it.
    Public,
}

impl Assurance {
    /// Returns the name that the JSON output and the Nix view use.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Assurance::Proof => "proof",
            Assurance::Fingerprint => "fingerprint",
            Assurance::Public => "public",
        }
    }
}

/// Returns the [`Assurance`] of a realisation of an object of `class` that was recorded with
/// `binding` and with an attestation of `attestation_kind` (the `kind` in the lock's record).
#[must_use]
pub fn assurance(class: Class, binding: Option<Binding>, attestation_kind: Option<&str>) -> Assurance {
    // TPM2_Certify signs a fresh nonce together with the loaded object, which proves that the
    // object is present, for any class.
    if attestation_kind == Scheme::TpmCertify.attestation_kind() {
        return Assurance::Proof;
    }
    match (class, binding) {
        (Class::PrivateKey, Some(b)) if b != Binding::TokenAsserted => Assurance::Proof,
        (Class::SecretKey, _) => Assurance::Fingerprint,
        _ => Assurance::Public,
    }
}

/// Checks that a private key can prove possession, or that the spec says explicitly that it does
/// not. `kind` is the object's type as the load parsed it.
fn check_binding(t: &Target, kind: ObjectKind) -> Result<()> {
    let invalid = |why: String| Err(KmError::Validation(format!("{t}: {why}").into()));
    let ed448 = matches!(kind, ObjectKind::Asymmetric { key: AsymmetricKey::Edwards(Curve::Ed448), .. });
    match (binding(t), t.on_token.binding) {
        (_, Some(Binding::PopSignPin)) => invalid(
            "binding = \"pop-sign-pin\" is recorded, not configured: write \"pop-sign\" (the default); \
             a CKA_ALWAYS_AUTHENTICATE key proves it with a PIN per use"
                .into(),
        ),
        (None, Some(b)) => invalid(format!("binding = \"{b}\" applies to private keys only")),
        // `publicOnly` reads only the public key object, so it implies "token-asserted". A proof
        // that is configured with it is refused, and never replaced without an error
        // (docs/DESIGN.md §3.6).
        (Some(Binding::TokenAsserted), Some(b)) if t.on_token.public_only && b != Binding::TokenAsserted => {
            invalid(format!("publicOnly cannot prove possession (binding = \"{b}\"): it implies \"token-asserted\""))
        }
        (Some(Binding::PopSign), _) if ed448 => invalid(
            "cakeys has no Ed448 verifier to prove possession with; opt in with binding = \"token-asserted\"".into(),
        ),
        // Only the sign proof has a step at which the login for each use can happen
        // (docs/DESIGN.md §3.6).
        (Some(b @ (Binding::PopEcdh | Binding::PopDecrypt | Binding::PopUnwrap)), _)
            if t.spec.flag("CKA_ALWAYS_AUTHENTICATE") == Some(true) =>
        {
            invalid(format!(
                "a CKA_ALWAYS_AUTHENTICATE key needs its PIN per use, and binding = \"{b}\" has no point for \
                 that login: only \"pop-sign\" proves possession with it; or opt in with binding = \
                 \"token-asserted\""
            ))
        }
        (Some(Binding::PopSign), _) if !t.spec.permitted(Permission::Sign) => invalid(
            "proving possession of the private key needs CKA_SIGN = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopEcdh), _) if !matches!(t.object.key_type, Some(Kt::Ec | Kt::EcEdwards)) => {
            invalid("binding = \"pop-ecdh\" proves possession by deriving: it applies to EC private keys only".into())
        }
        (Some(Binding::PopEcdh), _) if t.object.key_type == Some(Kt::EcEdwards) => invalid(
            "binding = \"pop-ecdh\" derives with CKM_ECDH1_DERIVE: it applies to Weierstrass EC keys, not Edwards"
                .into(),
        ),
        (Some(Binding::PopEcdh), _) if !t.spec.permitted(Permission::Derive) => invalid(
            "proving possession by deriving needs CKA_DERIVE = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopDecrypt), _) if t.object.key_type != Some(Kt::Rsa) => invalid(
            "binding = \"pop-decrypt\" proves possession by decrypting: it applies to RSA private keys only".into(),
        ),
        (Some(Binding::PopDecrypt), _) if !t.spec.permitted(Permission::Decrypt) => invalid(
            "proving possession by decrypting needs CKA_DECRYPT = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopUnwrap), _) if t.object.key_type != Some(Kt::Rsa) => invalid(
            "binding = \"pop-unwrap\" proves possession by unwrapping: it applies to RSA private keys only".into(),
        ),
        (Some(Binding::PopUnwrap), _) if !t.spec.permitted(Permission::Unwrap) => invalid(
            "proving possession by unwrapping needs CKA_UNWRAP = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        _ => Ok(()),
    }?;
    // When the declared allowed list forbids every mechanism of the proof, the token would refuse
    // each proof (15). So the spec is refused here, as a spec that forbids every commitment is
    // (review 2026-11-23 A-10).
    if let (Some(b), Some(allowed)) = (binding(t), t.spec.allowed_mechanisms()) {
        let needs = proof_mechanisms(b, kind);
        if !needs.is_empty() && !needs.iter().any(|m| allowed.iter().any(|a| a == m)) {
            return invalid(format!(
                "binding = \"{b}\" proves possession with one of {}, and the spec's CKA_ALLOWED_MECHANISMS \
                 allows none of them; allow one, or opt in with binding = \"token-asserted\" on this token",
                needs.join(", ")
            ));
        }
    }
    Ok(())
}

/// Returns the mechanisms that a proof by `binding` may run on a private key of `kind`. The key's
/// `CKA_ALLOWED_MECHANISMS` must allow one of them. These are the names of the first group of
/// `cakeys_pkcs11`'s `proof_mechanisms`, and a test there checks that the two lists are equal. The
/// result is empty when the binding runs no mechanism. The HMAC of `pop-unwrap` runs on the
/// unwrapped session key, which the private key's list does not restrict.
#[must_use]
pub fn proof_mechanisms(binding: Binding, kind: ObjectKind) -> &'static [&'static str] {
    use crate::sig::HashAlg;
    let ObjectKind::Asymmetric { key, .. } = kind else { return &[] };
    match (binding, key) {
        (Binding::PopSign | Binding::PopSignPin, AsymmetricKey::Ec(c)) => match HashAlg::for_curve(c) {
            Some(HashAlg::Sha256) => &["CKM_ECDSA_SHA256", "CKM_ECDSA"],
            Some(HashAlg::Sha384) => &["CKM_ECDSA_SHA384", "CKM_ECDSA"],
            Some(HashAlg::Sha512) => &["CKM_ECDSA_SHA512", "CKM_ECDSA"],
            None => &[],
        },
        (Binding::PopSign | Binding::PopSignPin, AsymmetricKey::Edwards(_)) => &["CKM_EDDSA"],
        (Binding::PopSign | Binding::PopSignPin, AsymmetricKey::Rsa { .. }) => &[
            "CKM_SHA256_RSA_PKCS",
            "CKM_RSA_PKCS",
            "CKM_SHA384_RSA_PKCS",
            "CKM_SHA512_RSA_PKCS",
            "CKM_SHA256_RSA_PKCS_PSS",
            "CKM_SHA384_RSA_PKCS_PSS",
            "CKM_SHA512_RSA_PKCS_PSS",
            "CKM_RSA_PKCS_PSS",
        ],
        (Binding::PopEcdh, _) => &["CKM_ECDH1_DERIVE"],
        (Binding::PopDecrypt, _) => &["CKM_RSA_PKCS_OAEP", "CKM_RSA_PKCS"],
        (Binding::PopUnwrap, _) => &["CKM_RSA_PKCS_OAEP"],
        (Binding::TokenAsserted, _) => &[],
    }
}

/// Checks that the declared attributes are booleans that can be set (or a mechanism list for
/// `CKA_ALLOWED_MECHANISMS`) and that the class can have (`cakeys_core::attrs`).
fn check_declared(t: &Target, class: Class, declared: &BTreeMap<String, AttrValue>) -> Result<()> {
    for (name, v) in declared {
        let applies = match v {
            AttrValue::Mechanisms(_) if name != attrs::ALLOWED_MECHANISMS => {
                return Err(KmError::Validation(
                    format!("{t}: {name}: only CKA_ALLOWED_MECHANISMS takes a mechanism list").into(),
                ));
            }
            AttrValue::Mechanisms(_) => attrs::has_allowed_mechanisms(class),
            AttrValue::Bool(_) if !attrs::is_declarable_bool(name) => {
                return Err(KmError::Validation(format!("{t}: unsupported policy attribute {name}").into()));
            }
            AttrValue::Bool(_) => attrs::declarable(class, name),
        };
        if !applies {
            return Err(KmError::Validation(format!("{t}: {name} does not apply to {class} objects").into()));
        }
    }
    Ok(())
}

/// Returns the best identity mode that the spec alone allows.
///
/// # Errors
///
/// Returns `Validation` for a spec whose binding, attributes or identity opt-ins do not fit the
/// object's class. The check runs here, so that no object is ever created for a spec that
/// cannot be used.
pub fn plan_mode(t: &Target) -> Result<Mode> {
    let invalid = |why: &str| Err(KmError::Validation(format!("{t}: {why}").into()));
    let kind = t.object.kind();
    check_binding(t, kind)?;
    // Checks the attribute names and values for each class. A private key's `publicAttributes`
    // apply to its public key object.
    check_declared(t, t.object.class, &t.spec.attributes)?;
    check_declared(t, Class::PublicKey, &t.spec.public_attributes)?;
    if !t.spec.public_attributes.is_empty() && t.object.class != Class::PrivateKey {
        return invalid("publicAttributes apply to private keys only");
    }
    if t.on_token.public_only {
        if t.object.class != Class::PrivateKey {
            return invalid("publicOnly applies to private keys only");
        }
        if !t.spec.attributes.is_empty() {
            return invalid("publicOnly cannot verify private-key policy attributes; leave attributes empty");
        }
    }
    // PIV attests asymmetric keys, and TPM2_Certify attests any object in the TPM. Certificates
    // and data objects are not keys, and no attestation scheme exists for them.
    if t.on_token.attestation && !t.object.class.is_key() {
        return invalid(
            "attestation = true applies to key objects only (PIV attests asymmetric keys, TPM2_Certify any TPM-resident object)",
        );
    }
    let kt = match kind {
        ObjectKind::Asymmetric { .. } | ObjectKind::Certificate | ObjectKind::Data => return Ok(Mode::Direct),
        ObjectKind::Secret { key_type, .. } => key_type,
    };
    let attr = |n: &str| t.spec.flag(n);
    let mode =
        if !declared_commits(t).is_empty() {
            Mode::Commitment
        } else if attr("CKA_EXTRACTABLE") == Some(true) {
            Mode::WrapRebind
        } else {
            // The usage attributes enable commitments, but the declared allowed mechanisms forbid
            // all of them.
            let enabled = enabled_commits(t);
            if !enabled.is_empty() {
                let mechs: Vec<&str> = enabled.iter().map(|c| c.mechanism()).collect();
                return Err(KmError::Validation(
                    format!(
                        "{t} has no re-verifiable identity: its CKA_ALLOWED_MECHANISMS allows none of the commitments \
                 its usage bits enable ({}); allow one of them, or declare CKA_EXTRACTABLE = true",
                        mechs.join(", ")
                    )
                    .into(),
                ));
            }
            // The weaker modes that this case would need (computed once and never checked again)
            // are not implemented: docs/DESIGN.md §3.4.
            let bits: Vec<&str> = match block_commits(kt) {
                Some(all) => all.iter().map(|c| c.usage()).collect(),
                None => vec!["CKA_SIGN"],
            };
            return Err(KmError::Validation(format!(
            "{t} has no re-verifiable identity (non-extractable, and no usage bit that commits a {kt} key: {}): \
             declare a usage bit that allows a commitment, or CKA_EXTRACTABLE = true",
            bits.join(", ")
        ).into()));
        };
    Ok(mode)
}

/// Returns, in order of preference, the commitments that the spec's declared usage attributes
/// allow and that its declared `CKA_ALLOWED_MECHANISMS` (if any) lets the key run. Only declared
/// attributes count. So a token's default never changes, without
/// an error, which identity is computed, and the schemes that are planned before any object
/// exists are the schemes that every later run computes and that the lock pins.
#[must_use]
pub fn declared_commits(t: &Target) -> Vec<Commit> {
    let permitted =
        |c: &Commit| t.spec.allowed_mechanisms().is_none_or(|allowed| allowed.iter().any(|m| m == c.mechanism()));
    enabled_commits(t).into_iter().filter(permitted).collect()
}

/// Returns the commitments that the spec's declared usage attributes enable, before the allowed
/// mechanisms restrict them.
fn enabled_commits(t: &Target) -> Vec<Commit> {
    let on = |n: &str| t.spec.flag(n) == Some(true);
    match t.object.key_type.and_then(block_commits) {
        Some(all) => all.iter().copied().filter(|c| on(c.usage())).collect(),
        None => match t.object.key_type.and_then(HmacHash::for_key_type) {
            Some(hash) if on("CKA_SIGN") => vec![Commit::Hmac(hash)],
            _ => vec![],
        },
    }
}

/// Returns the commitments of a block cipher key type in order of preference (the first one
/// computed is the primary scheme). Each one is enabled by its usage attribute
/// ([`Commit::usage`]), and a wrap-rebind copy computes all of them. Returns `None` for the types
/// whose commitment is an HMAC.
#[must_use]
pub fn block_commits(key_type: Kt) -> Option<&'static [Commit]> {
    match key_type {
        Kt::Aes => Some(&AES_COMMITS),
        Kt::Des3 => Some(&DES3_COMMITS),
        _ => None,
    }
}

/// The AES commitments in order of preference: `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`.
pub const AES_COMMITS: [Commit; 4] =
    [Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes), Commit::KcvEcbDecrypt(BlockCipher::Aes), Commit::Kw];

/// The DES3 commitments in order of preference: the two check values. `CKM_DES3_CMAC` is not
/// among them, because cryptoki 0.12 cannot name it (docs/OPEN.md). So a DES3 key that may only
/// sign or wrap has no identity that can be verified again, unless it is extractable.
pub const DES3_COMMITS: [Commit; 2] = [Commit::KcvEcb(BlockCipher::Des3), Commit::KcvEcbDecrypt(BlockCipher::Des3)];

#[cfg(test)]
mod tests {
    use super::*;

    /// The replay table (docs/archive/REVIEW-2026-11-13.md): only a fresh answer that the host
    /// verifies is a proof, a secret key's commitment is a fingerprint, and public bytes are
    /// public.
    #[test]
    fn assurance_follows_the_replay_table() {
        use Assurance::{Fingerprint, Proof, Public};
        let cases = [
            (Class::PrivateKey, Some(Binding::PopSign), None, Proof),
            (Class::PrivateKey, Some(Binding::PopSignPin), None, Proof),
            (Class::PrivateKey, Some(Binding::PopEcdh), None, Proof),
            (Class::PrivateKey, Some(Binding::PopDecrypt), None, Proof),
            (Class::PrivateKey, Some(Binding::PopUnwrap), None, Proof),
            (Class::PrivateKey, Some(Binding::TokenAsserted), None, Public),
            // An attestation that can be replayed does not raise the assurance, but an
            // attestation bound to a nonce is a proof.
            (Class::PrivateKey, Some(Binding::TokenAsserted), Some("yubico-piv"), Public),
            (Class::PrivateKey, Some(Binding::TokenAsserted), Some("tpm-certify"), Proof),
            (Class::SecretKey, None, None, Fingerprint),
            (Class::SecretKey, None, Some("tpm-certify"), Proof),
            (Class::PublicKey, None, None, Public),
            (Class::Certificate, None, None, Public),
            (Class::Data, None, None, Public),
        ];
        for (class, binding, kind, want) in cases {
            assert_eq!(assurance(class, binding, kind), want, "{class:?} {binding:?} {kind:?}");
        }
        assert_eq!(serde_json::to_string(&Fingerprint).unwrap(), "\"fingerprint\"");
        assert_eq!([Proof, Fingerprint, Public].map(Assurance::name), ["proof", "fingerprint", "public"]);
    }

    /// The order of strength of the AES commitments (docs/DESIGN.md §3.1, finding S15): CMAC,
    /// then the KCVs, then KW. `declared_commits` pairs the usage attributes with this list, so
    /// the order matters: the first enabled scheme is the primary identity.
    #[test]
    fn aes_commit_strength_order_is_pinned() {
        assert_eq!(
            AES_COMMITS,
            [Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes), Commit::KcvEcbDecrypt(BlockCipher::Aes), Commit::Kw]
        );
        assert_eq!(AES_COMMITS.map(Commit::usage), ["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"]);
        // DES3 has only the check values, with the encryption first.
        assert_eq!(DES3_COMMITS, [Commit::KcvEcb(BlockCipher::Des3), Commit::KcvEcbDecrypt(BlockCipher::Des3)]);
        assert_eq!(block_commits(Kt::GenericSecret), None);
    }

    /// A `Config` that was not made by loading keys.toml (the load refuses such a file) may name
    /// an object that it does not define. Planning a target refuses it (17).
    #[test]
    fn a_spec_of_an_undefined_object_is_refused() {
        let cfg: Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n[specs.s]\nobject = \"gone\"\ntokens.t = { locator = { CKA_LABEL = \"x\" }, origin = \"adopt\" }\n",
        )
        .unwrap();
        let e = Target::new(&cfg, "s", "t").err().unwrap();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("unknown object 'gone'")), "{e}");
    }

    /// Whether an object is visible only after a login (review 2026-11-24 B-4). The lock's record
    /// decides first, then the spec's declaration, then the class. A data object for which neither
    /// the lock nor the spec says anything is private (§9.2). A `publicOnly` adoption is looked
    /// for through its public key.
    #[test]
    fn needs_login_asks_the_lock_then_the_spec_then_the_class() {
        let needs = |class: &str, attrs: &str, on: &str, recorded: Option<bool>| {
            let ty = match class {
                "CKO_DATA" => "",
                "CKO_CERTIFICATE" => "certificateType = \"CKC_X_509\"\n",
                "CKO_SECRET_KEY" => "keyType = \"CKK_AES\"\nvalueLen = 32\n",
                _ => "keyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n",
            };
            let cfg: Config = toml::from_str(&format!(
                "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\nclass = \"{class}\"\n{ty}\n\
                 [specs.s]\nobject = \"k\"\nattributes = {{ {attrs} }}\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\"{on} }}\n"
            ))
            .unwrap();
            let policy = recorded.map_or_else(String::new, |p| format!("CKA_PRIVATE = {p}"));
            let lock: crate::config::Lock = toml::from_str(&format!(
                "version = 1\n[realisations.s.t]\nobject = \"k\"\nlocator = {{ CKA_LABEL = \"x\" }}\n\
                 specDigest = \"sha256-x\"\nmode = \"direct\"\nschemes = []\npolicy = {{ {policy} }}\n"
            ))
            .unwrap();
            Target::new(&cfg, "s", "t").unwrap().needs_login(&lock)
        };
        let data = |attrs, recorded| needs("CKO_DATA", attrs, "", recorded);
        assert_eq!(
            [data("", None), data("CKA_PRIVATE = false", None), data("CKA_PRIVATE = true", None)],
            [true, false, true],
            "a data object: the spec, else private"
        );
        assert_eq!(
            [data("CKA_PRIVATE = true", Some(false)), data("", Some(false)), data("CKA_PRIVATE = false", Some(true))],
            [false, false, true],
            "what the token reported first"
        );
        let key = |class| needs(class, "", "", None);
        assert_eq!(
            ["CKO_PRIVATE_KEY", "CKO_SECRET_KEY", "CKO_PUBLIC_KEY", "CKO_CERTIFICATE"].map(key),
            [true, true, false, false],
            "by class"
        );
        assert!(!needs("CKO_PRIVATE_KEY", "", ", publicOnly = true", None), "publicOnly");
    }

    /// Plans the target `s` on token `t` for an object of type `ty`, with `on` added to its token
    /// entry and `attrs` as its attributes. The `Config` is built without the load, as a test
    /// `Config` may be.
    fn planned(ty: &str, attrs: &str, on: &str) -> Result<Mode> {
        let cfg: Config = toml::from_str(&format!(
            "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\n{ty}\n\n[specs.s]\nobject = \"k\"\nattributes = {{ {attrs} }}\n\
             tokens.t = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\"{on} }}\n"
        ))
        .unwrap();
        Target::new(&cfg, "s", "t").and_then(|t| plan_mode(&t))
    }

    const EC: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    const RSA: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"";

    /// `publicOnly` implies `token-asserted`. Every proof that is configured with it is refused
    /// (17), and the run never records `token-asserted` in its place (review plan.rs F1). The
    /// plan succeeds with `token-asserted` itself or with no binding.
    #[test]
    fn public_only_refuses_every_configured_proof() {
        for (ty, b) in [(EC, "pop-sign"), (EC, "pop-ecdh"), (RSA, "pop-decrypt"), (RSA, "pop-unwrap")] {
            let e = planned(ty, "", &format!(", publicOnly = true, binding = \"{b}\"")).unwrap_err();
            assert!(
                matches!(&e, KmError::Validation(m) if m.contains("publicOnly cannot prove possession")
                    && m.contains(&format!("binding = \"{b}\""))),
                "{b}: {e}"
            );
        }
        for on in [", publicOnly = true, binding = \"token-asserted\"", ", publicOnly = true"] {
            assert_eq!(planned(EC, "", on).unwrap(), Mode::Direct, "{on}");
        }
    }

    /// A proof that the declared `CKA_ALLOWED_MECHANISMS` forbids is refused at load (17), as a
    /// commitment that it forbids is, and not at every proof on the token (15) (review 2026-11-23
    /// A-10).
    #[test]
    fn a_proof_the_allowed_mechanisms_forbid_is_refused_at_load() {
        let allow = |attrs: &str, ms: &str| format!("{attrs}, CKA_ALLOWED_MECHANISMS = [{ms}]");
        for (ty, attrs, on, forbidding, allowing) in [
            (EC, "CKA_SIGN = true", "", "\"CKM_ECDH1_DERIVE\"", "\"CKM_ECDSA\""),
            (EC, "CKA_DERIVE = true", ", binding = \"pop-ecdh\"", "\"CKM_ECDSA\"", "\"CKM_ECDH1_DERIVE\""),
            (RSA, "CKA_SIGN = true", "", "\"CKM_RSA_PKCS_OAEP\"", "\"CKM_SHA512_RSA_PKCS_PSS\""),
            (RSA, "CKA_DECRYPT = true", ", binding = \"pop-decrypt\"", "\"CKM_RSA_X_509\"", "\"CKM_RSA_PKCS\""),
            (RSA, "CKA_UNWRAP = true", ", binding = \"pop-unwrap\"", "\"CKM_RSA_PKCS\"", "\"CKM_RSA_PKCS_OAEP\""),
        ] {
            let e = planned(ty, &allow(attrs, forbidding), on).unwrap_err();
            assert!(
                matches!(&e, KmError::Validation(m) if m.contains("CKA_ALLOWED_MECHANISMS allows none of them")),
                "{attrs}{on}: {e}"
            );
            assert_eq!(planned(ty, &allow(attrs, allowing), on).unwrap(), Mode::Direct, "{attrs}{on}");
        }
        let asserted = ", binding = \"token-asserted\"";
        assert_eq!(planned(EC, &allow("CKA_SIGN = true", "\"CKM_ECDH1_DERIVE\""), asserted).unwrap(), Mode::Direct);
        // The proof uses the curve's hash: a P-384 key signs its proof with `CKM_ECDSA_SHA384`,
        // not with SHA-256.
        let p384 = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"";
        assert!(planned(p384, &allow("CKA_SIGN = true", "\"CKM_ECDSA_SHA256\""), "").is_err());
        assert!(planned(p384, &allow("CKA_SIGN = true", "\"CKM_ECDSA_SHA384\""), "").is_ok());
    }

    /// Ed448 has no verifier, whichever of its names keys.toml uses (review plan.rs F2: the check
    /// uses the parsed curve, not a string).
    #[test]
    fn ed448_cannot_prove_by_signing() {
        for curve in ["edwards448", "Ed448"] {
            let ty = format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"{curve}\"");
            let e = planned(&ty, "CKA_SIGN = true", "").unwrap_err();
            assert!(matches!(&e, KmError::Validation(m) if m.contains("no Ed448 verifier")), "{curve}: {e}");
            assert_eq!(planned(&ty, "CKA_SIGN = true", ", binding = \"token-asserted\"").unwrap(), Mode::Direct);
        }
        let ed25519 = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"";
        assert_eq!(planned(ed25519, "CKA_SIGN = true", "").unwrap(), Mode::Direct);
    }

    /// The error for an object type that the load would refuse names its target, whether the type
    /// is invalid (17) or unsupported (15) (review plan.rs F3).
    #[test]
    fn a_refused_object_type_names_its_target() {
        let unsupported = planned("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_RSA\"", "", "").unwrap_err();
        assert!(matches!(&unsupported, KmError::Unsupported(m) if m.starts_with("'k' (spec 's') on token 't': ")));
        let invalid = planned("class = \"CKO_DATA\"\nvalueLen = 3", "", "").unwrap_err();
        assert!(matches!(&invalid, KmError::Validation(m) if m.starts_with("'k' (spec 's') on token 't': ")));
    }

    /// A declared `CKA_ALLOWED_MECHANISMS` restricts the commitments that the usage attributes
    /// enable to the ones that the key may run. When it forbids all of them, an extractable key
    /// uses wrap-rebind, and any other key is refused (17) with an error that names the allowed
    /// list. The plan never selects a commitment that the token would then refuse.
    #[test]
    fn allowed_mechanisms_narrow_the_commitments() {
        let plan = |attrs: &str| {
            let cfg: Config = toml::from_str(&format!(
                "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\n\
                 valueLen = 32\n\n[specs.s]\nobject = \"k\"\nattributes = {{ {attrs} }}\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\" }}\n"
            ))
            .unwrap();
            let t = Target::new(&cfg, "s", "t").unwrap();
            (declared_commits(&t), plan_mode(&t))
        };
        let both = "CKA_SIGN = true, CKA_ENCRYPT = true, CKA_EXTRACTABLE = false";
        assert_eq!(plan(both).0, [Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes)]);
        let (commits, mode) = plan(&format!("{both}, CKA_ALLOWED_MECHANISMS = [\"CKM_AES_CMAC\"]"));
        assert_eq!((commits, mode.unwrap()), (vec![Commit::Cmac], Mode::Commitment));
        let (commits, mode) = plan(&format!("{both}, CKA_ALLOWED_MECHANISMS = [\"CKM_AES_ECB\"]"));
        assert_eq!((commits, mode.unwrap()), (vec![Commit::KcvEcb(BlockCipher::Aes)], Mode::Commitment));
        let gcm = "CKA_ALLOWED_MECHANISMS = [\"CKM_AES_GCM\"]";
        let e = plan(&format!("{both}, {gcm}")).1.unwrap_err();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("allows none of the commitments")), "{e}");
        let extractable = "CKA_SIGN = true, CKA_EXTRACTABLE = true";
        assert_eq!(plan(&format!("{extractable}, {gcm}")).1.unwrap(), Mode::WrapRebind);
    }
}
