//! What a (spec, token) pair asks for, decided from keys.toml alone: the identity mode, the
//! schemes it computes, how a private key is bound to its identity, and the checks a spec must
//! pass before any token is opened (exit 17).

use crate::attrs;
use crate::config::{AttrValue, Binding, Config, Mode, ObjectCfg, SpecCfg, SpecTokenCfg};
use crate::id::{Commit, HmacHash, Scheme};
use crate::types::{KeyType as Kt, ObjectClass as Class};
use crate::{KmError, Result};
use std::collections::BTreeMap;

/// One (spec, token) pair with everything it refers to.
pub struct Target<'a> {
    pub spec_name: &'a str,
    pub spec: &'a SpecCfg,
    pub object_name: &'a str,
    pub object: &'a ObjectCfg,
    pub token_name: &'a str,
    pub on_token: &'a SpecTokenCfg,
    /// The token the object is born on (`createOn`), when keys.toml names one.
    pub create_on: Option<&'a str>,
}

impl<'a> Target<'a> {
    /// The spec and the object it realises, as named, plus its policy on `token_name`.
    ///
    /// # Errors
    ///
    /// `NotFound` if keys.toml names no such spec, or the spec no such token; `Validation` if
    /// the spec references an unknown object, or `[tokens]` has no entry named `token_name`.
    pub fn new(cfg: &'a Config, spec_name: &'a str, token_name: &'a str) -> Result<Self> {
        let spec = cfg.specs.get(spec_name).ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}'")))?;
        let (object_name, object) = cfg.objects.get_key_value(&spec.object).ok_or_else(|| {
            KmError::Validation(format!("spec '{spec_name}' references unknown object '{}'", spec.object))
        })?;
        let on_token = spec
            .tokens
            .get(token_name)
            .ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}' has no token '{token_name}'")))?;
        if !cfg.tokens.contains_key(token_name) {
            return Err(KmError::Validation(format!("unknown token '{token_name}'")));
        }
        let create_on = cfg.create_on.get(object_name).map(String::as_str);
        Ok(Target { spec_name, spec, object_name, object, token_name, on_token, create_on })
    }

    /// Identity schemes this spec can compute (from the spec alone), in order of preference:
    /// the first one a realisation computes is its primary scheme. A token lacking a mechanism
    /// may compute fewer.
    #[must_use]
    pub fn schemes(&self) -> Vec<Scheme> {
        match (self.object.class, self.object.key_type) {
            (Class::PrivateKey | Class::PublicKey, _) => vec![Scheme::Rfc7093m4],
            (Class::Certificate, _) => vec![Scheme::Certhash, Scheme::Rfc7093m4],
            (Class::Data, _) => vec![Scheme::Valuehash],
            (_, Some(Kt::Aes)) => match declared_commits(self) {
                // No usable usage bit: wrap-rebind (if extractable) computes all of them.
                d if d.is_empty() => AES_COMMITS.iter().map(|c| c.scheme()).collect(),
                d => d.iter().map(|c| c.scheme()).collect(),
            },
            _ => vec![Scheme::Commitment],
        }
    }

    fn is_certificate(&self) -> bool {
        self.object.class == Class::Certificate
    }
}

/// How messages name the target: `'<object>' (spec '<spec>') on token '<token>'`.
impl std::fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}' (spec '{}') on token '{}'", self.object_name, self.spec_name, self.token_name)
    }
}

/// How `t`'s private key is bound to its identity: proven by signing, deriving or decrypting
/// (`pop-*`) unless the spec opts out (or adopts it publicOnly). `None` for every other class.
/// This is the planned method; the proof records `pop-sign-pin` for `pop-sign` when the token
/// reports the key `CKA_ALWAYS_AUTHENTICATE` (`docs/CKA_ALWAYS_AUTHENTICATE.md`).
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

/// What a realisation's check establishes against a module or token that may lie (the replay
/// analysis in docs/REVIEW-2026-11-13.md). Derived from the class, the recorded binding and the
/// attestation kind, never stored: the lock already holds all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Assurance {
    /// Possession proven over a fresh challenge the host verifies: a `pop-*` binding, or a
    /// nonce-bound attestation (`tpm-certify`). Replaying an earlier answer fails.
    Proof,
    /// A secret key's commitment: the token's deterministic output over a fixed input. It shows
    /// the material is the locked one, but anything that saw the output once can replay it; the
    /// host holds no key to check a fresh challenge with.
    Fingerprint,
    /// A hash of public bytes (public keys, certificates, data objects, and private keys adopted
    /// `token-asserted` or `publicOnly`): whoever has the bytes passes.
    Public,
}

impl Assurance {
    /// The name the JSON output and the Nix view use.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Assurance::Proof => "proof",
            Assurance::Fingerprint => "fingerprint",
            Assurance::Public => "public",
        }
    }
}

/// The [`Assurance`] of a realisation of an object of `class`, recorded with `binding` and an
/// attestation of `attestation_kind` (the lock record's `kind`).
#[must_use]
pub fn assurance(class: Class, binding: Option<Binding>, attestation_kind: Option<&str>) -> Assurance {
    // TPM2_Certify signs a fresh nonce over the loaded object: proof of presence for any class.
    if attestation_kind == Scheme::TpmCertify.attestation_kind() {
        return Assurance::Proof;
    }
    match (class, binding) {
        (Class::PrivateKey, Some(b)) if b != Binding::TokenAsserted => Assurance::Proof,
        (Class::SecretKey, _) => Assurance::Fingerprint,
        _ => Assurance::Public,
    }
}

/// A private key must be able to prove possession, or say explicitly that it does not.
fn check_binding(t: &Target) -> Result<()> {
    let invalid = |why: String| Err(KmError::Validation(format!("{t}: {why}")));
    match (binding(t), t.on_token.binding) {
        (_, Some(Binding::PopSignPin)) => invalid(
            "binding = \"pop-sign-pin\" is recorded, not configured: write \"pop-sign\" (the default); \
             a CKA_ALWAYS_AUTHENTICATE key proves it with a PIN per use"
                .into(),
        ),
        (None, Some(b)) => invalid(format!("binding = \"{b}\" applies to private keys only")),
        (Some(Binding::TokenAsserted), Some(Binding::PopSign)) => {
            invalid("publicOnly cannot prove possession (binding = \"pop-sign\")".into())
        }
        (Some(Binding::PopSign), _) if t.object.curve.as_deref().is_some_and(|c| c == "edwards448" || c == "Ed448") => {
            invalid(
                "cakeys has no Ed448 verifier to prove possession with; opt in with binding = \"token-asserted\""
                    .into(),
            )
        }
        // The per-use login needs a multi-part signature (cryptoki has no other point for it),
        // and CKM_EDDSA is single-part only.
        (Some(Binding::PopSign), _)
            if t.object.key_type == Some(Kt::EcEdwards) && t.spec.flag("CKA_ALWAYS_AUTHENTICATE") == Some(true) =>
        {
            invalid(
                "a CKA_ALWAYS_AUTHENTICATE Edwards key cannot prove possession yet: its per-use login needs \
                 a multi-part signature, and CKM_EDDSA is single-part only; opt in with binding = \
                 \"token-asserted\""
                    .into(),
            )
        }
        (Some(Binding::PopSign), _) if t.spec.flag("CKA_SIGN") != Some(true) => invalid(
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
        (Some(Binding::PopEcdh), _) if t.spec.flag("CKA_DERIVE") != Some(true) => invalid(
            "proving possession by deriving needs CKA_DERIVE = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopDecrypt), _) if t.object.key_type != Some(Kt::Rsa) => invalid(
            "binding = \"pop-decrypt\" proves possession by decrypting: it applies to RSA private keys only".into(),
        ),
        (Some(Binding::PopDecrypt), _) if t.spec.flag("CKA_DECRYPT") != Some(true) => invalid(
            "proving possession by decrypting needs CKA_DECRYPT = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// Declared attributes must be settable booleans (or a mechanism list for `CKA_ALLOWED_MECHANISMS`)
/// that the class can carry (`cakeys_core::attrs`).
fn check_declared(t: &Target, class: Class, declared: &BTreeMap<String, AttrValue>) -> Result<()> {
    for (name, v) in declared {
        let applies = match v {
            AttrValue::Mechanisms(_) if name != attrs::ALLOWED_MECHANISMS => {
                return Err(KmError::Validation(format!(
                    "{t}: {name}: only CKA_ALLOWED_MECHANISMS takes a mechanism list"
                )));
            }
            AttrValue::Mechanisms(_) => attrs::has_allowed_mechanisms(class),
            AttrValue::Bool(_) if !attrs::is_declarable_bool(name) => {
                return Err(KmError::Validation(format!("unsupported policy attribute {name}")));
            }
            AttrValue::Bool(_) => attrs::declarable(class, name),
        };
        if !applies {
            return Err(KmError::Validation(format!("{t}: {name} does not apply to {class} objects")));
        }
    }
    Ok(())
}

/// Best identity mode achievable from the spec alone; weak modes need a per-token opt-in.
///
/// # Errors
///
/// `Validation` for a spec whose binding, attributes or identity opt-ins do not fit the
/// object's class (checked here, so no object is ever created for an unusable spec).
pub fn plan_mode(t: &Target) -> Result<Mode> {
    let invalid = |why: &str| Err(KmError::Validation(format!("{t}: {why}")));
    check_binding(t)?;
    // Attribute shapes and names, per class: a private key's `publicAttributes` shape its public
    // key object.
    check_declared(t, t.object.class, &t.spec.attributes)?;
    check_declared(t, Class::PublicKey, &t.spec.public_attributes)?;
    if !t.spec.public_attributes.is_empty() && t.object.class != Class::PrivateKey {
        return invalid("publicAttributes apply to private keys only");
    }
    // The certificate type lives in `certificateType`; `keyType` names nothing on a certificate.
    match t.object.certificate_type.as_deref() {
        Some("CKC_X_509") if t.is_certificate() => {}
        Some(_) if t.is_certificate() => return invalid("certificateType must be CKC_X_509"),
        Some(_) => return invalid("certificateType applies to certificates only"),
        None if t.is_certificate() => return invalid("certificates need certificateType = \"CKC_X_509\""),
        None => {}
    }
    if t.is_certificate() && t.object.key_type.is_some() {
        return invalid("certificates take no keyType");
    }
    if t.on_token.public_only {
        if t.object.class != Class::PrivateKey {
            return invalid("publicOnly applies to private keys only");
        }
        if t.on_token.auto_create {
            return invalid("publicOnly cannot autoCreate (the private half is not visible)");
        }
        if !t.spec.attributes.is_empty() {
            return invalid("publicOnly cannot verify private-key policy attributes; leave attributes empty");
        }
    }
    // PIV attests asymmetric keys, TPM2_Certify any TPM-resident object; certificates and data
    // objects are not keys, and no attestation scheme exists for them.
    if t.on_token.attestation && !t.object.class.is_key() {
        return invalid(
            "attestation = true applies to key objects only (PIV attests asymmetric keys, TPM2_Certify any TPM-resident object)",
        );
    }
    if matches!(t.object.class, Class::PublicKey | Class::Data) {
        if t.on_token.auto_create {
            return invalid("public keys and data objects are adopted, not created");
        }
        if t.object.class == Class::PublicKey {
            t.object.checked_key_type()?;
        }
        return Ok(Mode::Direct);
    }
    if t.is_certificate() {
        if t.on_token.auto_create {
            return invalid("certificates are adopted, not created");
        }
        return Ok(Mode::Direct);
    }
    // CKA_TRUSTED is set by the token's security officer (or recorded on an adopted object), never
    // by generation.
    if t.on_token.auto_create && t.spec.flag("CKA_TRUSTED") == Some(true) {
        return invalid("CKA_TRUSTED = true cannot be generated; adopt the object instead of autoCreate");
    }
    let kt = t.object.checked_key_type()?;
    let attr = |n: &str| t.spec.flag(n);
    let mode = if kt.is_asymmetric() {
        Mode::Direct
    } else if !declared_commits(t).is_empty() {
        Mode::Commitment
    } else if attr("CKA_EXTRACTABLE") == Some(true) {
        Mode::WrapRebind
    } else {
        let allowed = &t.on_token.identity.allow;
        return match allowed.iter().min() {
            Some(m) => Ok(*m),
            None => Err(KmError::Validation(format!(
                "{t} has no re-verifiable identity (non-extractable; no CKA_SIGN, nor CKA_ENCRYPT/CKA_DECRYPT/CKA_WRAP on AES); \
                 opt in per token with identity.allow = [\"commit-at-creation\" | \"host-at-import\" | \"token-specific\"]"
            ))),
        };
    };
    Ok(mode)
}

/// Commitments the spec's declared usage bits allow, strongest-linking first. Only declared
/// attributes count: a token default never silently changes which identity is computed.
pub fn declared_commits(t: &Target) -> Vec<Commit> {
    let on = |n: &str| t.spec.flag(n) == Some(true);
    match t.object.key_type {
        Some(Kt::Aes) => ["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"]
            .into_iter()
            .zip(AES_COMMITS)
            .filter(|(a, _)| on(a))
            .map(|(_, c)| c)
            .collect(),
        kt => match kt.and_then(HmacHash::for_key_type) {
            Some(hash) if on("CKA_SIGN") => vec![Commit::Hmac(hash)],
            _ => vec![],
        },
    }
}

/// AES commitments in order of preference (the first computed is the primary scheme), each
/// enabled by the usage bit at the same position in `declared_commits`.
pub const AES_COMMITS: [Commit; 4] = [Commit::Cmac, Commit::KcvEcb, Commit::KcvEcbDecrypt, Commit::Kw];

#[cfg(test)]
mod tests {
    use super::*;

    /// The replay table (docs/REVIEW-2026-11-13.md): only a fresh, host-verified answer is a
    /// proof; a secret key's commitment is a fingerprint; public bytes are public.
    #[test]
    fn assurance_follows_the_replay_table() {
        use Assurance::{Fingerprint, Proof, Public};
        let cases = [
            (Class::PrivateKey, Some(Binding::PopSign), None, Proof),
            (Class::PrivateKey, Some(Binding::PopSignPin), None, Proof),
            (Class::PrivateKey, Some(Binding::PopEcdh), None, Proof),
            (Class::PrivateKey, Some(Binding::PopDecrypt), None, Proof),
            (Class::PrivateKey, Some(Binding::TokenAsserted), None, Public),
            // A replayable attestation upgrades nothing; a nonce-bound one is a proof.
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
        assert_eq!(Proof.name(), "proof");
    }

    /// The AES commitment strength order (docs/DESIGN.md §3.1, finding S15): CMAC, then the
    /// KCVs, then KW. `declared_commits` zips usage bits with it, so the order is load-bearing:
    /// the first enabled scheme is the primary identity.
    #[test]
    fn aes_commit_strength_order_is_pinned() {
        assert_eq!(AES_COMMITS, [Commit::Cmac, Commit::KcvEcb, Commit::KcvEcbDecrypt, Commit::Kw]);
    }
}
