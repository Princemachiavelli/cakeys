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
        Ok(Target { spec_name, spec, object_name, object, token_name, on_token })
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

/// A private key must be able to prove possession, or say explicitly that it does not.
fn check_binding(t: &Target) -> Result<()> {
    let invalid = |why: String| Err(KmError::Validation(format!("{t}: {why}")));
    match (binding(t), t.on_token.binding) {
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
        (Some(Binding::PopSign), _) if t.spec.flag("CKA_ALWAYS_AUTHENTICATE") == Some(true) => invalid(
            "CKA_ALWAYS_AUTHENTICATE = true needs a login per signature, and so would proving \
             possession; adopt it publicOnly, or opt in with binding = \"token-asserted\""
                .to_string(),
        ),
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

    /// The AES commitment strength order (docs/DESIGN.md §3.1, finding S15): CMAC, then the
    /// KCVs, then KW. `declared_commits` zips usage bits with it, so the order is load-bearing:
    /// the first enabled scheme is the primary identity.
    #[test]
    fn aes_commit_strength_order_is_pinned() {
        assert_eq!(AES_COMMITS, [Commit::Cmac, Commit::KcvEcb, Commit::KcvEcbDecrypt, Commit::Kw]);
    }
}
