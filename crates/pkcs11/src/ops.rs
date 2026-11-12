//! Idempotent verbs with HTTP-like semantics (PLAN.md, "Token verbs").

use crate::token::{self as hal, Token};
use cakeys_core::config::{
    AttestationRecord, AttrValue, Binding, Config, Immutables, Lock, LockRealisation, Mode, ObjectCfg, Observed,
    Provenance, SpecCfg, SpecTokenCfg,
};
use cakeys_core::attrs;
use cakeys_core::id::{self, Commit, HmacHash};
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{KeyType, ObjectHandle};
use serde::Serialize;
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
    pub fn new(cfg: &'a Config, spec_name: &'a str, token_name: &'a str) -> Result<Self> {
        let spec = cfg
            .specs
            .get(spec_name)
            .ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}'")))?;
        let (object_name, object) = cfg
            .objects
            .get_key_value(&spec.object)
            .ok_or_else(|| KmError::Validation(format!("spec '{spec_name}' references unknown object '{}'", spec.object)))?;
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
    pub fn schemes(&self) -> Vec<&'static str> {
        match (self.object.class.as_str(), self.object.key_type.as_str()) {
            ("CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY", _) => vec!["rfc7093m4"],
            ("CKO_CERTIFICATE", _) => vec!["certhash", "rfc7093m4"],
            ("CKO_DATA", _) => vec!["valuehash"],
            (_, "CKK_AES") => match declared_commits(self) {
                // No usable usage bit: wrap-rebind (if extractable) computes all of them.
                d if d.is_empty() => AES_COMMITS.iter().map(|c| c.scheme()).collect(),
                d => d.iter().map(|c| c.scheme()).collect(),
            },
            _ => vec!["commitment"],
        }
    }

    fn is_certificate(&self) -> bool {
        self.object.class == "CKO_CERTIFICATE"
    }

    /// The attestation scheme this spec's token computes when opted in (`attestation = true`),
    /// if the provider attests this class at all (§3.7 of docs/DESIGN.md).
    fn attestation_scheme(&self, tok: &Token) -> Option<&'static str> {
        self.on_token
            .attestation
            .then(|| tok.attestation_cap(self.object))
            .flatten()
            .map(|c| c.scheme)
    }
}

/// How messages name the target: `'<object>' (spec '<spec>') on token '<token>'`.
impl std::fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}' (spec '{}') on token '{}'", self.object_name, self.spec_name, self.token_name)
    }
}

/// `attestation = true` applies to key objects only: PIV attests asymmetric keys, TPM2_Certify
/// any TPM-resident object — but certificates and data objects are not keys, and no attestation
/// scheme exists for them.
const ATTESTABLE_CLASSES: [&str; 3] = ["CKO_PRIVATE_KEY", "CKO_PUBLIC_KEY", "CKO_SECRET_KEY"];

/// How `t`'s private key is bound to its identity: proven by signing, deriving or decrypting
/// (`pop-*`) unless the spec opts out (or adopts it publicOnly). `None` for every other class.
pub fn binding(t: &Target) -> Option<Binding> {
    if t.object.class != "CKO_PRIVATE_KEY" {
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
            invalid("cakeys has no Ed448 verifier to prove possession with; opt in with binding = \"token-asserted\"".into())
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
        (Some(Binding::PopEcdh), _) if !matches!(t.object.key_type.as_str(), "CKK_EC" | "CKK_EC_EDWARDS") => invalid(
            "binding = \"pop-ecdh\" proves possession by deriving: it applies to EC private keys only".into(),
        ),
        (Some(Binding::PopEcdh), _) if t.object.key_type == "CKK_EC_EDWARDS" => invalid(
            "binding = \"pop-ecdh\" derives with CKM_ECDH1_DERIVE: it applies to Weierstrass EC keys, not Edwards".into(),
        ),
        (Some(Binding::PopEcdh), _) if t.spec.flag("CKA_DERIVE") != Some(true) => invalid(
            "proving possession by deriving needs CKA_DERIVE = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopDecrypt), _) if t.object.key_type != "CKK_RSA" => invalid(
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
fn check_declared(t: &Target, class: &str, declared: &BTreeMap<String, AttrValue>) -> Result<()> {
    for (name, v) in declared {
        let applies = match v {
            AttrValue::Mechanisms(_) if name != attrs::ALLOWED_MECHANISMS => {
                return Err(KmError::Validation(format!("{t}: {name}: only CKA_ALLOWED_MECHANISMS takes a mechanism list")));
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
pub fn plan_mode(t: &Target) -> Result<Mode> {
    let invalid = |why: &str| Err(KmError::Validation(format!("{t}: {why}")));
    check_binding(t)?;
    // Attribute shapes and names, per class: a private key's `publicAttributes` shape its public
    // key object.
    check_declared(t, &t.object.class, &t.spec.attributes)?;
    check_declared(t, "CKO_PUBLIC_KEY", &t.spec.public_attributes)?;
    if !t.spec.public_attributes.is_empty() && t.object.class != "CKO_PRIVATE_KEY" {
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
    if t.is_certificate() && !t.object.key_type.is_empty() {
        return invalid("certificates take no keyType");
    }
    if t.on_token.public_only {
        if t.object.class != "CKO_PRIVATE_KEY" {
            return invalid("publicOnly applies to private keys only");
        }
        if t.on_token.auto_create {
            return invalid("publicOnly cannot autoCreate (the private half is not visible)");
        }
        if !t.spec.attributes.is_empty() {
            return invalid("publicOnly cannot verify private-key policy attributes; leave attributes empty");
        }
    }
    if t.on_token.attestation && !ATTESTABLE_CLASSES.contains(&t.object.class.as_str()) {
        return invalid("attestation = true applies to key objects only (PIV attests asymmetric keys, TPM2_Certify any TPM-resident object)");
    }
    if matches!(t.object.class.as_str(), "CKO_PUBLIC_KEY" | "CKO_DATA") {
        if t.on_token.auto_create {
            return invalid("public keys and data objects are adopted, not created");
        }
        if t.object.class == "CKO_PUBLIC_KEY" {
            hal::key_type_of(t.object)?;
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
    let kt = hal::key_type_of(t.object)?;
    let attr = |n: &str| t.spec.flag(n);
    let mode = if kt == KeyType::EC || kt == KeyType::EC_EDWARDS || kt == KeyType::RSA {
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
                "{} has no re-verifiable identity (non-extractable; no CKA_SIGN, nor CKA_ENCRYPT/CKA_DECRYPT/CKA_WRAP on AES); \
                 opt in per token with identity.allow = [\"commit-at-creation\" | \"host-at-import\" | \"token-specific\"]",
                t
            ))),
        };
    };
    Ok(mode)
}

/// Commitments the spec's declared usage bits allow, strongest-linking first. Only declared
/// attributes count: a token default never silently changes which identity is computed.
fn declared_commits(t: &Target) -> Vec<Commit> {
    let on = |n: &str| t.spec.flag(n) == Some(true);
    match t.object.key_type.as_str() {
        "CKK_AES" => ["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"]
            .into_iter()
            .zip(AES_COMMITS)
            .filter(|(a, _)| on(a))
            .map(|(_, c)| c)
            .collect(),
        kt => match HmacHash::for_key_type(kt) {
            Some(hash) if on("CKA_SIGN") => vec![Commit::Hmac(hash)],
            _ => vec![],
        },
    }
}

/// AES commitments in order of preference (the first computed is the primary scheme), each
/// enabled by the usage bit at the same position in `declared_commits`.
const AES_COMMITS: [Commit; 4] = [Commit::Cmac, Commit::KcvEcb, Commit::KcvEcbDecrypt, Commit::Kw];

/// Commitments to compute for a secret key on this token: those the spec allows (or, for a
/// wrap-rebind copy, every one for the key type) that the token implements.
fn commits(t: &Target, tok: &Token, mode: Mode) -> Result<Vec<Commit>> {
    let wanted = match (mode, t.object.key_type.as_str()) {
        (Mode::Commitment, _) => declared_commits(t),
        (Mode::WrapRebind, "CKK_AES") => AES_COMMITS.to_vec(),
        (Mode::WrapRebind, kt) => HmacHash::for_key_type(kt).map(Commit::Hmac).into_iter().collect(),
        _ => return Ok(vec![]),
    };
    let usable: Vec<Commit> = wanted.iter().copied().filter(|c| tok.has(hal::commit_mechanism(*c))).collect();
    if usable.is_empty() {
        let mechs: Vec<String> = wanted.iter().map(|c| hal::commit_mechanism(*c).to_string()).collect();
        return Err(tok.unsupported(format!(
            "token '{}' implements none of {} needed for mode '{mode}' of {}",
            tok.name,
            mechs.join(", "),
            t
        )));
    }
    Ok(usable)
}

/// Schemes this spec computes on this token: `Target::schemes` narrowed to the commitments the
/// token implements, plus the attestation scheme when the spec opted in and the provider
/// attests the class (§3.7). Needs no object, so callers can refuse before anything is created.
pub fn schemes_on(t: &Target, tok: &Token) -> Result<Vec<&'static str>> {
    let mut v = if t.object.class != "CKO_SECRET_KEY" {
        t.schemes()
    } else {
        commits(t, tok, plan_mode(t)?)?.iter().map(|c| c.scheme()).collect()
    };
    if let Some(s) = t.attestation_scheme(tok) {
        v.push(s);
    }
    Ok(v)
}

/// Token capabilities the mode needs, checked before anything is created.
fn check_capabilities(t: &Target, tok: &Token, mode: Mode) -> Result<()> {
    if mode.needs_opt_in() {
        return Err(KmError::Unsupported(format!(
            "identity mode '{mode}' (opted in for {}) is not implemented in this POC",
            t
        )));
    }
    // An attestation the provider cannot compute is refused up front (15), like a scheme the
    // token lacks: it is part of the identity this realisation promises from now on.
    if t.on_token.attestation {
        match tok.provider.attestation() {
            None => {
                return Err(tok.unsupported(format!(
                    "{} opts into attestation, but provider '{}' attests nothing on this module",
                    t,
                    tok.provider.name()
                )))
            }
            Some(cap) if !cap.classes.contains(&t.object.class.as_str()) => {
                return Err(tok.unsupported(format!(
                    "{} opts into attestation, but provider '{}' attests only {:?}",
                    t,
                    tok.provider.name(),
                    cap.classes
                )))
            }
            Some(_) => {}
        }
    }
    let mut need = Vec::new();
    if t.on_token.auto_create && t.object.key_type.starts_with("CKK_SHA") && t.object.key_type.ends_with("_HMAC") {
        // CKM_GENERIC_SECRET_KEY_GEN makes CKK_GENERIC_SECRET keys; there is no mechanism for
        // the hash-bound HMAC types (SoftHSM: CKR_TEMPLATE_INCONSISTENT).
        return Err(tok.unsupported(format!(
            "{}: PKCS#11 has no key generation for {}; generate a CKK_GENERIC_SECRET with CKA_SIGN, \
             or create the key elsewhere and adopt it",
            t,
            t.object.key_type
        )));
    }
    if t.on_token.auto_create {
        need.push(match hal::key_type_of(t.object)? {
            KeyType::EC => MechanismType::ECC_KEY_PAIR_GEN,
            KeyType::EC_EDWARDS => MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
            KeyType::RSA => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
            KeyType::AES => MechanismType::AES_KEY_GEN,
            _ => MechanismType::GENERIC_SECRET_KEY_GEN,
        });
    }
    commits(t, tok, mode)?;
    if mode == Mode::WrapRebind {
        need.push(MechanismType::AES_KEY_GEN);
        if !tok.has(MechanismType::AES_KEY_WRAP_PAD) {
            need.push(MechanismType::AES_KEY_WRAP);
        }
    }
    match need.into_iter().find(|m| !tok.has(*m)) {
        Some(m) => Err(tok.unsupported(format!(
            "token '{}' lacks {m} needed for mode '{mode}' of {}",
            tok.name,
            t
        ))),
        None => Ok(()),
    }
}

#[derive(Debug, Serialize)]
pub struct Resolved {
    pub object: String,
    pub spec: String,
    pub token: String,
    pub uri: String,
    pub mode: Mode,
    #[serde(rename = "publicOnly")]
    pub public_only: bool,
    #[serde(rename = "specDigest")]
    pub spec_digest: String,
    pub ids: BTreeMap<String, String>,
    /// Private keys: how the private object was bound to `ids` (proven when `pop-sign`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// The observed policy vector and immutables of the object found (§4.2 of docs/DESIGN.md).
    pub policy: BTreeMap<String, AttrValue>,
    #[serde(skip_serializing_if = "Immutables::is_empty")]
    pub immutables: Immutables,
    /// Label the commitment schemes in `ids` were computed with (none for public-material IDs).
    #[serde(rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// The attestation this realisation computed (§3.7), when its spec opted in: `kind` names
    /// the evidence, `root` the anchor it verified to, `id` the per-device attestation ID. Never
    /// in `ids`, which holds only the portable schemes shared across tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRecord>,
}

/// The label to compute `t`'s commitments with: the one the lock records for the object, else the
/// default for objects the lock does not know yet.
fn commitment_label(t: &Target, lock: &Lock) -> String {
    lock.objects
        .get(t.object_name)
        .and_then(|o| o.commitment_label.clone())
        .unwrap_or_else(|| id::DEFAULT_COMMITMENT_LABEL.to_owned())
}

/// GET: find by locator (exactly one), check type and attributes, compute IDs. Never writes,
/// neither the lock nor the token: a TPM Attestation Key that is not provisioned yet is an
/// error here, and only `realise` provisions it.
pub fn resolve(t: &Target, tok: &Token, lock: &Lock) -> Result<Option<Resolved>> {
    resolve_with(t, tok, lock, false)
}

fn resolve_with(t: &Target, tok: &Token, lock: &Lock, provision: bool) -> Result<Option<Resolved>> {
    let mode = plan_mode(t)?;
    let public_only = t.on_token.public_only;
    let Some(h) = tok.find_key(t.object, &t.on_token.locator, public_only)? else {
        return Ok(None);
    };
    tok.check(h, t.object, t.spec)?;
    if matches!(t.object.class.as_str(), "CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY" | "CKO_CERTIFICATE") {
        tok.check_unique_private_id(h)?;
    }
    tok.check_public_half(h, t.spec, &t.on_token.locator, public_only)?;
    let commits = commits(t, tok, mode)?;
    let label = commitment_label(t, lock);
    let binding = binding(t);
    let ids = tok.ids(h, t.object, &t.on_token.locator, mode, &commits, &label, binding)?;
    let attestation = match t.attestation_scheme(tok) {
        Some(scheme) => Some(attest(t, tok, lock, h, scheme, provision)?),
        None => None,
    };
    Ok(Some(Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: tok.uri(t.object, &t.on_token.locator)?,
        mode,
        public_only,
        spec_digest: id::spec_digest(t.object, t.spec),
        ids,
        binding,
        policy: tok.policy(h)?,
        immutables: tok.immutables(h),
        commitment_label: (!commits.is_empty()).then_some(label),
        attestation,
    }))
}

/// The attestation commitment (§3.7): per-device identity from signed provenance. The material
/// SPKI it must name comes from the same source `rfc7093m4` hashed, so an attestation of other
/// material is a conflict, not a second opinion.
///
/// Once the lock pins an attestation for this realisation, a run that cannot attest — the TPM
/// unreachable, no PIN, no attestation certificate — is a scheme downgrade (14), like any
/// scheme a realisation stops computing. Conflicts (13) and ambiguity (12) keep their codes:
/// they say the evidence is wrong, not absent.
fn attest(t: &Target, tok: &Token, lock: &Lock, h: ObjectHandle, scheme: &'static str, provision: bool) -> Result<AttestationRecord> {
    let asymmetric = matches!(t.object.class.as_str(), "CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY");
    let spki = if asymmetric { Some(tok.spki(h, &t.on_token.locator)?) } else { None };
    let kind = id::attestation_kind(scheme)
        .ok_or_else(|| KmError::Unsupported(format!("provider '{}' advertises unknown attestation scheme {scheme}", tok.provider.name())))?;
    let a = match tok.attest(h, t.object, spki.as_deref(), provision) {
        Ok(a) => a,
        Err(e @ (KmError::Unavailable(_) | KmError::Unsupported(_) | KmError::NotFound(_))) => {
            let locked = lock.realisation(t.spec_name, t.token_name).and_then(|r| r.attestation.as_ref());
            return Err(match locked {
                Some(was) => KmError::PreconditionFailed(format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it cannot compute now: {e}",
                    t,
                    was.kind
                )),
                None => e,
            });
        }
        Err(e) => return Err(e),
    };
    if a.scheme != scheme {
        return Err(KmError::Conflict(format!(
            "provider '{}' advertises {scheme} but attested {}",
            tok.provider.name(),
            a.scheme
        )));
    }
    Ok(AttestationRecord { kind: kind.to_owned(), root: a.root, id: a.id })
}

/// Compare computed IDs with the lock; optionally record them (only ever fills gaps).
fn reconcile(t: &Target, tok: &Token, r: &Resolved, lock: &mut Lock, update: bool) -> Result<bool> {
    // The lock pins the type its IDs were computed for: a different type is different material,
    // so say so instead of reporting a hash mismatch (also when updating).
    if let Some(locked) = lock.objects.get(t.object_name).and_then(|o| o.object_type.as_ref()) && locked != t.object {
        return Err(KmError::PreconditionFailed(format!(
            "the type of object '{}' in keys.toml changed since it was locked: locked {}, now {}; \
             different material needs a new object name",
            t.object_name,
            locked,
            t.object
        )));
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        // Like a lockfile out of date: keys.toml changed what this realisation is (another
        // object, locator, publicOnly or policy), so the lock must be re-recorded after review.
        if !update {
            let mut diff = Vec::new();
            if prev.object != t.object_name {
                diff.push(format!("object '{}' -> '{}'", prev.object, t.object_name));
            }
            if prev.locator != t.on_token.locator {
                diff.push(format!("locator {} -> {}", prev.locator, t.on_token.locator));
            }
            if prev.public_only != r.public_only {
                diff.push(format!("publicOnly {} -> {}", prev.public_only, r.public_only));
            }
            if prev.spec_digest != r.spec_digest {
                diff.push(format!("spec digest {} -> {}", prev.spec_digest, r.spec_digest));
            }
            if !diff.is_empty() {
                return Err(KmError::PreconditionFailed(format!(
                    "spec '{}' changed in keys.toml since it was realised on '{}' ({}); \
                     review the change, then `realise`",
                    t.spec_name,
                    t.token_name,
                    diff.join(", ")
                )));
            }
        }
        if r.mode > prev.mode {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: locked mode '{}', now only '{}'",
                t, prev.mode, r.mode
            )));
        }
        if let (Some(was), Some(now)) = (prev.binding, r.binding) && now.rank() > was.rank() {
            return Err(KmError::PreconditionFailed(format!(
                "binding downgrade for {}: locked binding '{was}', now only '{now}'",
                t
            )));
        }
        // The attestation is compared, even when realise writes the lock (§3.7). A different anchor means
        // a different device (or a re-provisioned TPM) signed the provenance; a different ID
        // under the same anchor means the attested object changed (re-imported, other
        // attributes or policy). Both are changes to review, never to re-record — and a lost
        // attestation is a scheme downgrade.
        match (&prev.attestation, &r.attestation) {
            (Some(was), Some(now)) if was.kind != now.kind || was.root != now.root => {
                return Err(KmError::PreconditionFailed(format!(
                    "attestation anchor for {} changed since it was realised ({} root {}, now {} root {}); \
                     the material needs a new object name",
                    t,
                    was.kind,
                    was.root,
                    now.kind,
                    now.root
                )));
            }
            (Some(was), Some(now)) if was.id != now.id => {
                return Err(KmError::HashMismatch {
                    what: format!("{} ({} attestation)", t, was.kind),
                    expected: was.id.clone(),
                    got: now.id.clone(),
                });
            }
            (Some(was), None) => {
                return Err(KmError::PreconditionFailed(format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it no longer computes",
                    t,
                    was.kind
                )));
            }
            (None, Some(now)) if !update => {
                eprintln!(
                    "note: {} also has a {} attestation the lock does not record; `realise` adds it",
                    t,
                    now.kind
                );
            }
            _ => {}
        }
        let lost: Vec<&String> = prev.schemes.iter().filter(|s| !r.ids.contains_key(*s)).collect();
        if !lost.is_empty() {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: it was realised with {lost:?}, which it no longer computes",
                t
            )));
        }
        // Fixed at creation: weaker now means the object was replaced (also when updating).
        let weakened = r.immutables.weakened_since(&prev.immutables);
        if !weakened.is_empty() {
            return Err(KmError::PreconditionFailed(format!(
                "{} was replaced since it was realised: {} no longer true; a new object needs a new name",
                t,
                weakened.join(", ")
            )));
        }
        // The token's object changed (policy set since, or another object with the same
        // material): review, like a changed spec.
        if !update {
            let mut diff: Vec<String> = prev
                .policy
                .iter()
                .filter(|(n, was)| r.policy.get(*n) != Some(was))
                .map(|(n, was)| format!("{n} {was} -> {}", r.policy.get(n).map_or("unreadable".into(), |b| b.to_string())))
                .collect();
            if prev.immutables != r.immutables {
                diff.push(format!(
                    "immutables {} -> {}",
                    prev.immutables,
                    r.immutables
                ));
            }
            if !diff.is_empty() {
                return Err(KmError::PreconditionFailed(format!(
                    "{} changed on the token since it was realised ({}); review, then `realise`",
                    t,
                    diff.join(", ")
                )));
            }
            let new: Vec<&String> = r.policy.keys().filter(|n| !prev.policy.contains_key(*n)).collect();
            if !new.is_empty() {
                eprintln!(
                    "note: {} also reports {new:?}, which the lock does not record; `realise` adds them",
                    t
                );
            }
        }
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        warn_provenance(t, tok, prev);
    }
    let unlisted = lock.unlisted_pairs(t.object_name);
    if !update && !unlisted.is_empty() {
        eprintln!(
            "note: {unlisted:?} share the public key of '{}' but are not listed as its pairs; `realise` records them",
            t.object_name
        );
    }
    let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
    // A deprecated computation still verifies — its identities are pinned — but the lock should
    // move to the replacement (docs/DESIGN.md §3.1); a lock write never adds a new one.
    for scheme in locked.iter().flat_map(|ids| ids.keys()).filter(|s| id::DEPRECATED_SCHEMES.contains(&s.as_str())) {
        eprintln!(
            "warning: the {scheme} identity of '{}' uses a deprecated computation; migrate to its replacement (docs/DESIGN.md §3.1)",
            t.object_name
        );
    }
    // Material is only linked through a shared scheme: never attach IDs to an object when none of
    // them can be compared with what is already locked (e.g. a CMAC-only and a KW-only spec).
    if let Some(ids) = locked.filter(|ids| !ids.is_empty()) && !r.ids.keys().any(|s| ids.contains_key(s)) {
        return Err(KmError::PreconditionFailed(format!(
            "{} computes {:?} but '{}' is locked only by {:?}: nothing shows it is the same \
             material; realise a spec that computes both first",
            t,
            r.ids.keys().collect::<Vec<_>>(),
            t.object_name,
            ids.keys().collect::<Vec<_>>()
        )));
    }
    let mut changed = false;
    let mut matched = false;
    let mut unlocked = Vec::new();
    for (scheme, got) in &r.ids {
        match locked.and_then(|ids| ids.get(scheme)) {
            Some(want) if want == got => matched = true,
            Some(want) => {
                return Err(KmError::HashMismatch { what: t.to_string(), expected: want.clone(), got: got.clone() })
            }
            None if update && id::DEPRECATED_SCHEMES.contains(&scheme.as_str()) => {}
            None if update => changed = true,
            None => unlocked.push((scheme, got)),
        }
    }
    // A scheme not yet in the lock (e.g. one a newer cakeys computes) is fine once another
    // scheme proved the identity; with nothing to compare it is first use and fails like a FOD.
    if let Some((_, got)) = unlocked.first().filter(|_| !matched) {
        return Err(KmError::HashMismatch { what: t.to_string(), expected: "<none>".into(), got: (*got).clone() });
    }
    // The material matches, but the lock does not say this spec is realised on this token: the
    // lock describes where objects live, not only what they are.
    if !update && lock.realisation(t.spec_name, t.token_name).is_none() {
        return Err(KmError::PreconditionFailed(format!(
            "{} matches the locked identity, but the lock records no realisation of spec '{}' on \
             token '{}'; review, then `realise`",
            t,
            t.spec_name,
            t.token_name
        )));
    }
    for (scheme, _) in &unlocked {
        eprintln!(
            "note: {} also has a {scheme} identity the lock does not record; `realise` adds it",
            t
        );
    }
    // Locked schemes not checked now: unknown to this cakeys (e.g. from a newer one), or not
    // computable for this spec on this token.
    for scheme in locked.into_iter().flat_map(|ids| ids.keys()).filter(|s| !r.ids.contains_key(*s)) {
        if id::KNOWN_SCHEMES.contains(&scheme.as_str()) {
            eprintln!("note: {} is not checked by its {scheme} identity here (not computable for this spec on this token)", t);
        } else {
            eprintln!("warning: the lock records a {scheme} identity for '{}' that this cakeys does not know; it is not checked", t.object_name);
        }
    }
    if update {
        // One object per material (checked again on load): refuse to record the same material
        // under a second name.
        let class = t.object.class.as_str();
        for (name, o) in lock.objects.iter().filter(|(n, o)| *n != t.object_name && o.object_type.as_ref().is_some_and(|ty| ty.class == class)) {
            if let Some((s, _)) = r.ids.iter().find(|(s, v)| !(class == "CKO_CERTIFICATE" && *s == "rfc7093m4") && o.ids.get(*s) == Some(v)) {
                return Err(KmError::PreconditionFailed(format!(
                    "{} is the same material as object '{name}' ({s}); use that object instead of a second name",
                    t
                )));
            }
        }
        let entry = lock.objects.entry(t.object_name.into()).or_default();
        if entry.object_type.is_none() {
            entry.object_type = Some(t.object.clone());
            changed = true;
        }
        if let Some(label) = &r.commitment_label && entry.commitment_label.as_ref().is_none_or(|l| l != label) {
            entry.commitment_label = Some(label.clone());
            changed = true;
        }
        for (scheme, got) in &r.ids {
            if id::DEPRECATED_SCHEMES.contains(&scheme.as_str()) && !entry.ids.contains_key(scheme) {
                eprintln!(
                    "note: {} also computes a {scheme} identity; not recorded: that computation is deprecated (docs/DESIGN.md §3.1)",
                    t
                );
                continue;
            }
            entry.ids.entry(scheme.clone()).or_insert_with(|| got.clone());
        }
        let real = LockRealisation {
            object: t.object_name.to_owned(),
            locator: t.on_token.locator.clone(),
            spec_digest: r.spec_digest.clone(),
            mode: r.mode,
            schemes: r.ids.keys().cloned().collect(),
            public_only: r.public_only,
            binding: r.binding,
            attestation: r.attestation.clone(),
            policy: r.policy.clone(),
            immutables: r.immutables.clone(),
            observed: Some(Observed {
                uri: r.uri.clone(),
                session: if tok.logged_in { "user" } else { "public" }.to_owned(),
                mechanisms: tok.mechanism_names().to_vec(),
            }),
            provenance: Some(Provenance {
                provider: tok.provider.name().to_owned(),
                cakeys_version: env!("CARGO_PKG_VERSION").to_owned(),
                module: tok.module.clone(),
                token: tok.token.clone(),
            }),
        };
        let slot = lock.realisations.entry(t.spec_name.into()).or_default();
        if slot.get(t.token_name) != Some(&real) {
            slot.insert(t.token_name.into(), real);
            changed = true;
        }
        // Partners in this file are recomputed; listed ones from other fragments are kept.
        let pairs = lock.computed_pairs();
        let present: Vec<String> = lock.objects.keys().cloned().collect();
        for (name, o) in lock.objects.iter_mut() {
            let mut want = pairs.get(name).cloned().unwrap_or_default();
            want.extend(o.pairs.iter().filter(|p| !present.contains(p)).cloned());
            if o.pairs != want {
                o.pairs = want;
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// `observed` and `provenance` never change a verdict: identity is enforced by the CA-IDs, so a
/// different module build or token only warns. `realise` re-binds them.
fn warn_provenance(t: &Target, tok: &Token, prev: &LockRealisation) {
    if prev.observed.as_ref().is_some_and(|o| o.session == "user") && !tok.logged_in {
        eprintln!(
            "warning: {} was realised in a user session; this public session cannot see other private keys under its CKA_ID",
            t
        );
    }
    if let Some(o) = &prev.observed {
        let gone: Vec<&str> =
            o.mechanisms.iter().filter(|m| !tok.mechanism_names().contains(m)).map(String::as_str).collect();
        if !gone.is_empty() {
            eprintln!(
                "warning: {} was realised where the token offered {}, which it no longer does (functions.<token> in Nix)",
                t,
                gone.join(", ")
            );
        }
    }
    let Some(p) = &prev.provenance else { return };
    if p.provider != tok.provider.name() {
        eprintln!("warning: {} was realised with provider {}, now {}", t, p.provider, tok.provider.name());
    }
    if p.cakeys_version != env!("CARGO_PKG_VERSION") {
        eprintln!("note: {} was realised by cakeys {}, now {}", t, p.cakeys_version, env!("CARGO_PKG_VERSION"));
    }
    let m = &p.module;
    if !m.same_build_identity(&tok.module) {
        eprintln!(
            "warning: {} was realised with module {} {} ({}), now {} {} ({})",
            t,
            m.description,
            m.version,
            m.manufacturer,
            tok.module.description,
            tok.module.version,
            tok.module.manufacturer
        );
    } else if m.path != tok.module.path {
        eprintln!("note: {} was realised with module file {}, now {}", t, m.path, tok.module.path);
    }
    let k = &p.token;
    if k != &tok.token {
        eprintln!(
            "warning: {} was realised on token {} #{} (firmware {}), now {} #{} (firmware {})",
            t,
            k.model,
            k.serial,
            k.firmware,
            tok.token.model,
            tok.token.serial,
            tok.token.firmware
        );
    }
}

/// GET + If-Match against the lock.
pub fn verify(t: &Target, tok: &Token, lock: &Lock) -> Result<Resolved> {
    let r = resolve(t, tok, lock)?.ok_or_else(|| KmError::NotFound(t.to_string()))?;
    reconcile(t, tok, &r, &mut lock.clone(), false)?;
    Ok(r)
}

/// PUT: create under the declared locator if absent (and `autoCreate`), then compare with the lock.
/// Re-running never creates a second object: the locator finds the first one.
pub fn realise(t: &Target, tok: &Token, lock: &mut Lock, update: bool) -> Result<(Resolved, bool)> {
    let mode = plan_mode(t)?;
    check_capabilities(t, tok, mode)?;
    let r = match resolve_with(t, tok, lock, true)? {
        Some(r) => r,
        None if t.on_token.auto_create => {
            // D1: the lock already pins this object's material, so a fresh generation can only
            // end in a mismatch; refuse before anything is created. (Had this token held the
            // same material, resolve above would have found it.)
            if let Some(ids) = lock.objects.get(t.object_name).map(|o| &o.ids).filter(|ids| !ids.is_empty()) {
                return Err(KmError::PreconditionFailed(format!(
                    "{}: the lock already pins object '{}' ({}); autoCreate would generate \
                     different material that can never match; put the same material under the \
                     locator, or give this token's key its own object name",
                    t,
                    t.object_name,
                    ids.keys().map(String::as_str).collect::<Vec<_>>().join(", ")
                )));
            }
            // If-None-Match: never create over anything else under the locator. On a PIV
            // token, generating into an occupied slot would silently replace its key.
            let present = tok.find_any(&t.on_token.locator)?;
            if !present.is_empty() {
                return Err(KmError::Conflict(format!(
                    "{} objects of another class already sit under the locator of {}; refusing to create",
                    present.len(),
                    t
                )));
            }
            tok.create(t.object, t.spec, &t.on_token.locator)?;
            eprintln!("created {}", t);
            match resolve_with(t, tok, lock, true).and_then(|r| {
                r.ok_or_else(|| KmError::NotFound(format!("{} vanished after creation", t)))
            }) {
                Ok(r) => r,
                Err(e) => {
                    // The locator was empty before (If-None-Match), so this removes only what we
                    // just made: a refused realise leaves nothing behind, unless the module cannot
                    // delete keys (ykcs11), which is then said rather than claimed.
                    match tok.destroy(t.object, &t.on_token.locator) {
                        Ok(n) => eprintln!(
                            "removed {n} object(s) just created for {}: its identity could not be established",
                            t
                        ),
                        Err(d) => eprintln!(
                            "the key just created for {} is still on the token (its identity could not be \
                             established, and removing it failed: {d})",
                            t
                        ),
                    }
                    return Err(e);
                }
            }
        }
        None => return Err(KmError::NotFound(format!("{} (autoCreate is off)", t))),
    };
    let changed = reconcile(t, tok, &r, lock, update)?;
    Ok((r, changed))
}

/// DELETE + If-Match. Absent is success; a different object under the locator is left alone.
pub fn delete(t: &Target, tok: &Token, lock: &mut Lock, if_match: Option<&str>, update: bool) -> Result<bool> {
    if t.on_token.public_only {
        return Err(KmError::Unsupported(format!(
            "{} is adopted publicOnly; deleting would remove only the public half",
            t
        )));
    }
    // An expected identity is only required when there is something to delete.
    if let Some(h) = tok.find_key(t.object, &t.on_token.locator, false)? {
        let mode = plan_mode(t)?;
        // Proven like `resolve`: If-Match must not pass on a public object beside another key.
        let got = tok.ids(h, t.object, &t.on_token.locator, mode, &commits(t, tok, mode)?, &commitment_label(t, lock), binding(t))?;
        // --if-match names the primary scheme; otherwise the first scheme the lock records.
        let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
        let primary = t.schemes().into_iter().find(|s| got.contains_key(*s));
        let (scheme, expected) = match if_match {
            Some(want) => (primary, Some(want.to_owned())),
            None => t
                .schemes()
                .into_iter()
                .filter(|s| got.contains_key(*s))
                .find_map(|s| locked.and_then(|ids| ids.get(s)).map(|w| (Some(s), Some(w.clone()))))
                .unwrap_or((primary, None)),
        };
        let scheme = scheme.ok_or_else(|| KmError::Unsupported(format!("no identity computed for {}", t)))?;
        let expected = expected
            .ok_or_else(|| KmError::PreconditionFailed(format!("no expected {scheme} for {}; pass --if-match", t)))?;
        if got.get(scheme) != Some(&expected) {
            return Err(KmError::PreconditionFailed(format!(
                "{} holds {:?}, expected {expected}; not deleting",
                t, got.get(scheme)
            )));
        }
    }
    let n = tok.destroy(t.object, &t.on_token.locator)?;
    if n > 0 {
        eprintln!("destroyed {n} object(s) for {}", t);
    }
    let mut changed = false;
    if update && let Some(m) = lock.realisations.get_mut(t.spec_name) {
        changed = m.remove(t.token_name).is_some();
        if m.is_empty() {
            lock.realisations.remove(t.spec_name);
        }
    }
    Ok(changed)
}

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
