//! Idempotent verbs with HTTP-like semantics (PLAN.md, "Token verbs").

use crate::config::{Config, Lock, LockRealisation, Mode, ObjectCfg, SpecCfg, SpecTokenCfg};
use crate::error::{KmError, Result};
use crate::hal::{self, Token};
use crate::id;
use cryptoki::mechanism::MechanismType;
use cryptoki::object::KeyType;
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

    fn what(&self) -> String {
        format!("'{}' (spec '{}') on token '{}'", self.object_name, self.spec_name, self.token_name)
    }

    pub fn primary_scheme(&self) -> &'static str {
        match self.object.class.as_str() {
            "CKO_PRIVATE_KEY" => "pubkeyhash",
            "CKO_CERTIFICATE" => "certhash",
            _ => "commitment",
        }
    }

    /// Identity schemes computed for this object (the primary one first).
    pub fn schemes(&self) -> &'static [&'static str] {
        match self.object.class.as_str() {
            "CKO_PRIVATE_KEY" => &["pubkeyhash"],
            "CKO_CERTIFICATE" => &["certhash", "pubkeyhash"],
            _ => &["commitment"],
        }
    }

    fn is_certificate(&self) -> bool {
        self.object.class == "CKO_CERTIFICATE"
    }
}

/// Best identity mode achievable from the spec alone; weak modes need a per-token opt-in.
pub fn plan_mode(t: &Target) -> Result<Mode> {
    let invalid = |why: &str| Err(KmError::Validation(format!("{}: {why}", t.what())));
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
    if t.is_certificate() {
        if t.on_token.auto_create {
            return invalid("certificates are adopted, not created");
        }
        if !t.spec.attributes.is_empty() {
            return invalid("certificates take no policy attributes");
        }
        if t.object.key_type != "CKC_X_509" {
            return invalid("certificateType must be CKC_X_509");
        }
        return Ok(Mode::Direct);
    }
    let kt = hal::key_type_of(t.object)?;
    let attr = |n: &str| t.spec.attributes.get(n).copied();
    let mode = if kt == KeyType::EC || kt == KeyType::RSA {
        Mode::Direct
    } else if kt == KeyType::GENERIC_SECRET && attr("CKA_SIGN") == Some(true) {
        Mode::Commitment
    } else if attr("CKA_EXTRACTABLE") == Some(true) {
        Mode::WrapRebind
    } else {
        let allowed = &t.on_token.identity.allow;
        return match allowed.iter().min() {
            Some(m) => Ok(*m),
            None => Err(KmError::Validation(format!(
                "{} has no re-verifiable identity (non-extractable, no usable CKA_SIGN); \
                 opt in per token with identity.allow = [\"commit-at-creation\" | \"host-at-import\" | \"token-specific\"]",
                t.what()
            ))),
        };
    };
    Ok(mode)
}

/// Token capabilities the mode needs, checked before anything is created.
fn check_capabilities(t: &Target, tok: &Token, mode: Mode) -> Result<()> {
    if mode.needs_opt_in() {
        return Err(KmError::Unsupported(format!(
            "identity mode '{mode}' (opted in for {}) is not implemented in this POC",
            t.what()
        )));
    }
    let mut need = Vec::new();
    if t.on_token.auto_create {
        need.push(match hal::key_type_of(t.object)? {
            KeyType::EC => MechanismType::ECC_KEY_PAIR_GEN,
            KeyType::RSA => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
            KeyType::AES => MechanismType::AES_KEY_GEN,
            _ => MechanismType::GENERIC_SECRET_KEY_GEN,
        });
    }
    match mode {
        Mode::Commitment => need.push(MechanismType::SHA256_HMAC),
        Mode::WrapRebind => {
            need.extend([MechanismType::AES_KEY_GEN, MechanismType::SHA256_HMAC]);
            if !tok.has(MechanismType::AES_KEY_WRAP_PAD) {
                need.push(MechanismType::AES_KEY_WRAP);
            }
        }
        _ => {}
    }
    match need.into_iter().find(|m| !tok.has(*m)) {
        Some(m) => Err(KmError::Unsupported(format!("token '{}' lacks {m} needed for mode '{mode}'", tok.name))),
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
}

/// GET: find by locator (exactly one), check type and attributes, compute IDs. Never writes.
pub fn resolve(t: &Target, tok: &Token) -> Result<Option<Resolved>> {
    let mode = plan_mode(t)?;
    let public_only = t.on_token.public_only;
    let Some(h) = tok.find_key(t.object, &t.on_token.locator, public_only)? else {
        return Ok(None);
    };
    tok.check(h, t.object, t.spec)?;
    Ok(Some(Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: tok.uri(t.object, &t.on_token.locator)?,
        mode,
        public_only,
        spec_digest: id::spec_digest(t.object, t.spec),
        ids: tok.ids(h, t.object, &t.on_token.locator, mode)?,
    }))
}

/// Compare computed IDs with the lock; optionally record them (only ever fills gaps).
fn reconcile(t: &Target, tok: &Token, r: &Resolved, lock: &mut Lock, update: bool) -> Result<bool> {
    if let Some(prev) = lock.realisations.get(t.spec_name).and_then(|m| m.get(t.token_name)) {
        if r.mode > prev.mode {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: locked mode '{}', now only '{}'",
                t.what(), prev.mode, r.mode
            )));
        }
    }
    let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
    let mut changed = false;
    for (scheme, got) in &r.ids {
        match locked.and_then(|ids| ids.get(scheme)) {
            Some(want) if want == got => {}
            Some(want) => {
                return Err(KmError::HashMismatch { what: t.what(), expected: want.clone(), got: got.clone() })
            }
            None if update => changed = true,
            None => {
                return Err(KmError::HashMismatch { what: t.what(), expected: "<none>".into(), got: got.clone() })
            }
        }
    }
    if update {
        let entry = lock.objects.entry(t.object_name.into()).or_default();
        for (scheme, got) in &r.ids {
            entry.ids.entry(scheme.clone()).or_insert_with(|| got.clone());
        }
        let real = LockRealisation {
            spec_digest: r.spec_digest.clone(),
            mode: r.mode,
            public_only: r.public_only,
            uri: r.uri.clone(),
            mechanisms: tok.mechanism_names(),
        };
        let slot = lock.realisations.entry(t.spec_name.into()).or_default();
        let differs = slot.get(t.token_name).is_none_or(|old| {
            old.spec_digest != real.spec_digest
                || old.mode != real.mode
                || old.public_only != real.public_only
                || old.uri != real.uri
                || old.mechanisms != real.mechanisms
        });
        if differs {
            slot.insert(t.token_name.into(), real);
            changed = true;
        }
    }
    Ok(changed)
}

/// GET + If-Match against the lock.
pub fn verify(t: &Target, tok: &Token, lock: &Lock) -> Result<Resolved> {
    let r = resolve(t, tok)?.ok_or_else(|| KmError::NotFound(t.what()))?;
    reconcile(t, tok, &r, &mut lock.clone(), false)?;
    Ok(r)
}

/// PUT: create under the declared locator if absent (and `autoCreate`), then compare with the lock.
/// Re-running never creates a second object: the locator finds the first one.
pub fn realise(t: &Target, tok: &Token, lock: &mut Lock, update: bool) -> Result<(Resolved, bool)> {
    let mode = plan_mode(t)?;
    check_capabilities(t, tok, mode)?;
    let r = match resolve(t, tok)? {
        Some(r) => r,
        None if t.on_token.auto_create => {
            // If-None-Match: never create over anything else under the locator. On a PIV
            // token, generating into an occupied slot would silently replace its key.
            let present = tok.find_any(&t.on_token.locator)?;
            if !present.is_empty() {
                return Err(KmError::Conflict(format!(
                    "{} objects of another class already sit under the locator of {}; refusing to create",
                    present.len(),
                    t.what()
                )));
            }
            tok.create(t.object, t.spec, &t.on_token.locator)?;
            eprintln!("created {}", t.what());
            resolve(t, tok)?.ok_or_else(|| KmError::NotFound(format!("{} vanished after creation", t.what())))?
        }
        None => return Err(KmError::NotFound(format!("{} (autoCreate is off)", t.what()))),
    };
    let changed = reconcile(t, tok, &r, lock, update)?;
    Ok((r, changed))
}

/// DELETE + If-Match. Absent is success; a different object under the locator is left alone.
pub fn delete(t: &Target, tok: &Token, lock: &mut Lock, if_match: Option<&str>, update: bool) -> Result<bool> {
    if t.on_token.public_only {
        return Err(KmError::Unsupported(format!(
            "{} is adopted publicOnly; deleting would remove only the public half",
            t.what()
        )));
    }
    // An expected identity is only required when there is something to delete.
    if let Some(h) = tok.find_key(t.object, &t.on_token.locator, false)? {
        let scheme = t.primary_scheme();
        let expected = if_match
            .map(str::to_owned)
            .or_else(|| lock.objects.get(t.object_name).and_then(|o| o.ids.get(scheme)).cloned())
            .ok_or_else(|| KmError::PreconditionFailed(format!("no expected {scheme} for {}; pass --if-match", t.what())))?;
        let got = tok.ids(h, t.object, &t.on_token.locator, plan_mode(t)?)?;
        if got.get(scheme) != Some(&expected) {
            return Err(KmError::PreconditionFailed(format!(
                "{} holds {:?}, expected {expected}; not deleting",
                t.what(), got.get(scheme)
            )));
        }
    }
    let n = tok.destroy(t.object, &t.on_token.locator)?;
    if n > 0 {
        eprintln!("destroyed {n} object(s) for {}", t.what());
    }
    let mut changed = false;
    if update {
        if let Some(m) = lock.realisations.get_mut(t.spec_name) {
            changed = m.remove(t.token_name).is_some();
            if m.is_empty() {
                lock.realisations.remove(t.spec_name);
            }
        }
    }
    Ok(changed)
}
