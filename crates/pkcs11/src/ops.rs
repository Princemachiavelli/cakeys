//! Idempotent verbs with HTTP-like semantics (PLAN.md, "Token verbs").

use crate::token::{self as hal, Token};
use cakeys_core::config::{Config, Lock, LockRealisation, Mode, ObjectCfg, SpecCfg, SpecTokenCfg};
use cakeys_core::id::{self, Commit, HmacHash};
use cakeys_core::{KmError, Result};
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
                t.what()
            ))),
        };
    };
    Ok(mode)
}

/// Commitments the spec's declared usage bits allow, strongest-linking first. Only declared
/// attributes count: a token default never silently changes which identity is computed.
fn declared_commits(t: &Target) -> Vec<Commit> {
    let on = |n: &str| t.spec.attributes.get(n).copied() == Some(true);
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
            t.what()
        )));
    }
    Ok(usable)
}

/// Schemes this spec computes on this token: `Target::schemes` narrowed to the commitments the
/// token implements. Needs no object, so callers can refuse before anything is created.
pub fn schemes_on(t: &Target, tok: &Token) -> Result<Vec<&'static str>> {
    if t.object.class != "CKO_SECRET_KEY" {
        return Ok(t.schemes());
    }
    Ok(commits(t, tok, plan_mode(t)?)?.iter().map(|c| c.scheme()).collect())
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
    if t.on_token.auto_create && t.object.key_type.starts_with("CKK_SHA") && t.object.key_type.ends_with("_HMAC") {
        // CKM_GENERIC_SECRET_KEY_GEN makes CKK_GENERIC_SECRET keys; there is no mechanism for
        // the hash-bound HMAC types (SoftHSM: CKR_TEMPLATE_INCONSISTENT).
        return Err(tok.unsupported(format!(
            "{}: PKCS#11 has no key generation for {}; generate a CKK_GENERIC_SECRET with CKA_SIGN, \
             or create the key elsewhere and adopt it",
            t.what(),
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
            t.what()
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
    /// Label the commitment schemes in `ids` were computed with (none for public-material IDs).
    #[serde(rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
}

/// The label to compute `t`'s commitments with: the one the lock records for the object, else the
/// default for objects the lock does not know yet.
fn commitment_label(t: &Target, lock: &Lock) -> String {
    lock.objects
        .get(t.object_name)
        .and_then(|o| o.commitment_label.clone())
        .unwrap_or_else(|| id::DEFAULT_COMMITMENT_LABEL.to_owned())
}

/// GET: find by locator (exactly one), check type and attributes, compute IDs. Never writes.
pub fn resolve(t: &Target, tok: &Token, lock: &Lock) -> Result<Option<Resolved>> {
    let mode = plan_mode(t)?;
    let public_only = t.on_token.public_only;
    let Some(h) = tok.find_key(t.object, &t.on_token.locator, public_only)? else {
        return Ok(None);
    };
    tok.check(h, t.object, t.spec)?;
    let commits = commits(t, tok, mode)?;
    let label = commitment_label(t, lock);
    Ok(Some(Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: tok.uri(t.object, &t.on_token.locator)?,
        mode,
        public_only,
        spec_digest: id::spec_digest(t.object, t.spec),
        ids: tok.ids(h, t.object, &t.on_token.locator, mode, &commits, &label)?,
        commitment_label: (!commits.is_empty()).then_some(label),
    }))
}

/// Compare computed IDs with the lock; optionally record them (only ever fills gaps).
fn reconcile(t: &Target, tok: &Token, r: &Resolved, lock: &mut Lock, update: bool) -> Result<bool> {
    // The lock pins the type its IDs were computed for: a different type is different material,
    // so say so instead of reporting a hash mismatch (also when updating).
    if let Some(locked) = lock.objects.get(t.object_name).and_then(|o| o.object_type.as_ref()) {
        if locked != t.object {
            return Err(KmError::PreconditionFailed(format!(
                "the type of object '{}' in keys.toml changed since it was locked: locked {}, now {}; \
                 different material needs a new object name",
                t.object_name,
                serde_json::to_string(locked).unwrap_or_default(),
                serde_json::to_string(t.object).unwrap_or_default()
            )));
        }
    }
    if let Some(prev) = lock.realisations.get(t.spec_name).and_then(|m| m.get(t.token_name)) {
        // Like a lockfile out of date: the policy changed, so the lock must be re-recorded.
        if !update && prev.spec_digest != r.spec_digest {
            return Err(KmError::PreconditionFailed(format!(
                "spec '{}' changed in keys.toml since it was realised on '{}' (spec digest {} -> {}); \
                 review the change, then `realise --update-lock`",
                t.spec_name, t.token_name, prev.spec_digest, r.spec_digest
            )));
        }
        if r.mode > prev.mode {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: locked mode '{}', now only '{}'",
                t.what(), prev.mode, r.mode
            )));
        }
    }
    if let Some(prev) = lock.realisations.get(t.spec_name).and_then(|m| m.get(t.token_name)) {
        warn_provenance(t, tok, prev);
    }
    let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
    // Material is only linked through a shared scheme: never attach IDs to an object when none of
    // them can be compared with what is already locked (e.g. a CMAC-only and a KW-only spec).
    if let Some(ids) = locked.filter(|ids| !ids.is_empty()) {
        if !r.ids.keys().any(|s| ids.contains_key(s)) {
            return Err(KmError::PreconditionFailed(format!(
                "{} computes {:?} but '{}' is locked only by {:?}: nothing shows it is the same \
                 material; realise a spec that computes both first",
                t.what(),
                r.ids.keys().collect::<Vec<_>>(),
                t.object_name,
                ids.keys().collect::<Vec<_>>()
            )));
        }
    }
    let mut changed = false;
    let mut matched = false;
    let mut unlocked = Vec::new();
    for (scheme, got) in &r.ids {
        match locked.and_then(|ids| ids.get(scheme)) {
            Some(want) if want == got => matched = true,
            Some(want) => {
                return Err(KmError::HashMismatch { what: t.what(), expected: want.clone(), got: got.clone() })
            }
            None if update => changed = true,
            None => unlocked.push((scheme, got)),
        }
    }
    // A scheme not yet in the lock (e.g. one a newer cakeys computes) is fine once another
    // scheme proved the identity; with nothing to compare it is first use and fails like a FOD.
    if let Some((_, got)) = unlocked.first().filter(|_| !matched) {
        return Err(KmError::HashMismatch { what: t.what(), expected: "<none>".into(), got: (*got).clone() });
    }
    for (scheme, _) in &unlocked {
        eprintln!(
            "note: {} also has a {scheme} identity the lock does not record; `realise --update-lock` adds it",
            t.what()
        );
    }
    // Locked schemes not checked now: unknown to this cakeys (e.g. from a newer one), or not
    // computable for this spec on this token.
    for scheme in locked.into_iter().flat_map(|ids| ids.keys()).filter(|s| !r.ids.contains_key(*s)) {
        if id::KNOWN_SCHEMES.contains(&scheme.as_str()) {
            eprintln!("note: {} is not checked by its {scheme} identity here (not computable for this spec on this token)", t.what());
        } else {
            eprintln!("warning: the lock records a {scheme} identity for '{}' that this cakeys does not know; it is not checked", t.object_name);
        }
    }
    if update {
        let entry = lock.objects.entry(t.object_name.into()).or_default();
        if entry.object_type.is_none() {
            entry.object_type = Some(t.object.clone());
            changed = true;
        }
        if let Some(label) = &r.commitment_label {
            if entry.commitment_label.as_ref().is_none_or(|l| l != label) {
                entry.commitment_label = Some(label.clone());
                changed = true;
            }
        }
        for (scheme, got) in &r.ids {
            entry.ids.entry(scheme.clone()).or_insert_with(|| got.clone());
        }
        let real = LockRealisation {
            spec_digest: r.spec_digest.clone(),
            mode: r.mode,
            public_only: r.public_only,
            uri: r.uri.clone(),
            module: Some(tok.module.clone()),
            token: Some(tok.token.clone()),
            provider: Some(tok.provider.name().to_owned()),
            cakeys_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            mechanisms: tok.mechanism_names(),
        };
        let slot = lock.realisations.entry(t.spec_name.into()).or_default();
        let differs = slot.get(t.token_name).is_none_or(|old| {
            old.spec_digest != real.spec_digest
                || old.mode != real.mode
                || old.public_only != real.public_only
                || old.uri != real.uri
                || old.module != real.module
                || old.token != real.token
                || old.provider != real.provider
                || old.cakeys_version != real.cakeys_version
                || old.mechanisms != real.mechanisms
        });
        if differs {
            slot.insert(t.token_name.into(), real);
            changed = true;
        }
    }
    Ok(changed)
}

/// Module and token identity are provenance: identity itself is enforced by the CA-IDs, so a
/// different module build or token only warns. `realise --update-lock` re-binds them.
fn warn_provenance(t: &Target, tok: &Token, prev: &LockRealisation) {
    if let Some(p) = prev.provider.as_deref().filter(|p| *p != tok.provider.name()) {
        eprintln!("warning: {} was realised with provider {p}, now {}", t.what(), tok.provider.name());
    }
    if let Some(v) = prev.cakeys_version.as_deref().filter(|v| *v != env!("CARGO_PKG_VERSION")) {
        eprintln!("note: {} was realised by cakeys {v}, now {}", t.what(), env!("CARGO_PKG_VERSION"));
    }
    if let Some(m) = &prev.module {
        if !m.same_build_identity(&tok.module) {
            eprintln!(
                "warning: {} was realised with module {} {} ({}), now {} {} ({})",
                t.what(),
                m.description,
                m.version,
                m.manufacturer,
                tok.module.description,
                tok.module.version,
                tok.module.manufacturer
            );
        } else if m.path != tok.module.path {
            eprintln!(
                "note: {} was realised with module file {}, now {}",
                t.what(),
                m.path,
                tok.module.path
            );
        }
    }
    if let Some(k) = &prev.token {
        if k != &tok.token {
            eprintln!(
                "warning: {} was realised on token {} #{} (firmware {}), now {} #{} (firmware {})",
                t.what(),
                k.model,
                k.serial,
                k.firmware,
                tok.token.model,
                tok.token.serial,
                tok.token.firmware
            );
        }
    }
}

/// GET + If-Match against the lock.
pub fn verify(t: &Target, tok: &Token, lock: &Lock) -> Result<Resolved> {
    let r = resolve(t, tok, lock)?.ok_or_else(|| KmError::NotFound(t.what()))?;
    reconcile(t, tok, &r, &mut lock.clone(), false)?;
    Ok(r)
}

/// PUT: create under the declared locator if absent (and `autoCreate`), then compare with the lock.
/// Re-running never creates a second object: the locator finds the first one.
pub fn realise(t: &Target, tok: &Token, lock: &mut Lock, update: bool) -> Result<(Resolved, bool)> {
    let mode = plan_mode(t)?;
    check_capabilities(t, tok, mode)?;
    let r = match resolve(t, tok, lock)? {
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
            match resolve(t, tok, lock).and_then(|r| {
                r.ok_or_else(|| KmError::NotFound(format!("{} vanished after creation", t.what())))
            }) {
                Ok(r) => r,
                Err(e) => {
                    // The locator was empty before (If-None-Match), so this removes only what we
                    // just made: a refused realise leaves nothing behind.
                    let n = tok.destroy(t.object, &t.on_token.locator).unwrap_or(0);
                    eprintln!("removed {n} object(s) just created for {}: its identity could not be established", t.what());
                    return Err(e);
                }
            }
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
        let mode = plan_mode(t)?;
        let got = tok.ids(h, t.object, &t.on_token.locator, mode, &commits(t, tok, mode)?, &commitment_label(t, lock))?;
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
        let scheme = scheme.ok_or_else(|| KmError::Unsupported(format!("no identity computed for {}", t.what())))?;
        let expected = expected
            .ok_or_else(|| KmError::PreconditionFailed(format!("no expected {scheme} for {}; pass --if-match", t.what())))?;
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
