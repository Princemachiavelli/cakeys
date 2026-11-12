//! Idempotent verbs with HTTP-like semantics (PLAN.md, "Token verbs").

use crate::token::{self as hal, Token};
use cakeys_core::config::{
    AttestationRecord, Lock, Mode, Observed, Provenance, Session,
};
use cakeys_core::id::{self, Commit, HmacHash, Scheme};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{KeyType, ObjectHandle};

pub use cakeys_core::plan::{Target, binding, plan_mode};
use cakeys_core::plan::{AES_COMMITS, declared_commits};
pub use cakeys_core::reconcile::{Facts, LockWrite, Notes, Resolved};
use cakeys_core::reconcile::{self, commitment_label};

/// The attestation scheme `t`'s token computes when opted in (`attestation = true`), if the
/// provider attests this class at all (§3.7 of docs/DESIGN.md).
fn attestation_scheme(t: &Target, tok: &Token) -> Option<Scheme> {
    t.on_token.attestation.then(|| tok.attestation_cap(t.object)).flatten().map(|c| c.scheme)
}

/// Commitments to compute for a secret key on this token: those the spec allows (or, for a
/// wrap-rebind copy, every one for the key type) that the token implements.
fn commits(t: &Target, tok: &Token, mode: Mode) -> Result<Vec<Commit>> {
    let wanted = match (mode, t.object.key_type) {
        (Mode::Commitment, _) => declared_commits(t),
        (Mode::WrapRebind, Some(Kt::Aes)) => AES_COMMITS.to_vec(),
        (Mode::WrapRebind, kt) => kt.and_then(HmacHash::for_key_type).map(Commit::Hmac).into_iter().collect(),
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
pub fn schemes_on(t: &Target, tok: &Token) -> Result<Vec<Scheme>> {
    let mut v = if t.object.class != Class::SecretKey {
        t.schemes()
    } else {
        commits(t, tok, plan_mode(t)?)?.iter().map(|c| c.scheme()).collect()
    };
    if let Some(s) = attestation_scheme(t, tok) {
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
            Some(cap) if !cap.classes.contains(&t.object.class) => {
                return Err(tok.unsupported(format!(
                    "{} opts into attestation, but provider '{}' attests only {:?}",
                    t,
                    tok.provider.name(),
                    cap.classes.iter().map(|c| c.name()).collect::<Vec<_>>()
                )))
            }
            Some(_) => {}
        }
    }
    let mut need = Vec::new();
    if t.on_token.auto_create && let Some(kt) = t.object.key_type.filter(|k| k.is_hash_bound_hmac()) {
        // CKM_GENERIC_SECRET_KEY_GEN makes CKK_GENERIC_SECRET keys; there is no mechanism for
        // the hash-bound HMAC types (SoftHSM: CKR_TEMPLATE_INCONSISTENT).
        return Err(tok.unsupported(format!(
            "{}: PKCS#11 has no key generation for {}; generate a CKK_GENERIC_SECRET with CKA_SIGN, \
             or create the key elsewhere and adopt it",
            t,
            kt
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
    if t.object.class.is_asymmetric() || t.object.class == Class::Certificate {
        tok.check_unique_private_id(h)?;
    }
    tok.check_public_half(h, t.spec, &t.on_token.locator, public_only)?;
    let commits = commits(t, tok, mode)?;
    let label = commitment_label(t, lock);
    let binding = binding(t);
    let ids = tok.ids(h, t.object, &t.on_token.locator, mode, &commits, &label, binding)?;
    let attestation = match attestation_scheme(t, tok) {
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
fn attest(t: &Target, tok: &Token, lock: &Lock, h: ObjectHandle, scheme: Scheme, provision: bool) -> Result<AttestationRecord> {
    let asymmetric = t.object.class.is_asymmetric();
    let spki = if asymmetric { Some(tok.spki(h, &t.on_token.locator)?) } else { None };
    let kind = scheme
        .attestation_kind()
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

/// What this run sees of `tok` (session, mechanisms, module, token), for the lock to record or
/// compare.
fn facts(tok: &Token, r: &Resolved) -> Facts {
    Facts {
        observed: Observed {
            uri: r.uri.clone(),
            session: if tok.logged_in { Session::User } else { Session::Public },
            mechanisms: tok.mechanism_names().to_vec(),
        },
        provenance: Provenance {
            provider: tok.provider.name().to_owned(),
            cakeys_version: env!("CARGO_PKG_VERSION").to_owned(),
            module: tok.module.clone(),
            token: tok.token.clone(),
        },
    }
}

/// GET + If-Match against the lock.
pub fn verify(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Resolved> {
    let r = resolve(t, tok, lock)?.ok_or_else(|| KmError::NotFound(t.to_string()))?;
    reconcile::compare(t, &r, lock, &facts(tok, &r), LockWrite::Compare, notes)?;
    Ok(r)
}

/// PUT: create under the declared locator if absent (and `autoCreate`), then compare with the lock.
/// Re-running never creates a second object: the locator finds the first one.
pub fn realise(t: &Target, tok: &Token, lock: &mut Lock, write: LockWrite, notes: &mut Notes) -> Result<(Resolved, bool)> {
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
            notes.say(format!("created {t}"));
            match resolve_with(t, tok, lock, true).and_then(|r| {
                r.ok_or_else(|| KmError::NotFound(format!("{} vanished after creation", t)))
            }) {
                Ok(r) => r,
                Err(e) => {
                    // The locator was empty before (If-None-Match), so this removes only what we
                    // just made: a refused realise leaves nothing behind, unless the module cannot
                    // delete keys (ykcs11), which is then said rather than claimed.
                    match tok.destroy(t.object, &t.on_token.locator) {
                        Ok(n) => notes.say(format!(
                            "removed {n} object(s) just created for {}: its identity could not be established",
                            t
                        )),
                        Err(d) => notes.say(format!(
                            "the key just created for {} is still on the token (its identity could not be \
                             established, and removing it failed: {d})",
                            t
                        )),
                    }
                    return Err(e);
                }
            }
        }
        None => return Err(KmError::NotFound(format!("{} (autoCreate is off)", t))),
    };
    let changed = reconcile::reconcile(t, &r, lock, &facts(tok, &r), write, notes)?;
    Ok((r, changed))
}

/// DELETE + If-Match. Absent is success; a different object under the locator is left alone.
pub fn delete(t: &Target, tok: &Token, lock: &mut Lock, if_match: Option<&str>, write: LockWrite, notes: &mut Notes) -> Result<bool> {
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
        let primary = t.schemes().into_iter().find(|s| got.contains_key(s.name()));
        let (scheme, expected) = match if_match {
            Some(want) => (primary, Some(want.to_owned())),
            None => t
                .schemes()
                .into_iter()
                .filter(|s| got.contains_key(s.name()))
                .find_map(|s| locked.and_then(|ids| ids.get(s.name())).map(|w| (Some(s), Some(w.clone()))))
                .unwrap_or((primary, None)),
        };
        let scheme = scheme.ok_or_else(|| KmError::Unsupported(format!("no identity computed for {}", t)))?;
        let expected = expected
            .ok_or_else(|| KmError::PreconditionFailed(format!("no expected {scheme} for {}; pass --if-match", t)))?;
        if got.get(scheme.name()) != Some(&expected) {
            return Err(KmError::PreconditionFailed(format!(
                "{} holds {:?}, expected {expected}; not deleting",
                t, got.get(scheme.name())
            )));
        }
    }
    let n = tok.destroy(t.object, &t.on_token.locator)?;
    if n > 0 {
        notes.say(format!("destroyed {n} object(s) for {t}"));
    }
    let mut changed = false;
    if write == LockWrite::Record && let Some(m) = lock.realisations.get_mut(t.spec_name) {
        changed = m.remove(t.token_name).is_some();
        if m.is_empty() {
            lock.realisations.remove(t.spec_name);
        }
    }
    Ok(changed)
}
