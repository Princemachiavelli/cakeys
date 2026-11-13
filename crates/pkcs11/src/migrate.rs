//! Export and import against tokens and the lock (MIGRATE.md): each side's capabilities, the
//! objects a source holds, and the transport key. The decisions are `cakeys_core::migrate`'s.

use crate::ops::{self, Notes, Target};
use crate::{Registry, Token};
use cakeys_core::config::{AttrValue, Lock};
use cakeys_core::migrate::{Material, Side, Transport};
use cakeys_core::types::{KeyType, ObjectClass};
use cakeys_core::{KmError, Result};
use std::collections::BTreeSet;

pub use cakeys_core::migrate::{Allow, FileFormat, Plan, To, plan};

/// A token's capabilities, from the open token: its provider's profile over its usable
/// mechanisms.
#[must_use]
pub fn side(tok: &Token) -> Side {
    tok.provider.migration(&tok.name, tok.mechanism_names())
}

/// A token's capabilities from the lock alone, for a token this host cannot open: the provider
/// its realisations recorded and the union of their observed mechanisms. `None` when the lock
/// records nothing on the token, or a provider this build does not link.
#[must_use]
pub fn side_from_lock(token: &str, lock: &Lock, registry: &Registry) -> Option<Side> {
    let recorded: Vec<_> = lock.realisations.values().filter_map(|by_token| by_token.get(token)).collect();
    let provider = recorded.iter().find_map(|r| r.provenance.as_ref().map(|p| p.provider.clone()))?;
    let mechanisms: BTreeSet<String> =
        recorded.iter().filter_map(|r| r.observed.as_ref()).flat_map(|o| o.mechanisms.iter().cloned()).collect();
    let mechanisms: Vec<String> = mechanisms.into_iter().collect();
    Some(registry.named(&provider)?.migration(token, &mechanisms))
}

/// A target's capabilities from its transport file: its provider's profile over the mechanisms
/// the file lists (`None`: a provider this build does not link).
#[must_use]
pub fn side_from_transport(t: &Transport, registry: &Registry) -> Option<Side> {
    Some(registry.named(&t.provider)?.migration(&t.token, &t.mechanisms))
}

/// The objects realised on `token` (only `object`, if given), with what the planner needs from
/// the lock: the object's type and one realisation's recorded policy and immutables.
///
/// # Errors
///
/// `PreconditionFailed` when `object` has no realisation on `token`, or the lock records no
/// type for it: the plan is made from what the lock pins, so realise it first.
pub fn materials<'a>(lock: &'a Lock, token: &str, object: Option<&str>) -> Result<Vec<Material<'a>>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for by_token in lock.realisations.values() {
        let Some(r) = by_token.get(token) else { continue };
        if object.is_some_and(|o| o != r.object) || !seen.insert(r.object.as_str()) {
            continue;
        }
        let ty = lock.objects.get(&r.object).and_then(|o| o.object_type.as_ref()).ok_or_else(|| {
            KmError::PreconditionFailed(format!("the lock records no type for object '{}'", r.object))
        })?;
        out.push(Material { object: &r.object, ty, policy: &r.policy, immutables: &r.immutables });
    }
    if out.is_empty() {
        return Err(KmError::PreconditionFailed(match object {
            Some(o) => {
                format!("object '{o}' has no realisation on token '{token}' in the lock; realise it there first")
            }
            None => format!("the lock records no realisation on token '{token}': nothing to plan"),
        }));
    }
    Ok(out)
}

/// The transport key's public half (`cakeys transport`, MIGRATE.md D3). The spec must name an
/// RSA private key that may unwrap and never leaves the token, and its realisation must verify
/// against the lock: the locked identity is what makes the public key trustworthy to a source.
///
/// # Errors
///
/// `Validation` for anything but an RSA private key; `PreconditionFailed` when the realisation
/// does not allow `CKA_UNWRAP` or is extractable; whatever `verify` refuses.
pub fn transport(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Transport> {
    if t.object.class != ObjectClass::PrivateKey || t.object.key_type != Some(KeyType::Rsa) {
        return Err(KmError::Validation(format!(
            "{t}: a transport key is an RSA private key (MIGRATE.md D3), not a {}",
            t.object.class
        )));
    }
    ops::verify(t, tok, lock, notes)?;
    let policy = lock.realisation(t.spec_name, t.token_name).map(|r| &r.policy);
    let flag = |name: &str| policy.and_then(|p| p.get(name)) == Some(&AttrValue::Bool(true));
    if !flag("CKA_UNWRAP") {
        return Err(KmError::PreconditionFailed(format!("{t}: a transport key must allow CKA_UNWRAP")));
    }
    if flag("CKA_EXTRACTABLE") {
        return Err(KmError::PreconditionFailed(format!(
            "{t}: a transport key must never leave the token (CKA_EXTRACTABLE = false)"
        )));
    }
    if flag("CKA_DECRYPT") {
        notes.note(format_args!("{t} also decrypts; a transport key that only unwraps is recommended"));
    }
    let h = tok
        .find_key(t.object, &t.on_token.locator, false)?
        .ok_or_else(|| KmError::NotFound(format!("{t}: the transport key")))?;
    let spki = tok.spki(h, &t.on_token.locator)?;
    Transport::new(&tok.name, tok.provider.name(), t.object_name, &spki, tok.mechanism_names())
}
