//! Export and import against tokens and the lock (MIGRATE.md): each side's capabilities, the
//! objects a source holds, and the transport key. The decisions are `cakeys_core::migrate`'s;
//! each side's capabilities come from the token's resolved capability profiles
//! (docs/PROVIDERS.md phase 2) when one is committed for its provider, else from the
//! provider's own `migration` hook.

use crate::ops::{self, Notes, Target};
use crate::resolution::{self, Resolved};
use crate::{Registry, Token};
use cakeys_core::config::{AttrValue, Lock, ModuleInfo, TokenCfg};
use cakeys_core::migrate::{Accept, Material, OaepHash, PlaintextImport, Side, Transport};
use cakeys_core::types::{KeyType, ObjectClass};
use cakeys_core::{KmError, Result};
use cakeys_profile::{PlaintextKind, Profile};
use std::collections::BTreeSet;
use std::str::FromStr;

pub use cakeys_core::migrate::{Allow, FileFormat, Plan, To, plan};

/// A token's capabilities, from the open token: its resolved capability profile over its
/// usable mechanisms, the layers' subtractions included; the provider's `migration` hook
/// when no module profile is committed for it.
///
/// # Errors
///
/// The mapping error when a committed profile's migration rows name something the baseline
/// does not know: a commit-time bug in the profile, named with its profile.
pub fn side(tok: &Token) -> Result<Side> {
    match &tok.profiles.module {
        Some(p) => side_of(p, &tok.profiles, &tok.name, tok.provider.name(), tok.mechanism_names()),
        None => Ok(tok.provider.migration(&tok.name, tok.mechanism_names())),
    }
}

/// A token's capabilities from the lock alone, for a token this host cannot open: the provider
/// its realisations recorded, the union of their observed mechanisms, and the profiles that
/// resolve from what the lock recorded. `None` when the lock records nothing on the token, or
/// a provider this build does not link.
#[must_use]
pub fn side_from_lock(token: &str, lock: &Lock, registry: &Registry) -> Option<Result<Side>> {
    let recorded: Vec<_> = lock.realisations.values().filter_map(|by_token| by_token.get(token)).collect();
    let provider = recorded.iter().find_map(|r| r.provenance.as_ref().map(|p| p.provider.clone()))?;
    let mechanisms: BTreeSet<String> =
        recorded.iter().filter_map(|r| r.observed.as_ref()).flat_map(|o| o.mechanisms.iter().cloned()).collect();
    let mechanisms: Vec<String> = mechanisms.into_iter().collect();
    // The lock records the module and the token it ran against: resolve what the profiles say
    // about exactly that (the forwarder, the binding layer), like an open would.
    let (module, token_info) =
        recorded.iter().find_map(|r| r.provenance.as_ref().map(|p| (p.module.clone(), p.token.clone())))?;
    let cfg = TokenCfg { provider: Some(provider.clone()), ..lockless_token_cfg() };
    let resolved = resolution::resolve(&cfg, &module, Some(&token_info), &provider).ok()?;
    if resolved.module.is_none() {
        return Some(Ok(registry.named(&provider)?.migration(token, &mechanisms)));
    }
    Some(side_of(resolved.module.as_ref()?, &resolved, token, &provider, &mechanisms))
}

/// A target's capabilities from its transport file: its provider's profile over the mechanisms
/// the file lists (`None`: a provider this build does not link).
#[must_use]
pub fn side_from_transport(t: &Transport, registry: &Registry) -> Option<Result<Side>> {
    let resolved = resolution::resolve(&lockless_token_cfg(), &moduleless_info(), None, &t.provider).ok()?;
    match resolved.module {
        Some(ref p) => Some(side_of(p, &resolved, &t.token, &t.provider, &t.mechanisms)),
        None => Some(Ok(registry.named(&t.provider)?.migration(&t.token, &t.mechanisms))),
    }
}

/// The per-module unwrap-template rules, as data (MIGRATE.md D6): what the wrapping code of
/// MIGRATE phase 3 must drop from a target's unwrap template (`SoftHSM`: `CKA_VALUE_LEN`).
#[must_use]
pub fn unwrap_refusals(tok: &Token) -> Vec<&str> {
    let mut out: Vec<&str> =
        tok.profiles.module.iter().flat_map(|p| p.unwrap.refuse.iter().flatten().map(String::as_str)).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Build a [`Side`] from a module profile over a resolved stack: the spec-compliant base,
/// with the profile's migration rows (and its wrap hashes) applied, the layers' mechanism and
/// key-type subtractions honoured.
///
/// # Errors
///
/// The mapping error when a row names a class, key type, curve or hash the baseline does not
/// know, naming the profile and the row.
fn side_of(module: &Profile, stack: &Resolved, token: &str, provider: &str, mechanisms: &[String]) -> Result<Side> {
    let who = |what: &str| KmError::Validation(format!("module profile {}: {what}", module.profile));
    let mut side = Side::pkcs11(token, provider, mechanisms.iter().cloned());
    // What the stack subtracts: the advertisement's broken rows and every layer's drops.
    side.mechanisms.retain(|m| !stack.subtracted_mechanisms().contains(m.as_str()));
    let m = module.migration.as_ref();
    if let Some(exports) = m.and_then(|m| m.exports) {
        side.exports = exports;
    }
    if let Some(unwraps) = m.and_then(|m| m.unwraps) {
        side.unwraps = unwraps;
    }
    // Never probed keeps the spec-compliant default; probed and empty means no OAEP method.
    if let Some(oaep) = &module.wrap.oaep {
        side.oaep = oaep.iter().map(|h| oaep_hash(h).map_err(|e| who(&e))).collect::<Result<_>>()?;
    }
    if let Some(rows) = m.map(|m| &m.public_accepts).filter(|r| !r.is_empty()) {
        side.public_import =
            rows.iter().filter_map(|r| accept_of(r, stack).map_err(|e| who(&e)).transpose()).collect::<Result<_>>()?;
    }
    if let Some(kind) = m.and_then(|m| m.plaintext_import) {
        let rows: &[cakeys_profile::AcceptRow] = m.map(|m| m.plaintext_accepts.as_slice()).unwrap_or_default();
        let accepts: Vec<Accept> =
            rows.iter().filter_map(|r| accept_of(r, stack).map_err(|e| who(&e)).transpose()).collect::<Result<_>>()?;
        side.plaintext_import = Some(match kind {
            PlaintextKind::CreateObject => PlaintextImport::CreateObject,
            PlaintextKind::Tpm2Ptool => PlaintextImport::Tpm2Ptool(accepts),
            PlaintextKind::PivImport => PlaintextImport::PivImport(accepts),
        });
    }
    Ok(side)
}

/// One migration accept row, as the planner's [`Accept`], or [`None`] when a layer subtracts
/// every key type the row names: the binding cannot name them, so they are not imported
/// through it either.
fn accept_of(row: &cakeys_profile::AcceptRow, stack: &Resolved) -> std::result::Result<Option<Accept>, String> {
    let class = ObjectClass::from_str(&row.class).map_err(|e| format!("{}: {e}", row.class))?;
    let key_types: std::result::Result<Vec<KeyType>, String> = row
        .key_types
        .iter()
        .filter(|k| !stack.subtracted_key_types().contains(k.as_str()))
        .map(|k| KeyType::from_str(k).map_err(|e| format!("{k}: {e}")))
        .collect();
    let key_types = key_types?;
    if !row.key_types.is_empty() && key_types.is_empty() {
        return Ok(None);
    }
    let curves: std::result::Result<Vec<&'static str>, String> = row
        .curves
        .iter()
        .map(|c| {
            cakeys_profile::baseline::CURVES
                .iter()
                .copied()
                .find(|known| known.eq(&c.as_str()))
                .ok_or_else(|| format!("unknown curve: {c}"))
        })
        .collect();
    Ok(Some(Accept {
        class,
        key_types,
        curves: curves?,
        modulus_bits: match (row.min_bits, row.max_bits) {
            (Some(lo), Some(hi)) => Some((lo, hi)),
            (None, Some(hi)) => Some((0, hi)),
            (Some(lo), None) => Some((lo, u32::MAX)),
            (None, None) => None,
        },
    }))
}

/// `SHA-1`/`SHA-256` as [`OaepHash`]es.
fn oaep_hash(name: &str) -> std::result::Result<OaepHash, String> {
    match name {
        "SHA-1" => Ok(OaepHash::Sha1),
        "SHA-256" => Ok(OaepHash::Sha256),
        other => Err(format!("unknown OAEP hash: {other}")),
    }
}

/// A minimal token config for resolution from records: nothing extra, the provider pinned.
fn lockless_token_cfg() -> TokenCfg {
    TokenCfg {
        module: None,
        provider: None,
        profiles: vec![],
        token_label: String::new(),
        pin_file: None,
        pin_env: None,
        mgm_key_file: None,
        mgm_key_env: None,
        system_feature: None,
        scratch: false,
        scratch_id: None,
        options: toml::Table::new(),
    }
}

/// The `ModuleInfo` a transport file implies: only the provider is known, so nothing to
/// detect a forwarder from — the binding layer still applies.
pub(crate) fn moduleless_info() -> ModuleInfo {
    ModuleInfo {
        path: String::new(),
        hash: None,
        description: String::new(),
        manufacturer: String::new(),
        version: String::new(),
        cryptoki: String::new(),
    }
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

/// Where `export` or `migrate` sends the material.
pub enum Dest<'a> {
    /// A token in keys.toml.
    Token(&'a str),
    /// A target this host cannot reach, by its transport file: the parsed file, and how to
    /// name it in messages.
    Transport(&'a Transport, &'a str),
    File(FileFormat),
}

/// What to plan moving.
pub struct Request<'a> {
    /// Only this object; default: every object realised on `from`.
    pub object: Option<&'a str>,
    /// The source token.
    pub from: &'a str,
    pub dest: Dest<'a>,
    /// Allow the `host` and `file` paths: plaintext in this process's memory (MIGRATE.md D2).
    pub host_plaintext: bool,
}

/// The plans of one invocation (MIGRATE.md D9).
pub struct Moves {
    /// The destination's name: the target token, or the file format.
    pub to: String,
    /// Where each side's capabilities came from: the open `token`, the `lock`, the `transport
    /// file`, or `-` for a file.
    pub source_from: &'static str,
    pub target_from: &'static str,
    pub plans: Vec<Plan>,
}

impl Moves {
    /// Whether every object can move as invoked.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) when any plan is blocked.
    pub fn ready(&self) -> Result<()> {
        let blocked = self.plans.iter().filter(|p| !p.ready).count();
        if blocked > 0 {
            return Err(KmError::Unsupported(format!(
                "{blocked} of {} objects cannot move as invoked",
                self.plans.len()
            )));
        }
        Ok(())
    }
}

/// Plan each object's move as `req` asks, from what the lock pins. `open` opens a token
/// read-only; one that does not open is planned from what the lock recorded there.
///
/// # Errors
///
/// [`materials`]' refusals; a side that neither opens nor is recorded in the lock (the open's
/// error); `Unsupported` for a transport file of a provider this build does not link, and
/// `Validation` when its profile does not map.
pub fn plan_moves(
    lock: &Lock,
    registry: &Registry,
    req: &Request,
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    notes: &mut Notes,
) -> Result<Moves> {
    let materials = materials(lock, req.from, req.object)?;
    let mut side = |name: &str| side_or_lock(name, lock, registry, open, notes);
    let (source, source_from) = side(req.from)?;
    let mut allow = Allow { host_plaintext: req.host_plaintext, ..Allow::default() };
    let (target, target_from, to_name) = match &req.dest {
        Dest::Token(name) => {
            let (side, from) = side(name)?;
            (Some(side), from, (*name).to_owned())
        }
        Dest::Transport(t, shown) => {
            // Phase 3b sets this only after the source's SO marked the key trusted there.
            allow.trusted_transport = t.trusted;
            let side = side_from_transport(t, registry)
                .ok_or_else(|| {
                    KmError::Unsupported(format!("{shown}: provider '{}' is not in this build", t.provider))
                })?
                .map_err(|e| KmError::Validation(format!("{shown}: {e}")))?;
            (Some(side), "transport file", t.token.clone())
        }
        Dest::File(f) => (None, "-", format!("{f:?} file").to_lowercase()),
    };
    let to = match (&target, &req.dest) {
        (Some(side), _) => To::Token(side),
        (None, Dest::File(f)) => To::File(*f),
        (None, _) => unreachable!("only a file has no side"),
    };
    let plans = materials.iter().map(|m| plan(m, &source, &to, allow)).collect();
    Ok(Moves { to: to_name, source_from, target_from, plans })
}

/// A token's capabilities: from the open token, else from what the lock recorded there.
fn side_or_lock(
    name: &str,
    lock: &Lock,
    registry: &Registry,
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    notes: &mut Notes,
) -> Result<(Side, &'static str)> {
    match open(name, notes) {
        Ok(tok) => Ok((side(&tok)?, "token")),
        Err(e) => match side_from_lock(name, lock, registry) {
            Some(side) => {
                notes.note(format_args!("capabilities of '{name}' come from the lock: the token did not open ({e})"));
                Ok((side?, "lock"))
            }
            None => Err(e),
        },
    }
}
