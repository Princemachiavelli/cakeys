//! Export and import against tokens and the lock (MIGRATE.md): each side's capabilities, the
//! objects a source holds, and the transport key. The decisions are [`crate::plan`]'s; each
//! side's capabilities come from the token's resolved capability profiles (docs/PROVIDERS.md
//! phase 2) when one is committed for its provider, else from the provider's own `migration`
//! hook.

use crate::plan::{Allow, FileFormat, Material, Plan, To, plan};
use crate::transport::Transport;
use cakeys_core::config::{AttrValue, Lock, Observation, TokenCfg, TokenObservation};
use cakeys_core::migrate::{Accept, Method, PlaintextImport, Side};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::{KeyType, ObjectClass};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::resolution::{self, Resolved, moduleless_info};
use cakeys_pkcs11::{Registry, Token};
use cakeys_profile::{PlaintextKind, Profile};
use std::collections::BTreeSet;
use std::str::FromStr;

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

/// A token's capabilities from the lock alone, for a token this host cannot open: the token's
/// observation (review A3) — its provider, mechanisms, and the profiles that resolve from the
/// module and token it recorded. `None` when the observation records no provider, or one this
/// build does not link.
#[must_use]
pub fn side_from_lock(
    token: &str,
    observed: &Observation,
    registry: &Registry,
    notes: &mut Notes,
) -> Option<Result<Side>> {
    let provider = observed.provider.clone()?;
    // The lock records the module and the token it ran against: resolve what the profiles say
    // about exactly that (the forwarder, the binding layer), like an open would.
    let (module, token_info) = (observed.module.as_ref()?, observed.token.as_ref()?);
    let cfg = TokenCfg { provider: Some(provider.clone()), ..lockless_token_cfg() };
    let resolved = resolution::resolve(&cfg, module, Some(token_info), &provider).ok()?;
    warn_hidden(token, &resolved, notes);
    if resolved.module.is_none() {
        return Some(Ok(registry.named(&provider)?.migration(token, &observed.mechanisms)));
    }
    Some(side_of(resolved.module.as_ref()?, &resolved, token, &provider, &observed.mechanisms))
}

/// A token behind a passthrough that hides its module (a `requires-provider` layer) is planned
/// as a spec-compliant module until keys.toml names that module's provider: say so loudly.
fn warn_hidden(token: &str, resolved: &Resolved, notes: &mut Notes) {
    if let Some(why) = &resolved.hidden {
        notes.warn(format_args!(
            "'{token}' is planned as a spec-compliant module: {why}; set `provider` in [tokens.{token}]"
        ));
    }
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
    if let Some(secret) = m.and_then(|m| m.secret_unwraps) {
        side.secret_unwraps = secret;
    }
    if let Some(trusted) = m.and_then(|m| m.trusted_wrap) {
        side.trusted_wrap = trusted;
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
        transport_with: None,
    }
}

/// The objects realised on `token` (only `object`, if given), with what the planner needs from
/// the lock: the object's type and one realisation's recorded policy and immutables.
///
/// # Errors
///
/// `PreconditionFailed` when `object` has no realisation on `token`, or the lock records no
/// type for it: the plan is made from what the lock pins, so realise it first.
pub fn materials<'a>(lock: &'a Lock, token: &str, objects: &[&str]) -> Result<Vec<Material<'a>>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for by_token in lock.realisations.values() {
        let Some(r) = by_token.get(token) else { continue };
        if !(objects.is_empty() || objects.contains(&r.object.as_str())) || !seen.insert(r.object.as_str()) {
            continue;
        }
        let ty = lock.objects.get(&r.object).and_then(|o| o.object_type.as_ref()).ok_or_else(|| {
            KmError::PreconditionFailed(format!("the lock records no type for object '{}'", r.object))
        })?;
        out.push(Material { object: &r.object, ty, policy: &r.policy, immutables: &r.immutables });
    }
    if let Some(o) = objects.iter().find(|o| !seen.contains(**o)) {
        return Err(KmError::PreconditionFailed(format!(
            "object '{o}' has no realisation on token '{token}' in the lock; realise it there first"
        )));
    }
    if out.is_empty() {
        return Err(KmError::PreconditionFailed(format!(
            "the lock records no realisation on token '{token}': nothing to plan"
        )));
    }
    Ok(out)
}

/// The transport key's public half (`camigrate transport`, MIGRATE.md D3). The spec must name an
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
    warn_decrypting(t, lock, notes);
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
    /// Only these objects; default (empty): every object realised on `from`.
    pub objects: &'a [&'a str],
    /// The source token.
    pub from: &'a str,
    pub dest: Dest<'a>,
    /// Allow the `host` and `file` paths: plaintext in this process's memory (MIGRATE.md D2).
    pub host_plaintext: bool,
    /// The target's transport key, by its spec, when several are realised there (MIGRATE.md D3).
    pub transport_key: Option<&'a str>,
    /// The source holds a copy of that transport key its SO marked `CKA_TRUSTED` (MIGRATE.md D2,
    /// `enforced`).
    pub trusted_transport: bool,
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
    let materials = materials(lock, req.from, req.objects)?;
    let mut side = |name: &str| side_or_lock(name, lock, registry, open, notes);
    let (source, source_from) = side(req.from)?;
    let allow = Allow { host_plaintext: req.host_plaintext, trusted_transport: req.trusted_transport };
    let (target, target_from, to_name) = match &req.dest {
        Dest::Token(name) => {
            let (side, from) = side(name)?;
            (Some(side), from, (*name).to_owned())
        }
        Dest::Transport(t, shown) => {
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
    let mut plans: Vec<Plan> = materials.iter().map(|m| plan(m, &source, &to, allow)).collect();
    // A sealed move needs the transport key it wraps to: realised on a target token, or pinned by
    // this lock when it comes as a file (D3: the lock is the authenticated channel).
    let sealed = |p: &Plan| matches!(p.method, Some(Method::RsaOaepAesKwp(_) | Method::RsaOaep(_)));
    let missing = match &req.dest {
        Dest::Token(name) => match transport_spec(lock, name, req.transport_key) {
            Err(why) => Some(why),
            // Not open here: the export seals to the public key the lock recorded, or cannot.
            Ok(spec) if target_from == "lock" => {
                let object = lock.realisation(spec, name).map(|r| r.object.as_str());
                object.and_then(|o| lock.objects.get(o)).and_then(|o| o.public_key.as_ref()).is_none().then(|| {
                    format!(
                        "'{name}' is not open, and the lock records no public key for its transport key '{spec}': \
                         realise it there again with transportWith naming it"
                    )
                })
            }
            Ok(_) => None,
        },
        Dest::Transport(t, shown) => pinned(lock, t).err().map(|e| format!("{shown}: {e}")),
        Dest::File(_) => None,
    };
    if let Some(why) = missing {
        for p in plans.iter_mut().filter(|p| p.ready && sealed(p)) {
            p.ready = false;
            p.reasons.push(why.clone());
        }
    }
    Ok(Moves { to: to_name, source_from, target_from, plans })
}

/// A token's capabilities: from the open token, else from what the lock recorded there. A
/// passthrough with no provider named behind it is planned as a spec-compliant module, loudly.
fn side_or_lock(
    name: &str,
    lock: &Lock,
    registry: &Registry,
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    notes: &mut Notes,
) -> Result<(Side, &'static str)> {
    let e = match open(name, notes) {
        Ok(tok) => {
            warn_hidden(name, &tok.profiles, notes);
            return Ok((side(&tok)?, "token"));
        }
        Err(e) => e,
    };
    let observed = match lock.token_observation(name) {
        TokenObservation::One(o) => o,
        TokenObservation::None => return Err(e),
        TokenObservation::Several(groups) => {
            notes.note(format_args!(
                "capabilities of '{name}' cannot come from the lock: {}",
                TokenObservation::several(name, &groups)
            ));
            return Err(e);
        }
    };
    match side_from_lock(name, observed, registry, notes) {
        Some(side) => {
            notes.note(format_args!("capabilities of '{name}' come from the lock: the token did not open ({e})"));
            Ok((side?, "lock"))
        }
        None => Err(e),
    }
}

/// The spec of the transport key realised on `token` (MIGRATE.md D3): the one `chosen` names —
/// `--transport-key`, else the token's `transportWith` — never one picked by what it can do. The
/// lock must record it there as an RSA private key that may unwrap and never leaves the token.
///
/// # Errors
///
/// Why there is no such key.
pub fn transport_spec<'a>(lock: &'a Lock, token: &str, chosen: Option<&str>) -> std::result::Result<&'a str, String> {
    let Some(chosen) = chosen else {
        return Err(format!(
            "no transport key is named for '{token}' (MIGRATE.md D3): set transportWith in [tokens.{token}] to the \
             spec of an RSA key there that may unwrap and never leaves the token, realise it, or pass --transport-key"
        ));
    };
    let Some((spec, r)) =
        lock.realisations.get_key_value(chosen).and_then(|(spec, by_token)| Some((spec, by_token.get(token)?)))
    else {
        return Err(format!(
            "transport key '{chosen}' is not realised on '{token}' in the lock: realise it there first"
        ));
    };
    let is_true = |n: &str| r.policy.get(n) == Some(&AttrValue::Bool(true));
    let rsa = lock
        .objects
        .get(&r.object)
        .and_then(|o| o.object_type.as_ref())
        .is_some_and(|t| t.class == ObjectClass::PrivateKey && t.key_type == Some(KeyType::Rsa));
    if !rsa || !is_true("CKA_UNWRAP") || is_true("CKA_EXTRACTABLE") {
        return Err(format!(
            "'{chosen}' on '{token}' is no transport key: an RSA private key that may unwrap (CKA_UNWRAP) and never \
             leaves the token (CKA_EXTRACTABLE = false), as the lock records it"
        ));
    }
    Ok(spec.as_str())
}

/// The public key to seal to for the transport key `t`, from the lock alone (`publicKey`, held
/// to the locked identity on load): no target needs to be open. `None` when the lock has none
/// yet (realised before `transportWith` named it). A transport key that may also decrypt is
/// warned about: whoever holds the target's PIN could decrypt what is sealed to it.
///
/// # Errors
///
/// `Validation` when the recorded key is no SPKI.
pub fn locked_transport(t: &Target, lock: &Lock, notes: &mut Notes) -> Result<Option<crate::sealed::TransportKey>> {
    use base64::Engine as _;
    warn_decrypting(t, lock, notes);
    let Some(o) = lock.objects.get(t.object_name) else { return Ok(None) };
    let (Some(k), Some(id)) = (&o.public_key, o.ids.get("rfc7093m4")) else { return Ok(None) };
    let spki = base64::engine::general_purpose::STANDARD
        .decode(k)
        .map_err(|e| KmError::Validation(format!("{t}: the lock's publicKey: {e}")))?;
    Ok(Some(crate::sealed::TransportKey { object: t.object_name.to_owned(), rfc7093m4: id.clone(), spki }))
}

/// A transport key whose recorded policy also decrypts: the target's PIN holder could
/// `C_Decrypt` a bundle's wrapped key-encryption key out of the token.
fn warn_decrypting(t: &Target, lock: &Lock, notes: &mut Notes) {
    let policy = lock.realisation(t.spec_name, t.token_name).map(|r| &r.policy);
    if policy.and_then(|p| p.get("CKA_DECRYPT")) == Some(&AttrValue::Bool(true)) {
        notes.warn(format_args!(
            "{t} also decrypts (CKA_DECRYPT): whoever holds the target's PIN can decrypt what is sealed to it \
             out of the token; a transport key that only unwraps proves possession with binding = \"pop-unwrap\""
        ));
    }
}

/// A transport file's key is the one the lock pins for its object.
///
/// # Errors
///
/// Why it is not.
pub fn pinned(lock: &Lock, t: &Transport) -> std::result::Result<(), String> {
    match lock.objects.get(&t.object).and_then(|o| o.ids.get("rfc7093m4")) {
        Some(id) if *id == t.rfc7093m4 => Ok(()),
        Some(id) => Err(format!("its key {} is not the {id} the lock pins for '{}'", t.rfc7093m4, t.object)),
        None => Err(format!("the lock pins no key for its object '{}', so nothing vouches for it", t.object)),
    }
}
