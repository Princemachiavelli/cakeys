//! Export and import against tokens and the lock (docs/CAMIGRATE.md): each side's capabilities, the
//! objects a source holds, and the transport key. The decisions are [`crate::plan`]'s; each
//! side's capabilities come from the token's resolved capability profiles (docs/CAPROBE.md
//! phase 2) when one is committed for its provider, else a spec-compliant module's
//! (`Side::pkcs11`).

use crate::plan::{Allow, FileFormat, Material, Plan, To, plan};
use crate::transport::Transport;
use cakeys_core::config::{AttrValue, Lock, Observation, TokenCfg, TokenObservation};
use cakeys_core::migrate::{Accept, Method, PlaintextImport, Probed, ProbedWays, Side};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::{KeyType, ObjectClass};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::resolution::{self, Resolved, moduleless_info};
use cakeys_pkcs11::{Registry, Token};
use cakeys_profile::{Capability, KeyKind, Move, On, PlaintextKind, Profile, Way};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

/// A token's capabilities, from the open token: its resolved capability profile over its
/// usable mechanisms, the layers' subtractions included; a spec-compliant module's
/// (`Side::pkcs11`) when no module profile is committed for it.
///
/// # Errors
///
/// The mapping error when a committed profile's migration rows name something the baseline
/// does not know: a commit-time bug in the profile, named with its profile.
pub(crate) fn side(tok: &Token) -> Result<Side> {
    match &tok.profiles.module {
        Some(p) => side_of(p, &tok.profiles, &tok.name, tok.provider.name(), &tok.mechanism_names()),
        None => Ok(Side::pkcs11(&tok.name, tok.provider.name(), tok.mechanism_names())),
    }
}

/// A token's capabilities from the lock alone, for a token this host cannot open: the token's
/// observation (review A3) — its provider, mechanisms, and the profiles that resolve from the
/// module and token it recorded. `None` when the observation records no provider, or one this
/// build does not link.
#[must_use]
pub(crate) fn side_from_lock(
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
    let mut resolved = match resolved(token, resolution::resolve(&cfg, module, Some(token_info), &provider)) {
        Ok(r) => r,
        Err(e) => return Some(Err(e)),
    };
    // What this token answered decides before the profile of its kind.
    resolved.with_answers(token, observed);
    warn_hidden(token, &resolved, notes);
    if resolved.module.is_none() {
        let name = match registry.named(&provider) {
            Ok(p) => p?.name(),
            Err(e) => return Some(Err(e)),
        };
        return Some(Ok(Side::pkcs11(token, name, observed.mechanisms.iter().cloned())));
    }
    Some(side_of(resolved.module.as_ref()?, &resolved, token, &provider, &observed.mechanisms))
}

/// A resolution of `token`'s profiles that failed is invalid (17), as a token open maps it:
/// never read as "no provider", which would blame the lock or the build instead.
fn resolved(token: &str, r: std::result::Result<Resolved, String>) -> Result<Resolved> {
    r.map_err(|e| KmError::Validation(format!("resolving the profiles of '{token}': {e}").into()))
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
pub(crate) fn side_from_transport(t: &Transport, registry: &Registry) -> Option<Result<Side>> {
    let resolved =
        match resolved(&t.token, resolution::resolve(&lockless_token_cfg(), &moduleless_info(), None, &t.provider)) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
    match resolved.module {
        Some(ref p) => Some(side_of(p, &resolved, &t.token, &t.provider, &t.mechanisms)),
        None => registry
            .named(&t.provider)
            .transpose()
            .map(|p| p.map(|p| Side::pkcs11(&t.token, p.name(), t.mechanisms.iter().cloned()))),
    }
}

/// The per-module unwrap-template rules, as data (docs/CAMIGRATE.md D6): what `sealed::import`
/// drops from a target's unwrap template (`SoftHSM`: `CKA_VALUE_LEN`).
#[must_use]
pub(crate) fn unwrap_refusals(tok: &Token) -> Vec<String> {
    refusals_of(tok.profiles.module.as_ref())
}

/// [`unwrap_refusals`] of a module profile, for a [`Side`] too.
fn refusals_of(module: Option<&Profile>) -> Vec<String> {
    let mut out: Vec<String> = module.iter().flat_map(|p| p.unwrap_refuse().into_iter().flatten()).collect();
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
    let who = |what: &str| KmError::Validation(format!("module profile {}: {what}", module.profile).into());
    let mut side = Side::pkcs11(token, provider, mechanisms.iter().cloned());
    // What the stack subtracts: the advertisement's broken rows and every layer's drops.
    side.mechanisms.retain(|m| !stack.subtracted_mechanisms().contains(m.as_str()));
    let m = module.migration.as_ref();
    for (way, field) in [
        (Move::Export, &mut side.exports),
        (Move::Unwrap, &mut side.unwraps),
        (Move::SecretUnwrap, &mut side.secret_unwraps),
        (Move::TrustedWrap, &mut side.trusted_wrap),
    ] {
        if let Some(answer) = module.moves(way) {
            *field = answer;
        }
    }
    // Never probed keeps the spec-compliant default; probed and empty means no OAEP method.
    if let Some(oaep) = &module.wrap_oaep() {
        side.oaep = oaep.iter().map(|h| oaep_hash(h).map_err(|e| who(&e))).collect::<Result<_>>()?;
    }
    if let Some(rows) = m.map(|m| &m.public_accepts).filter(|r| !r.is_empty()) {
        side.public_import =
            rows.iter().filter_map(|r| accept_of(r, stack).map_err(|e| who(&e)).transpose()).collect::<Result<_>>()?;
    }
    if let Some(rows) = m.map(|m| &m.refuses) {
        side.refuses =
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
    side.probed = probed_of(module, stack, &side.mechanisms);
    side.derive_sealed = module.answer(&Capability::DeriveSealed);
    side.unwrap_refuse = refusals_of(Some(module));
    side.public_keys = cakeys_pkcs11::token::accepts_public_keys(Some(module));
    Ok(side)
}

/// What the providers of a move's two sides refuse of the templates its run will send
/// (`Provider::template`), asked before anything runs: the source's ([`source_refusal`]), then
/// the target's ([`target_refusal`]). `Err` names the first refusal; `Ok(Some(note))` when the
/// plan cannot build what the run will send, and only the run asks.
pub(crate) fn template_refusal(
    dst: &Target,
    method: &Method,
    exposure: cakeys_core::migrate::Exposure,
    source: &Side,
    target: &Side,
    registry: &Registry,
) -> std::result::Result<Option<String>, String> {
    source_refusal(method, exposure, source, registry)?;
    target_refusal(dst, method, target, registry)
}

/// The provider of `side` asked about one template.
fn ask(
    side: &Side,
    registry: &Registry,
    req: &cakeys_pkcs11::Template<'_>,
    t: Vec<cryptoki::object::Attribute>,
) -> std::result::Result<(), String> {
    match registry.named(&side.provider).map_err(|e| e.to_string())? {
        Some(p) => {
            p.adjusted(req, t).map(drop).map_err(|e| format!("provider '{}' on '{}': {e}", p.name(), side.token))
        }
        None => Ok(()),
    }
}

/// The source's part of [`template_refusal`], and all a plan asks where nothing lands on a token
/// here (a transport file, a key file): the session keys its export makes, under the export's
/// own conditions ([`shares_kek`], [`side_rfc5649`]): the host's KEK for a key handed over (to
/// a target, or written to a file), the transport key and the shared KEK for a sealed one.
///
/// [`shares_kek`]: crate::sealed::shares_kek
/// [`side_rfc5649`]: crate::sealed::side_rfc5649
pub(crate) fn source_refusal(
    method: &Method,
    exposure: cakeys_core::migrate::Exposure,
    source: &Side,
    registry: &Registry,
) -> std::result::Result<(), String> {
    use crate::sealed::{shares_kek, side_rfc5649};
    use cakeys_pkcs11::templates::session;
    use cakeys_pkcs11::{SessionKey, Template};
    let session_key = |key| ask(source, registry, &Template::Session(key), session(key));
    match method {
        Method::HostPkcs8
        | Method::HostRaw
        | Method::PivImport
        | Method::Tpm2Ptool
        | Method::Pkcs8Pbes2
        | Method::Pkcs12 => session_key(SessionKey::HostKek),
        Method::RsaOaep(_) | Method::RsaOaepAesKwp(_) => {
            session_key(SessionKey::TransportKey)?;
            if shares_kek(method, exposure, side_rfc5649(source), source.has("CKM_AES_KEY_GEN")) {
                session_key(SessionKey::ExportKek)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The target's part of [`template_refusal`], and what an import's dry run asks of the open
/// target: the object `method` creates under `dst` (a key by `C_CreateObject` or `C_UnwrapKey`,
/// a public object), an imported private key's public half where the target makes one, the KEK
/// a composed unwrap makes there ([`side_rfc5649`]), and the session keys of the proof and
/// commitments its record makes. A public object's value and a public key's material are not
/// read yet, so absent.
///
/// [`side_rfc5649`]: crate::sealed::side_rfc5649
pub(crate) fn target_refusal(
    dst: &Target,
    method: &Method,
    target: &Side,
    registry: &Registry,
) -> std::result::Result<Option<String>, String> {
    use crate::sealed::{side_rfc5649, unwrap_declared};
    use cakeys_pkcs11::templates::{import_key, known_policy, object, public_half, session};
    use cakeys_pkcs11::{Declared, SessionKey, Template, Via};
    let ask = |req: Template<'_>, t: Result<Vec<cryptoki::object::Attribute>>| {
        ask(target, registry, &req, t.map_err(|e| format!("{dst}: {e}"))?)
    };
    let known = |attrs| known_policy(attrs).map_err(|e| format!("{dst}: {e}"));
    let unknown = Some(format!(
        "{dst}: a mechanism its spec allows is none the profiles name, so the providers are asked about its \
         templates only when it moves"
    ));
    let on = Declared::from(dst);
    let private = dst.object.class == ObjectClass::PrivateKey;
    let key = private || dst.object.class == ObjectClass::SecretKey;
    let (Some(policy), Some(public_policy)) = (known(&dst.spec.attributes)?, known(&dst.spec.public_attributes)?)
    else {
        return Ok(unknown);
    };
    match method {
        Method::RsaOaep(_) | Method::RsaOaepAesKwp(_) => {
            let Some(unwrapped) = known(&unwrap_declared(&dst.spec.attributes, &target.unwrap_refuse))? else {
                return Ok(unknown);
            };
            ask(Template::Import(on, Via::Unwrap), import_key(on, unwrapped))?;
            if matches!(method, Method::RsaOaepAesKwp(_)) && side_rfc5649(target) {
                ask(Template::Session(SessionKey::ImportKek), Ok(session(SessionKey::ImportKek)))?;
            }
            if private {
                ask(Template::PublicHalf(on), public_half(on, public_policy, None))?;
            }
        }
        // `tpm2_ptool` imports outside PKCS#11; a provider's own method is its own.
        Method::Tpm2Ptool | Method::Vendor { .. } => {}
        // Through the host, from a token or a file: a private or secret key by C_CreateObject,
        // anything else created as a public object is (a private data object from its file).
        method if key && *method != Method::Public => {
            ask(Template::Import(on, Via::CreateObject), import_key(on, policy))?;
            if private && target.public_keys {
                ask(Template::PublicHalf(on), public_half(on, public_policy, None))?;
            }
        }
        _ => ask(Template::Object(on), object(on, policy, None))?,
    }
    // What the target's `lock` makes once the object is there: its proof's and commitments' keys.
    let mode = ops::plan_mode(dst).map_err(|e| format!("{dst}: {e}"))?;
    let has = |m: cryptoki::mechanism::MechanismType| Some(target.has(&m.to_string()));
    let seals = ops::ecdh_seals(target.derive_sealed, Some(target.has("CKM_SHA256_HMAC")));
    for (key, t) in ops::session_templates(dst, mode, &has, seals).map_err(|e| format!("{dst}: {e}"))? {
        ask(Template::Session(key), Ok(t))?;
    }
    Ok(None)
}

/// The probed rows of `module` (`docs/CAPROBE_MIGRATION.md`), by way, each as the objects it
/// covers. A row of a key type a layer subtracts answers no: the binding cannot name it. A yes
/// by a mechanism the stack no longer offers (`via`, `usable` the mechanisms left: p11-kit hides
/// `SoftHSM`'s RFC 5649 key wraps) is left out, as is a row naming a key type, class or curve
/// this build does not know: unknown, so the claims and the mechanisms decide.
fn probed_of(module: &Profile, stack: &Resolved, usable: &BTreeSet<String>) -> ProbedWays {
    let subtracted = stack.subtracted_key_types();
    let mut ways = ProbedWays::default();
    for (c, row) in &module.capabilities {
        let (rows, class, key) = match c {
            Capability::Import { key_type, on } => (&mut ways.import, None, Some((key_type, on))),
            Capability::Create { class, key } => {
                (&mut ways.create, Some(class.as_str()), key.as_ref().map(|(k, o)| (k, o)))
            }
            Capability::Export { way: Way::Host, key_type, on } => (&mut ways.export_host, None, Some((key_type, on))),
            Capability::Export { way: Way::Sealed, key_type, on } => {
                (&mut ways.export_sealed, None, Some((key_type, on)))
            }
            Capability::Unwrap { key_type, on } => (&mut ways.unwrap, None, Some((key_type, on))),
            _ => continue,
        };
        let Some((covers, gone)) = covers_of(class, key, &subtracted) else { continue };
        let hidden = row.via.as_ref().is_some_and(|v| v.starts_with("CKM_") && !usable.contains(v));
        if row.answer.yes() && hidden {
            continue;
        }
        rows.push(Probed { covers, yes: row.answer.yes() && !gone, via: row.via.clone() });
    }
    ways
}

/// What a probed row covers: its class (a key's, by its key type, unless named) narrowed to its
/// key type and curve, RSA size or length; and whether a layer subtracts that key type.
fn covers_of(class: Option<&str>, key: Option<(&KeyKind, &On)>, subtracted: &BTreeSet<&str>) -> Option<(Accept, bool)> {
    let Some((key_type, on)) = key else {
        return Some((Accept::class(ObjectClass::from_str(class?).ok()?), false));
    };
    let kt = KeyType::from_str(key_type.name()).ok()?;
    let class = match class {
        Some(c) => ObjectClass::from_str(c).ok()?,
        None if matches!(kt, KeyType::Ec | KeyType::EcEdwards | KeyType::Rsa) => ObjectClass::PrivateKey,
        None => ObjectClass::SecretKey,
    };
    let base = Accept::key(class, &[kt]);
    let covers = match on {
        On::Item(curve) => {
            Accept { curves: vec![cakeys_profile::baseline::CURVES.iter().copied().find(|c| c == curve)?], ..base }
        }
        On::Bits(bits) => Accept { modulus_bits: Some((*bits, *bits)), ..base },
        On::Bytes(n) => Accept { value_len: Some(u64::from(*n)), ..base },
    };
    Some((covers, subtracted.contains(key_type.name())))
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
        value_len: None,
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
    TokenCfg::labelled(String::new())
}

/// The objects realised on `token` (only `object`, if given), with what the planner needs from
/// the lock: the object's type and one realisation's recorded policy and immutables.
///
/// # Errors
///
/// `PreconditionFailed` when `object` has no realisation on `token`, or the lock records no
/// type for it: the plan is made from what the lock pins, so lock it first.
pub(crate) fn materials<'a>(lock: &'a Lock, token: &str, objects: &[&str]) -> Result<Vec<Material<'a>>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for by_token in lock.realisations.values() {
        let Some(r) = by_token.get(token) else { continue };
        if !(objects.is_empty() || objects.contains(&r.object.as_str())) || !seen.insert(r.object.as_str()) {
            continue;
        }
        let ty = lock.objects.get(&r.object).and_then(|o| o.object_type.as_ref()).ok_or_else(|| {
            KmError::PreconditionFailed(format!("the lock records no type for object '{}'", r.object).into())
        })?;
        out.push(Material { object: &r.object, ty, policy: &r.policy, immutables: &r.immutables });
    }
    if let Some(o) = objects.iter().find(|o| !seen.contains(**o)) {
        return Err(KmError::PreconditionFailed(
            format!("object '{o}' has no realisation on token '{token}' in the lock; lock it there first").into(),
        ));
    }
    if out.is_empty() {
        return Err(KmError::PreconditionFailed(
            format!("the lock records no realisation on token '{token}': nothing to plan").into(),
        ));
    }
    Ok(out)
}

/// The transport key's public half (`camigrate transport`, docs/CAMIGRATE.md D3). The spec must name an
/// RSA private key that may unwrap and never leaves the token, and its realisation must verify
/// against the lock: the locked identity is what makes the public key trustworthy to a source.
///
/// # Errors
///
/// `Validation` for anything but an RSA private key; `PreconditionFailed` when the realisation
/// does not allow `CKA_UNWRAP` or is extractable; whatever `verify` refuses.
pub(crate) fn transport(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Transport> {
    if t.object.class != ObjectClass::PrivateKey || t.object.key_type != Some(KeyType::Rsa) {
        return Err(KmError::Validation(
            format!("{t}: a transport key is an RSA private key (docs/CAMIGRATE.md D3), not a {}", t.object.class)
                .into(),
        ));
    }
    ops::verify(t, tok, lock, notes)?;
    let none = BTreeMap::new();
    let policy = lock.realisation(t.spec_name, t.token_name).map_or(&none, |r| &r.policy);
    if let Some(why) = transport_fault(true, policy) {
        return Err(KmError::PreconditionFailed(format!("{t}: a transport key {why}").into()));
    }
    warn_decrypting(t, lock, notes);
    let h = tok
        .find_key(t.object, &t.on_token.locator, false)?
        .ok_or_else(|| KmError::NotFound(format!("{t}: the transport key").into()))?;
    let spki = tok.spki(h, &t.on_token.locator)?;
    Transport::new(&tok.name, tok.provider.name(), t.object_name, &spki, &tok.mechanism_names())
}

/// Where `export` or `migrate` sends the material.
pub(crate) enum Dest<'a> {
    /// A token in keys.toml.
    Token(&'a str),
    /// A target this host cannot reach, by its transport file: the parsed file, and how to
    /// name it in messages.
    Transport(&'a Transport, &'a str),
    File(FileFormat),
}

/// What to plan moving.
pub(crate) struct Request<'a> {
    /// Only these objects; default (empty): every object realised on `from`.
    pub objects: &'a [&'a str],
    /// The source token.
    pub from: &'a str,
    pub dest: Dest<'a>,
    /// Allow the `host` and `file` paths: plaintext in this process's memory (docs/CAMIGRATE.md D2).
    pub host_plaintext: bool,
    /// The target's transport key, by its spec, when several are realised there (docs/CAMIGRATE.md D3).
    pub transport_key: Option<&'a str>,
    /// The source holds a copy of that transport key its SO marked `CKA_TRUSTED` (docs/CAMIGRATE.md D2,
    /// `enforced`).
    pub trusted_transport: bool,
}

/// Where a side's capabilities came from, as a plan says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known {
    /// The open token.
    Token,
    /// What the lock recorded of a token that did not open.
    Lock,
    /// A transport file.
    TransportFile,
    /// A key file has no side.
    Nowhere,
}

impl Known {
    /// The word a plan prints.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Known::Token => "token",
            Known::Lock => "lock",
            Known::TransportFile => "transport file",
            Known::Nowhere => "-",
        }
    }
}

/// The plans of one invocation (docs/CAMIGRATE.md D9).
pub(crate) struct Moves {
    /// The destination's name: the target token, or the file format.
    pub to: String,
    /// Where each side's capabilities came from.
    pub source_from: Known,
    pub target_from: Known,
    pub plans: Vec<Plan>,
    /// The source's capabilities, to check the templates its export will send.
    pub source: Side,
    /// The target's capabilities (none for a file), to check what its `lock` will need.
    pub target: Option<Side>,
}

impl Moves {
    /// Whether every object can move as invoked.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) when any plan is blocked.
    pub(crate) fn ready(&self) -> Result<()> {
        let blocked: Vec<String> =
            self.plans.iter().filter(|p| !p.ready).map(|p| format!("{}: {}", p.object, p.reasons.join("; "))).collect();
        if blocked.is_empty() {
            return Ok(());
        }
        // With why: the run itself prints no plan, only `--dry-run` does.
        Err(KmError::Unsupported(
            format!(
                "{} of {} objects cannot move as invoked ({})",
                blocked.len(),
                self.plans.len(),
                blocked.join(" | ")
            )
            .into(),
        ))
    }
}

/// Plan each object's move as `req` asks, from what the lock pins. `source` is the source token
/// as the caller opened it, once per run; `open` opens a target token, as the caller's run will
/// use it (read-only to plan, read-write for a `migrate` that writes there). A side that does not
/// open is planned from what the lock recorded there. The source and target tokens, when they
/// opened, are handed back for the run to use (review lib.rs F5: the target was opened again).
///
/// # Errors
///
/// [`materials`]' refusals; a side that neither opens nor is recorded in the lock (the open's
/// error); `Unsupported` for a transport file of a provider this build does not link, and
/// `Validation` when its profile does not map.
pub(crate) fn plan_moves(
    lock: &Lock,
    registry: &Registry,
    req: &Request,
    source: Result<Token>,
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    notes: &mut Notes,
) -> Result<(Moves, Option<Token>, Option<Token>)> {
    let materials = materials(lock, req.from, req.objects)?;
    let (source, source_from, source_token) = side_or_lock(req.from, source, lock, registry, notes)?;
    let allow = Allow { host_plaintext: req.host_plaintext, trusted_transport: req.trusted_transport };
    let mut target_token = None;
    let (target, target_from, to_name) = match &req.dest {
        Dest::Token(name) => {
            let opened = open(name, notes);
            let (side, from, token) = side_or_lock(name, opened, lock, registry, notes)?;
            target_token = token;
            (Some(side), from, (*name).to_owned())
        }
        Dest::Transport(t, shown) => {
            let side = side_from_transport(t, registry)
                .ok_or_else(|| {
                    KmError::Unsupported(format!("{shown}: provider '{}' is not in this build", t.provider).into())
                })?
                .map_err(|e| KmError::Validation(format!("{shown}: {e}").into()))?;
            (Some(side), Known::TransportFile, t.token.clone())
        }
        Dest::File(f) => (None, Known::Nowhere, format!("{f:?} file").to_lowercase()),
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
            Ok(spec) if target_from == Known::Lock => {
                let object = lock.realisation(spec, name).map(|r| r.object.as_str());
                object.and_then(|o| lock.objects.get(o)).and_then(|o| o.public_key.as_ref()).is_none().then(|| {
                    format!(
                        "'{name}' is not open, and the lock records no public key for its transport key '{spec}': \
                         lock it there again with migrate.transportWith naming it"
                    )
                })
            }
            Ok(_) => None,
        },
        Dest::Transport(t, shown) => pinned(lock, t, req.transport_key).err().map(|e| format!("{shown}: {e}")),
        Dest::File(_) => None,
    };
    if let Some(why) = missing {
        for p in plans.iter_mut().filter(|p| p.ready && sealed(p)) {
            p.ready = false;
            p.reasons.push(why.clone());
        }
    }
    Ok((Moves { to: to_name, source_from, target_from, plans, source, target }, source_token, target_token))
}

/// A token's capabilities: from the token `opened`, else from what the lock recorded there,
/// with the token when it opened. A passthrough with no provider named behind it is planned as
/// a spec-compliant module, loudly.
fn side_or_lock(
    name: &str,
    opened: Result<Token>,
    lock: &Lock,
    registry: &Registry,
    notes: &mut Notes,
) -> Result<(Side, Known, Option<Token>)> {
    let e = match opened {
        Ok(tok) => {
            warn_hidden(name, &tok.profiles, notes);
            return Ok((side(&tok)?, Known::Token, Some(tok)));
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
            Ok((side?, Known::Lock, None))
        }
        None => Err(e),
    }
}

/// The spec of the transport key realised on `token` (docs/CAMIGRATE.md D3): the one `chosen` names —
/// `--transport-key`, else the token's `transportWith` — never one picked by what it can do. The
/// lock must record it there as an RSA private key that may unwrap and never leaves the token.
///
/// # Errors
///
/// Why there is no such key.
pub(crate) fn transport_spec<'a>(
    lock: &'a Lock,
    token: &str,
    chosen: Option<&str>,
) -> std::result::Result<&'a str, String> {
    let Some(chosen) = chosen else {
        return Err(format!(
            "no transport key is named for '{token}' (docs/CAMIGRATE.md D3): set transportWith in [tokens.{token}.migrate] to the \
             spec of an RSA key there that may unwrap and never leaves the token, lock it, or pass --transport-key"
        ));
    };
    let Some((spec, r)) =
        lock.realisations.get_key_value(chosen).and_then(|(spec, by_token)| Some((spec, by_token.get(token)?)))
    else {
        return Err(format!("transport key '{chosen}' is not realised on '{token}' in the lock: lock it there first"));
    };
    let rsa = lock
        .objects
        .get(&r.object)
        .and_then(|o| o.object_type.as_ref())
        .is_some_and(|t| t.class == ObjectClass::PrivateKey && t.key_type == Some(KeyType::Rsa));
    match transport_fault(rsa, &r.policy) {
        Some(why) => {
            Err(format!("'{chosen}' on '{token}' is no transport key: a transport key {why}, as the lock records it"))
        }
        None => Ok(spec.as_str()),
    }
}

/// Why a key the lock records (`rsa`: an RSA private key; its realisation's `policy`) is no
/// transport key (docs/CAMIGRATE.md D3): one rule for [`transport`] and [`transport_spec`]
/// (review D8). keys.toml's own check (`check_transport_keys`) holds the declarations instead.
fn transport_fault(rsa: bool, policy: &BTreeMap<String, AttrValue>) -> Option<&'static str> {
    let is_true = |n: &str| policy.get(n) == Some(&AttrValue::Bool(true));
    if !rsa {
        Some("must be an RSA private key")
    } else if !is_true("CKA_UNWRAP") {
        Some("must allow CKA_UNWRAP")
    } else if is_true("CKA_EXTRACTABLE") {
        Some("must never leave the token (CKA_EXTRACTABLE = false)")
    } else {
        None
    }
}

/// The public key to seal to for the transport key `t`, from the lock alone (`publicKey`, held
/// to the locked identity on load): no target needs to be open. `None` when the lock has none
/// yet (realised before `transportWith` named it). A transport key that may also decrypt is
/// warned about: whoever holds the target's PIN could decrypt what is sealed to it.
///
/// # Errors
///
/// `Validation` when the recorded key is no SPKI.
pub(crate) fn locked_transport(
    t: &Target,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<Option<crate::sealed::TransportKey>> {
    use base64::Engine as _;
    warn_decrypting(t, lock, notes);
    let Some(o) = lock.objects.get(t.object_name) else { return Ok(None) };
    let (Some(k), Some(id)) = (&o.public_key, o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name())) else {
        return Ok(None);
    };
    let spki = base64::engine::general_purpose::STANDARD
        .decode(k)
        .map_err(|e| KmError::Validation(format!("{t}: the lock's publicKey: {e}").into()))?;
    crate::sealed::check_transport_size(&spki)?;
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

/// A transport file's key is its token's transport key as the lock pins it (docs/CAMIGRATE.md D3:
/// the lock is the authenticated channel): the spec `chosen` names (`--transport-key`, else the
/// file's token's `transportWith`) is realised on the file's token as a transport key
/// ([`transport_spec`]), on the file's object, whose locked identity is the file's key. Any
/// other key the lock pins (another token's transport key, a certificate's subject key) is
/// refused, since whoever swapped the file may hold it (review 2026-11-23 C-1).
///
/// # Errors
///
/// Why it is not.
pub(crate) fn pinned(lock: &Lock, t: &Transport, chosen: Option<&str>) -> std::result::Result<(), String> {
    let spec = transport_spec(lock, &t.token, chosen)?;
    let realised = lock.realisation(spec, &t.token).map(|r| r.object.as_str());
    if realised != Some(t.object.as_str()) {
        return Err(format!(
            "its object '{}' is not the transport key of '{}': the lock realises '{spec}' there as '{}'",
            t.object,
            t.token,
            realised.unwrap_or("nothing")
        ));
    }
    match lock.objects.get(&t.object).and_then(|o| o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name())) {
        Some(id) if *id == t.rfc7093m4 => Ok(()),
        Some(id) => Err(format!("its key {} is not the {id} the lock pins for '{}'", t.rfc7093m4, t.object)),
        None => Err(format!("the lock pins no key for its object '{}', so nothing vouches for it", t.object)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(migration: &str) -> Profile {
        Profile::from_toml(&format!("profile = \"m/1\"\nmode = \"observed\"\n{migration}")).unwrap()
    }

    /// A resolution that fails is the token's own error (17, naming it and why), never read as
    /// "no provider" (review tokens.rs F1: a transport file's then said its provider was not
    /// in this build).
    #[test]
    fn a_failed_resolution_is_invalid_not_absent() {
        let e = resolved("far", Err("two families claim one manufacturer".into())).unwrap_err();
        assert_eq!(e.exit_code(), 17);
        assert!(e.to_string().contains("'far'") && e.to_string().contains("two families"), "{e}");
        assert!(resolved("far", Ok(Resolved::default())).is_ok());
    }

    /// A module profile's migration rows become the planner's side: how plaintext gets in, the
    /// sizes a row leaves open on one end, and a row whose key types a layer subtracts dropped.
    #[test]
    fn migration_rows_become_the_planners_side() {
        let stack = Resolved::default();
        let side = |p: &Profile, stack: &Resolved| side_of(p, stack, "t", "m", &[]);
        let piv = cakeys_profile::Set::embedded().unwrap().find("ykcs11/2.7").unwrap().clone();
        assert!(
            matches!(side(&piv, &stack).unwrap().plaintext_import, Some(PlaintextImport::PivImport(a)) if a.len() == 3)
        );
        let p = profile(
            "[migration]\nplaintext-import = \"create-object\"\n\
             [[migration.public-accepts]]\nclass = \"CKO_PUBLIC_KEY\"\nkey-types = [\"CKK_RSA\"]\nmax-bits = 4096\n\
             [[migration.public-accepts]]\nclass = \"CKO_PUBLIC_KEY\"\nkey-types = [\"CKK_RSA\"]\nmin-bits = 2048\n\
             [[migration.public-accepts]]\nclass = \"CKO_SECRET_KEY\"\nkey-types = [\"CKK_SHA384_HMAC\"]\n",
        );
        let got = side(&p, &stack).unwrap();
        assert_eq!(got.plaintext_import, Some(PlaintextImport::CreateObject));
        let bits: Vec<_> = got.public_import.iter().map(|a| a.modulus_bits).collect();
        assert_eq!(bits, [Some((0, 4096)), Some((2048, u32::MAX)), None]);
        // The unpatched binding layer cannot name the SHA-384 HMAC key type: that row goes.
        let layer = cakeys_profile::Set::embedded().unwrap().find("cryptoki/0.12").unwrap().clone();
        let unpatched = Resolved { layers: vec![layer], ..Resolved::default() };
        assert_eq!(side(&p, &unpatched).unwrap().public_import.len(), 2);
    }

    /// A row the baseline does not know is refused (17) with the profile named. An OAEP hash no
    /// probe tries loads (a newer cakeys's, review D4) and offers no wrap; a row with no hash
    /// does not load.
    #[test]
    fn rows_the_baseline_does_not_know_are_refused() {
        let head = "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n";
        let sha3 = Profile::from_toml(&format!("{head}\"wrap.rsa-oaep.SHA-3\" = {{ answer = \"yes\" }}\n")).unwrap();
        assert_eq!(sha3.wrap_oaep(), None);
        let none = Profile::from_toml(&format!("{head}\"wrap.rsa-oaep.\" = {{ answer = \"yes\" }}\n"));
        assert!(none.unwrap_err().contains("names no capability"));
        for (row, why) in [
            (
                "[[migration.public-accepts]]\nclass = \"CKO_PUBLIC_KEY\"\ncurves = [\"curve9\"]\n",
                "unknown curve: curve9",
            ),
            ("[[migration.public-accepts]]\nclass = \"CKO_NOPE\"\n", "CKO_NOPE"),
        ] {
            let e = side_of(&profile(row), &Resolved::default(), "t", "m", &[]).unwrap_err();
            assert!(matches!(&e, KmError::Validation(m) if m.contains("module profile m/1") && m.contains(why)), "{e}");
        }
    }

    /// A provider that records what each template is for, and refuses one purpose.
    struct Asked(std::sync::Arc<std::sync::Mutex<Vec<String>>>, &'static str);

    impl cakeys_pkcs11::Provider for Asked {
        fn name(&self) -> &'static str {
            "asked"
        }
        fn matches(&self, _: &cakeys_core::config::ModuleInfo) -> bool {
            false
        }
        fn template(&self, req: &cakeys_pkcs11::Template<'_>, _: &mut cakeys_pkcs11::Attributes) -> Result<()> {
            use cakeys_pkcs11::Template as T;
            let asked = match req {
                T::Generate(_, half) => format!("generate {half:?}"),
                T::Import(_, via) => format!("import {via:?}"),
                T::PublicHalf(_) => "public half".into(),
                T::Object(_) => "object".into(),
                T::TrustedCopy => "trusted copy".into(),
                T::Session(key) => format!("{key:?}"),
            };
            let refused = asked.starts_with(self.1);
            self.0.lock().unwrap().push(asked);
            if refused { Err(KmError::Unsupported("asked refuses".into())) } else { Ok(()) }
        }
    }

    /// A move's plan asks the providers about what its run sends, under the run's conditions: the
    /// source's session keys, the target's object, public half, KEK and the record's proof secret;
    /// and a refusal is the plan's.
    #[test]
    fn a_plan_asks_the_providers_what_the_move_sends() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let cfg: cakeys_core::config::Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\nattributes = { CKA_DERIVE = true }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" }, origin = \"import\", binding = \"pop-ecdh\" }\n",
        )
        .unwrap();
        let dst = Target::new(&cfg, "s", "t").unwrap();
        let side = |mechs: &[&str]| Side::pkcs11("t", "asked", mechs.iter().map(|m| (*m).to_owned()));
        let ask = |method: Method, source: &Side, target: &Side, refuse: &'static str| {
            let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let registry = Registry::new().with(Asked(std::sync::Arc::clone(&asked), refuse));
            let out =
                template_refusal(&dst, &method, cakeys_core::migrate::Exposure::Sealed, source, target, &registry);
            let asked = asked.lock().unwrap().clone();
            (out, asked)
        };
        let kwp = ["CKM_AES_KEY_WRAP_PAD", "CKM_AES_KEY_GEN", "CKM_SHA256_HMAC"];
        let composed = Method::RsaOaepAesKwp(OaepHash::Sha256);
        let (out, asked) = ask(composed.clone(), &side(&kwp), &side(&kwp), "-");
        assert_eq!(out, Ok(None));
        assert_eq!(
            asked,
            [
                "TransportKey",
                "ExportKek",
                "import Unwrap",
                "ImportKek",
                "public half",
                "ProofSecret { binding: PopEcdh, sealed: true }"
            ]
        );
        // No RFC 5649 on either side: no KEK is made, so none is asked about; no HMAC on the
        // target: the proof derives into a readable secret.
        let (_, asked) = ask(composed.clone(), &side(&[]), &side(&[]), "-");
        assert_eq!(
            asked,
            ["TransportKey", "import Unwrap", "public half", "ProofSecret { binding: PopEcdh, sealed: false }"]
        );
        // The host path: the source's KEK, the target's import; PIV makes no public half.
        let piv = Side { public_keys: false, ..side(&kwp) };
        let (_, asked) = ask(Method::PivImport, &side(&kwp), &piv, "-");
        assert_eq!(asked, ["HostKek", "import CreateObject", "ProofSecret { binding: PopEcdh, sealed: true }"]);
        // A refusal blocks the plan, naming the provider and the token.
        let (out, asked) = ask(composed, &side(&kwp), &side(&kwp), "import");
        let why = out.unwrap_err();
        assert!(why.contains("provider 'asked' on 't'") && why.contains("asked refuses"), "{why}");
        assert_eq!(asked.last().map(String::as_str), Some("import Unwrap"), "the first refusal ends it");
        // A key file written on the host: the source's KEK alone, refused there.
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let registry = Registry::new().with(Asked(std::sync::Arc::clone(&asked), "HostKek"));
        let out = source_refusal(&Method::Pkcs12, cakeys_core::migrate::Exposure::File, &side(&kwp), &registry);
        assert!(out.is_err_and(|why| why.contains("asked refuses")));
        assert_eq!(*asked.lock().unwrap(), ["HostKek"]);
    }
}
