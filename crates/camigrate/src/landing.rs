//! The planner's rules past the method choice (review 2026-11-23 C-23: they sat in lib.rs, a
//! third layer after `plan::plan` and `tokens::plan_moves`): what keeps an object home, which
//! pair a move lands on, what the landing token must take (the write's own rules, asked with
//! the functions the write asks them with: review 2026-11-24 D-2, D-3), and what a bundle or a
//! key file can carry. [`block`] runs them over a run's plans, in one place, so the dry run and
//! the run block alike (C-2).

use cakeys_core::KmError;
use cakeys_core::config::{Config, KeyOrigin, Lock, SpecCfg, SpecTokenCfg};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_pkcs11::ops::{self, Notes, Seat, Target, Verb};
use cakeys_pkcs11::{Registry, Token};

use crate::plan::{self, FileFormat};
use crate::{MoveCtx, Run, host, public, tokens};

/// Block each plan the run would refuse, said in the plan, in the order the run meets it: what
/// never leaves `from` (said first), a target with no import pair, the landing pair's own
/// checks — or, with nothing landing on a token, the source's export — and what the destination
/// carries. The transport key a sealed move wraps to is the plan's (`tokens::plan_moves`).
/// `target` is the target token of a move, when it opened: what lands there now is checked
/// against it as the write checks it.
pub(crate) fn block(run: &Run, ctx: &MoveCtx, moves: &mut tokens::Moves, target: Option<&Token>) {
    let (cfg, registry) = (&run.opener.cfg, run.opener.registry);
    let MoveCtx { objects, from, dest, specs, .. } = *ctx;
    let (bundle, target_token) = (dest.bundle(), dest.to());
    // What lands on the target now, a move's, meets the target token's own checks there.
    let lands = target.filter(|_| !bundle);
    // Without names, what is kept home is left out quietly; named, it is refused (15).
    if objects.is_empty() {
        moves.plans.retain(|p| no_export(cfg, &p.object, from).is_none());
    }
    for p in &mut moves.plans {
        if let Some(why) = no_export(cfg, &p.object, from) {
            p.block_first(format!("{why}: it never leaves '{from}'"));
        }
        // A move lands only on a pair that says `origin = "import"`: an object realised on
        // the target by no such pair cannot move there, whatever else would carry it.
        if let (false, Some(to)) = (bundle, target_token)
            && let Some(why) = no_import_pair(cfg, &p.object, to)
        {
            p.block_first(why);
        }
        match target_token {
            Some(to) => match import_target(cfg, &p.object, to, spec_for(cfg, specs, &p.object), MOVE) {
                Ok(landing) => {
                    landing_checks(p, &landing, &moves.source, moves.target.as_ref(), registry);
                    if let Some(tok) = lands {
                        landed_checks(p, &landing, tok, &run.lock);
                    }
                }
                // A move must pick its landing pair now: several, and no `--spec` naming
                // one, is refused by the run, so by the plan. (An object with none is
                // blocked already, by `no_import_pair`.) A bundle lands later, under the
                // pair its import picks.
                Err(e) if p.ready && !bundle => p.block(e.to_string()),
                Err(_) => {}
            },
            // Nothing lands on a token here: the source's export is all the run makes.
            None => {
                if let (true, Some(method)) = (p.ready, &p.method) {
                    let exposure = p.exposure.unwrap_or(Exposure::Sealed);
                    if let Err(why) = tokens::source_refusal(method, exposure, &moves.source, registry) {
                        p.block(why);
                    }
                }
            }
        }
    }
    match dest {
        tokens::Dest::File(format) => limit_file_plans(run, &mut moves.plans, *format, from),
        _ if bundle => limit_bundle_plans(&mut moves.plans),
        _ => limit_token_plans(&mut moves.plans),
    }
}

/// What an import's dry run asks of the open `target` before it says ready, as the import asks
/// before it creates anything: the capability check of the record that follows
/// (`ops::check_import`), and the target's provider about the templates `method` sends there
/// ([`tokens::target_refusal`]).
///
/// # Errors
///
/// What `ops::check_import` refuses; the provider's refusal (15).
pub(crate) fn import_checks(
    dst: &Target,
    target: &cakeys_pkcs11::Token,
    method: &Method,
    registry: &Registry,
    notes: &mut Notes,
) -> cakeys_core::Result<()> {
    cakeys_pkcs11::ops::check_import(dst, target)?;
    match tokens::target_refusal(dst, method, &tokens::side(target)?, registry) {
        Ok(None) => Ok(()),
        Ok(Some(note)) => {
            notes.note(format_args!("{note}"));
            Ok(())
        }
        Err(why) => Err(KmError::Unsupported(why.into())),
    }
}

/// What a ready plan `p` must still pass where it lands on `to`, said in the plan since the run
/// would refuse it: the target's `lock` must prove possession of a private key the way its spec
/// says; the providers must take the templates the move sends (`Provider::template`, refused
/// before anything is created); and the static rules every import asks before its write
/// (`ops::static_rules`, [`Verb::Import`]): where the module can place the key (a PIV slot by
/// `CKA_ID`, review 2026-11-24 D-2), the attestation the spec opts into, and never one of an
/// imported key where the provider attests only what the device made (PIV, docs/CAMIGRATE.md
/// D8). A provider this plan cannot name defers them, said in the notes. `dst` is the landing
/// pair, the one `--spec` names.
fn landing_checks(
    p: &mut plan::Plan,
    dst: &Target,
    source: &crate::side::Side,
    target: Option<&crate::side::Side>,
    registry: &Registry,
) {
    if let (true, Some(target)) = (p.ready, target)
        && let Some(why) = unprovable(dst, target)
    {
        p.block(why);
    }
    if let (true, Some(method), Some(target)) = (p.ready, p.method.clone(), target) {
        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
        match tokens::template_refusal(dst, &method, exposure, source, target, registry) {
            Ok(None) => {}
            Ok(Some(note)) => p.notes.push(note),
            Err(why) => p.block(why),
        }
    }
    if let (true, Some(target)) = (p.ready, target) {
        static_checks(p, dst, &target.provider, registry);
    }
    // What only the run holds (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4): the blob
    // the target unwraps, and the key the source hands over, held to the lock's identity (D-5).
    if p.ready {
        match p.exposure {
            Some(Exposure::Sealed | Exposure::Enforced) => {
                p.deferred.extend([crate::sealed::UNWRAPS, crate::sealed::IDENTITY]);
            }
            Some(Exposure::Host | Exposure::File) => p.deferred.push(crate::sealed::IDENTITY),
            Some(Exposure::Public) | None => {}
        }
    }
}

/// [`landing_checks`]' static rules of `dst`, with the provider named `provider`.
fn static_checks(p: &mut plan::Plan, dst: &Target, provider: &str, registry: &Registry) {
    let named = registry.named(provider);
    let seat = match &named {
        Ok(Some(p)) => Seat::Resolved(p.as_ref()),
        Ok(None) => Seat::Unresolved(format!("provider '{provider}' is not in this build")),
        Err(e) => Seat::Unresolved(e.to_string()),
    };
    let verdicts = ops::plan_mode(dst).and_then(|mode| ops::static_rules(dst, mode, seat, Verb::Import, None));
    match verdicts {
        Ok(v) => {
            p.notes.extend(ops::deferred_lines(&v.deferred));
            p.deferred.extend(v.deferred.iter().map(|d| d.rule.name()));
            if let Some(r) = v.refusals.into_iter().next() {
                p.refuse(r.error);
            }
        }
        Err(e) => p.refuse(e),
    }
}

/// What a ready plan `p` that lands on the open token `to` now (a move's) must pass there, as
/// the write asks it of `to` before anything is created: the import's own checks
/// (`ops::check_import`) and a locator nothing would collide with ([`public::free_locator`];
/// review 2026-11-24 D-3: only the run asked it, and refused 13 after a ready plan). A pair the
/// lock records there already is verified by the run, and moves nothing.
fn landed_checks(p: &mut plan::Plan, dst: &Target, to: &Token, lock: &Lock) {
    if !p.ready || lock.realisation(dst.spec_name, dst.token_name).is_some() {
        return;
    }
    if let Err(e) = ops::check_import(dst, to) {
        return p.refuse(e);
    }
    let spki = match public_half(dst, to, lock) {
        Ok(spki) => spki,
        Err(e) => return p.refuse(e),
    };
    let landed = public::free_locator(dst, to, spki.as_deref()).and_then(|occupied| {
        if p.method == Some(Method::Tpm2Ptool) { host::ptool_free(dst, &occupied) } else { Ok(()) }
    });
    if let Err(e) = landed {
        p.refuse(e);
    }
}

/// The public key of `dst`'s object that a public key object under its locator on `to`
/// already holds, the identity the lock pins (`rfc7093m4`): the key's public half, which the
/// import reuses, so no collision ([`public::free_locator`]). The run holds the source's, which
/// it verifies to be that identity first.
///
/// # Errors
///
/// `Unavailable` (16) when the token fails a search.
fn public_half(dst: &Target, to: &Token, lock: &Lock) -> cakeys_core::Result<Option<Vec<u8>>> {
    let pinned = lock.objects.get(dst.object_name).and_then(|o| o.ids.get("rfc7093m4"));
    let (true, Some(pinned)) = (matches!(dst.object.class, Class::PrivateKey | Class::PublicKey), pinned) else {
        return Ok(None);
    };
    let loc = &dst.on_token.locator;
    Ok(to
        .find(cryptoki::object::ObjectClass::PUBLIC_KEY, loc)?
        .into_iter()
        .filter_map(|p| to.spki(p, loc).ok())
        .find(|spki| cakeys_core::id::sri(spki) == *pinned))
}

/// Whether a bundle carries what `method` moves: sealed keys and public objects.
pub(crate) fn in_bundle(method: &Method) -> bool {
    matches!(method, Method::RsaOaepAesKwp(_) | Method::RsaOaep(_) | Method::Public)
}

/// A bundle carries sealed keys and public objects only: a move the plan sends another way
/// (through the host, a provider's own method) is `migrate`'s, said in the plan, since the
/// export would refuse it.
fn limit_bundle_plans(plans: &mut [plan::Plan]) {
    for p in plans.iter_mut().filter(|p| p.ready) {
        if let Some(method) = p.method.as_ref().filter(|m| !in_bundle(m)) {
            p.block(format!(
                "a bundle carries sealed keys and public objects, not {}: move it with `camigrate migrate`",
                method.name()
            ));
        }
    }
}

/// The methods a move onto a token runs today: a public object, a sealed key, the host path, a
/// `tpm2_ptool` or PIV import. A vendor's own method is a later docs/CAMIGRATE.md phase.
fn built(method: &Method) -> bool {
    matches!(
        method,
        Method::Public
            | Method::RsaOaepAesKwp(_)
            | Method::RsaOaep(_)
            | Method::HostPkcs8
            | Method::HostRaw
            | Method::Tpm2Ptool
            | Method::PivImport
    )
}

/// A move onto a token runs only a [`built`] method: another blocks the plan, so the dry run
/// says what the run refuses (D9; review 2026-11-23 C-2: only the run refused it).
fn limit_token_plans(plans: &mut [plan::Plan]) {
    for p in plans.iter_mut().filter(|p| p.ready) {
        if !p.method.as_ref().is_some_and(built) {
            let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
            p.block(format!(
                "moving by {method} is a later docs/CAMIGRATE.md phase; public objects, sealed keys and the host \
                 path into PKCS#11 tokens move"
            ));
        }
    }
}

/// Why `object` cannot move to `to`: specs realise it there, and none says `origin = "import"`.
fn no_import_pair(cfg: &Config, object: &str, to: &str) -> Option<String> {
    let origins: Vec<KeyOrigin> = cfg
        .specs
        .values()
        .filter(|s| s.object == object)
        .filter_map(|s| s.tokens.get(to).map(SpecTokenCfg::key_origin))
        .collect();
    (!origins.is_empty() && !origins.contains(&KeyOrigin::Import)).then(|| {
        format!(
            "no spec realises '{object}' on '{to}' with origin = \"import\": a move lands only where keys.toml \
             says origin = \"import\""
        )
    })
}

/// The source of `object` on `from`: the spec of a realisation the lock records there.
pub(crate) fn source_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    object: &str,
    from: &'a str,
) -> cakeys_core::Result<Target<'a>> {
    realised_target(cfg, lock, object, from, "object")
}

/// The spec `--spec` names for `object`, if one does.
pub(crate) fn spec_for<'a>(cfg: &Config, specs: &'a [String], object: &str) -> Option<&'a str> {
    specs.iter().map(String::as_str).find(|s| cfg.specs.get(*s).is_some_and(|c| c.object == object))
}

/// Every `--spec` must select something: a spec keys.toml names, of one of the `objects` being
/// moved, on `token`. A name that selects nothing is refused (17), never ignored.
pub(crate) fn specs_select<'a>(
    cfg: &Config,
    specs: &[String],
    objects: impl Iterator<Item = &'a str>,
    token: &str,
    landing: &[KeyOrigin],
) -> cakeys_core::Result<()> {
    let objects: Vec<&str> = objects.collect();
    for name in specs {
        let Some(spec) = cfg.specs.get(name) else {
            return Err(KmError::Validation(format!("--spec '{name}': keys.toml has no such spec").into()));
        };
        if !spec.tokens.contains_key(token) || !objects.contains(&spec.object.as_str()) {
            return Err(KmError::Validation(
                format!(
                    "--spec '{name}' selects nothing: it realises '{}', which is not being moved to '{token}' under it",
                    spec.object
                )
                .into(),
            ));
        }
    }
    specs_import(cfg, specs, token, landing)
}

/// The pairs a move from another token lands on.
pub(crate) const MOVE: &[KeyOrigin] = &[KeyOrigin::Import];
/// The pairs an object from its own file lands on (docs/FILE.md F6).
pub(crate) const FROM_FILE: &[KeyOrigin] = &[KeyOrigin::File];
/// The pairs a key file given by `--in` lands on: a move's, or a pair born in a file.
pub(crate) const KEY_FILE: &[KeyOrigin] = &[KeyOrigin::Import, KeyOrigin::File];

/// `origin = "import"`, or each of `landing` so, joined by "or".
fn landing_names(landing: &[KeyOrigin]) -> String {
    landing.iter().map(|o| format!("origin = \"{o}\"")).collect::<Vec<_>>().join(" or ")
}

/// Every `--spec` that realises its object on `token` says one of `landing` there: a move lands
/// on no other pair (17). Checked by the dry run too, which plans without the names.
pub(crate) fn specs_import(
    cfg: &Config,
    specs: &[String],
    token: &str,
    landing: &[KeyOrigin],
) -> cakeys_core::Result<()> {
    for name in specs {
        if let Some(on) = cfg.specs.get(name).and_then(|s| s.tokens.get(token))
            && !landing.contains(&on.key_origin())
        {
            return Err(KmError::Validation(
                format!(
                    "--spec '{name}' realises its object on '{token}' with origin = \"{}\": a move lands only where \
                 keys.toml says {}",
                    on.key_origin(),
                    landing_names(landing)
                )
                .into(),
            ));
        }
    }
    Ok(())
}

/// Where `object` goes on `to`: its one spec there whose origin is one of `landing`, or the one
/// `--spec` names. A pair that says the key is created or adopted there is never a target.
pub(crate) fn import_target<'a>(
    cfg: &'a Config,
    object: &str,
    to: &'a str,
    spec: Option<&str>,
    landing: &[KeyOrigin],
) -> cakeys_core::Result<Target<'a>> {
    let on_to = |s: &'a SpecCfg| s.tokens.get(to).filter(|_| s.object == object);
    let named = |name: &str| spec.is_none_or(|n| n == name);
    let specs: Vec<&str> = cfg
        .specs
        .iter()
        .filter(|(name, s)| named(name) && on_to(s).is_some_and(|t| landing.contains(&t.key_origin())))
        .map(|(name, _)| name.as_str())
        .collect();
    let elsewhere =
        cfg.specs.iter().find_map(|(name, s)| on_to(s).filter(|_| named(name)).map(|t| (name, t.key_origin())));
    match specs.as_slice() {
        [one] => Target::new(cfg, one, to),
        [] => Err(KmError::Validation(match (spec, elsewhere) {
            (_, Some((name, origin))) => format!(
                "spec '{name}' realises object '{object}' on token '{to}' with origin = \"{origin}\": a move lands \
                 only where keys.toml says {}",
                landing_names(landing)
            )
            .into(),
            (Some(n), None) => format!("spec '{n}' does not realise object '{object}' on token '{to}'").into(),
            (None, None) => {
                format!("keys.toml has no spec of object '{object}' on token '{to}' to import it under").into()
            }
        })),
        several => Err(KmError::Validation(
            format!("object '{object}' has several specs on token '{to}' ({}); pass --spec", several.join(", ")).into(),
        )),
    }
}

/// Why the target could not prove possession of a private key moved to `dst` the way its spec
/// says (`cakeys_pkcs11` would refuse after the key was created): `None` when it can, or the
/// object is no private key. The proof's own check (`cakeys_pkcs11::token::proof_refusal`), on
/// what the plan knows of the target.
fn unprovable(dst: &Target, target: &crate::side::Side) -> Option<String> {
    let binding = cakeys_core::plan::expected_binding(dst)?;
    let side = cakeys_pkcs11::token::ProofSide {
        token: &target.token,
        profile: None,
        has: Box::new(|m| target.mechanisms.contains(&m.to_string())),
        unwraps: target.unwraps,
    };
    match cakeys_pkcs11::token::proof_refusal(dst.object, binding, &side) {
        Ok(None) => None,
        Ok(Some(why)) => Some(format!("{dst} could not prove possession of the key once there: {why}")),
        Err(e) => Some(format!("{dst} could not prove possession of the key once there: {e}")),
    }
}

/// What keeps `object` on `from`, if anything does: a spec's `noExport`, or being a token's
/// transport key (`transportWith`), which never leaves by default. A transport key is
/// non-extractable already (keys.toml refuses one that does not say so), so it cannot move;
/// this says why plainly and keeps a move without names from stopping at it.
pub(crate) fn no_export(cfg: &Config, object: &str, from: &str) -> Option<String> {
    let realises = |s: &SpecCfg| s.object == object && s.tokens.contains_key(from);
    if let Some((name, _)) = cfg.specs.iter().find(|(_, s)| s.migrate.no_export && realises(s)) {
        return Some(format!("migrate.noExport in spec '{name}'"));
    }
    cfg.tokens.iter().find_map(|(token, t)| {
        let spec = t.migrate.transport_with.as_deref()?;
        realises(cfg.specs.get(spec)?)
            .then(|| format!("the transport key of token '{token}' (migrate.transportWith = \"{spec}\")"))
    })
}

/// The realisation of `object` on `token` the lock records, as a target; `what` names the
/// object in the refusal (a bundle's transport key names its object).
pub(crate) fn realised_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    object: &str,
    token: &'a str,
    what: &str,
) -> cakeys_core::Result<Target<'a>> {
    let spec = lock
        .realisations
        .iter()
        .find(|(_, by_token)| by_token.get(token).is_some_and(|r| r.object == object))
        .and_then(|(spec, _)| cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()))
        .ok_or_else(|| {
            KmError::PreconditionFailed(
                format!("{what} '{object}' has no realisation on '{token}' under a spec keys.toml still names").into(),
            )
        })?;
    Target::new(cfg, spec, token)
}

/// A key file holds one key, and a PKCS#12 the certificate the lock pairs with it on the
/// source: said in the plan, since the export would refuse both.
fn limit_file_plans(run: &Run, plans: &mut [plan::Plan], format: FileFormat, from: &str) {
    let several = plans.len();
    for p in plans.iter_mut().filter(|p| p.ready) {
        if several > 1 {
            p.block(format!("a key file holds one key, and {several} are planned: name the one to export"));
        } else if format == FileFormat::Pkcs12 && run.paired_certificate_target(&p.object, from).is_none() {
            p.block(format!(
                "pkcs12 carries the key with its certificate, and the lock pairs no certificate with '{}' on \
                 '{from}': lock it there, or export --to-key-file pkcs8",
                p.object
            ));
        }
    }
}
