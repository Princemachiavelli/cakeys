//! The planner's rules that apply after the method is chosen (review 2026-11-23 C-23: they used
//! to be in lib.rs, as a third layer after `plan::plan` and `tokens::plan_moves`). The rules
//! decide what keeps an object on its source token, which pair a move lands on, what the landing
//! token must accept, and what a bundle or a key file can carry. The landing token's rules are
//! the write's own rules, checked with the same functions that the write calls (review 2026-11-24
//! D-2, D-3). [`block`] applies all of them to a run's plans in one place, so that the dry run
//! and the run block the same plans (C-2).

use cakeys_core::config::{Config, KeyOrigin, Lock, SpecCfg, SpecTokenCfg};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{Check, KmError, Reason};
use cakeys_pkcs11::ops::{self, Notes, Seat, Target, Verb};
use cakeys_pkcs11::{Registry, Token};

use crate::plan::{self, FileFormat};
use crate::{MoveCtx, Run, host, public, tokens};

/// Blocks each plan that the run would refuse, and records the reason in the plan. The checks run
/// in the order in which the run meets them. First come an object that never leaves `from` and a
/// target with no import pair; their reasons are listed first. Then come the landing pair's own
/// checks, or the source's export checks when nothing lands on a token. Last comes what the
/// destination can carry. The plan already holds the transport key to which a sealed move wraps
/// (`tokens::plan_moves`). `target` is the target token of a move, when it is open; an object
/// that lands there now is checked against it in the same way that the write checks it.
pub(crate) fn block(run: &Run, ctx: &MoveCtx, moves: &mut tokens::Moves, target: Option<&Token>) {
    let (cfg, registry) = (&run.opener.cfg, run.opener.registry);
    let MoveCtx { objects, from, dest, specs, .. } = *ctx;
    let (bundle, target_token) = (dest.bundle(), dest.to());
    // An object that lands on the target now (in a move, not in a bundle) must pass the target
    // token's own checks there.
    let lands = target.filter(|_| !bundle);
    // When no objects are named, an object that must stay on its source is left out without a
    // message. When it is named, it is refused (15).
    if objects.is_empty() {
        moves.plans.retain(|p| no_export(cfg, &p.object, from).is_none());
    }
    for p in &mut moves.plans {
        if let Some(why) = no_export(cfg, &p.object, from) {
            p.block_first(format!("{why}: it never leaves '{from}'"));
        }
        // A move lands only on a pair that says `origin = "import"`. An object that the target
        // realises with no such pair cannot move there, whatever method would carry it.
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
                // A move must pick its landing pair now. The run refuses an object with several
                // landing pairs when no `--spec` names one, so the plan refuses it too. (An
                // object with no landing pair is already blocked by `no_import_pair`.) A bundle
                // lands later, under the pair that its import picks.
                Err(e) if p.ready && !bundle => p.block(e.to_string()),
                Err(_) => {}
            },
            // Nothing lands on a token here, so the run only makes the source's export.
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

/// Reads the source token `source` in a dry run before the dry run reports ready, in the same way
/// that the run reads it before the move (docs/CAMIGRATE.md D9). Review 2026-11-24 L4b-3 found
/// that the dry runs planned from the lock alone and never searched the source, so a second
/// object under a locator was planned as ready, and the run then refused it (12). Nothing is read
/// when the verdict refuses the plans, because the run then ends before it reads any object.
/// Otherwise, the object of each ready plan is found under its locator and verified against the
/// lock by the same function that the run uses to find it: [`public::material`] for a public
/// object, and [`host::source_key`] for a key, which makes the same calls as the sealed export's
/// `hold`. A plan whose object fails is blocked, and its reasons say why.
///
/// # Errors
///
/// The first failure in the order of the plans, which is the failure with which the run ends.
pub(crate) fn search(
    run: &Run,
    ctx: &MoveCtx,
    moves: &mut tokens::Moves,
    source: &Token,
    notes: &mut Notes,
) -> cakeys_core::Result<()> {
    if moves.verdict(ctx.take(), ctx.from).is_err() {
        return Ok(());
    }
    let (cfg, lock) = (&run.opener.cfg, &run.lock);
    let mut first = None;
    for p in moves.plans.iter_mut().filter(|p| p.ready) {
        let found = source_target(cfg, lock, &p.object, ctx.from).and_then(|src| {
            if p.method == Some(Method::Public) {
                public::material(&src, source, lock, notes).map(drop)
            } else {
                host::source_key(&src, source, lock, notes).map(drop)
            }
        });
        if let Err(e) = found {
            p.block(crate::trust::reason(e.clone()));
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), Err)
}

/// Runs the checks that an import's dry run makes on the open `target` before it reports ready.
/// The import makes the same checks before it creates anything: the capability check of the
/// record that follows (`ops::check_import`), and the target provider's check of the templates
/// that `method` sends there ([`tokens::target_refusal`]).
///
/// # Errors
///
/// The errors of `ops::check_import`, and the provider's refusal (15).
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

/// Checks what a ready plan `p` must still pass on the target side `target` where it lands, and
/// blocks the plan when the run would refuse it. The target must be able to prove possession of
/// a private key in the way that its spec says. The providers must accept the templates that the
/// move sends (`Provider::template`, which refuses before anything is created). The plan must
/// also pass the static rules that every import checks before its write (`ops::static_rules`,
/// [`Verb::Import`]): where the module can place the key (a PIV slot by `CKA_ID`, review
/// 2026-11-24 D-2), the attestation that the spec opts into, and no attestation of an imported
/// key where the provider attests only keys that the device generated (PIV, docs/CAMIGRATE.md
/// D8). When the target's provider cannot be resolved (for example, because it is not in this
/// build), these rules are deferred, and the notes say so. `dst` is the landing pair: the target's
/// one import pair for the object, or the pair that `--spec` names.
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
    // Some checks need what only the run holds (docs/archive/REVIEW-2026-11-24/phase1-design.md
    // §1.4): the blob that the target unwraps, and the key that the source hands over, which is
    // checked against the lock's identity (D-5). The plan lists these checks as deferred.
    if p.ready {
        match p.exposure {
            Some(Exposure::Sealed | Exposure::Enforced) => {
                p.deferred.extend([crate::sealed::UNWRAPS.name(), crate::sealed::IDENTITY.name()]);
            }
            Some(Exposure::Host | Exposure::File) => p.deferred.push(crate::sealed::IDENTITY.name()),
            Some(Exposure::Public) | None => {}
        }
    }
}

/// Checks the static rules of [`landing_checks`] for `dst`, with the provider named `provider`.
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

/// Checks what a ready plan `p` that lands on the open token `to` now (in a move) must pass there.
/// The write makes the same checks on `to` before it creates anything. The checks are the
/// import's own checks (`ops::check_import`); a locator with which nothing would collide
/// ([`public::free_locator`]; review 2026-11-24 D-3 found that only the run checked it, and it
/// refused with 13 after a ready plan); and, for a public half on the token that the import
/// reuses, that it holds the spec's `publicAttributes`, which the run's record checks (13; the
/// exact twin saw a ready plan refused in this way on p11-kit). A pair that the lock already
/// records on the token is verified by the run and moves nothing, so it is not checked here.
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
        if let Some(h) = occupied.public_half {
            to.check_public_half(h, dst.spec, &dst.on_token.locator, true)?;
        }
        if p.method == Some(Method::Tpm2Ptool) { host::ptool_free(dst, &occupied) } else { Ok(()) }
    });
    if let Err(e) = landed {
        p.refuse(e);
    }
}

/// Returns the public key of `dst`'s object when a public key object under its locator on `to`
/// already holds it, that is, a public key with the identity that the lock pins (`rfc7093m4`).
/// That object is the key's public half, which the import reuses, so it is not a collision
/// ([`public::free_locator`]). The run instead holds the source's public key, which it first
/// verifies to have that identity.
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

/// Returns whether a bundle can carry what `method` moves. A bundle carries only sealed keys and
/// public objects.
pub(crate) fn in_bundle(method: &Method) -> bool {
    matches!(method, Method::RsaOaepAesKwp(_) | Method::RsaOaep(_) | Method::Public)
}

/// Blocks each ready plan whose method a bundle cannot carry. A bundle carries only sealed keys
/// and public objects, and a move that the plan sends another way (through the host, or by a
/// provider's own method) must use `migrate`. The plan says so, because the export would refuse
/// it.
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

/// Returns whether a move onto a token can run `method` today: a public object, a sealed key, the
/// host path, a `tpm2_ptool` import or a PIV import. A vendor's own method is a later
/// docs/CAMIGRATE.md phase.
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

/// Blocks each ready plan whose method is not [`built`], because a move onto a token runs only
/// such a method. The dry run then reports what the run refuses (D9; review 2026-11-23 C-2 found
/// that only the run refused it).
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

/// Returns why `object` cannot move to `to` when specs realise it there and none of them says
/// `origin = "import"`, and `None` otherwise.
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

/// Returns the source of `object` on `from`: the spec of a realisation that the lock records
/// there.
pub(crate) fn source_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    object: &str,
    from: &'a str,
) -> cakeys_core::Result<Target<'a>> {
    realised_target(cfg, lock, object, from, "object")
}

/// Returns the spec that `--spec` names for `object`, if there is one.
pub(crate) fn spec_for<'a>(cfg: &Config, specs: &'a [String], object: &str) -> Option<&'a str> {
    specs.iter().map(String::as_str).find(|s| cfg.specs.get(*s).is_some_and(|c| c.object == object))
}

/// Checks that every `--spec` selects something: a spec that keys.toml names, of one of the
/// `objects` being moved, on `token`. A name that selects nothing is refused (17), never ignored.
/// It then checks the landing origins with [`specs_import`].
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

/// The origins of the pairs on which a move from another token lands.
pub(crate) const MOVE: &[KeyOrigin] = &[KeyOrigin::Import];
/// The origins of the pairs on which an object from its own file lands (docs/FILE.md F6).
pub(crate) const FROM_FILE: &[KeyOrigin] = &[KeyOrigin::File];
/// The origins of the pairs on which a key file given by `--in` lands: a move's pair, or a pair
/// whose object is born in a file.
pub(crate) const KEY_FILE: &[KeyOrigin] = &[KeyOrigin::Import, KeyOrigin::File];

/// Returns `origin = "<origin>"` for each origin in `landing`, joined by "or".
fn landing_names(landing: &[KeyOrigin]) -> String {
    landing.iter().map(|o| format!("origin = \"{o}\"")).collect::<Vec<_>>().join(" or ")
}

/// Checks that every `--spec` that realises its object on `token` says one of the `landing`
/// origins there, because a move lands on no other pair (17). The dry run also calls this
/// check, because it plans without the names.
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

/// Returns where `object` goes on `to`: its one spec there whose origin is one of `landing`, or
/// the spec that `--spec` names. A pair that says that the key is created or adopted there is
/// never a target.
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

/// Returns why the target could not prove possession of a private key moved to `dst` in the way
/// that its spec says (`cakeys_pkcs11` would refuse after the key was created). Returns `None`
/// when it can, or when the object is not a private key. It runs the proof's own check
/// (`cakeys_pkcs11::token::proof_refusal`) on what the plan knows of the target.
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

/// Returns what keeps `object` on `from`, if anything does: a spec's `noExport`, or the fact that
/// the object is a token's transport key (`transportWith`), which never leaves by default. A
/// transport key is already non-extractable (keys.toml refuses one that does not say so), so it
/// cannot move. This function states that reason plainly, and it lets a move without names skip
/// the key instead of stopping at it.
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

/// Returns the realisation of `object` on `token` that the lock records, as a target. `what` is
/// the word that names the object in the refusal; its only caller, [`source_target`], passes
/// "object".
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
            KmError::PreconditionFailed(Reason::check(
                Check::LockRealised,
                format!("{what} '{object}' has no realisation on '{token}' under a spec keys.toml still names"),
            ))
        })?;
    Target::new(cfg, spec, token)
}

/// Blocks the plans that a key file cannot carry, because the export would refuse them. A key
/// file holds one key, and a PKCS#12 file also holds the certificate that the lock pairs with
/// that key on the source.
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
