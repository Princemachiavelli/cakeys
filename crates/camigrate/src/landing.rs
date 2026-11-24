//! The planner's rules past the method choice (review 2026-11-23 C-23: they sat in lib.rs, a
//! third layer after `plan::plan` and `tokens::plan_moves`): what keeps an object home, which
//! pair a move lands on, what the landing token must take, what a bundle or a key file can
//! carry, and the transport key a sealed move wraps to. [`block`] runs them over a run's plans,
//! in one place, so the dry run and the run block alike (C-2).

use cakeys_core::KmError;
use cakeys_core::config::{Config, KeyOrigin, Lock, SpecCfg, SpecTokenCfg};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_pkcs11::Registry;
use cakeys_pkcs11::ops::{Notes, Target};

use crate::plan::{self, FileFormat};
use crate::{MoveArgs, MoveCtx, Run, tokens};

/// Block each plan the run would refuse, said in the plan, in the order the run meets it: what
/// never leaves `from` (said first), a target with no import pair, the landing pair's own
/// checks — or, with nothing landing on a token, the source's export — a transport key whose
/// spec is gone, and what the destination carries. `transport_key` is the one the plan sealed to.
pub(crate) fn block(run: &Run, ctx: &MoveCtx, transport_key: Option<&str>, moves: &mut tokens::Moves) {
    let (cfg, registry) = (&run.opener.cfg, run.opener.registry);
    let MoveCtx { objects, from, dest, specs, .. } = *ctx;
    let (bundle, target_token) = (dest.bundle(), dest.token());
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
                Ok(landing) => landing_checks(p, &landing, &moves.source, moves.target.as_ref(), registry),
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
    // A sealed move wraps under the transport key's spec in keys.toml: one the lock still
    // names and keys.toml no longer has is said here, where the move itself would stop.
    if let Some(to) = target_token
        && let Ok(spec) = tokens::transport_spec(&run.lock, to, transport_key)
        && !cfg.specs.contains_key(spec)
    {
        let sealed = |p: &plan::Plan| matches!(p.method, Some(Method::RsaOaepAesKwp(_) | Method::RsaOaep(_)));
        for p in moves.plans.iter_mut().filter(|p| p.ready && sealed(p)) {
            p.block(format!("the transport key's spec '{spec}' is gone from keys.toml"));
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
/// before anything is created); an imported key is never attested where the provider attests
/// only what the device made (PIV, docs/CAMIGRATE.md D8), the check the import itself makes.
/// `dst` is the landing pair, the one `--spec` names.
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
    if let (true, Some(target)) = (p.ready, target)
        && let Ok(Some(provider)) = registry.named(&target.provider)
        && let Err(why) = cakeys_pkcs11::ops::check_imported_attestation(dst, provider.as_ref())
    {
        p.block(why);
    }
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

/// The public key `lock` records for the transport key realised as `spec` on `token`, if any.
///
/// # Errors
///
/// `Validation` (17) for a recorded public key that is not base64: never read as none.
pub(crate) fn locked_spki(lock: &Lock, spec: &str, token: &str) -> cakeys_core::Result<Option<Vec<u8>>> {
    use base64::Engine as _;
    let Some(key) =
        lock.realisation(spec, token).and_then(|r| lock.objects.get(&r.object)).and_then(|o| o.public_key.as_ref())
    else {
        return Ok(None);
    };
    base64::engine::general_purpose::STANDARD.decode(key).map(Some).map_err(|e| {
        KmError::Validation(format!("the lock's publicKey of transport key '{spec}' on '{token}': {e}").into())
    })
}

/// The transport key to seal to on `to`: `--transport-spec`, else the token's `transportWith`.
pub(crate) fn transport_choice<'a>(cfg: &'a Config, to: &str, how: &'a MoveArgs) -> Option<&'a str> {
    how.transport_spec.as_deref().or_else(|| cfg.tokens.get(to).and_then(|t| t.migrate.transport_with.as_deref()))
}

/// The target `token`'s transport key, as a target: the spec `tokens::transport_spec` finds.
pub(crate) fn transport_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    token: &'a str,
    chosen: Option<&str>,
) -> cakeys_core::Result<Target<'a>> {
    let spec = tokens::transport_spec(lock, token, chosen).map_err(|e| KmError::PreconditionFailed(e.into()))?;
    let spec = cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()).ok_or_else(|| {
        KmError::PreconditionFailed(format!("the transport key's spec '{spec}' is gone from keys.toml").into())
    })?;
    Target::new(cfg, spec, token)
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
                 '{from}': lock it there, or export --to-file pkcs8",
                p.object
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    /// The transport key's recorded public key: none where the lock records none, the bytes
    /// where it does, and 17 for one that does not decode, never "none" (review lib.rs F10).
    #[test]
    fn a_locked_public_key_that_does_not_decode_is_invalid() {
        use cakeys_core::config::{Lock, LockObject};
        let text = "version = 1\n[objects.t]\npublicKey = \"AAEC\"\n\
                    [realisations.tr.tok]\nobject = \"t\"\nspecDigest = \"sha256-x\"\nmode = \"direct\"\n\
                    schemes = []\nlocator = { CKA_LABEL = \"t\" }\npolicy = {}\n";
        let mut lock: Lock = toml::from_str(text).unwrap();
        assert_eq!(super::locked_spki(&lock, "tr", "tok").unwrap(), Some(vec![0, 1, 2]));
        assert_eq!(super::locked_spki(&lock, "tr", "other").unwrap(), None);
        lock.objects.insert("t".into(), LockObject { public_key: Some("!".into()), ..LockObject::default() });
        let e = super::locked_spki(&lock, "tr", "tok").unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("publicKey"), "{e}");
    }
}
