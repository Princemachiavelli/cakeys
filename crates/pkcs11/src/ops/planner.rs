//! The create planner: which pairs `create` makes, in what order, and why it skips the rest;
//! then making the selected ones.

#[allow(
    clippy::wildcard_imports,
    reason = "the ops/ split files work on the parent module's imports, as token/'s (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// Why `create` never makes `t`'s object: its pair's origin is not `create`.
pub(super) fn not_origin_create(t: &Target) -> Option<String> {
    match t.on_token.key_origin() {
        KeyOrigin::Create => None,
        KeyOrigin::Import => Some(format!(
            "origin = \"import\": camigrate brings its material here (camigrate migrate {} --to {}), never `create`",
            t.object_name, t.token_name
        )),
        KeyOrigin::Adopt => Some("origin = \"adopt\": it is found there, never created".into()),
        KeyOrigin::File => Some(format!(
            "origin = \"file\": camigrate brings its material here from the object's migrate.file \
             (camigrate import {} --to {}), never `create`",
            t.object_name, t.token_name
        )),
    }
}

/// Why `create` without a named pair leaves `t` alone: its origin is not `create`, or the lock
/// already pins its material (another token then needs that same material, which only
/// importing or migrating can put there).
fn not_created(t: &Target, lock: &Lock) -> Option<String> {
    not_origin_create(t).or_else(|| pinned(t, lock))
}

/// Why a pair's object is not created again: the lock already pins its material, so `create`
/// verifies the key that is there instead.
pub(super) fn pinned(t: &Target, lock: &Lock) -> Option<String> {
    lock.objects.get(t.object_name).filter(|o| !o.ids.is_empty()).map(|_| {
        format!(
            "the lock already pins object '{}': the run verifies it is there and matches, as `check` \
             does, and makes nothing",
            t.object_name
        )
    })
}

/// Whether `create` would generate `t`'s object: its origin is `create` and the lock does not
/// pin it yet. What the static gate asks generation for.
#[must_use]
pub fn creates(t: &Target, lock: &Lock) -> bool {
    not_created(t, lock).is_none()
}

/// The (spec, token) pairs `create` selects, in config order: [`Config::select`], and a
/// selection naming a spec or an object that matches nothing is refused like the other verbs
/// refuse it.
///
/// # Errors
///
/// `Validation` (17), as [`Config::select`] and [`Config::address`].
pub fn create_pairs<'a>(
    cfg: &'a Config,
    object: Option<&str>,
    spec: Option<&str>,
    token: Option<&str>,
) -> Result<Vec<(&'a str, &'a str)>> {
    let pairs = cfg.select(object, spec, token)?;
    if pairs.is_empty() && (object.is_some() || spec.is_some()) {
        cfg.address(object, spec, token)?;
    }
    Ok(pairs)
}

/// What `create` does with one selected pair ([`plan_create`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Created; a key already under the locator is `Exists` (19) when the run gets there.
    Create,
    /// The lock pins it: the run verifies the key that is there, as `check` does, and makes
    /// nothing ([`Made::Verified`]).
    Verify,
    /// Left alone: its origin is not `create`.
    Skip,
    /// The capability profiles say the token cannot make it.
    Refuse,
}

impl Action {
    /// The name `create --dry-run` prints.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Verify => "verify",
            Action::Skip => "skip",
            Action::Refuse => "refuse",
        }
    }

    /// Whether the run opens the pair's token: to create it or to verify it.
    #[must_use]
    pub fn runs(self) -> bool {
        matches!(self, Action::Create | Action::Verify)
    }
}

/// One selected pair and what `create` does with it, decided before any token is opened.
pub struct Planned<'a> {
    /// The spec.
    pub spec: &'a str,
    /// The token.
    pub token: &'a str,
    /// The object the spec realises.
    pub object: &'a str,
    /// What `create` does with it.
    pub action: Action,
    /// Why: the skip's reason, the profiles' refusals, or what they leave undecided.
    pub reasons: Vec<String>,
}

/// What `create` does with each selected pair ([`create_pairs`]), decided from keys.toml, the
/// lock and the capability profiles alone, before any token is opened: a pair whose origin is
/// not `create` is skipped (unless the address names that one pair: an object or a spec, and a
/// token); one whose object the lock pins is verified, never made again; every other pair goes
/// through the static gate ([`crate::gate::check`]), whose *no* refuses it and whose *unknown*
/// is a reason to try. A token whose profiles are not known without opening it is not gated
/// here; the live check still refuses before generating.
///
/// # Errors
///
/// [`create_pairs`]' refusals; `Validation` (17) for a named pair whose origin is not
/// `create`, or a spec `plan_mode` refuses; the gate's own errors.
pub fn plan_create<'a>(
    cfg: &'a Config,
    object: Option<&str>,
    spec: Option<&str>,
    token: Option<&str>,
    lock: &Lock,
    registry: &Registry,
) -> Result<Vec<Planned<'a>>> {
    let pairs = create_pairs(cfg, object, spec, token)?;
    let named = token.is_some() && (object.is_some() || spec.is_some()) && pairs.len() == 1;
    let mut stacks = std::collections::BTreeMap::new();
    let mut out = Vec::new();
    for (spec_name, token_name) in pairs {
        let t = Target::new(cfg, spec_name, token_name)?;
        let planned =
            |action, reasons| Planned { spec: spec_name, token: token_name, object: t.object_name, action, reasons };
        let mode = plan_mode(&t)?;
        if let Some(why) = not_origin_create(&t) {
            if named {
                return Err(KmError::Validation(format!("{t}: {why}").into()));
            }
            out.push(planned(Action::Skip, vec![why]));
            continue;
        }
        let (action, why) = match pinned(&t, lock) {
            Some(why) => (Action::Verify, vec![why]),
            None => (Action::Create, Vec::new()),
        };
        if !stacks.contains_key(token_name) {
            let token_cfg = &cfg.tokens[token_name];
            stacks.insert(token_name, crate::gate::stack(token_name, token_cfg, lock)?);
        }
        out.push(match &stacks[token_name] {
            Ok(stack) => {
                let v = crate::gate::check(&t, mode, stack, registry, Verb::of(&t, lock))?;
                if v.refusals.is_empty() {
                    planned(action, [why, v.deferred.iter().map(ToString::to_string).collect()].concat())
                } else {
                    planned(Action::Refuse, v.refusals.iter().map(ToString::to_string).collect())
                }
            }
            Err(e) => planned(action, [why, vec![format!("{t}: not checked before opening the token: {e}")]].concat()),
        });
    }
    Ok(out)
}

/// What [`create_selected`] did.
pub struct Created {
    /// The realised objects, in the order they were created.
    pub created: Vec<Resolved>,
    /// Whether the lock changed and `persist` saved it.
    pub changed: bool,
    /// The failure that ended the run, if any.
    pub failed: Option<KmError>,
}

/// The `create` verb: [`create`] over each of `pairs` (what [`plan_create`] decided to create or
/// verify), in order. Every step of a pair, opening its token included, ends the run there,
/// reported in [`Created::failed`] beside what was created before; a verified key is said in a
/// note. Each pair that changed `lock` is `persist`ed before the next pair is touched, so a run
/// killed or failing later never leaves a key on a token the lock file does not record; a
/// failed save ends the run as a pair's failure does.
///
/// At most one token is open at a time: each is closed before the next opens.
///
/// # Errors
///
/// None of its own: a pair's failure, or its record's, is [`Created::failed`].
pub fn create_selected(
    cfg: &Config,
    pairs: &[(&str, &str)],
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    lock: &mut Lock,
    write: LockWrite,
    persist: &mut dyn FnMut(&Lock) -> Result<()>,
    notes: &mut Notes,
) -> Created {
    let mut out = Created { created: Vec::new(), changed: false, failed: None };
    let mut current: Option<Token> = None;
    for &(spec_name, token_name) in pairs {
        let mut pair = || -> Result<Made> {
            let t = Target::new(cfg, spec_name, token_name)?;
            // Another token's module is finalized (dropped) before the next open.
            let tok = match current.take().filter(|tok| tok.name == token_name) {
                Some(tok) => current.insert(tok),
                None => current.insert(open(token_name, notes)?),
            };
            create(&t, tok, lock, write, notes)
        };
        match pair() {
            Ok(Made::Created(r, c)) => {
                let saved = if c { persist(lock) } else { Ok(()) };
                out.created.push(r);
                if let Err(e) = saved {
                    notes.say(format!(
                        "'{spec_name}' on token '{token_name}' was created, but the lock could not record it"
                    ));
                    out.failed = Some(e);
                    break;
                }
                out.changed |= c;
            }
            Ok(Made::Verified(_)) => {}
            Err(e) => {
                out.failed = Some(e);
                break;
            }
        }
    }
    out
}
