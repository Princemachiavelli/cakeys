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
    /// A rule refuses it: the capability profiles' before any token opens, or the token's
    /// ([`token_rules`], `create --dry-run`).
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
    /// The rules that refuse it ([`Action::Refuse`]).
    pub refusals: Vec<Refusal>,
    /// The rules only the write can decide: the run asks them.
    pub deferred: Vec<Deferred>,
    /// Why else: the skip's reason, the verification's.
    pub notes: Vec<String>,
    /// Whether its refusals are the open token's ([`plan_on_tokens`]): the run ends there, as the
    /// write's own [`token_rules`] would end it; `--skip-unsupported` skips only the profiles'.
    pub on_token: bool,
    /// The failure that ended [`plan_on_tokens`] at this pair, as it would end the run there.
    pub failed: Option<KmError>,
}

/// A planned pair the run creates or verifies, no rule refusing it: what the write takes
/// ([`create_selected`]). Only [`Planned::ready`] makes one.
#[derive(Clone, Copy)]
pub struct Ready<'p, 'a>(&'p Planned<'a>);

impl<'a> Ready<'_, 'a> {
    /// The spec.
    #[must_use]
    pub fn spec(&self) -> &'a str {
        self.0.spec
    }

    /// The token.
    #[must_use]
    pub fn token(&self) -> &'a str {
        self.0.token
    }
}

impl<'a> Planned<'a> {
    /// The pair, for the write, when the run creates or verifies it and no rule refuses it.
    #[must_use]
    pub fn ready(&self) -> Option<Ready<'_, 'a>> {
        (self.action.runs() && self.refusals.is_empty()).then_some(Ready(self))
    }
}

impl Planned<'_> {
    /// Why, as lines: the notes, the refusals, then what is deferred ([`deferred_lines`]).
    #[must_use]
    pub fn reasons(&self) -> Vec<String> {
        let refusals = self.refusals.iter().map(ToString::to_string);
        self.notes.iter().cloned().chain(refusals).chain(deferred_lines(&self.deferred)).collect()
    }
}

/// What `create` does with each selected pair ([`create_pairs`]), decided from keys.toml, the
/// lock and the capability profiles alone, before any token is opened: a pair whose origin is
/// not `create` is skipped (unless the address names that one pair: an object or a spec, and a
/// token); one whose object the lock pins is verified, never made again; every other pair goes
/// through the static gate ([`crate::gate::check`]), whose *no* refuses it and whose *unknown*
/// is deferred to the run. A token whose provider and profiles are known only when it opens
/// defers each of their rules by name; the live check asks them before generating.
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
        let planned = |action, notes| Planned {
            spec: spec_name,
            token: token_name,
            object: t.object_name,
            action,
            refusals: Vec::new(),
            deferred: Vec::new(),
            notes,
            on_token: false,
            failed: None,
        };
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
        let v = crate::gate::check(&t, mode, &stacks[token_name], registry, Verb::of(&t, lock))?;
        out.push(if v.refusals.is_empty() {
            Planned { deferred: v.deferred, ..planned(action, why) }
        } else {
            Planned { refusals: v.refusals, ..planned(Action::Refuse, Vec::new()) }
        });
    }
    Ok(out)
}

/// `create --dry-run`'s second half (review 2026-11-24 C-4): each pair the run would create or
/// verify ([`Planned::ready`]), on its token opened by `open` (read-only, a write-protected one
/// refused as the write's open refuses it), asked the token's rules ([`token_rules`]) as the
/// write asks them, in the run's order, one token open at a time. A refusal makes its row
/// [`Action::Refuse`], [`Planned::on_token`]; a pair they pass has nothing deferred left, the
/// open token having decided it. A failure that is no rule's (opening the token, a login, a
/// search: 16 when the token is absent or fails) ends it at that pair, as it ends the run
/// ([`create_selected`]): it is that pair's [`Planned::failed`], which its row carries (review
/// 2026-11-24 L4a-2: the dry run exited 16 with every row 0), and no pair after it is asked.
pub fn plan_on_tokens(
    cfg: &Config,
    planned: &mut [Planned<'_>],
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    lock: &Lock,
    notes: &mut Notes,
) {
    let mut current: Option<Token> = None;
    for p in planned.iter_mut().filter(|p| p.ready().is_some()) {
        let (spec, token) = (p.spec, p.token);
        let asked = Target::new(cfg, spec, token).and_then(|t| {
            // Another token's module is finalized (dropped) before the next open.
            let tok = match current.take().filter(|tok| tok.name == token) {
                Some(tok) => current.insert(tok),
                None => current.insert(open(token, notes)?),
            };
            // Create's rules, a verified pair's too: the write asks them of a pinned key it does
            // not find.
            token_rules(&t, tok, lock, Verb::Create)
        });
        match asked {
            // The open token decided what the profiles left to it.
            Ok(refusals) if refusals.is_empty() => p.deferred.clear(),
            Ok(refusals) => (p.action, p.refusals, p.on_token) = (Action::Refuse, refusals, true),
            Err(e) => {
                p.failed = Some(e);
                return;
            }
        }
    }
}

/// What [`create_selected`] did.
pub struct Created<'a> {
    /// Each pair the run reached, in order: the last is the one whose failure ended it, if any.
    pub reached: Vec<Reached<'a>>,
    /// Whether the lock changed and `persist` saved it.
    pub changed: bool,
}

/// One pair [`create_selected`] reached, and what became of it: made or verified; made, and its
/// record not saved; or failed before anything was made.
pub struct Reached<'a> {
    /// The spec.
    pub spec: &'a str,
    /// The token.
    pub token: &'a str,
    /// What it made or verified.
    pub made: Option<Made>,
    /// The failure that ended the run at this pair.
    pub failed: Option<KmError>,
}

impl Created<'_> {
    /// The failure that ended the run, if one did.
    #[must_use]
    pub fn failed(&self) -> Option<&KmError> {
        self.reached.last().and_then(|r| r.failed.as_ref())
    }
}

/// The `create` verb: [`create`] over each of `ready` (what [`plan_create`] decided to create or
/// verify, no rule refusing it), in order; [`create`] asks the token's rules again before it
/// writes. Every step of a pair, opening its token included, ends the run there,
/// reported in that pair's [`Reached::failed`] beside what was created before; a verified key is said in a
/// note. Each pair that changed `lock` is `persist`ed before the next pair is touched, so a run
/// killed or failing later never leaves a key on a token the lock file does not record; a
/// failed save ends the run as a pair's failure does.
///
/// At most one token is open at a time: each is closed before the next opens.
///
/// # Errors
///
/// None of its own: a pair's failure, or its record's, is [`Created::failed`].
pub fn create_selected<'a>(
    cfg: &Config,
    ready: &[Ready<'_, 'a>],
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    lock: &mut Lock,
    write: LockWrite,
    persist: &mut dyn FnMut(&Lock) -> Result<()>,
    notes: &mut Notes,
) -> Created<'a> {
    let mut out = Created { reached: Vec::new(), changed: false };
    let mut current: Option<Token> = None;
    for (spec_name, token_name) in ready.iter().map(|r| (r.spec(), r.token())) {
        let mut pair = || -> Result<Made> {
            let t = Target::new(cfg, spec_name, token_name)?;
            // Another token's module is finalized (dropped) before the next open.
            let tok = match current.take().filter(|tok| tok.name == token_name) {
                Some(tok) => current.insert(tok),
                None => current.insert(open(token_name, notes)?),
            };
            create(&t, tok, lock, write, notes)
        };
        let (made, failed) = match pair() {
            Ok(Made::Created(r, c)) => {
                let saved = if c { persist(lock) } else { Ok(()) };
                if saved.is_err() {
                    notes.say(format!(
                        "'{spec_name}' on token '{token_name}' was created, but the lock could not record it"
                    ));
                }
                out.changed |= c && saved.is_ok();
                (Some(Made::Created(r, c)), saved.err())
            }
            Ok(verified) => (Some(verified), None),
            Err(e) => (None, Some(e)),
        };
        let stop = failed.is_some();
        out.reached.push(Reached { spec: spec_name, token: token_name, made, failed });
        if stop {
            break;
        }
    }
    out
}
