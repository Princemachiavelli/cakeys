//! The planner of `create`. It decides which pairs `create` makes, in what order, and why it
//! skips the other pairs. It then makes the selected pairs.

#[allow(
    clippy::wildcard_imports,
    reason = "the ops/ split files work on the parent module's imports, as token/'s (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// Returns the reason why `create` never makes the object of `t`, which is that the pair's origin
/// is not `create`. Returns `None` when the origin is `create`.
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

/// Returns the reason why `create` without a named pair leaves `t` alone. The reason is that the
/// origin is not `create`, or that the lock already records the object's material. In the second
/// case, another token needs that same material, and only an import or a migration can put it
/// there.
fn not_created(t: &Target, lock: &Lock) -> Option<String> {
    not_origin_create(t).or_else(|| pinned(t, lock))
}

/// Returns the reason why a pair's object is not created again, which is that the lock already
/// records its material. `create` then verifies the key that is there instead. Returns `None`
/// when the lock records no ID for the object.
pub(super) fn pinned(t: &Target, lock: &Lock) -> Option<String> {
    lock.objects.get(t.object_name).filter(|o| !o.ids.is_empty()).map(|_| {
        format!(
            "the lock already pins object '{}': the run verifies it is there and matches, as `check` \
             does, and makes nothing",
            t.object_name
        )
    })
}

/// Returns whether `create` would generate the object of `t`: the origin is `create`, and the
/// lock does not record the object yet. The static gate checks the generation only for such an
/// object.
#[must_use]
pub fn creates(t: &Target, lock: &Lock) -> bool {
    not_created(t, lock).is_none()
}

/// Returns the (spec, token) pairs that `create` selects, in the order of the configuration
/// ([`Config::select`]). A selection that names a spec or an object but matches nothing is
/// refused, as the other verbs refuse it.
///
/// # Errors
///
/// `Validation` (exit 17), from [`Config::select`] or [`Config::address`].
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
    /// The run creates the object. A key that is already under the locator gives `Exists`
    /// (exit 19) when the run reaches the pair.
    Create,
    /// The lock records the object, so the run verifies the key that is there, as `check` does,
    /// and makes nothing ([`Made::Verified`]).
    Verify,
    /// The run leaves the pair alone, because its origin is not `create`.
    Skip,
    /// A rule refuses the pair. The rule is either a rule of the capability profiles, checked
    /// before any token is opened, or a rule of the token ([`token_rules`], which
    /// `create --dry-run` checks).
    Refuse,
}

impl Action {
    /// Returns the name that `create --dry-run` prints.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Verify => "verify",
            Action::Skip => "skip",
            Action::Refuse => "refuse",
        }
    }

    /// Returns whether the run opens the pair's token, which it does to create or to verify the
    /// object.
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
    /// The object that the spec realises.
    pub object: &'a str,
    /// What `create` does with the pair.
    pub action: Action,
    /// The refusals of the rules that refuse the pair ([`Action::Refuse`]).
    pub refusals: Vec<Refusal>,
    /// The rules that only the write can decide. The run checks them.
    pub deferred: Vec<Deferred>,
    /// The other reasons: why the pair is skipped, or why it is verified.
    pub notes: Vec<String>,
    /// Whether the refusals come from the open token ([`plan_on_tokens`]). The run ends at such a
    /// refusal, as the write's own [`token_rules`] would end it. `--skip-unsupported` skips only
    /// the refusals of the profiles.
    pub on_token: bool,
    /// The failure that ended [`plan_on_tokens`] at this pair. The same failure would end the run
    /// at this pair.
    pub failed: Option<KmError>,
}

/// A planned pair that the run creates or verifies and that no rule refuses. The write
/// ([`create_selected`]) takes only this type, and only [`Planned::ready`] makes one.
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
    /// Returns the pair for the write when the run creates or verifies it and no rule refuses it.
    #[must_use]
    pub fn ready(&self) -> Option<Ready<'_, 'a>> {
        (self.action.runs() && self.refusals.is_empty()).then_some(Ready(self))
    }
}

impl Planned<'_> {
    /// Returns the reasons as lines: the notes, then the refusals, then the deferred rules
    /// ([`deferred_lines`]).
    #[must_use]
    pub fn reasons(&self) -> Vec<String> {
        let refusals = self.refusals.iter().map(ToString::to_string);
        self.notes.iter().cloned().chain(refusals).chain(deferred_lines(&self.deferred)).collect()
    }
}

/// Decides what `create` does with each selected pair ([`create_pairs`]). The decision uses only
/// keys.toml, the lock and the capability profiles, and it is made before any token is opened:
///
/// - A pair whose origin is not `create` is skipped, unless the address names that one pair (an
///   object or a spec, and a token). A named pair of another origin is refused.
/// - A pair whose object the lock records is planned as [`Action::Verify`] and is never made
///   again.
/// - Every pair that is not skipped goes through the static gate ([`crate::gate::check`]). A *no*
///   from the gate refuses the pair, and an *unknown* is deferred to the run.
///
/// For a token whose provider and profiles are known only when the token is opened, the plan
/// defers each of their rules by name, and the live check checks them before the generation.
///
/// # Errors
///
/// The refusals of [`create_pairs`]. `Validation` (exit 17) for a named pair whose origin is not
/// `create`, or for a spec that `plan_mode` refuses. The errors of the gate itself.
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

/// The second half of `create --dry-run` (review 2026-11-24 C-4). For each pair that the run
/// would create or verify ([`Planned::ready`]), the function opens the pair's token with `open` and
/// checks the token's rules ([`token_rules`]) as the write checks them. `open` opens the token
/// read-only, and it refuses a write-protected token as the write's open refuses it. The pairs
/// are checked in the run's order, with one token open at a time.
///
/// A refusal sets the pair's action to [`Action::Refuse`] and sets [`Planned::on_token`]. A pair
/// that passes the rules has no deferred rule left, because the open token decided them. A
/// failure that belongs to no rule (at the open of the token, at a login, or at a search; exit 16
/// when the token is absent or fails) ends the dry run at that pair, as it ends the run
/// ([`create_selected`]). The failure is stored in that pair's [`Planned::failed`], and the
/// pair's row shows it (review 2026-11-24 L4a-2: the dry run once exited 16 while every row
/// showed 0). No pair after that pair is checked.
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
            // The module of the previous token is finalized (dropped) before the next token is
            // opened.
            let tok = match current.take().filter(|tok| tok.name == token) {
                Some(tok) => current.insert(tok),
                None => current.insert(open(token, notes)?),
            };
            // Check the rules of `create` also for a pair that is planned as verified, because the
            // write checks them when it does not find a key that the lock records.
            token_rules(&t, tok, lock, Verb::Create)
        });
        match asked {
            // The open token decided the rules that the profiles left undecided.
            Ok(refusals) if refusals.is_empty() => p.deferred.clear(),
            Ok(refusals) => (p.action, p.refusals, p.on_token) = (Action::Refuse, refusals, true),
            Err(e) => {
                p.failed = Some(e);
                return;
            }
        }
    }
}

/// The result of [`create_selected`].
pub struct Created<'a> {
    /// Each pair that the run reached, in order. If a failure ended the run, the last pair is the
    /// pair that failed.
    pub reached: Vec<Reached<'a>>,
    /// Whether the lock changed and `persist` saved it.
    pub changed: bool,
}

/// One pair that [`create_selected`] reached, and its outcome. The pair was made or verified, or
/// it was made but its record in the lock was not saved, or it failed before anything was made.
pub struct Reached<'a> {
    /// The spec.
    pub spec: &'a str,
    /// The token.
    pub token: &'a str,
    /// What the run made or verified for the pair.
    pub made: Option<Made>,
    /// The failure that ended the run at this pair.
    pub failed: Option<KmError>,
}

impl Created<'_> {
    /// Returns the failure that ended the run, if there was one.
    #[must_use]
    pub fn failed(&self) -> Option<&KmError> {
        self.reached.last().and_then(|r| r.failed.as_ref())
    }
}

/// The `create` verb. It runs [`create`] on each pair of `ready`, in order. `ready` holds the
/// pairs that [`plan_create`] decided to create or verify and that no rule refuses, and [`create`]
/// checks the token's rules again before it writes. A failure in any step of a pair, including
/// the open of its token, ends the run at that pair. The failure is reported in that pair's
/// [`Reached::failed`], next to what was created before. A verified key is reported in a note.
///
/// Each pair that changed `lock` is saved with `persist` before the next pair is touched. As a
/// result, a run that is killed or that fails later never leaves a key on a token that the lock
/// file does not record. A failed save ends the run in the same way as a pair's failure.
///
/// At most one token is open at a time: each token is closed before the next one is opened.
///
/// # Errors
///
/// The function returns no error of its own. A pair's failure, or the failure to save its
/// record, is in [`Created::failed`].
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
            // The module of the previous token is finalized (dropped) before the next token is
            // opened.
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
