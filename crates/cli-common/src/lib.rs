//! What the `cakeys`, `caprobe` and `camigrate` command lines share (README.md, "Three
//! tools"): the providers this build links, opening a token keys.toml names, printing a run's
//! notes, and the documented exit codes. Each binary is a library over this, so a downstream
//! binary can link extra provider crates: `cakeys::main(&cakeys::default_registry().with(P))`.

use cakeys_core::config::{
    Config, Lock, Observation, TokenCfg, TokenObservation, UpdateGuard, load_config, load_lock, lock_for_update,
    lock_unwritable, save_lock,
};
use cakeys_core::{EXIT_CODES, KmError, LOCK_WRITTEN};
use cakeys_pkcs11::ops::Notes;
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{ChainTime, Registry, Token, providers};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

pub mod outcome;
pub use outcome::{DeferredRow, Outcome, refused};

/// The providers this build links, in detection order. Built through the same public API a
/// third party uses; `tpm2` and `ykcs11` are cargo features (both on by default). kmsp11 and
/// aws-cloudhsm link nothing native, so they are always in. Modules with no code (softhsm,
/// kryoptic) are named and detected by their profiles.
#[must_use]
pub fn default_registry() -> Registry {
    let registry = Registry::new().with(cakeys_kmsp11::Kmsp11).with(cakeys_aws_cloudhsm::AwsCloudHsm);
    #[cfg(feature = "ykcs11")]
    let registry = registry.with(cakeys_ykcs11::Ykcs11);
    #[cfg(feature = "tpm2")]
    let registry = registry.with(cakeys_tpm2_pkcs11::Tpm2Pkcs11);
    registry.with(providers::P11Kit)
}

/// Activate the profile set every token open resolves against (`cakeys_profile::Set::activate`):
/// the embedded profiles plus keys.toml's `profileDirs`, right after the config is read and
/// before anything asks for a profile, which nothing else activates (ISSUES.md Q24). Says
/// which profiles the directories added: a profile from outside the build is named as such.
/// `replacing` (caprobe's `--profiles`) is loaded over the rest, and may replace.
///
/// # Errors
///
/// `Validation` (17) for a directory that cannot be read or a file it may not add.
pub fn activate_profiles(cfg: &Config, replacing: Option<&Path>, notes: &mut Notes) -> Result<(), KmError> {
    let activate = || {
        cakeys_profile::Set::activate_replacing(&cfg.profile_dirs, replacing).map_err(|e| {
            let from = replacing.map(|d| format!(" (or --profiles {})", d.display())).unwrap_or_default();
            KmError::Validation(format!("profileDirs{from}: {e}").into())
        })
    };
    let set = activate()?;
    if cfg.profile_dirs.is_empty() {
        return Ok(());
    }
    let added: Vec<&str> = set.all().iter().skip(embedded_count()).map(|p| p.profile.as_str()).collect();
    notes.say(format!(
        "profiles added from profileDirs ({}): {}",
        cfg.profile_dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "),
        if added.is_empty() { "none".to_owned() } else { added.join(", ") }
    ));
    Ok(())
}

/// How many profiles the embedded set holds, without parsing it a second time: the set keeps
/// them first, in file order, one per file (`embedded_profiles_are_one_per_file`), and a
/// profile directory only appends ([`cakeys_profile::Set::adding_dir`] refuses a name already
/// loaded), so what follows them is what the directories (and any `--profiles`) added.
fn embedded_count() -> usize {
    cakeys_profile::embedded::PROFILE_FILES.len()
}

/// Run a command line's `dispatch`, its notes going to stderr as they are said (review
/// 2026-11-23 C-7), and map the result to the documented exit code. The code is
/// [`LOCK_WRITTEN`] (22) if the run wrote the lock, even if a later pair failed; otherwise it is
/// the error's own code, or 0 if there was no error. A failure after a write exits 22 because a
/// script that reviews the lock only on exit 22 would otherwise miss the written lock; the failed
/// pair's row and a note on stderr still give the failure's code (review 2026-11-24 L5).
pub fn main(dispatch: impl FnOnce(&mut Notes) -> anyhow::Result<()>) -> ExitCode {
    let mut notes = Notes::streaming();
    match dispatch(&mut notes) {
        Ok(()) if notes.wrote_lock() => ExitCode::from(LOCK_WRITTEN),
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            let code = e.downcast_ref::<KmError>().map_or(1, KmError::exit_code);
            if !notes.wrote_lock() {
                return ExitCode::from(code);
            }
            eprintln!(
                "note: the run exits {LOCK_WRITTEN}, not {code}, because it wrote the lock before this failure. \
                 Review and commit the lock, then retry the failed pairs; each failed row shows its exit code."
            );
            ExitCode::from(LOCK_WRITTEN)
        }
    }
}

/// `cmd` with the exit-code table ([`EXIT_CODES`]) after its help, the same in every tool
/// (review 2026-11-23 C-10).
#[must_use]
pub fn with_exit_codes(cmd: clap::Command) -> clap::Command {
    let rows: Vec<String> = EXIT_CODES.iter().map(|(code, means)| format!("  {code:>2}  {means}")).collect();
    cmd.after_help(format!("Exit codes (docs/CAKEYS.md):\n{}", rows.join("\n")))
}

/// The arguments of this process, parsed by `cmd` (the tool's [`with_exit_codes`] command) into
/// `C`. Exits as clap does on a usage error (2) or `--help`.
#[must_use]
pub fn parse<C: clap::FromArgMatches>(cmd: clap::Command) -> C {
    C::from_arg_matches(&cmd.get_matches()).unwrap_or_else(|e| e.exit())
}

/// `--module TOKEN=PATH` overrides, by token, each naming a token keys.toml (`cfg`) has.
///
/// # Errors
///
/// `Validation` (17), an invalid option rather than the 1 of an error without a code, for an
/// override not of the form `TOKEN=PATH`, with either half empty, for a token given twice
/// (which one would win is a guess), or for a token `cfg` does not name: a typo would otherwise
/// leave keys.toml's module in place without a word.
pub fn module_overrides(args: &[String], cfg: &Config) -> Result<BTreeMap<String, String>, KmError> {
    let invalid = |m: &str, why: &str| KmError::Validation(format!("--module {m:?}: {why}").into());
    let mut modules = BTreeMap::new();
    for m in args {
        let (token, path) = m.split_once('=').ok_or_else(|| invalid(m, "expects TOKEN=PATH"))?;
        if token.is_empty() || path.is_empty() {
            return Err(invalid(m, "expects TOKEN=PATH, neither of them empty"));
        }
        if !cfg.tokens.contains_key(token) {
            return Err(invalid(m, &format!("keys.toml names no token '{token}'")));
        }
        if modules.insert(token.to_owned(), path.to_owned()).is_some() {
            return Err(invalid(m, &format!("the token '{token}' is given a module twice")));
        }
    }
    Ok(modules)
}

/// keys.toml's entry for the token `name`.
///
/// # Errors
///
/// `Validation` (17) when keys.toml has no such token.
pub fn token_cfg<'a>(cfg: &'a Config, name: &str) -> Result<&'a TokenCfg, KmError> {
    cfg.tokens.get(name).ok_or_else(|| KmError::Validation(format!("unknown token '{name}'").into()))
}

/// Open the token `name` for a verb; a PIN counter that reports an earlier failed login is a
/// warning.
///
/// # Errors
///
/// Whatever [`open_quiet`] refuses.
pub fn open_token(
    cfg: &Config,
    modules: &BTreeMap<String, String>,
    registry: &Registry,
    name: &str,
    access: Access,
    chain_time: ChainTime,
    notes: &mut Notes,
) -> Result<Token, KmError> {
    let tok = open_quiet(cfg, modules, registry, name, access, chain_time)?;
    if let Some(w) = tok.pin_warning() {
        notes.warn(w);
    }
    Ok(tok)
}

/// [`open_token`] without the warning, for callers that report it themselves (`ops::check`).
///
/// # Errors
///
/// `Validation` for a token keys.toml does not name; whatever [`Token::open`] refuses.
pub fn open_quiet(
    cfg: &Config,
    modules: &BTreeMap<String, String>,
    registry: &Registry,
    name: &str,
    access: Access,
    chain_time: ChainTime,
) -> Result<Token, KmError> {
    Token::open(name, token_cfg(cfg, name)?, modules.get(name).map(String::as_str), registry, access, chain_time)
}

/// What a verb opens tokens with: keys.toml, the `--module` overrides and the providers. Kept
/// apart from the lock, so a verb opens tokens while it changes the lock (ISSUES.md Q14).
pub struct Opener<'a> {
    /// keys.toml.
    pub cfg: Config,
    /// `--module TOKEN=PATH` overrides, by token.
    pub modules: BTreeMap<String, String>,
    /// The providers this binary links.
    pub registry: &'a Registry,
    /// What the lock recorded of each token ([`Opener::recall`]), put over its profile at
    /// every open.
    recorded: BTreeMap<String, Observation>,
}

impl<'a> Opener<'a> {
    /// keys.toml at `config`, with the profile set it names activated ([`activate_profiles`]),
    /// and the `--module` overrides `modules`.
    ///
    /// # Errors
    ///
    /// Whatever [`load_config`], [`module_overrides`] or [`activate_profiles`] refuses.
    pub fn load(
        config: &Path,
        modules: &[String],
        registry: &'a Registry,
        notes: &mut Notes,
    ) -> anyhow::Result<Opener<'a>> {
        let cfg = load_config(config)?;
        let modules = module_overrides(modules, &cfg)?;
        activate_profiles(&cfg, None, notes)?;
        Ok(Opener { cfg, modules, registry, recorded: BTreeMap::new() })
    }

    /// Open every token from now on with what `lock` recorded of it ([`Token::with_answers`]),
    /// so a verb decides by the answers the token's own runs demonstrated, as `validate` does
    /// (ISSUES.md B18). Only for a verb whose verdicts may take an observation (`create`, not
    /// `check` or `lock`: docs/LOCK.md); caprobe never does, as it measures the module.
    pub fn recall(&mut self, lock: &Lock) {
        self.recorded = self
            .cfg
            .tokens
            .keys()
            .filter_map(|name| match lock.token_observation(name) {
                TokenObservation::One(o) => Some((name.clone(), o.clone())),
                TokenObservation::None | TokenObservation::Several(_) => None,
            })
            .collect();
    }

    /// `tok` with what the lock recorded of it.
    fn recalled(&self, mut tok: Token) -> Token {
        if let Some(o) = self.recorded.get(&tok.name) {
            tok.with_answers(o);
        }
        tok
    }

    /// [`open_token`] of the token `name`, for every verb but `check`: an attestation chain out of
    /// its dates by the clock is a warning, not a refusal (`check` refuses it; [`ChainTime::Warn`]).
    ///
    /// # Errors
    ///
    /// Whatever [`open_token`] refuses.
    pub fn open(&self, name: &str, access: Access, notes: &mut Notes) -> Result<Token, KmError> {
        open_token(&self.cfg, &self.modules, self.registry, name, access, ChainTime::warn_now(), notes)
            .map(|tok| self.recalled(tok))
    }

    /// [`open_quiet`] of the token `name`, holding its attestation chains to `chain_time`
    /// (`check`).
    ///
    /// # Errors
    ///
    /// Whatever [`open_quiet`] refuses.
    pub fn open_quiet(&self, name: &str, access: Access, chain_time: ChainTime) -> Result<Token, KmError> {
        open_quiet(&self.cfg, &self.modules, self.registry, name, access, chain_time).map(|tok| self.recalled(tok))
    }
}

/// The lock at `path`, for a verb that `writes` it or only reads it. A lock that is not there
/// is refused unless `new_lock` (`--new-lock`) says to start one: a mistyped `--lock` never
/// reads as an empty lock, nor becomes a second one (review 2026-11-23 C-16). A writing verb is
/// refused up front when the lock cannot be written (`instead` says what to do), before any
/// token is touched: never a key created and then not recorded. It holds the lock's advisory
/// sidecar (M3) for as long as the returned guard lives, across load and save, so concurrent
/// updaters queue instead of losing each other's writes.
///
/// # Errors
///
/// `Validation` (17) for a lock that is not there without `new_lock`; `LockUnwritable` (21) for
/// a lock a writing verb cannot write; whatever [`lock_for_update`] or [`load_lock`] refuses.
pub fn read_lock(
    path: &Path,
    new_lock: bool,
    writes: bool,
    instead: &str,
) -> anyhow::Result<(Lock, Option<UpdateGuard>)> {
    if !new_lock && !path.exists() {
        return Err(KmError::Validation(
            format!("no lock at {}: check --lock, or pass --new-lock to start one there", path.display()).into(),
        )
        .into());
    }
    if writes && let Some(why) = lock_unwritable(path) {
        let e = KmError::LockUnwritable(format!("cannot write the lock {}: {why}; {instead}", path.display()).into());
        return Err(lock_rule(e).into());
    }
    // Said before it blocks: a run waiting on another updater says what it waits for.
    let waiting =
        |sidecar: &Path| eprintln!("note: waiting for {}: another run is updating the lock", sidecar.display());
    let guard = if writes { Some(lock_for_update(path, waiting)?) } else { None };
    Ok((load_lock(path)?, guard))
}

/// `e`, naming the rule a lock that cannot be written breaks (`lock-writable`) where it is one
/// (21), so a row says which rule ended the pair ([`Outcome::rule`]).
#[must_use]
pub fn lock_rule(e: KmError) -> KmError {
    if e.exit_code() == 21 { e.with_rule(cakeys_pkcs11::ops::Rule::LockWritable.name()) } else { e }
}

/// Save `lock` to `path` if the verb `changed` it, and say so ([`Notes::lock_written`]: the
/// run then exits [`LOCK_WRITTEN`]).
///
/// # Errors
///
/// Whatever [`save_lock`] refuses.
pub fn save_changed(path: &Path, lock: &Lock, changed: bool, notes: &mut Notes) -> anyhow::Result<()> {
    if changed {
        save_lock(path, lock).map_err(lock_rule)?;
        notes.lock_written(path);
    }
    Ok(())
}

/// Print `v` as pretty JSON on stdout.
///
/// # Errors
///
/// When `v` does not serialize.
pub fn print<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tokens: &[&str]) -> Config {
        let text = tokens.iter().map(|t| format!("[tokens.{t}]\ntokenLabel = \"{t}\"\n")).collect::<Vec<_>>().concat();
        cakeys_core::config::parse_config_with(&text, Path::new("keys.toml"), &|_| None).unwrap()
    }

    fn overrides(args: &[&str]) -> Result<BTreeMap<String, String>, KmError> {
        module_overrides(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(), &cfg(&["a", "b"]))
    }

    /// Every malformed or misdirected `--module` is invalid (17), each saying why; one per
    /// token of keys.toml is taken as given.
    #[test]
    fn module_overrides_refuse_what_they_cannot_apply() {
        let ok = overrides(&["a=/lib/a.so", "b=/lib/b=c.so"]).unwrap();
        assert_eq!(ok, BTreeMap::from([("a".into(), "/lib/a.so".into()), ("b".into(), "/lib/b=c.so".into())]));
        for (args, why) in [
            (&["a"][..], "expects TOKEN=PATH"),
            (&["=/lib/a.so"][..], "neither of them empty"),
            (&["a="][..], "neither of them empty"),
            (&["typo=/lib/a.so"][..], "keys.toml names no token 'typo'"),
            (&["a=/lib/one.so", "a=/lib/two.so"][..], "given a module twice"),
        ] {
            let e = overrides(args).unwrap_err();
            assert_eq!(e.exit_code(), 17, "{args:?}: {e}");
            assert!(e.to_string().contains(why), "{args:?}: {e}");
        }
    }

    /// Every tool's help ends with the one exit-code table, a row per code, each with what it
    /// means (review 2026-11-23 C-10).
    #[test]
    fn the_help_carries_every_exit_code() {
        let help = with_exit_codes(clap::Command::new("t")).render_help().to_string();
        for (code, means) in EXIT_CODES {
            assert!(help.contains(&format!("{code:>2}  {means}")), "{code} is not in\n{help}");
        }
    }

    /// This test checks that `main` returns exit 22 exactly when the run wrote the lock. A run
    /// that wrote the lock and then failed must exit 22, not 0 and not the failure's code, and a
    /// run that wrote nothing must exit 0 or with the failure's code. Before review 2026-11-24 L5,
    /// a `lock`, `create`, `delete` or camigrate run of several pairs that failed after a write
    /// exited with the failure's code although the lock had changed.
    #[test]
    fn a_run_exits_22_exactly_when_it_wrote_the_lock() {
        let path = Path::new("keys.lock");
        let failure = |code: u8| match code {
            13 => Some(anyhow::Error::from(KmError::Conflict("pair 2".into()))),
            21 => Some(KmError::LockUnwritable("pair 2".into()).into()),
            1 => Some(anyhow::anyhow!("pair 2: no KmError")),
            _ => None,
        };
        for (wrote, failed, want) in [
            (false, 0, 0),
            (true, 0, LOCK_WRITTEN),
            (false, 13, 13),
            (true, 13, LOCK_WRITTEN),
            (false, 21, 21),
            (true, 21, LOCK_WRITTEN),
            (false, 1, 1),
            (true, 1, LOCK_WRITTEN),
        ] {
            let code = main(|notes| {
                if wrote {
                    notes.lock_written(path);
                }
                failure(failed).map_or(Ok(()), Err)
            });
            let want = format!("{:?}", ExitCode::from(want));
            assert_eq!(format!("{code:?}"), want, "wrote the lock: {wrote}, failed with {failed}");
        }
    }

    /// A lock that is not there is refused (17) unless `--new-lock`, which reads it as empty;
    /// a writing run then says it wrote it, and exits 22 (review 2026-11-23 C-16).
    #[test]
    fn a_missing_lock_is_refused_unless_a_new_one_is_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        let Err(e) = read_lock(&path, false, false, "") else { panic!("a missing lock was read") };
        let e = e.downcast_ref::<KmError>().unwrap();
        assert!(e.exit_code() == 17 && e.to_string().contains("--new-lock"), "{e}");
        // Inside a Nix build sandbox a lock write is refused up front (`lock_unwritable`), so
        // `--new-lock` makes none there: the writing half of this test runs outside it.
        if cakeys_core::config::in_nix_build() {
            let Err(e) = read_lock(&path, true, true, "") else { panic!("a sandboxed run made a lock") };
            assert!(e.to_string().contains("Nix build sandbox"), "{e}");
            return;
        }
        let (lock, guard) = read_lock(&path, true, true, "").unwrap();
        assert!(lock.realisations.is_empty() && guard.is_some());
        let mut notes = Notes::default();
        save_changed(&path, &lock, false, &mut notes).unwrap();
        assert!(!notes.wrote_lock() && !path.exists());
        save_changed(&path, &lock, true, &mut notes).unwrap();
        assert!(notes.wrote_lock() && path.exists());
        let code = main(|notes| {
            notes.lock_written(&path);
            Ok(())
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(LOCK_WRITTEN)));
    }

    /// `activate_profiles` names what `profileDirs` added by position, after the embedded
    /// profiles: that holds only while every embedded file brings a profile of its own name.
    #[test]
    fn embedded_profiles_are_one_per_file() {
        assert_eq!(cakeys_profile::Set::embedded().unwrap().all().len(), embedded_count());
    }
}
