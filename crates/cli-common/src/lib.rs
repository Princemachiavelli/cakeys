//! The code that the `cakeys`, `caprobe` and `camigrate` command lines share (README.md, "Three
//! tools"): the providers that this build links, the opening of a token that keys.toml names, the
//! printing of a run's notes, and the documented exit codes. Each binary is a library on top of
//! this crate, so a downstream binary can link extra provider crates:
//! `cakeys::main(&cakeys::default_registry().with(P))`.

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

/// Returns the providers that this build links, in the order of detection. The registry is built
/// through the same public API that a third party uses. `tpm2` and `ykcs11` are cargo features
/// (both are on by default). kmsp11 and aws-cloudhsm link no native code, so they are always
/// included. Modules without provider code (softhsm, kryoptic) are named and detected by their
/// profiles.
#[must_use]
pub fn default_registry() -> Registry {
    let registry = Registry::new().with(cakeys_kmsp11::Kmsp11).with(cakeys_aws_cloudhsm::AwsCloudHsm);
    #[cfg(feature = "ykcs11")]
    let registry = registry.with(cakeys_ykcs11::Ykcs11);
    #[cfg(feature = "tpm2")]
    let registry = registry.with(cakeys_tpm2_pkcs11::Tpm2Pkcs11);
    registry.with(providers::P11Kit)
}

/// Activates the profile set against which every token open resolves
/// (`cakeys_profile::Set::activate`): the embedded profiles plus keys.toml's `profileDirs`. The
/// caller calls this right after the config is read and before any code asks for a profile, and
/// no other code activates the set (ISSUES.md Q24). It reports in a note which profiles the
/// directories added, so that a profile from outside the build is named as such. `replacing`
/// (caprobe's `--profiles`) is loaded over the other profiles, and it may replace them.
///
/// # Errors
///
/// Returns `Validation` (17) for a directory that cannot be read, or for a file that the
/// directory may not add.
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

/// Returns how many profiles the embedded set holds, without parsing the set a second time. The
/// set keeps the embedded profiles first, in file order, one profile per file
/// (`embedded_profiles_are_one_per_file`). A profile directory only appends
/// ([`cakeys_profile::Set::adding_dir`] refuses a name that is already loaded), so the profiles
/// after them are the profiles that the directories (and any `--profiles`) added.
fn embedded_count() -> usize {
    cakeys_profile::embedded::PROFILE_FILES.len()
}

/// Runs a command line's `dispatch`, with its notes written to stderr as they are made (review
/// 2026-11-23 C-7), and maps the result to the documented exit code. The code is
/// [`LOCK_WRITTEN`] (22) if the run wrote the lock, even if a later pair failed. Otherwise, it is
/// the error's own code, or 0 if there was no error. A failure after a write exits with 22
/// because a script that reviews the lock only on exit 22 would otherwise miss the written lock.
/// The failed pair's row and a note on stderr still give the failure's code (review 2026-11-24
/// L5).
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

/// Returns `cmd` with the exit-code table ([`EXIT_CODES`]) after its help, which is the same in
/// every tool (review 2026-11-23 C-10). The help is wrapped at the terminal's width, but at no more
/// than 100 columns, so that a paragraph stays readable on a wide terminal.
#[must_use]
pub fn with_exit_codes(cmd: clap::Command) -> clap::Command {
    let rows: Vec<String> = EXIT_CODES.iter().map(|(code, means)| format!("  {code:>2}  {means}")).collect();
    cmd.max_term_width(100).after_help(format!("Exit codes (docs/CAKEYS.md):\n{}", rows.join("\n")))
}

/// Returns the arguments of this process, parsed by `cmd` (the tool's [`with_exit_codes`]
/// command) into `C`. It exits as clap does on a usage error (2) or on `--help`.
#[must_use]
pub fn parse<C: clap::FromArgMatches>(cmd: clap::Command) -> C {
    C::from_arg_matches(&cmd.get_matches()).unwrap_or_else(|e| e.exit())
}

/// Returns the `--module TOKEN=PATH` overrides, by token. Each override must name a token that
/// keys.toml (`cfg`) has.
///
/// # Errors
///
/// Returns `Validation` (17), which marks an invalid option, instead of the 1 of an error without
/// a code. It does so for an override that is not of the form `TOKEN=PATH`, for an override with
/// an empty half, for a token that is given twice (because it is not clear which value should
/// apply), and for a token that `cfg` does not name. Without the last check, a typo would leave
/// keys.toml's module in place without any message.
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

/// Returns keys.toml's entry for the token `name`.
///
/// # Errors
///
/// Returns `Validation` (17) when keys.toml has no such token.
pub fn token_cfg<'a>(cfg: &'a Config, name: &str) -> Result<&'a TokenCfg, KmError> {
    cfg.tokens.get(name).ok_or_else(|| KmError::Validation(format!("unknown token '{name}'").into()))
}

/// Opens the token `name` for a verb. A PIN counter that reports an earlier failed login causes a
/// warning.
///
/// # Errors
///
/// Returns every error of [`open_quiet`].
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

/// Works as [`open_token`] without the warning, for callers that report it themselves
/// (`ops::check`).
///
/// # Errors
///
/// Returns `Validation` for a token that keys.toml does not name, and every error of
/// [`Token::open`].
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

/// What a verb needs to open tokens: keys.toml, the `--module` overrides and the providers. It is
/// kept separate from the lock, so that a verb can open tokens while it changes the lock
/// (ISSUES.md Q14).
pub struct Opener<'a> {
    /// keys.toml.
    pub cfg: Config,
    /// The `--module TOKEN=PATH` overrides, by token.
    pub modules: BTreeMap<String, String>,
    /// The providers this binary links.
    pub registry: &'a Registry,
    /// What the lock recorded about each token ([`Opener::recall`]). It is applied over the
    /// token's profile at every open.
    recorded: BTreeMap<String, Observation>,
}

impl<'a> Opener<'a> {
    /// Loads keys.toml from `config`, activates the profile set that it names
    /// ([`activate_profiles`]), and reads the `--module` overrides `modules`.
    ///
    /// # Errors
    ///
    /// Returns every error of [`load_config`], [`module_overrides`] and [`activate_profiles`].
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

    /// From now on, opens every token with what `lock` recorded about it
    /// ([`Token::with_answers`]), so that a verb decides by the answers that the token's own runs
    /// demonstrated, as `validate` does (ISSUES.md B18). It is only for a verb whose verdicts may
    /// use an observation (`create`, but not `check` or `lock`: docs/LOCK.md). caprobe never calls
    /// it, because caprobe measures the module.
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

    /// Returns `tok` with what the lock recorded about it.
    fn recalled(&self, mut tok: Token) -> Token {
        if let Some(o) = self.recorded.get(&tok.name) {
            tok.with_answers(o);
        }
        tok
    }

    /// Opens the token `name` with [`open_token`], for every verb except `check`. An attestation
    /// chain that is outside its validity dates by the clock causes a warning, not a refusal
    /// (`check` refuses it; [`ChainTime::Warn`]).
    ///
    /// # Errors
    ///
    /// Returns every error of [`open_token`].
    pub fn open(&self, name: &str, access: Access, notes: &mut Notes) -> Result<Token, KmError> {
        open_token(&self.cfg, &self.modules, self.registry, name, access, ChainTime::warn_now(), notes)
            .map(|tok| self.recalled(tok))
    }

    /// Opens the token `name` with [`open_quiet`], and checks its attestation chains at
    /// `chain_time` (for `check`).
    ///
    /// # Errors
    ///
    /// Returns every error of [`open_quiet`].
    pub fn open_quiet(&self, name: &str, access: Access, chain_time: ChainTime) -> Result<Token, KmError> {
        open_quiet(&self.cfg, &self.modules, self.registry, name, access, chain_time).map(|tok| self.recalled(tok))
    }
}

/// Returns the lock at `path`, for a verb that `writes` the lock or only reads it. A missing lock
/// is refused unless `new_lock` (`--new-lock`) says to start one, so a mistyped `--lock` never
/// reads as an empty lock and never creates a second lock (review 2026-11-23 C-16). A verb that
/// writes is refused at the start when the lock cannot be written (`instead` says what to do
/// instead), before any token is accessed, so that a key is never created and then not
/// recorded. The function holds the lock's advisory sidecar file (M3) for as long as the
/// returned guard lives, across the load and the save, so that concurrent updaters wait in turn
/// instead of losing each other's writes.
///
/// # Errors
///
/// Returns `Validation` (17) for a missing lock without `new_lock`, `LockUnwritable` (21) for a
/// lock that a verb that writes cannot write, and every error of [`lock_for_update`] and
/// [`load_lock`].
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
    // The note is printed before the call blocks, so that a run that waits for another updater
    // says what it waits for.
    let waiting =
        |sidecar: &Path| eprintln!("note: waiting for {}: another run is updating the lock", sidecar.display());
    let guard = if writes { Some(lock_for_update(path, waiting)?) } else { None };
    Ok((load_lock(path)?, guard))
}

/// Returns `e` with the rule `lock-writable` attached when `e` is an unwritable lock (21), so
/// that a row says which rule ended the pair ([`Outcome::rule`]).
#[must_use]
pub fn lock_rule(e: KmError) -> KmError {
    if e.exit_code() == 21 { e.with_rule(cakeys_pkcs11::ops::Rule::LockWritable) } else { e }
}

/// Saves `lock` to `path` if the verb `changed` it, and records that it did
/// ([`Notes::lock_written`]: the run then exits with [`LOCK_WRITTEN`]).
///
/// # Errors
///
/// Returns every error of [`save_lock`].
pub fn save_changed(path: &Path, lock: &Lock, changed: bool, notes: &mut Notes) -> anyhow::Result<()> {
    if changed {
        save_lock(path, lock).map_err(lock_rule)?;
        notes.lock_written(path);
    }
    Ok(())
}

/// Prints `v` as pretty JSON on stdout.
///
/// # Errors
///
/// Returns an error when `v` cannot be serialized.
pub fn print<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::{Reason, Rule};

    fn cfg(tokens: &[&str]) -> Config {
        let text = tokens.iter().map(|t| format!("[tokens.{t}]\ntokenLabel = \"{t}\"\n")).collect::<Vec<_>>().concat();
        cakeys_core::config::parse_config_with(&text, Path::new("keys.toml"), &|_| None).unwrap()
    }

    fn overrides(args: &[&str]) -> Result<BTreeMap<String, String>, KmError> {
        module_overrides(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(), &cfg(&["a", "b"]))
    }

    /// Every malformed `--module`, or one that names a wrong token, is invalid (17), and each
    /// error gives the reason. One override for each token of keys.toml is accepted as given.
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

    /// The help of every tool ends with the same exit-code table, with a row for each code that
    /// says what the code means (review 2026-11-23 C-10).
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
            13 => Some(anyhow::Error::from(KmError::Conflict(Reason::rule(Rule::LocatorFree, "pair 2")))),
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

    /// A missing lock is refused (17) unless `--new-lock` is given, which reads it as empty. A
    /// run that writes then reports that it wrote the lock, and exits with 22 (review 2026-11-23
    /// C-16).
    #[test]
    fn a_missing_lock_is_refused_unless_a_new_one_is_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        let Err(e) = read_lock(&path, false, false, "") else { panic!("a missing lock was read") };
        let e = e.downcast_ref::<KmError>().unwrap();
        assert!(e.exit_code() == 17 && e.to_string().contains("--new-lock"), "{e}");
        // Inside a Nix build sandbox, a lock write is refused at the start (`lock_unwritable`),
        // so `--new-lock` creates no lock there. The half of this test that writes runs only
        // outside the sandbox.
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

    /// `activate_profiles` finds the profiles that `profileDirs` added by their position after
    /// the embedded profiles. That works only while every embedded file adds exactly one profile
    /// with its own name.
    #[test]
    fn embedded_profiles_are_one_per_file() {
        assert_eq!(cakeys_profile::Set::embedded().unwrap().all().len(), embedded_count());
    }
}
