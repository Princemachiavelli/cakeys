//! What the `cakeys`, `caprobe` and `camigrate` command lines share (README.md, "Three
//! tools"): the providers this build links, opening a token keys.toml names, printing a run's
//! notes, and the documented exit codes. Each binary is a library over this, so a downstream
//! binary can link extra provider crates: `cakeys::main(&cakeys::default_registry().with(P))`.

use cakeys_core::KmError;
use cakeys_core::config::{
    Config, Lock, TokenCfg, UpdateGuard, load_config, load_lock, lock_for_update, lock_unwritable, save_lock,
};
use cakeys_pkcs11::ops::Notes;
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{ChainTime, Registry, Token, providers};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

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
    if cfg.profile_dirs.is_empty() {
        return activate().map(drop);
    }
    let built: Vec<String> = cakeys_profile::Set::embedded()
        .map_err(|e| KmError::Validation(e.into()))?
        .all()
        .iter()
        .map(|p| p.profile.clone())
        .collect();
    let set = activate()?;
    let added: Vec<&str> =
        set.all().iter().map(|p| p.profile.as_str()).filter(|p| !built.iter().any(|b| b == p)).collect();
    notes.say(format!(
        "profiles added from profileDirs ({}): {}",
        cfg.profile_dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "),
        if added.is_empty() { "none".to_owned() } else { added.join(", ") }
    ));
    Ok(())
}

/// Run a command line's `dispatch`, print what the run noticed (before the error line, if any:
/// never lost to a failure), and map an error to the documented exit code.
pub fn main(dispatch: impl FnOnce(&mut Notes) -> anyhow::Result<()>) -> ExitCode {
    let mut notes = Notes::default();
    let result = dispatch(&mut notes);
    for line in notes.lines() {
        eprintln!("{line}");
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(e.downcast_ref::<KmError>().map_or(1, KmError::exit_code))
        }
    }
}

/// `--module TOKEN=PATH` overrides, by token.
///
/// # Errors
///
/// `Validation` (17) when an override is not of the form `TOKEN=PATH`: an invalid option, not
/// the 1 of an error without a code.
pub fn module_overrides(args: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    args.iter()
        .map(|m| {
            m.split_once('=')
                .map(|(t, p)| (t.to_owned(), p.to_owned()))
                .ok_or_else(|| KmError::Validation(format!("--module {m:?}: expects TOKEN=PATH").into()).into())
        })
        .collect()
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
}

impl<'a> Opener<'a> {
    /// keys.toml at `config`, with the profile set it names activated ([`activate_profiles`]),
    /// and the `--module` overrides `modules`.
    ///
    /// # Errors
    ///
    /// A malformed override; whatever [`load_config`] or [`activate_profiles`] refuses.
    pub fn load(
        config: &Path,
        modules: &[String],
        registry: &'a Registry,
        notes: &mut Notes,
    ) -> anyhow::Result<Opener<'a>> {
        let modules = module_overrides(modules)?;
        let cfg = load_config(config)?;
        activate_profiles(&cfg, None, notes)?;
        Ok(Opener { cfg, modules, registry })
    }

    /// [`open_token`] of the token `name`, for every verb but `check`: an attestation chain out of
    /// its dates by the clock is a warning, not a refusal (`check` refuses it; [`ChainTime::Warn`]).
    ///
    /// # Errors
    ///
    /// Whatever [`open_token`] refuses.
    pub fn open(&self, name: &str, access: Access, notes: &mut Notes) -> Result<Token, KmError> {
        open_token(&self.cfg, &self.modules, self.registry, name, access, ChainTime::warn_now(), notes)
    }

    /// [`open_quiet`] of the token `name`, holding its attestation chains to `chain_time`
    /// (`check`).
    ///
    /// # Errors
    ///
    /// Whatever [`open_quiet`] refuses.
    pub fn open_quiet(&self, name: &str, access: Access, chain_time: ChainTime) -> Result<Token, KmError> {
        open_quiet(&self.cfg, &self.modules, self.registry, name, access, chain_time)
    }
}

/// The lock at `path`, for a verb that `writes` it or only reads it. A writing verb is refused
/// up front when the lock cannot be written (`instead` says what to do), before any token is
/// touched: never a key created and then not recorded. It holds the lock's advisory sidecar
/// (M3) for as long as the returned guard lives, across load and save, so concurrent updaters
/// queue instead of losing each other's writes.
///
/// # Errors
///
/// `LockUnwritable` (21) for a lock a writing verb cannot write; whatever
/// [`lock_for_update`] or [`load_lock`] refuses.
pub fn read_lock(path: &Path, writes: bool, instead: &str) -> anyhow::Result<(Lock, Option<UpdateGuard>)> {
    if writes && let Some(why) = lock_unwritable(path) {
        return Err(KmError::LockUnwritable(
            format!("cannot write the lock {}: {why}; {instead}", path.display()).into(),
        )
        .into());
    }
    // Said before it blocks: a run waiting on another updater says what it waits for.
    let waiting =
        |sidecar: &Path| eprintln!("note: waiting for {}: another run is updating the lock", sidecar.display());
    let guard = if writes { Some(lock_for_update(path, waiting)?) } else { None };
    Ok((load_lock(path)?, guard))
}

/// Save `lock` to `path` if the verb `changed` it, and say so.
///
/// # Errors
///
/// Whatever [`save_lock`] refuses.
pub fn save_changed(path: &Path, lock: &Lock, changed: bool, notes: &mut Notes) -> anyhow::Result<()> {
    if changed {
        save_lock(path, lock)?;
        notes.say(format!("updated {}", path.display()));
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
