//! What the `cakeys`, `caprobe` and `camigrate` command lines share (docs/SCOPE.md, "Three
//! tools"): the providers this build links, opening a token keys.toml names, printing a run's
//! notes, and the documented exit codes. Each binary is a library over this, so a downstream
//! binary can link extra provider crates: `cakeys::main(&cakeys::default_registry().with(P))`.

use anyhow::Context as _;
use cakeys_core::KmError;
use cakeys_core::config::{Config, TokenCfg};
use cakeys_pkcs11::ops::Notes;
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{Registry, Token, providers};
use std::collections::BTreeMap;
use std::process::ExitCode;

/// The providers this build links, in detection order. Built through the same public API a
/// third party uses; `tpm2` and `ykcs11` are cargo features (both on by default).
#[must_use]
pub fn default_registry() -> Registry {
    let registry = Registry::new().with(providers::SoftHsm).with(providers::Kryoptic);
    #[cfg(feature = "ykcs11")]
    let registry = registry.with(cakeys_ykcs11::Ykcs11);
    #[cfg(feature = "tpm2")]
    let registry = registry.with(cakeys_tpm2_pkcs11::Tpm2Pkcs11);
    registry.with(providers::P11Kit)
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
/// When an override is not of the form `TOKEN=PATH`.
pub fn module_overrides(args: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    args.iter()
        .map(|m| m.split_once('=').map(|(t, p)| (t.to_owned(), p.to_owned())))
        .collect::<Option<_>>()
        .context("--module expects TOKEN=PATH")
}

/// keys.toml's entry for the token `name`.
///
/// # Errors
///
/// `Validation` (17) when keys.toml has no such token.
pub fn token_cfg<'a>(cfg: &'a Config, name: &str) -> Result<&'a TokenCfg, KmError> {
    cfg.tokens.get(name).ok_or_else(|| KmError::Validation(format!("unknown token '{name}'")))
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
    notes: &mut Notes,
) -> Result<Token, KmError> {
    let tok = open_quiet(cfg, modules, registry, name, access)?;
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
) -> Result<Token, KmError> {
    Token::open(name, token_cfg(cfg, name)?, modules.get(name).map(String::as_str), registry, access)
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
