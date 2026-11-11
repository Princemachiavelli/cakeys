mod config;
mod error;
mod hal;
mod id;
mod ops;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{load_config, load_lock, save_lock, Config};
use error::KmError;
use hal::Token;
use ops::Target;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

/// Content-addressed identity for PKCS#11 objects.
///
/// Exit codes: 0 ok, 10 hash mismatch (first use: record the `got:` hash), 11 not found,
/// 12 ambiguous, 13 conflict, 14 precondition failed, 15 unsupported, 16 unavailable,
/// 17 invalid spec, 1 other.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Declarative input (keys.toml).
    #[arg(short, long, env = "KM_CONFIG")]
    config: PathBuf,
    /// Lock file; defaults to the config path with a `.lock` extension.
    #[arg(short, long, env = "KM_LOCK")]
    lock: Option<PathBuf>,
    /// Override a token's PKCS#11 module: `<token>=<path>` (repeatable).
    #[arg(long = "module", value_name = "TOKEN=PATH")]
    modules: Vec<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the spec statically (identity modes, opt-ins, types). Touches no token.
    Validate,
    /// Find the object by its locator and print its identity as JSON. Never writes.
    Resolve { spec: String, #[arg(long)] token: String },
    /// Resolve, then compare with the lock (If-Match). Prints the PKCS#11 URI.
    Verify { spec: String, #[arg(long)] token: String },
    /// Create under the declared locator if absent and autoCreate is set, then compare with the lock.
    Realise {
        spec: String,
        #[arg(long)]
        token: String,
        /// Record missing hashes and realisation details in the lock (never overwrites a hash).
        #[arg(long)]
        update_lock: bool,
    },
    /// Delete by locator if it holds the expected identity. Absent is success.
    Delete {
        spec: String,
        #[arg(long)]
        token: String,
        /// Expected CA-ID; defaults to the locked one.
        #[arg(long)]
        if_match: Option<String>,
        #[arg(long)]
        update_lock: bool,
    },
    /// Pseudo-FOD pre-use check: `<object>.id.<scheme>`. Realises (respecting autoCreate),
    /// verifies against the lock, and prints the URI on stdout. Never writes the lock.
    Check {
        reference: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        spec: Option<String>,
    },
    /// Print a token's mechanisms as JSON.
    Caps { #[arg(long)] token: String },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(e.downcast_ref::<KmError>().map_or(1, KmError::exit_code))
        }
    }
}

fn open_token(cfg: &Config, modules: &BTreeMap<String, String>, name: &str) -> Result<Token, KmError> {
    let tcfg = cfg
        .tokens
        .get(name)
        .ok_or_else(|| KmError::Validation(format!("unknown token '{name}'")))?;
    Token::open(name, tcfg, modules.get(name).map(String::as_str))
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    let mut lock = load_lock(&lock_path)?;
    let modules: BTreeMap<String, String> = cli
        .modules
        .iter()
        .map(|m| m.split_once('=').map(|(t, p)| (t.to_owned(), p.to_owned())))
        .collect::<Option<_>>()
        .context("--module expects TOKEN=PATH")?;

    match &cli.cmd {
        Cmd::Validate => {
            for (spec_name, spec) in &cfg.specs {
                for token in spec.tokens.keys() {
                    let t = Target::new(&cfg, spec_name, token)?;
                    let mode = ops::plan_mode(&t)?;
                    let note = if mode.needs_opt_in() { " (opted in)" } else { "" };
                    println!("{spec_name} on {token}: mode {mode}{note}");
                }
            }
        }
        Cmd::Resolve { spec, token } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, token)?;
            let r = ops::resolve(&t, &tok)?.ok_or_else(|| KmError::NotFound(format!("{spec} on {token}")))?;
            print(&r);
        }
        Cmd::Verify { spec, token } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, token)?;
            println!("{}", ops::verify(&t, &tok, &lock)?.uri);
        }
        Cmd::Realise { spec, token, update_lock } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, token)?;
            let (r, changed) = ops::realise(&t, &tok, &mut lock, *update_lock)?;
            if changed {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {}", lock_path.display());
            }
            print(&r);
        }
        Cmd::Delete { spec, token, if_match, update_lock } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, token)?;
            if ops::delete(&t, &tok, &mut lock, if_match.as_deref(), *update_lock)? {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {}", lock_path.display());
            }
        }
        Cmd::Check { reference, token, spec } => {
            let (object, scheme) = match reference.split_once(".id.") {
                Some((o, s)) => (o, Some(s)),
                None => (reference.as_str(), None),
            };
            let (spec_name, token_name) = cfg.pick_spec(object, spec.as_deref(), token.as_deref())?;
            let t = Target::new(&cfg, &spec_name, &token_name)?;
            if let Some(s) = scheme {
                if s != t.primary_scheme() {
                    return Err(KmError::Unsupported(format!(
                        "scheme '{s}' for '{object}'; this POC computes '{}'",
                        t.primary_scheme()
                    ))
                    .into());
                }
            }
            let tok = open_token(&cfg, &modules, &token_name)?;
            let (r, _) = ops::realise(&t, &tok, &mut lock, false)?;
            println!("{}", r.uri);
        }
        Cmd::Caps { token } => {
            let tok = open_token(&cfg, &modules, token)?;
            print(&serde_json::json!({ "token": token, "mechanisms": tok.mechanism_names() }));
        }
    }
    Ok(())
}

fn print<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}
