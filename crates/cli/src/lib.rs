//! The `cakeys` command line, as a library so a downstream binary can link extra provider
//! crates: `cakeys::main(cakeys::default_registry().with(MyProvider))`.

use anyhow::Context;
use clap::{Parser, Subcommand};
use cakeys_core::config::{load_config, lock_for_update, load_lock, save_lock, Config};
use cakeys_core::KmError;
use cakeys_pkcs11::ops::{self, Target};
use cakeys_pkcs11::{Registry, Token};
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
    #[arg(short, long, env = "CAKEYS_CONFIG")]
    config: PathBuf,
    /// Lock file; defaults to the config path with a `.lock` extension.
    #[arg(short, long, env = "CAKEYS_LOCK")]
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
    /// Print a token's provider and usable mechanisms as JSON.
    Caps { #[arg(long)] token: String },
}

/// The providers this crate links. Built through the same public API a third party uses.
pub fn default_registry() -> Registry {
    Registry::new()
        .with(cakeys_softhsm::SoftHsm)
        .with(cakeys_ykcs11::Ykcs11)
        .with(cakeys_tpm2_pkcs11::Tpm2Pkcs11)
        .with(cakeys_p11_kit::P11Kit)
}

/// Run the CLI with the given providers; maps errors to the documented exit codes.
pub fn main(registry: Registry) -> ExitCode {
    match run(&registry) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(e.downcast_ref::<KmError>().map_or(1, KmError::exit_code))
        }
    }
}

fn open_token(
    cfg: &Config,
    modules: &BTreeMap<String, String>,
    registry: &Registry,
    name: &str,
) -> Result<Token, KmError> {
    let tcfg = cfg
        .tokens
        .get(name)
        .ok_or_else(|| KmError::Validation(format!("unknown token '{name}'")))?;
    Token::open(name, tcfg, modules.get(name).map(String::as_str), registry)
}

fn run(registry: &Registry) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    // A run that may write the lock holds its advisory sidecar lock across load and save (M3),
    // so concurrent updaters queue instead of losing each other's writes. Held to the end of run.
    let _update_guard = match &cli.cmd {
        Cmd::Realise { update_lock: true, .. } | Cmd::Delete { update_lock: true, .. } => {
            Some(lock_for_update(&lock_path)?)
        }
        _ => None,
    };
    let mut lock = load_lock(&lock_path)?;
    let modules: BTreeMap<String, String> = cli
        .modules
        .iter()
        .map(|m| m.split_once('=').map(|(t, p)| (t.to_owned(), p.to_owned())))
        .collect::<Option<_>>()
        .context("--module expects TOKEN=PATH")?;

    match &cli.cmd {
        Cmd::Validate => {
            for (name, t) in &cfg.tokens {
                if let Some(p) = t.provider.as_deref().filter(|p| !registry.knows(p)) {
                    return Err(KmError::Validation(format!(
                        "token '{name}': unknown provider '{p}' (registered: generic, {})",
                        registry.names().join(", ")
                    ))
                    .into());
                }
            }
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
            let tok = open_token(&cfg, &modules, registry, token)?;
            let r = ops::resolve(&t, &tok, &lock)?.ok_or_else(|| KmError::NotFound(format!("{spec} on {token}")))?;
            print(&r);
        }
        Cmd::Verify { spec, token } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            println!("{}", ops::verify(&t, &tok, &lock)?.uri);
        }
        Cmd::Realise { spec, token, update_lock } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            let (r, changed) = ops::realise(&t, &tok, &mut lock, *update_lock)?;
            if changed {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {}", lock_path.display());
            }
            print(&r);
        }
        Cmd::Delete { spec, token, if_match, update_lock } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            if ops::delete(&t, &tok, &mut lock, if_match.as_deref(), *update_lock)? {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {}", lock_path.display());
            }
        }
        Cmd::Check { reference, token, spec } => {
            let (object, scheme) = match reference.split_once(".id.") {
                Some((o, s)) => (o, Some(cakeys_core::id::canonical_scheme(s))),
                None => (reference.as_str(), None),
            };
            let (spec_name, token_name) = cfg.pick_spec(object, spec.as_deref(), token.as_deref())?;
            let t = Target::new(&cfg, &spec_name, &token_name)?;
            if let Some(s) = scheme {
                if !t.schemes().contains(&s) {
                    return Err(KmError::Unsupported(format!(
                        "scheme '{s}' for '{object}'; it has {:?}",
                        t.schemes()
                    ))
                    .into());
                }
            }
            let tok = open_token(&cfg, &modules, registry, &token_name)?;
            // The token may lack a mechanism the spec allows: refuse before realise can create.
            if let Some(s) = scheme {
                let on_token = ops::schemes_on(&t, &tok)?;
                if !on_token.contains(&s) {
                    return Err(KmError::Unsupported(format!(
                        "scheme '{s}' for spec '{spec_name}' on '{token_name}'; it computes {on_token:?}"
                    ))
                    .into());
                }
            }
            let (r, _) = ops::realise(&t, &tok, &mut lock, false)?;
            // An explicitly requested scheme must itself be locked (and so verified), not just
            // computed next to another scheme that matched.
            if let Some(s) = scheme {
                if lock.objects.get(&t.spec.object).and_then(|o| o.ids.get(s)).is_none() {
                    return Err(KmError::HashMismatch {
                        what: format!("'{object}' (scheme {s})"),
                        expected: "<none>".into(),
                        got: r.ids.get(s).cloned().unwrap_or_default(),
                    }
                    .into());
                }
            }
            println!("{}", r.uri);
        }
        Cmd::Caps { token } => {
            let tok = open_token(&cfg, &modules, registry, token)?;
            print(&serde_json::json!({
                "token": token,
                "provider": tok.provider.name(),
                "mechanisms": tok.mechanism_names(),
            }));
        }
    }
    Ok(())
}

fn print<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}
