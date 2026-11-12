//! The `cakeys` command line, as a library so a downstream binary can link extra provider
//! crates: `cakeys::main(cakeys::default_registry().with(MyProvider))`.

use anyhow::Context;
use clap::{Parser, Subcommand};
use cakeys_core::config::{gc, load_config, lock_for_update, lock_unwritable, load_lock, save_lock, Config};
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
    /// Create under the declared locator if absent and autoCreate is set, then compare with the
    /// lock, recording what it lacks (missing hashes and realisation details; never overwriting
    /// a hash) unless --no-update-lock.
    Realise {
        spec: String,
        #[arg(long)]
        token: String,
        #[command(flatten)]
        write: LockWrite,
    },
    /// Delete by locator if it holds the expected identity, and remove its realisation from the
    /// lock unless --no-update-lock. Absent is success.
    Delete {
        spec: String,
        #[arg(long)]
        token: String,
        /// Expected CA-ID; defaults to the locked one.
        #[arg(long)]
        if_match: Option<String>,
        #[command(flatten)]
        write: LockWrite,
    },
    /// Print lock entries whose spec or object is gone from the config; --apply removes them.
    Gc {
        /// Remove exactly the printed entries.
        #[arg(long)]
        apply: bool,
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

/// Whether `realise`/`delete` write the lock: by default they do, like `nix build` with
/// `flake.lock`. Where the lock cannot be written (a Nix build sandbox, a read-only lock or
/// directory) the run is refused up front unless `--no-update-lock` says so explicitly.
#[derive(clap::Args)]
struct LockWrite {
    /// Compare with the lock only; never write it (first use is then exit 10 with `got:`).
    #[arg(long, conflicts_with = "update_lock")]
    no_update_lock: bool,
    /// Write the lock (the default; kept so existing scripts can say it).
    #[arg(long)]
    update_lock: bool,
}

impl LockWrite {
    fn enabled(&self) -> bool {
        !self.no_update_lock
    }
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
    let writes = match &cli.cmd {
        Cmd::Realise { write, .. } | Cmd::Delete { write, .. } => write.enabled(),
        Cmd::Gc { apply } => *apply,
        _ => false,
    };
    // Refused before any token is touched: never a key created and then not recorded.
    if writes && let Some(why) = lock_unwritable(&lock_path) {
        let opt_out = if matches!(cli.cmd, Cmd::Gc { .. }) { "drop --apply" } else { "pass --no-update-lock" };
        return Err(KmError::PreconditionFailed(format!(
            "cannot write the lock {}: {why}; {opt_out} to compare without writing",
            lock_path.display()
        ))
        .into());
    }
    let _update_guard = if writes { Some(lock_for_update(&lock_path)?) } else { None };
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
        Cmd::Realise { spec, token, write } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            let (r, changed) = ops::realise(&t, &tok, &mut lock, write.enabled())?;
            if changed {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {}", lock_path.display());
            }
            print(&r);
        }
        Cmd::Delete { spec, token, if_match, write } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            if ops::delete(&t, &tok, &mut lock, if_match.as_deref(), write.enabled())? {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {}", lock_path.display());
            }
        }
        Cmd::Gc { apply } => {
            let stale = gc(&cfg, &mut lock, *apply);
            for entry in &stale {
                println!("{entry}");
            }
            if stale.is_empty() {
                eprintln!("nothing to collect: every lock entry is named by the config");
            } else if *apply {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {} ({} entries removed)", lock_path.display(), stale.len());
            } else {
                eprintln!("{} stale entries; pass --apply to remove them", stale.len());
            }
        }
        Cmd::Check { reference, token, spec } => {
            let (object, scheme) = match reference.split_once(".id.") {
                Some((o, s)) => (o, Some(cakeys_core::id::canonical_scheme(s))),
                None => (reference.as_str(), None),
            };
            let (spec_name, token_name) = cfg.pick_spec(object, spec.as_deref(), token.as_deref())?;
            let t = Target::new(&cfg, &spec_name, &token_name)?;
            // The schemes the spec can compute; an attestation scheme (§3.7) depends on the
            // token's provider, so only schemes_on below can tell whether this one computes it.
            if let Some(s) = scheme {
                let attested = t.on_token.attestation && cakeys_core::id::is_attestation_scheme(s);
                if !attested && !t.schemes().contains(&s) {
                    return Err(KmError::Unsupported(format!(
                        "scheme '{s}' for '{object}'; it has {:?}{}",
                        t.schemes(),
                        if t.on_token.attestation { " plus its token's attestation scheme" } else { "" }
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
            // computed next to another scheme that matched. An attestation is locked on this
            // realisation (§3.7), not on the object.
            if let Some(s) = scheme {
                let (locked, got) = if cakeys_core::id::is_attestation_scheme(s) {
                    let kind = cakeys_core::id::attestation_kind(s);
                    let locked = lock
                        .realisation(&spec_name, &token_name)
                        .and_then(|r| r.attestation.as_ref())
                        .is_some_and(|a| Some(a.kind.as_str()) == kind);
                    (locked, r.attestation.as_ref().map(|a| a.id.clone()))
                } else {
                    (lock.objects.get(&t.spec.object).is_some_and(|o| o.ids.contains_key(s)), r.ids.get(s).cloned())
                };
                if !locked {
                    return Err(KmError::HashMismatch {
                        what: format!("'{object}' (scheme {s})"),
                        expected: "<none>".into(),
                        got: got.unwrap_or_default(),
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
