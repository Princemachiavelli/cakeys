//! The `camigrate` command line (docs/SCOPE.md, "Three tools"): it moves keys between tokens
//! (MIGRATE.md). It is the only tool that handles key material; so far it plans (`--dry-run`)
//! and writes transport files, and moves nothing. A library, so a downstream binary can link
//! extra provider crates: `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

mod plan;
mod tokens;
mod transport;

use anyhow::Context as _;
use cakeys_cli_common::{module_overrides, open_token, print};
use cakeys_core::KmError;
use cakeys_core::config::{Config, Lock, load_config, load_lock};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_pkcs11::Registry;
use cakeys_pkcs11::ops::{Notes, Target};
use cakeys_pkcs11::token::Access;
use clap::{Parser, Subcommand};
use plan::FileFormat;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use transport::Transport;

pub use cakeys_cli_common::default_registry;

/// Move keys between PKCS#11 tokens, checked against keys.lock (MIGRATE.md).
///
/// Exit codes: 0 ok, 11 not found, 14 precondition failed, 15 unsupported (an object cannot
/// move as invoked), 16 unavailable, 17 invalid spec, 1 other.
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
    /// Plan exporting objects realised on a token, shaped for a target (MIGRATE.md): per object,
    /// the method, how exposed the material is on the way, and why not when it cannot move. Only
    /// --dry-run is implemented; exports move nothing yet.
    Export {
        /// The object to export; default: every object realised on --token.
        object: Option<String>,
        /// The source token.
        #[arg(long)]
        token: String,
        /// The intended target token in keys.toml: its capabilities are read from the open token,
        /// else from what the lock recorded there.
        #[arg(long, required_unless_present_any = ["transport", "to_file"])]
        target: Option<String>,
        /// The target's transport file (`camigrate transport`), for a target this host cannot
        /// reach.
        #[arg(long, conflicts_with = "target")]
        transport: Option<PathBuf>,
        /// Export to a passphrase-protected file instead of a token.
        #[arg(long, value_enum, conflicts_with_all = ["target", "transport"])]
        to_file: Option<FileArg>,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Plan moving objects from one token to another, both reachable from this host (MIGRATE.md).
    /// Only --dry-run is implemented.
    Migrate {
        /// The object to move; default: every object realised on --from.
        object: Option<String>,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Write the transport file for a transport key (MIGRATE.md D3): an RSA private key that may
    /// unwrap, realised and locked on the target. Exports to this token wrap to it.
    Transport {
        spec: String,
        #[arg(long)]
        token: String,
        /// Where to write it; default: stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// How `export` and `migrate` may move material.
#[derive(clap::Args)]
struct MoveArgs {
    /// Print the plan and move nothing (the only mode implemented so far).
    #[arg(long)]
    dry_run: bool,
    /// Print the plan as JSON.
    #[arg(long)]
    json: bool,
    /// Allow the `host` and `file` paths: plaintext in this process's memory (MIGRATE.md D2).
    #[arg(long)]
    allow_host_plaintext: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum FileArg {
    Pkcs8,
    Pkcs12,
}

/// Run the command line with the given providers; maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parse the arguments, load keys.toml and the lock, and run the verb. Nothing here writes the
/// lock yet.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let modules = module_overrides(&cli.modules)?;
    let cfg = load_config(&cli.config)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    let lock = load_lock(&lock_path)?;
    let run = Run { cfg, modules, registry, lock };
    match &cli.cmd {
        Cmd::Export { object, token, target, transport, to_file, how } => {
            let dest = match (target, transport, to_file) {
                (_, _, Some(FileArg::Pkcs8)) => Dest::File(FileFormat::Pkcs8),
                (_, _, Some(FileArg::Pkcs12)) => Dest::File(FileFormat::Pkcs12),
                (_, Some(path), None) => Dest::Transport(path),
                (Some(t), None, None) => Dest::Token(t),
                (None, None, None) => unreachable!("clap requires one of --target, --transport, --to-file"),
            };
            run.plan_moves(object.as_deref(), token, &dest, how, notes)
        }
        Cmd::Migrate { object, from, to, how } => run.plan_moves(object.as_deref(), from, &Dest::Token(to), how, notes),
        Cmd::Transport { spec, token, out } => {
            let t = Target::new(&run.cfg, spec, token)?;
            let tok = open_token(&run.cfg, &run.modules, registry, token, Access::Read, notes)?;
            let text = tokens::transport(&t, &tok, &run.lock, notes)?.to_toml();
            match out {
                Some(path) => {
                    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
                    notes.say(format!("wrote {}", path.display()));
                }
                None => print!("{text}"),
            }
            Ok(())
        }
    }
}

/// What a verb works with once the arguments are parsed: keys.toml, the lock, and how tokens
/// are opened.
struct Run<'a> {
    cfg: Config,
    modules: BTreeMap<String, String>,
    registry: &'a Registry,
    lock: Lock,
}

/// Where `export` or `migrate` sends the material.
enum Dest<'a> {
    Token(&'a str),
    Transport(&'a Path),
    File(FileFormat),
}

impl Run<'_> {
    /// Plan each object's move from `from` to `dest` and print it (MIGRATE.md D9); 15 when any
    /// object cannot move as invoked. Moving is not implemented yet: without --dry-run, refused.
    fn plan_moves(
        &self,
        object: Option<&str>,
        from: &str,
        dest: &Dest,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        if !how.dry_run {
            return Err(KmError::Unsupported(
                "export and migrate move nothing yet: only --dry-run is implemented (MIGRATE.md phase 1; \
                 phase 2 moves public objects, phase 3 sealed keys)"
                    .into(),
            )
            .into());
        }
        let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
        let open = |name: &str, notes: &mut Notes| open_token(cfg, modules, registry, name, Access::Read, notes);
        let transport = match dest {
            Dest::Transport(path) => {
                let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
                Some((Transport::parse(&text, path)?, path.display().to_string()))
            }
            _ => None,
        };
        let dest = match (dest, &transport) {
            (Dest::Token(name), _) => tokens::Dest::Token(name),
            (Dest::File(f), _) => tokens::Dest::File(*f),
            (Dest::Transport(_), Some((t, shown))) => tokens::Dest::Transport(t, shown),
            (Dest::Transport(_), None) => unreachable!("parsed above"),
        };
        let req = tokens::Request { object, from, dest, host_plaintext: how.allow_host_plaintext };
        let moves = tokens::plan_moves(&self.lock, registry, &req, &open, notes)?;
        let (to_name, source_from, target_from, plans) =
            (&moves.to, moves.source_from, moves.target_from, &moves.plans);
        if how.json {
            print(&serde_json::json!({
                "from": from,
                "to": to_name,
                "capabilities": { "from": source_from, "to": target_from },
                "plans": plans,
            }))?;
        } else {
            println!(
                "{from} -> {to_name} (capabilities: {from} from the {source_from}, {to_name} from the {target_from})"
            );
            for p in plans {
                let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
                let exposure = p.exposure.map_or("-", Exposure::name);
                let status = if p.ready { "ready" } else { "blocked" };
                println!("  {:<24} {method:<26} {exposure:<9} {status}", p.object);
                for r in &p.reasons {
                    println!("      - {r}");
                }
                for n in &p.notes {
                    println!("      note: {n}");
                }
            }
        }
        Ok(moves.ready()?)
    }
}
