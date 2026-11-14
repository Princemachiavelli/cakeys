//! The `camigrate` command line (docs/SCOPE.md, "Three tools"): it moves keys between tokens
//! (MIGRATE.md). It is the only tool that handles key material; so far it plans (`--dry-run`)
//! and writes transport files, and moves nothing. A library, so a downstream binary can link
//! extra provider crates: `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

pub mod bundle;
mod plan;
mod public;
mod tokens;
mod transport;

use anyhow::Context as _;
use cakeys_cli_common::{module_overrides, open_token, print};
use cakeys_core::KmError;
use cakeys_core::config::{Config, Lock, load_config, load_lock, lock_for_update, lock_unwritable, save_lock};
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
    /// Move objects from one token to another, both reachable from this host (MIGRATE.md):
    /// each is created on --to and recorded in the lock with where it came from. Public
    /// objects (certificates, public keys, data) move; keys only with --dry-run so far.
    Migrate {
        /// The object to move; default: every object realised on --from.
        object: Option<String>,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        /// The spec to realise each object under on --to, when its object has several there.
        #[arg(long)]
        spec: Option<String>,
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

/// Parse the arguments, then load keys.toml and the lock — refusing up front a run that writes a
/// lock it cannot (MIGRATE.md D8: never inside a Nix build) — and run the verb.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let modules = module_overrides(&cli.modules)?;
    let cfg = load_config(&cli.config)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    // Only a real `migrate` writes the lock; it holds the advisory sidecar lock across load and
    // save, as cakeys' writing verbs do.
    let writes = matches!(&cli.cmd, Cmd::Migrate { how, .. } if !how.dry_run);
    if writes && let Some(why) = lock_unwritable(&lock_path) {
        return Err(KmError::PreconditionFailed(format!(
            "cannot write the lock {}: {why}; moving keys records them there",
            lock_path.display()
        ))
        .into());
    }
    let _update_guard = if writes { Some(lock_for_update(&lock_path)?) } else { None };
    let lock = load_lock(&lock_path)?;
    let mut run = Run { cfg, modules, registry, lock, lock_path };
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
        Cmd::Migrate { object, from, to, how, .. } if how.dry_run => {
            run.plan_moves(object.as_deref(), from, &Dest::Token(to), how, notes)
        }
        Cmd::Migrate { object, from, to, spec, how } => {
            run.migrate(object.as_deref(), from, to, spec.as_deref(), how, notes)
        }
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
    lock_path: PathBuf,
}

/// Where `export` or `migrate` sends the material.
enum Dest<'a> {
    Token(&'a str),
    Transport(&'a Path),
    File(FileFormat),
}

impl Run<'_> {
    /// Plan each object's move from `from` to `dest` and print it (MIGRATE.md D9); 15 when any
    /// object cannot move as invoked. Export writes no bundle yet: without --dry-run, refused.
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
                "export writes no bundle yet: only --dry-run is implemented (bundles come with MIGRATE.md \
                 phase 3); `migrate` moves public objects between reachable tokens"
                    .into(),
            )
            .into());
        }
        Ok(self.plan(object, from, dest, how, notes)?.ready()?)
    }

    /// `migrate` for real (MIGRATE.md phase 2): plan and print as `--dry-run` does, refuse (15)
    /// before anything moves when an object cannot move or needs a method not built yet, then
    /// move each object and record it. What moved before a failure is still recorded, never a
    /// copy left on the target without its realisation.
    fn migrate(
        &mut self,
        object: Option<&str>,
        from: &str,
        to: &str,
        spec: Option<&str>,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let moves = self.plan(object, from, &Dest::Token(to), how, notes)?;
        moves.ready()?;
        if let Some(p) = moves.plans.iter().find(|p| p.method != Some(Method::Public)) {
            let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
            return Err(KmError::Unsupported(format!(
                "{}: moving by {method} is MIGRATE.md phase 3; only public objects move so far (pass \
                 --dry-run for the plan)",
                p.object
            ))
            .into());
        }
        let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
        let source = open_token(cfg, modules, registry, from, Access::Read, notes)?;
        let target = open_token(cfg, modules, registry, to, Access::Write, notes)?;
        let (mut changed, mut failed) = (false, None);
        for p in &moves.plans {
            let pair = source_target(cfg, &self.lock, &p.object, from)
                .and_then(|src| Ok((src, target_target(cfg, &p.object, to, spec)?)));
            let outcome =
                pair.and_then(|(src, dst)| public::import(&src, &source, &dst, &target, &mut self.lock, notes));
            match outcome {
                Ok(public::Moved::Imported) => {
                    changed = true;
                    notes.say(format!("moved {} from {from} to {to} (public)", p.object));
                }
                Ok(public::Moved::AlreadyThere) => {
                    notes.note(format_args!("{} is already on {to} and verifies; nothing to move", p.object));
                }
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if changed {
            save_lock(&self.lock_path, &self.lock)?;
            notes.say(format!("updated {}", self.lock_path.display()));
        }
        failed.map_or(Ok(()), |e| Err(e.into()))
    }

    /// Plan each object's move and print the plans, as a table or as JSON.
    fn plan(
        &self,
        object: Option<&str>,
        from: &str,
        dest: &Dest,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<tokens::Moves> {
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
        Ok(moves)
    }
}

/// The source of `object` on `from`: the spec of a realisation the lock records there.
fn source_target<'a>(cfg: &'a Config, lock: &Lock, object: &str, from: &'a str) -> cakeys_core::Result<Target<'a>> {
    let spec = lock
        .realisations
        .iter()
        .find(|(_, by_token)| by_token.get(from).is_some_and(|r| r.object == object))
        .and_then(|(spec, _)| cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()))
        .ok_or_else(|| {
            KmError::PreconditionFailed(format!(
                "object '{object}' has no realisation on '{from}' under a spec keys.toml still names"
            ))
        })?;
    Target::new(cfg, spec, from)
}

/// Where `object` goes on `to`: its one spec there, or the one `--spec` names.
fn target_target<'a>(
    cfg: &'a Config,
    object: &str,
    to: &'a str,
    spec: Option<&str>,
) -> cakeys_core::Result<Target<'a>> {
    let specs: Vec<&str> = cfg
        .specs
        .iter()
        .filter(|(name, s)| s.object == object && s.tokens.contains_key(to) && spec.is_none_or(|n| n == *name))
        .map(|(name, _)| name.as_str())
        .collect();
    match specs.as_slice() {
        [one] => Target::new(cfg, one, to),
        [] => Err(KmError::Validation(match spec {
            Some(n) => format!("spec '{n}' does not realise object '{object}' on token '{to}'"),
            None => format!("keys.toml has no spec of object '{object}' on token '{to}' to import it under"),
        })),
        several => Err(KmError::Validation(format!(
            "object '{object}' has several specs on token '{to}' ({}); pass --spec",
            several.join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    /// A binding patched to name `CKM_AES_KEY_WRAP_KWP` (the Nix build's) is built with the `kwp`
    /// feature that uses it: the patch without the feature would plan a method the run cannot
    /// perform.
    #[test]
    fn the_kwp_feature_comes_with_the_patched_binding() {
        assert!(
            !cakeys_pkcs11::binding::patched() || cfg!(feature = "kwp"),
            "the patched cryptoki is linked without camigrate's `kwp` feature (nix/package.nix buildFeatures)"
        );
    }
}
