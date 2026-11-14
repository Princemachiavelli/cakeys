//! The `cakeys` command line (docs/SCOPE.md, "Three tools"): it pins and verifies. As a
//! library so a downstream binary can link extra provider crates:
//! `cakeys::main(&cakeys::default_registry().with(MyProvider))`.

use anyhow::Context;
use cakeys_cli_common::{module_overrides, open_quiet, open_token, print};
use cakeys_core::KmError;
use cakeys_core::config::{Config, Lock, gc, load_config, load_lock, lock_for_update, lock_unwritable, save_lock};
use cakeys_core::migrate::{Exposure, Method, Transport};
use cakeys_pkcs11::migrate::{self, FileFormat};
use cakeys_pkcs11::ops::{self, LockWrite, Notes, Target};
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{Registry, Token};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub use cakeys_cli_common::default_registry;

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
    Resolve {
        spec: String,
        #[arg(long)]
        token: String,
    },
    /// Resolve, then compare with the lock (If-Match). Prints the PKCS#11 URI.
    Verify {
        spec: String,
        #[arg(long)]
        token: String,
    },
    /// Create under the declared locator if absent and autoCreate is set, then compare with the
    /// lock, recording what it lacks (missing hashes and realisation details; never overwriting
    /// a hash) unless --no-update-lock.
    Realise {
        spec: String,
        #[arg(long)]
        token: String,
        #[command(flatten)]
        write: LockWriteArgs,
    },
    /// Create keys explicitly, autoCreate or not (it only opts the first-use flows in): every
    /// (spec, token) pair selected whose object the lock does not pin yet, then record them like
    /// realise; pinned, adopted-only and publicOnly pairs are skipped with a note. Naming both
    /// SPEC and --token creates that pair or says why not. Prints the realised objects as JSON.
    Create {
        /// Only this spec; default: every spec.
        spec: Option<String>,
        /// Only this token; default: every token.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        write: LockWriteArgs,
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
        write: LockWriteArgs,
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
        /// The target's transport file (`cakeys transport`), for a target this host cannot reach.
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

/// Whether `realise`/`delete` write the lock: by default they do, like `nix build` with
/// `flake.lock`. Where the lock cannot be written (a Nix build sandbox, a read-only lock or
/// directory) the run is refused up front unless `--no-update-lock` says so explicitly.
#[derive(clap::Args)]
struct LockWriteArgs {
    /// Compare with the lock only; never write it (first use is then exit 10 with `got:`).
    #[arg(long, conflicts_with = "update_lock")]
    no_update_lock: bool,
    /// Write the lock (the default; kept so existing scripts can say it).
    #[arg(long)]
    update_lock: bool,
}

impl LockWriteArgs {
    fn mode(&self) -> LockWrite {
        if self.no_update_lock { LockWrite::Compare } else { LockWrite::Record }
    }
}

/// Run the command line with the given providers; maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parse the arguments, then load keys.toml and the lock — refusing up front a run that may write
/// a lock it cannot — and run the verb.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = &cli.config;
    let modules = module_overrides(&cli.modules)?;
    let cfg = load_config(config)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| config.with_extension("lock"));
    // A run that may write the lock holds its advisory sidecar lock across load and save (M3),
    // so concurrent updaters queue instead of losing each other's writes. Held to the end of run.
    let writes = match &cli.cmd {
        Cmd::Realise { write, .. } | Cmd::Create { write, .. } | Cmd::Delete { write, .. } => {
            write.mode() == LockWrite::Record
        }
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
    let lock = load_lock(&lock_path)?;
    Run { cfg, modules, registry, lock, lock_path }.verb(&cli.cmd, notes)
}

/// What a verb works with once the arguments are parsed: keys.toml, the lock and where it is
/// saved, and how tokens are opened.
struct Run<'a> {
    cfg: Config,
    modules: BTreeMap<String, String>,
    registry: &'a Registry,
    lock: Lock,
    lock_path: PathBuf,
}

impl Run<'_> {
    fn verb(&mut self, cmd: &Cmd, notes: &mut Notes) -> anyhow::Result<()> {
        match cmd {
            Cmd::Validate => self.validate(notes),
            Cmd::Resolve { spec, token } => {
                let t = Target::new(&self.cfg, spec, token)?;
                let tok = self.open(token, Access::Read, notes)?;
                let r = ops::resolve(&t, &tok, &self.lock)?
                    .ok_or_else(|| KmError::NotFound(format!("{spec} on {token}")))?;
                print(&r)
            }
            Cmd::Verify { spec, token } => {
                let t = Target::new(&self.cfg, spec, token)?;
                let tok = self.open(token, Access::Read, notes)?;
                println!("{}", ops::verify(&t, &tok, &self.lock, notes)?.uri);
                Ok(())
            }
            Cmd::Realise { spec, token, write } => {
                let t = Target::new(&self.cfg, spec, token)?;
                let tok = self.open(token, Access::Write, notes)?;
                let (r, changed) = ops::realise(&t, &tok, &mut self.lock, write.mode(), notes)?;
                self.save(changed, notes)?;
                print(&r)
            }
            Cmd::Create { spec, token, write } => self.create(spec.as_deref(), token.as_deref(), write.mode(), notes),
            Cmd::Delete { spec, token, if_match, write } => {
                let t = Target::new(&self.cfg, spec, token)?;
                let tok = self.open(token, Access::Write, notes)?;
                let changed = ops::delete(&t, &tok, &mut self.lock, if_match.as_deref(), write.mode(), notes)?;
                self.save(changed, notes)
            }
            Cmd::Gc { apply } => {
                let stale = gc(&self.cfg, &mut self.lock, *apply);
                for entry in &stale {
                    println!("{entry}");
                }
                if stale.is_empty() {
                    eprintln!("nothing to collect: every lock entry is named by the config");
                } else if *apply {
                    save_lock(&self.lock_path, &self.lock)?;
                    eprintln!("updated {} ({} entries removed)", self.lock_path.display(), stale.len());
                } else {
                    eprintln!("{} stale entries; pass --apply to remove them", stale.len());
                }
                Ok(())
            }
            Cmd::Check { reference, token, spec } => {
                let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
                let open = |name: &str, access| open_quiet(cfg, modules, registry, name, access);
                let r = ops::check(cfg, reference, spec.as_deref(), token.as_deref(), open, &mut self.lock, notes)?;
                println!("{}", r.uri);
                Ok(())
            }
            Cmd::Export { object, token, target, transport, to_file, how } => {
                let dest = match (target, transport, to_file) {
                    (_, _, Some(FileArg::Pkcs8)) => Dest::File(FileFormat::Pkcs8),
                    (_, _, Some(FileArg::Pkcs12)) => Dest::File(FileFormat::Pkcs12),
                    (_, Some(path), None) => Dest::Transport(path),
                    (Some(t), None, None) => Dest::Token(t),
                    (None, None, None) => unreachable!("clap requires one of --target, --transport, --to-file"),
                };
                self.plan_moves(object.as_deref(), token, &dest, how, notes)
            }
            Cmd::Migrate { object, from, to, how } => {
                self.plan_moves(object.as_deref(), from, &Dest::Token(to), how, notes)
            }
            Cmd::Transport { spec, token, out } => {
                let t = Target::new(&self.cfg, spec, token)?;
                let tok = self.open(token, Access::Read, notes)?;
                let text = migrate::transport(&t, &tok, &self.lock, notes)?.to_toml();
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

    fn open(&self, name: &str, access: Access, notes: &mut Notes) -> Result<Token, KmError> {
        open_token(&self.cfg, &self.modules, self.registry, name, access, notes)
    }

    /// Save the lock if the verb changed it.
    fn save(&self, changed: bool, notes: &mut Notes) -> anyhow::Result<()> {
        if changed {
            save_lock(&self.lock_path, &self.lock)?;
            notes.say(format!("updated {}", self.lock_path.display()));
        }
        Ok(())
    }

    /// `validate`: each token's options (with a named provider), then the static gate
    /// (docs/PROVIDERS.md phase 4) — each target's needs against its token's capability
    /// profiles, resolved from keys.toml and the lock. No token is opened.
    fn validate(&self, notes: &mut Notes) -> anyhow::Result<()> {
        for (name, t) in &self.cfg.tokens {
            let Some(p) = t.provider.as_deref() else { continue };
            // A named provider checks the token's options here too; an auto-detected one
            // can only be known, and check them, once the token is opened.
            let provider = self.registry.named(p).ok_or_else(|| {
                KmError::Validation(format!(
                    "token '{name}': unknown provider '{p}' (registered: generic, {})",
                    self.registry.names().join(", ")
                ))
            })?;
            provider.check_options(name, &t.options)?;
        }
        let mut stacks = BTreeMap::new();
        for (name, t) in &self.cfg.tokens {
            match cakeys_pkcs11::gate::stack(name, t, &self.lock)? {
                Ok(stack) => {
                    stacks.insert(name.as_str(), stack);
                }
                Err(why) => notes.note(format_args!("validate: {why}")),
            }
        }
        let mut refusals = Vec::new();
        for (spec_name, spec) in &self.cfg.specs {
            for token in spec.tokens.keys() {
                let t = Target::new(&self.cfg, spec_name, token)?;
                let mode = ops::plan_mode(&t)?;
                let note = if mode.needs_opt_in() { " (opted in)" } else { "" };
                println!("{spec_name} on {token}: mode {mode}{note}");
                if let Some(stack) = stacks.get(token.as_str()) {
                    let v = cakeys_pkcs11::gate::check(&t, mode, stack, self.registry)?;
                    for n in &v.notes {
                        notes.note(format_args!("validate: {n}"));
                    }
                    refusals.extend(v.refusals);
                }
            }
        }
        for (name, stack) in &stacks {
            for n in &stack.resolved.notes {
                notes.note(format_args!("validate: token '{name}' ({}): {n}", stack.source));
            }
        }
        if refusals.is_empty() {
            return Ok(());
        }
        for r in &refusals {
            eprintln!("{r}");
        }
        let one = refusals.len() == 1;
        Err(KmError::Unsupported(format!(
            "{} target{} need{} what the capability profiles say the token cannot do",
            refusals.len(),
            if one { "" } else { "s" },
            if one { "s" } else { "" }
        ))
        .into())
    }

    /// `create`: every selected pair ([`create_pairs`]), then the lock records what was created,
    /// also when a later pair failed — never a key made and lost.
    fn create(
        &mut self,
        spec: Option<&str>,
        token: Option<&str>,
        write: LockWrite,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
        let open = |name: &str, notes: &mut Notes| open_token(cfg, modules, registry, name, Access::Write, notes);
        let done = ops::create_selected(cfg, spec, token, &open, &mut self.lock, write, notes)?;
        self.save(done.changed, notes)?;
        print(&done.created)?;
        done.failed.map_or(Ok(()), |e| Err(e.into()))
    }

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
            (Dest::Token(name), _) => migrate::Dest::Token(name),
            (Dest::File(f), _) => migrate::Dest::File(*f),
            (Dest::Transport(_), Some((t, shown))) => migrate::Dest::Transport(t, shown),
            (Dest::Transport(_), None) => unreachable!("parsed above"),
        };
        let req = migrate::Request { object, from, dest, host_plaintext: how.allow_host_plaintext };
        let moves = migrate::plan_moves(&self.lock, registry, &req, &open, notes)?;
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

/// Where `export` or `migrate` sends the material.
enum Dest<'a> {
    Token(&'a str),
    Transport(&'a Path),
    File(FileFormat),
}
