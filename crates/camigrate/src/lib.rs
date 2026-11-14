//! The `camigrate` command line (docs/SCOPE.md, "Three tools"): it moves keys between tokens
//! (MIGRATE.md). It is the only tool that handles key material; so far it plans (`--dry-run`)
//! and writes transport files, and moves nothing. A library, so a downstream binary can link
//! extra provider crates: `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

pub mod bundle;
mod host;
mod plan;
mod public;
mod sealed;
mod tokens;
mod transport;

use anyhow::Context as _;
use bundle::Bundle;
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
    /// Export objects realised on a token, shaped for a target (MIGRATE.md): with --dry-run, per
    /// object the method, how exposed the material is on the way, and why not when it cannot
    /// move; else the keys, sealed to the target's transport key, and the public objects as one
    /// bundle for `import`.
    /// Named objects are all or nothing: one that cannot move fails the export and no bundle is
    /// written.
    Export {
        /// The objects to export; default: every object realised on --token that can move (the
        /// others warned about, except a spec's `noExport`).
        objects: Vec<String>,
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
        /// Where to write the bundle; default: stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Import a bundle (`export`'s) on a token, each key under the spec that realises its object
    /// there: checked against the lock before the token is touched, unwrapped with the transport
    /// key realised there, then recorded with where it came from. Each key on its own: one that
    /// fails (an identity that is not the locked one is 10) leaves nothing, the others still
    /// import, and the run exits with the first failure.
    Import {
        #[arg(long)]
        token: String,
        /// The spec to realise an object under, when it has several on --token (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        /// The bundle.
        #[arg(long = "in", value_name = "BUNDLE")]
        input: PathBuf,
        /// Check the bundle against the lock and the token, and import nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move objects from one token to another, both reachable from this host (MIGRATE.md):
    /// each is created on --to and recorded in the lock with where it came from. Public objects
    /// move as they are; keys sealed to --to's transport key, through the host only wrapped.
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
    /// unwrap, realised and locked on the target. Exports to this token wrap to it. With
    /// --trusted, instead make the source's SO trust it (D2, `enforced`).
    Transport {
        spec: String,
        #[arg(long)]
        token: String,
        /// Where to write it; default: stdout.
        #[arg(long, conflicts_with = "trusted")]
        out: Option<PathBuf>,
        /// The source token whose SO marks a copy of the transport key `CKA_TRUSTED` (with its
        /// `mgmKeyFile`/`mgmKeyEnv`), from the public key the lock records: a key there with
        /// `CKA_WRAP_WITH_TRUSTED` then wraps under it and nothing else.
        #[arg(long, value_name = "SOURCE")]
        trusted: Option<String>,
    },
}

/// How `export` and `migrate` may move material.
#[derive(clap::Args)]
struct MoveArgs {
    /// Print the plan and move nothing.
    #[arg(long)]
    dry_run: bool,
    /// The target's transport key, by its spec (MIGRATE.md D3); default: the target token's
    /// `transportWith`.
    #[arg(long)]
    transport_key: Option<String>,
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
    // A real `migrate` or `import` writes the lock; it holds the advisory sidecar lock across load
    // and save, as cakeys' writing verbs do. A real `export` is an admin operation too (D8).
    let writes = matches!(&cli.cmd, Cmd::Migrate { how, .. } if !how.dry_run)
        || matches!(&cli.cmd, Cmd::Import { dry_run: false, .. });
    let exports = matches!(&cli.cmd, Cmd::Export { how, .. } if !how.dry_run);
    let trusts = matches!(&cli.cmd, Cmd::Transport { trusted: Some(_), .. });
    if (exports || trusts) && in_nix_build() {
        let verb = if exports { "export" } else { "transport --trusted" };
        return Err(KmError::PreconditionFailed(format!(
            "{verb} is an admin operation (MIGRATE.md D8), refused inside a Nix build"
        ))
        .into());
    }
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
        Cmd::Export { objects, token, target, transport, to_file, out, how } => {
            let dest = match (target, transport, to_file) {
                (_, _, Some(FileArg::Pkcs8)) => Dest::File(FileFormat::Pkcs8),
                (_, _, Some(FileArg::Pkcs12)) => Dest::File(FileFormat::Pkcs12),
                (_, Some(path), None) => Dest::Transport(path),
                (Some(t), None, None) => Dest::Token(t),
                (None, None, None) => unreachable!("clap requires one of --target, --transport, --to-file"),
            };
            let objects: Vec<&str> = objects.iter().map(String::as_str).collect();
            if how.dry_run {
                return run.plan_moves(&objects, token, &dest, how, notes);
            }
            run.export(&objects, token, &dest, out.as_deref(), how, notes)
        }
        Cmd::Import { token, spec, input, dry_run } => run.import(token, spec, input, *dry_run, notes),
        Cmd::Migrate { object, from, to, how, .. } if how.dry_run => {
            run.plan_moves(object.as_deref().as_slice(), from, &Dest::Token(to), how, notes)
        }
        Cmd::Migrate { object, from, to, spec, how } => {
            run.migrate(object.as_deref(), from, to, spec.as_deref(), how, notes)
        }
        Cmd::Transport { spec, token, trusted: Some(source), .. } => run.trust(spec, token, source, notes),
        Cmd::Transport { spec, token, out, trusted: None } => {
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
    /// `--dry-run`: plan each object's move from `from` to `dest` and print it (MIGRATE.md D9);
    /// 15 when any object cannot move as invoked.
    fn plan_moves(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Dest,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        Ok(self.plan(objects, from, dest, how, true, notes)?.ready()?)
    }

    /// `export` for real: plan as `--dry-run` does, then wrap every key to the target's
    /// transport key — the one the lock records for the token, else the open token's, or a
    /// transport file the lock pins — and write them as one bundle. Named objects are all or
    /// nothing: one that cannot move fails the export before anything is wrapped. Without names,
    /// every key that can move is exported and the others are warned about. The bundle is
    /// written whole or not at all; nothing on either token changes.
    fn export(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Dest,
        out: Option<&Path>,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let moves = self.plan(objects, from, dest, how, false, notes)?;
        // Named objects are all or nothing; without names, whatever can move does, and what
        // cannot (a key made non-extractable, ...) is warned about and left out.
        if !objects.is_empty() {
            moves.ready()?;
        }
        let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
        let mut items = Vec::new();
        for p in &moves.plans {
            if !p.ready {
                // Meant never to leave (noExport): left out quietly.
                if no_export(cfg, &p.object, from).is_none() {
                    notes.warn(format_args!("{}: left out of the bundle: {}", p.object, p.reasons.join("; ")));
                }
                continue;
            }
            match &p.method {
                Some(method @ (Method::RsaOaepAesKwp(_) | Method::RsaOaep(_) | Method::Public)) => {
                    items.push(sealed::Item {
                        src: source_target(cfg, &self.lock, &p.object, from)?,
                        method: method.clone(),
                        exposure: p.exposure.unwrap_or(Exposure::Sealed),
                    });
                }
                method => {
                    let method = method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
                    return Err(KmError::Unsupported(format!(
                        "{}: a bundle carries sealed keys and public objects, not {method}",
                        p.object
                    ))
                    .into());
                }
            }
        }
        if items.is_empty() {
            return Err(KmError::Unsupported(format!("nothing on '{from}' can go into a bundle")).into());
        }
        let source = open_token(cfg, modules, registry, from, Access::Read, notes)?;
        let transport = match dest {
            Dest::Token(to) => {
                let tr = transport_target(cfg, &self.lock, to, transport_choice(cfg, to, how))?;
                if let Some(key) = tokens::locked_transport(&tr, &self.lock, notes)? {
                    key
                } else {
                    let target = open_token(cfg, modules, registry, to, Access::Read, notes)?;
                    notes.note(format_args!(
                        "{tr}: the lock records no public key for it yet; realise it again to export without '{to}'"
                    ));
                    tokens::transport(&tr, &target, &self.lock, notes)?.key()?
                }
            }
            Dest::Transport(path) => {
                let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
                Transport::parse(&text, path)?.key()?
            }
            Dest::File(_) => unreachable!("a file plan is never sealed"),
        };
        let bundle = sealed::export(&items, &source, &self.lock, &transport, notes)?;
        let text = bundle.to_toml();
        let what = bundle.keys.iter().map(|k| format!("{} by {}", k.object, k.method)).collect::<Vec<_>>().join(", ");
        match out {
            Some(path) => {
                // Whole or not at all: a temporary file beside it, renamed into place.
                let name = path.file_name().map_or_else(|| "bundle".into(), |n| n.to_string_lossy().into_owned());
                let tmp = path.with_file_name(format!(".{name}.tmp"));
                std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
                std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
                notes.say(format!("wrote {} ({what})", path.display()));
            }
            None => print!("{text}"),
        }
        Ok(())
    }

    /// `import`: read the bundle, then each key on its own: check it against the lock and the
    /// token, and (without --dry-run) import it under the spec that realises its object on
    /// `token` and record it. A key that fails leaves nothing and is reported; the others still
    /// import, the lock records them, and the run exits with the first failure.
    fn import(
        &mut self,
        token: &str,
        specs: &[String],
        input: &Path,
        dry_run: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let text = std::fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
        let bundle = Bundle::parse(&text, input)?;
        let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
        let tr = realised_target(cfg, &self.lock, &bundle.transport.object, token)?;
        let access = if dry_run { Access::Read } else { Access::Write };
        let target = open_token(cfg, modules, registry, token, access, notes)?;
        let (mut changed, mut failed) = (false, None);
        // Keys first: a public key object then finds the public half its key's import made.
        let public = Method::Public.name();
        let entries =
            bundle.keys.iter().filter(|e| e.method != public).chain(bundle.keys.iter().filter(|e| e.method == public));
        for e in entries {
            let spec =
                specs.iter().map(String::as_str).find(|s| cfg.specs.get(*s).is_some_and(|c| c.object == e.object));
            let dst = match target_target(cfg, &e.object, token, spec) {
                Ok(dst) => dst,
                Err(err) => {
                    notes.say(format!("{}: not imported: {err}", e.object));
                    failed.get_or_insert(err);
                    continue;
                }
            };
            let lock = &mut self.lock;
            let outcome = if dry_run {
                sealed::preflight(&bundle, e, &dst, &target, &tr, lock, notes).map(|_| None)
            } else {
                sealed::import(&bundle, e, &dst, &target, &tr, lock, notes).map(Some)
            };
            match outcome {
                Ok(None) => {
                    println!(
                        "{dst}: {} by {} ({}) from {}: ready",
                        e.object, e.method, e.exposure, bundle.source.token
                    );
                }
                Ok(Some(public::Moved::Imported)) => {
                    changed = true;
                    notes.say(format!("imported {} from {} into {dst}", e.object, bundle.source.token));
                }
                Ok(Some(public::Moved::AlreadyThere)) => {
                    notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                }
                Err(err) => {
                    notes.say(format!("{dst}: not imported: {err}"));
                    failed.get_or_insert(err);
                }
            }
        }
        if changed {
            save_lock(&self.lock_path, &self.lock)?;
            notes.say(format!("updated {}", self.lock_path.display()));
        }
        failed.map_or(Ok(()), |e| Err(e.into()))
    }

    /// `migrate` for real: plan and print as `--dry-run` does, refuse (15) before anything moves
    /// when an object cannot move or needs a method not built yet, then move each object and
    /// record it: a public object as it is (phase 2), a key sealed to the target's transport key,
    /// the bundle in memory (phase 3). What moved before a failure is still recorded, never a
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
        let moves = self.plan(object.as_slice(), from, &Dest::Token(to), how, true, notes)?;
        moves.ready()?;
        let built = |m: &Method| {
            matches!(
                m,
                Method::Public
                    | Method::RsaOaepAesKwp(_)
                    | Method::RsaOaep(_)
                    | Method::HostPkcs8
                    | Method::HostRaw
                    | Method::Tpm2Ptool
            )
        };
        if let Some(p) = moves.plans.iter().find(|p| !p.method.as_ref().is_some_and(built)) {
            let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
            return Err(KmError::Unsupported(format!(
                "{}: moving by {method} is a later MIGRATE.md phase; public objects, sealed keys and the host path into PKCS#11 tokens \
                 move (pass --dry-run for the plan)",
                p.object
            ))
            .into());
        }
        let (cfg, modules, registry) = (&self.cfg, &self.modules, self.registry);
        let source = open_token(cfg, modules, registry, from, Access::Read, notes)?;
        let mut target = Some(open_token(cfg, modules, registry, to, Access::Write, notes)?);
        // tpm2-pkcs11 sees what `tpm2_ptool` imported only once opened again: the old one first.
        let reopen = |t: &mut Option<cakeys_pkcs11::Token>, notes: &mut Notes| -> cakeys_core::Result<()> {
            *t = None;
            *t = Some(open_token(cfg, modules, registry, to, Access::Write, notes)?);
            Ok(())
        };
        let (mut changed, mut failed) = (false, None);
        for p in &moves.plans {
            let pair = source_target(cfg, &self.lock, &p.object, from)
                .and_then(|src| Ok((src, target_target(cfg, &p.object, to, spec)?)));
            let lock = &mut self.lock;
            let target = &mut target;
            let outcome = pair.and_then(|(src, dst)| {
                if p.method == Some(Method::Tpm2Ptool) {
                    return host::import_ptool(&src, &source, &dst, target, &reopen, lock, notes);
                }
                let target = target
                    .as_ref()
                    .ok_or_else(|| KmError::Unavailable(format!("the target token '{to}' is not open")))?;
                match &p.method {
                    Some(method @ (Method::RsaOaepAesKwp(_) | Method::RsaOaep(_))) => {
                        let tr = transport_target(cfg, lock, to, transport_choice(cfg, to, how))?;
                        let key = tokens::transport(&tr, target, lock, notes)?.key()?;
                        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
                        let item = sealed::Item { src, method: method.clone(), exposure };
                        let bundle = sealed::export(&[item], &source, lock, &key, notes)?;
                        sealed::import(&bundle, &bundle.keys[0], &dst, target, &tr, lock, notes)
                    }
                    Some(method @ (Method::HostPkcs8 | Method::HostRaw)) => {
                        host::import(&src, &source, &dst, target, lock, method, notes)
                    }
                    _ => public::import(&src, &source, &dst, target, lock, notes),
                }
            });
            match outcome {
                Ok(public::Moved::Imported) => {
                    changed = true;
                    let how = p.method.as_ref().map_or_else(String::new, Method::name);
                    notes.say(format!("moved {} from {from} to {to} ({how})", p.object));
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

    /// Plan each object's move and, with `show`, print the plans, as a table or as JSON (an
    /// export that writes the bundle to stdout shows none: stdout is the bundle).
    fn plan(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Dest,
        how: &MoveArgs,
        show: bool,
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
        let target_token = match dest {
            tokens::Dest::Token(name) => Some(name),
            _ => None,
        };
        let transport_key = match dest {
            tokens::Dest::Token(name) => transport_choice(cfg, name, how),
            _ => how.transport_key.as_deref(),
        };
        let spki = match &dest {
            tokens::Dest::Token(name) => tokens::transport_spec(&self.lock, name, transport_key)
                .ok()
                .and_then(|spec| self.locked_spki(spec, name)),
            tokens::Dest::Transport(t, _) => t.spki().ok(),
            tokens::Dest::File(_) => None,
        };
        // Whether the source's SO made a trusted copy of that key (`transport --trusted`).
        let trusted_transport = spki.is_some_and(|spki| {
            open(from, notes).and_then(|tok| tok.trusted(&spki)).is_ok_and(|(copy, _)| copy.is_some())
        });
        let req = tokens::Request {
            objects,
            from,
            dest,
            host_plaintext: how.allow_host_plaintext,
            transport_key,
            trusted_transport,
        };
        let mut moves = tokens::plan_moves(&self.lock, registry, &req, &open, notes)?;
        for p in &mut moves.plans {
            if let Some(spec) = no_export(cfg, &p.object, from) {
                p.ready = false;
                p.reasons.insert(0, format!("noExport in spec '{spec}': it never leaves '{from}'"));
            }
            // The target's realise must prove possession of a private key the way its spec says.
            if let (true, Some(to)) = (p.ready, target_token)
                && let Ok(dst) = target_target(cfg, &p.object, to, None)
                && let Some(why) = unprovable(&dst, &moves.target_mechanisms)
            {
                p.ready = false;
                p.reasons.push(why);
            }
        }
        let (to_name, source_from, target_from, plans) =
            (&moves.to, moves.source_from, moves.target_from, &moves.plans);
        if !show {
            return Ok(moves);
        }
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

/// The target `token`'s transport key, as a target: the spec `tokens::transport_spec` finds.
/// Why the target could not prove possession of a private key moved to `dst` the way its spec's
/// binding says (`cakeys_pkcs11` would refuse after the key was created): `None` when it can,
/// or the object is no private key. The mechanisms each proof uses, any of a group.
fn unprovable(dst: &Target, mechanisms: &std::collections::BTreeSet<String>) -> Option<String> {
    use cakeys_core::config::Binding;
    use cakeys_core::types::KeyType as Kt;
    let groups: &[&[&str]] = match (cakeys_core::plan::binding(dst)?, dst.object.key_type?) {
        (Binding::PopSign | Binding::PopSignPin, Kt::Ec) => {
            &[&["CKM_ECDSA", "CKM_ECDSA_SHA256", "CKM_ECDSA_SHA384", "CKM_ECDSA_SHA512"]]
        }
        (Binding::PopSign | Binding::PopSignPin, Kt::EcEdwards) => &[&["CKM_EDDSA"]],
        (Binding::PopSign | Binding::PopSignPin, Kt::Rsa) => &[&["CKM_SHA256_RSA_PKCS"]],
        (Binding::PopEcdh, _) => &[&["CKM_ECDH1_DERIVE"]],
        (Binding::PopDecrypt, _) => &[&["CKM_RSA_PKCS_OAEP"]],
        (Binding::PopUnwrap, _) => &[&["CKM_RSA_PKCS_OAEP"], &["CKM_SHA256_HMAC"]],
        _ => return None,
    };
    let lacks = groups.iter().find(|g| !g.iter().any(|m| mechanisms.contains(*m)))?;
    Some(format!(
        "{dst} could not prove possession of the key once there: it lacks {} (or name another binding)",
        lacks.join(" or ")
    ))
}

/// The spec that keeps `object` on `from` (`noExport`), if one does.
fn no_export<'a>(cfg: &'a Config, object: &str, from: &str) -> Option<&'a str> {
    cfg.specs
        .iter()
        .find(|(_, s)| s.no_export && s.object == object && s.tokens.contains_key(from))
        .map(|(name, _)| name.as_str())
}

impl Run<'_> {
    /// `transport --trusted`: the source's SO makes a `CKA_TRUSTED` copy of the transport key
    /// realised as `spec` on `token`, from the public key the lock records (so the lock vouches
    /// for it, never a file). Nothing to do when the source already trusts it; any other trusted
    /// object there is warned about, since `enforced` is only as narrow as the trusted set.
    fn trust(&self, spec: &str, token: &str, source: &str, notes: &mut Notes) -> anyhow::Result<()> {
        let spec = tokens::transport_spec(&self.lock, token, Some(spec)).map_err(KmError::PreconditionFailed)?;
        let spki = self.locked_spki(spec, token).ok_or_else(|| {
            KmError::PreconditionFailed(format!(
                "the lock records no public key for transport key '{spec}' on '{token}': realise it there with \
                 transportWith naming it"
            ))
        })?;
        let tok = open_token(&self.cfg, &self.modules, self.registry, source, Access::Write, notes)?;
        let (copy, others) = tok.trusted(&spki)?;
        if copy.is_some() {
            notes.note(format_args!("'{source}' already trusts transport key '{spec}' of '{token}'"));
        } else {
            let (n, e) = sealed::rsa_parts(&spki)?;
            tok.create_trusted_copy(n, e, &format!("cakeys-transport-{token}-{spec}"))?;
            notes.say(format!("'{source}' trusts transport key '{spec}' of '{token}' (CKA_TRUSTED, by its SO)"));
        }
        if others > 0 {
            notes.warn(format_args!(
                "{others} other object(s) on '{source}' are CKA_TRUSTED: a CKA_WRAP_WITH_TRUSTED key there wraps \
                 under any of them, so `enforced` is only as narrow as that set"
            ));
        }
        Ok(())
    }

    /// The public key the lock records for the transport key realised as `spec` on `token`.
    fn locked_spki(&self, spec: &str, token: &str) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let object = &self.lock.realisation(spec, token)?.object;
        let key = self.lock.objects.get(object)?.public_key.as_ref()?;
        base64::engine::general_purpose::STANDARD.decode(key).ok()
    }
}

/// The transport key to seal to on `to`: `--transport-key`, else the token's `transportWith`.
fn transport_choice<'a>(cfg: &'a Config, to: &str, how: &'a MoveArgs) -> Option<&'a str> {
    how.transport_key.as_deref().or_else(|| cfg.tokens.get(to).and_then(|t| t.transport_with.as_deref()))
}

fn transport_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    token: &'a str,
    chosen: Option<&str>,
) -> cakeys_core::Result<Target<'a>> {
    let spec = tokens::transport_spec(lock, token, chosen).map_err(KmError::PreconditionFailed)?;
    let spec = cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()).ok_or_else(|| {
        KmError::PreconditionFailed(format!("the transport key's spec '{spec}' is gone from keys.toml"))
    })?;
    Target::new(cfg, spec, token)
}

/// The realisation of `object` on `token` the lock records, as a target (a bundle's transport key
/// names its object).
fn realised_target<'a>(cfg: &'a Config, lock: &Lock, object: &str, token: &'a str) -> cakeys_core::Result<Target<'a>> {
    let spec = lock
        .realisations
        .iter()
        .find(|(_, by_token)| by_token.get(token).is_some_and(|r| r.object == object))
        .and_then(|(spec, _)| cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()))
        .ok_or_else(|| {
            KmError::PreconditionFailed(format!(
                "the bundle's transport key '{object}' is not realised on '{token}' under a spec keys.toml names"
            ))
        })?;
    Target::new(cfg, spec, token)
}

/// Inside a Nix build sandbox (`NIX_BUILD_TOP` set, `IN_NIX_SHELL` not), where an export, an
/// admin operation (MIGRATE.md D8), is refused like a lock write.
fn in_nix_build() -> bool {
    std::env::var_os("NIX_BUILD_TOP").is_some() && std::env::var_os("IN_NIX_SHELL").is_none()
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
