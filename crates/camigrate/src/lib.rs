//! The `camigrate` command line (README.md, "Three tools"): it moves keys between tokens
//! (docs/CAMIGRATE.md). It is the only tool that handles key material: it plans a move
//! (`--dry-run`), then makes it exactly as planned. A library, so a downstream binary can link
//! extra provider crates: `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

pub mod bundle;
mod file;
mod host;
mod keyfile;
mod plan;
mod public;
mod sealed;
mod tokens;
mod transport;

use anyhow::Context as _;
use bundle::Bundle;
use cakeys_cli_common::{Opener, print, read_lock, save_changed};
use cakeys_core::KmError;
use cakeys_core::config::{
    ALLOW_NIX_STORE_KEYS, Config, KeyOrigin, Lock, Origin, SpecCfg, SpecTokenCfg, in_nix_build, save_lock, write_whole,
};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_pkcs11::Registry;
use cakeys_pkcs11::ops::{Notes, Target};
use cakeys_pkcs11::token::Access;
use clap::{Parser, Subcommand};
use plan::FileFormat;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use transport::Transport;
use zeroize::Zeroizing;

pub use cakeys_cli_common::default_registry;

/// Move keys between PKCS#11 tokens, checked against keys.lock (docs/CAMIGRATE.md).
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
    /// Export objects realised on a token, shaped for a target (docs/CAMIGRATE.md): with --dry-run, per
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
        /// Where to write the bundle (default: stdout), or the key file (required to write one).
        #[arg(long)]
        out: Option<PathBuf>,
        /// The passphrase a key file is encrypted under, read from this file (one line);
        /// required to write one.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Import a bundle (`export`'s) on a token, each key under the spec that realises its object
    /// there: checked against the lock before the token is touched, unwrapped with the transport
    /// key realised there, then recorded with where it came from. Each key on its own: one that
    /// fails (an identity that is not the locked one is 10) leaves nothing, the others still
    /// import, and the run exits with the first failure.
    /// Without --in, import each object a pair on --token says is born in a file
    /// (`origin = "file"`) from its object's `migrate.file` (docs/FILE.md), each on its own as well.
    Import {
        /// Without --in: the objects to import from their files; default: every one a pair on
        /// --token says `origin = "file"` for.
        #[arg(conflicts_with = "input")]
        objects: Vec<String>,
        #[arg(long)]
        token: String,
        /// The spec to realise an object under, when it has several on --token (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        /// The bundle.
        #[arg(long = "in", value_name = "BUNDLE")]
        input: Option<PathBuf>,
        /// Check the bundle, the key file or the objects' files against the lock and the token,
        /// and import nothing.
        #[arg(long)]
        dry_run: bool,
        /// Read --in as a passphrase-protected key file (`export --to-file`'s: encrypted PKCS#8
        /// or PKCS#12) under the passphrase in this file, not as a bundle. Without --in, the
        /// passphrase of every encrypted file, over keys.toml's. Needs --allow-host-plaintext:
        /// the key is in this process's memory on the way in.
        #[arg(long, value_name = "FILE", requires = "allow_host_plaintext")]
        passphrase_file: Option<PathBuf>,
        /// Allow a key file's plaintext in this process's memory (docs/CAMIGRATE.md D2).
        #[arg(long)]
        allow_host_plaintext: bool,
    },
    /// Move objects from one token to another, both reachable from this host (docs/CAMIGRATE.md):
    /// each is created on --to and recorded in the lock with where it came from. Public objects
    /// move as they are; keys sealed to --to's transport key, through the host only wrapped.
    Migrate {
        /// The object to move; default: every object realised on --from.
        object: Option<String>,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        /// The spec to realise an object under on --to, when it has several there (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Write the transport file for a token's transport key (docs/CAMIGRATE.md D3): an RSA private
    /// key that may unwrap, realised and locked on the target. Exports to this token wrap to it.
    /// With --trusted, instead make the source's SO trust it (D2, `enforced`).
    Transport {
        /// The transport key's object; default: the token's `migrate.transportWith`.
        object: Option<String>,
        /// The transport key's spec, where the object has several on --token.
        #[arg(long)]
        spec: Option<String>,
        /// The target token the key is on.
        #[arg(long)]
        token: String,
        /// Where to write it; default: stdout.
        #[arg(long, conflicts_with = "trusted")]
        out: Option<PathBuf>,
        /// The source token whose SO marks a copy of the transport key `CKA_TRUSTED` (with its
        /// `soCredentialFile`/`soCredentialEnv`), from the public key the lock records: a key there with
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
    /// The target's transport key, by its spec (docs/CAMIGRATE.md D3); default: the target token's
    /// `transportWith`.
    #[arg(long)]
    transport_key: Option<String>,
    /// Print the plan as JSON.
    #[arg(long)]
    json: bool,
    /// Allow the `host` and `file` paths: plaintext in this process's memory (docs/CAMIGRATE.md D2).
    #[arg(long)]
    allow_host_plaintext: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum FileArg {
    Pkcs8,
    Pkcs12,
}

/// The command line's definition: its verbs and flags, for the test that every one of them is
/// used by an integration test (`tests/common/surface.rs`).
#[must_use]
pub fn command() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}

/// Run the command line with the given providers; maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parse the arguments, then load keys.toml and the lock — refusing up front a run that writes a
/// lock it cannot (docs/CAMIGRATE.md D8: never inside a Nix build) — and run the verb.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let opener = Opener::load(&cli.config, &cli.modules, registry, notes)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    // A real `migrate` or `import` writes the lock; it holds the advisory sidecar lock across load
    // and save, as cakeys' writing verbs do. A real `export` is an admin operation too (D8).
    let writes = matches!(&cli.cmd, Cmd::Migrate { how, .. } if !how.dry_run)
        || matches!(&cli.cmd, Cmd::Import { dry_run: false, .. });
    let exports = matches!(&cli.cmd, Cmd::Export { how, .. } if !how.dry_run);
    // A key file is decrypted into this process's memory, also to check it (--dry-run); so is
    // an object's own file, without --in.
    let reads_key_file =
        matches!(&cli.cmd, Cmd::Import { passphrase_file: Some(_), .. } | Cmd::Import { input: None, .. });
    let trusts = matches!(&cli.cmd, Cmd::Transport { trusted: Some(_), .. });
    if (exports || reads_key_file || trusts) && in_nix_build() {
        let verb = match (exports, reads_key_file) {
            (true, _) => "export",
            (_, true) => "import of a key file",
            _ => "transport --trusted",
        };
        return Err(KmError::PreconditionFailed(
            format!(
                "{verb} is an admin operation (docs/CAMIGRATE.md D8), refused inside a Nix build \
                 ({ALLOW_NIX_STORE_KEYS}=1 runs it as outside, for throwaway keys only)"
            )
            .into(),
        )
        .into());
    }
    if let Cmd::Migrate { to: target, .. } | Cmd::Import { token: target, .. } = &cli.cmd {
        needs_login(&opener.cfg, target)?;
    }
    let (lock, _update_guard) = read_lock(&lock_path, writes, "moving keys records them there")?;
    let mut run = Run { opener, lock, lock_path };
    match &cli.cmd {
        Cmd::Export { objects, token, target, transport, to_file, out, passphrase_file, how } => {
            let dest = match (target, transport, to_file) {
                (_, _, Some(FileArg::Pkcs8)) => Destination::File(FileFormat::Pkcs8),
                (_, _, Some(FileArg::Pkcs12)) => Destination::File(FileFormat::Pkcs12),
                (_, Some(path), None) => Destination::transport(path)?,
                (Some(t), None, None) => Destination::Bundle(t),
                (None, None, None) => unreachable!("clap requires one of --target, --transport, --to-file"),
            };
            let objects: Vec<&str> = objects.iter().map(String::as_str).collect();
            if how.dry_run {
                // Without names a bundle takes what can move, so its plan fails only when nothing can.
                let partial = objects.is_empty() && !matches!(dest, Destination::File(_));
                return run.plan_moves(&objects, token, &dest, &[], how, partial, notes);
            }
            if let Destination::File(_) = &dest {
                let (Some(out), Some(pass)) = (out, passphrase_file) else {
                    return Err(
                        KmError::Validation("writing a key file needs --out and --passphrase-file".into()).into()
                    );
                };
                return run.export_file(&objects, token, &dest, out, pass, how, notes);
            }
            run.export(&objects, token, &dest, out.as_deref(), how, notes)
        }
        Cmd::Import { objects, token, spec, input: None, dry_run, passphrase_file, allow_host_plaintext } => {
            let how =
                FileImport { pass: passphrase_file.as_deref(), plaintext: *allow_host_plaintext, dry_run: *dry_run };
            run.import_files(token, objects, spec, &how, notes)
        }
        Cmd::Import { token, spec, input: Some(input), dry_run, passphrase_file: Some(pass), .. } => {
            run.import_file(token, spec, input, pass, *dry_run, notes)
        }
        Cmd::Import { token, spec, input: Some(input), dry_run, .. } => run.import(token, spec, input, *dry_run, notes),
        Cmd::Migrate { object, from, to, spec, how } if how.dry_run => {
            specs_import(&run.opener.cfg, spec, to, MOVE)?;
            run.plan_moves(object.as_deref().as_slice(), from, &Destination::Token(to), spec, how, false, notes)
        }
        Cmd::Migrate { object, from, to, spec, how } => run.migrate(object.as_deref(), from, to, spec, how, notes),
        Cmd::Transport { object, spec, token, trusted: Some(source), .. } => {
            let spec = transport_named(&run.opener.cfg, object.as_deref(), spec.as_deref(), token)?;
            run.trust(&spec, token, source, notes)
        }
        Cmd::Transport { object, spec, token, out, trusted: None } => {
            let spec = transport_named(&run.opener.cfg, object.as_deref(), spec.as_deref(), token)?;
            let t = Target::new(&run.opener.cfg, &spec, token)?;
            let tok = run.opener.open(token, Access::Read, notes)?;
            let text = tokens::transport(&t, &tok, &run.lock, notes)?.to_toml()?;
            match out {
                Some(path) => {
                    write_whole(path, text.as_bytes(), 0o644)?;
                    notes.say(format!("wrote {}", path.display()));
                }
                None => print!("{text}"),
            }
            Ok(())
        }
    }
}

/// The spec of the transport key `transport` names on `token`: the address's pair
/// (`[<object>] [--spec]`, as cakeys' verbs take it), else the token's `migrate.transportWith`.
///
/// # Errors
///
/// `Validation` (17) for a name keys.toml lacks, an address no pair on `token` matches, or a
/// token that names no transport key when the address is left out; `Ambiguous` (12) for an
/// object with several specs there.
fn transport_named(cfg: &Config, object: Option<&str>, spec: Option<&str>, token: &str) -> cakeys_core::Result<String> {
    if object.is_some() || spec.is_some() {
        return Ok(cfg.address(object, spec, Some(token))?.0);
    }
    let t = cfg.tokens.get(token).ok_or_else(|| KmError::Validation(format!("unknown token '{token}'").into()))?;
    t.migrate.transport_with.clone().ok_or_else(|| {
        KmError::Validation(
            format!(
                "no transport key is named for '{token}': set transportWith in [tokens.{token}.migrate], or name its \
             object or --spec"
            )
            .into(),
        )
    })
}

/// What a verb works with once the arguments are parsed: keys.toml, the lock, and how tokens
/// are opened.
struct Run<'a> {
    opener: Opener<'a>,
    lock: Lock,
    lock_path: PathBuf,
}

/// Where `export` or `migrate` sends the material.
enum Destination<'a> {
    /// A token, by `migrate`.
    Token(&'a str),
    /// A bundle sealed to a token's transport key, by `export --target`.
    Bundle(&'a str),
    /// A transport file, read once (by [`Destination::transport`]): the plan checks against the
    /// lock the very key the export seals to.
    Transport(&'a Path, Transport),
    File(FileFormat),
}

impl<'a> Destination<'a> {
    /// `--transport <path>`: the file read and parsed, once for the run.
    fn transport(path: &'a Path) -> anyhow::Result<Destination<'a>> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(Destination::Transport(path, Transport::parse(&text, path)?))
    }
}

impl Run<'_> {
    /// Save the lock if the verb changed it: also when a later object failed, so what moved is
    /// never left on a token without its realisation.
    fn save(&self, changed: bool, notes: &mut Notes) -> anyhow::Result<()> {
        save_changed(&self.lock_path, &self.lock, changed, notes)
    }

    /// Record one object's write at once, before the run touches another (the save is atomic):
    /// a run killed or failing later never leaves an object on a token the lock does not record,
    /// and on ykcs11 cakeys cannot remove it. [`Self::save`] says so once, at the end.
    fn record(&self, what: &dyn std::fmt::Display) -> anyhow::Result<()> {
        save_lock(&self.lock_path, &self.lock)
            .with_context(|| format!("{what} is on the token, but the lock could not record it"))
    }

    /// `--dry-run`: plan each object's move from `from` to `dest` and print it (docs/CAMIGRATE.md D9);
    /// 15 when any object cannot move as invoked — or, for a `partial` move (an export without
    /// names, which leaves out what cannot move), when none can: the real run's own verdict.
    #[expect(clippy::too_many_arguments, reason = "the move command's parts, as the CLI hands them over")]
    fn plan_moves(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Destination,
        specs: &[String],
        how: &MoveArgs,
        partial: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let moves = self.plan(objects, from, dest, specs, how, true, notes)?;
        if partial && moves.plans.iter().any(|p| p.ready) {
            return Ok(());
        }
        Ok(moves.ready()?)
    }

    /// `export` for real: plan as `--dry-run` does, then wrap every key to the target's
    /// transport key — the one the lock records for the token, else the open token's, or a
    /// transport file the lock pins — and write them as one bundle. Public objects need no
    /// transport key, and a bundle of them alone is made without one. Named objects are all or
    /// nothing: one that cannot move fails the export before anything is wrapped. Without names,
    /// every key that can move is exported and the others are warned about. The bundle is
    /// written whole or not at all; nothing on either token changes.
    fn export(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Destination,
        out: Option<&Path>,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let moves = self.plan(objects, from, dest, &[], how, false, notes)?;
        // Named objects are all or nothing; without names, whatever can move does, and what
        // cannot (a key made non-extractable, ...) is warned about and left out.
        if !objects.is_empty() {
            moves.ready()?;
        }
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let mut items = Vec::new();
        for p in &moves.plans {
            if !p.ready {
                // Meant never to leave (noExport): left out quietly.
                if no_export(cfg, &p.object, from).is_none() {
                    notes.warn(format_args!("{}: left out of the bundle: {}", p.object, p.reasons.join("; ")));
                }
                continue;
            }
            // Ready means a method a bundle carries (`limit_bundle_plans`).
            let Some(method) = p.method.clone().filter(in_bundle) else {
                unreachable!("{}: the plan blocks what a bundle cannot carry", p.object)
            };
            items.push(sealed::Item {
                src: source_target(cfg, &self.lock, &p.object, from)?,
                method,
                exposure: p.exposure.unwrap_or(Exposure::Sealed),
            });
        }
        if items.is_empty() {
            return Err(KmError::Unsupported(format!("nothing on '{from}' can go into a bundle").into()).into());
        }
        let source = opener.open(from, Access::Scratch, notes)?;
        let wraps = items.iter().any(|i| i.method != Method::Public);
        let transport = match dest {
            _ if !wraps => None,
            Destination::Bundle(to) => {
                let tr = transport_target(cfg, &self.lock, to, transport_choice(cfg, to, how))?;
                Some(if let Some(key) = tokens::locked_transport(&tr, &self.lock, notes)? {
                    key
                } else {
                    let target = opener.open(to, Access::Read, notes)?;
                    notes.note(format_args!(
                        "{tr}: the lock records no public key for it yet; lock it again to export without '{to}'"
                    ));
                    tokens::transport(&tr, &target, &self.lock, notes)?.key()?
                })
            }
            // The plan checked this same parsed file against the lock; sealing checks it again,
            // so nothing wraps to a key the lock does not pin, whatever the plan let through.
            Destination::Transport(path, t) => {
                tokens::pinned(&self.lock, t)
                    .map_err(|why| KmError::PreconditionFailed(format!("{}: {why}", path.display()).into()))?;
                Some(t.key()?)
            }
            Destination::Token(_) | Destination::File(_) => {
                unreachable!("an export makes a bundle or a key file, and a file plan is never sealed")
            }
        };
        let bundle = sealed::export(&items, &source, &self.lock, transport.as_ref(), notes)?;
        let text = bundle.to_toml()?;
        let what = bundle.keys.iter().map(|k| format!("{} by {}", k.object, k.method)).collect::<Vec<_>>().join(", ");
        match out {
            Some(path) => {
                write_whole(path, text.as_bytes(), 0o644)?;
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
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        specs_select(cfg, specs, bundle.keys.iter().map(|e| e.object.as_str()), token, MOVE)?;
        let tr = match &bundle.transport {
            Some(t) => Some(realised_target(cfg, &self.lock, &t.object, token, "the bundle's transport key")?),
            None => None,
        };
        let access = if dry_run { Access::Read } else { Access::Write };
        let target = opener.open(token, access, notes)?;
        let (mut changed, mut failed) = (false, None);
        // Keys first: a public key object then finds the public half its key's import made.
        let public = Method::Public.name();
        let entries =
            bundle.keys.iter().filter(|e| e.method != public).chain(bundle.keys.iter().filter(|e| e.method == public));
        for e in entries {
            let dst = match import_target(cfg, &e.object, token, spec_for(cfg, specs, &e.object), MOVE) {
                Ok(dst) => dst,
                Err(err) => {
                    notes.say(format!("{}: not imported: {err}", e.object));
                    failed.get_or_insert(err);
                    continue;
                }
            };
            let lock = &mut self.lock;
            // As the import itself: a key already realised there is verified, not refused for
            // sitting under its own locator. A key it would create must be one a bundle file can
            // carry under its binding.
            let outcome = public::already_there(&dst, &target, lock, notes).and_then(|there| {
                if there {
                    return Ok(Some(public::Moved::AlreadyThere));
                }
                sealed::check_carried(e, &dst)?;
                if !dry_run {
                    return sealed::import(&bundle, e, &dst, &target, tr.as_ref(), lock, notes).map(Some);
                }
                sealed::preflight(&bundle, e, &dst, &target, tr.as_ref(), lock, notes)?;
                let method = e.method().map_err(|e| KmError::Validation(e.into()))?;
                import_checks(&dst, &target, &method, opener.registry, notes).map(|()| None)
            });
            match outcome {
                Ok(None) => {
                    println!(
                        "{dst}: {} by {} ({}) from {}: ready",
                        e.object, e.method, e.exposure, bundle.source.token
                    );
                }
                Ok(Some(public::Moved::Imported)) => {
                    changed = true;
                    self.record(&dst)?;
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
        self.save(changed, notes)?;
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
        specs: &[String],
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        // Before the plan, as the dry run does: both refuse a named target that is no import pair.
        specs_import(&self.opener.cfg, specs, to, MOVE)?;
        let moves = self.plan(object.as_slice(), from, &Destination::Token(to), specs, how, true, notes)?;
        moves.ready()?;
        specs_select(&self.opener.cfg, specs, moves.plans.iter().map(|p| p.object.as_str()), to, MOVE)?;
        let built = |m: &Method| {
            matches!(
                m,
                Method::Public
                    | Method::RsaOaepAesKwp(_)
                    | Method::RsaOaep(_)
                    | Method::HostPkcs8
                    | Method::HostRaw
                    | Method::Tpm2Ptool
                    | Method::PivImport
            )
        };
        if let Some(p) = moves.plans.iter().find(|p| !p.method.as_ref().is_some_and(built)) {
            let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
            return Err(KmError::Unsupported(format!(
                "{}: moving by {method} is a later docs/CAMIGRATE.md phase; public objects, sealed keys and the host path into PKCS#11 tokens \
                 move (pass --dry-run for the plan)",
                p.object
            ).into())
            .into());
        }
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let source = opener.open(from, Access::Scratch, notes)?;
        let mut target = Some(opener.open(to, Access::Write, notes)?);
        // tpm2-pkcs11 sees what `tpm2_ptool` imported only once opened again: the old one first.
        let reopen = |t: &mut Option<cakeys_pkcs11::Token>, notes: &mut Notes| -> cakeys_core::Result<()> {
            *t = None;
            *t = Some(opener.open(to, Access::Write, notes)?);
            Ok(())
        };
        let (mut changed, mut failed) = (false, None);
        for p in &moves.plans {
            let pair = source_target(cfg, &self.lock, &p.object, from)
                .and_then(|src| Ok((src, import_target(cfg, &p.object, to, spec_for(cfg, specs, &p.object), MOVE)?)));
            let lock = &mut self.lock;
            let target = &mut target;
            let outcome = pair.and_then(|(src, dst)| {
                if p.method == Some(Method::Tpm2Ptool) {
                    return host::import_ptool(&src, &source, &dst, target, &reopen, lock, notes);
                }
                let target = target
                    .as_ref()
                    .ok_or_else(|| KmError::Unavailable(format!("the target token '{to}' is not open").into()))?;
                match &p.method {
                    Some(method @ (Method::RsaOaepAesKwp(_) | Method::RsaOaep(_))) => {
                        let tr = transport_target(cfg, lock, to, transport_choice(cfg, to, how))?;
                        let key = tokens::transport(&tr, target, lock, notes)?.key()?;
                        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
                        let item = sealed::Item { src, method: method.clone(), exposure };
                        let bundle = sealed::export(&[item], &source, lock, Some(&key), notes)?;
                        sealed::import(&bundle, &bundle.keys[0], &dst, target, Some(&tr), lock, notes)
                    }
                    Some(method @ (Method::HostPkcs8 | Method::HostRaw | Method::PivImport)) => {
                        host::import(&src, &source, &dst, target, lock, method, notes)
                    }
                    _ => public::import(&src, &source, &dst, target, lock, notes),
                }
            });
            match outcome {
                Ok(public::Moved::Imported) => {
                    changed = true;
                    self.record(&format_args!("'{}' on token '{to}'", p.object))?;
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
        self.save(changed, notes)?;
        failed.map_or(Ok(()), |e| Err(e.into()))
    }

    /// A key file holds one key, and a PKCS#12 the certificate the lock pairs with it on the
    /// source: said in the plan, since the export would refuse both.
    fn limit_file_plans(&self, plans: &mut [plan::Plan], format: FileFormat, from: &str) {
        let several = plans.len();
        for p in plans.iter_mut().filter(|p| p.ready) {
            if several > 1 {
                p.ready = false;
                p.reasons.push(format!("a key file holds one key, and {several} are planned: name the one to export"));
            } else if format == FileFormat::Pkcs12 && self.paired_certificate_target(&p.object, from).is_none() {
                p.ready = false;
                p.reasons.push(format!(
                    "pkcs12 carries the key with its certificate, and the lock pairs no certificate with '{}' on \
                     '{from}': lock it there, or export --to-file pkcs8",
                    p.object
                ));
            }
        }
    }

    /// Plan each object's move and, with `show`, print the plans, as a table or as JSON (an
    /// export that writes the bundle to stdout shows none: stdout is the bundle). `specs` are the
    /// `--spec` names, which pick an object's landing pair on a target token.
    #[expect(clippy::too_many_arguments, reason = "the move command's parts, as the CLI hands them over")]
    fn plan(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Destination,
        specs: &[String],
        how: &MoveArgs,
        show: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<tokens::Moves> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let open = |name: &str, notes: &mut Notes| opener.open(name, Access::Read, notes);
        let bundle = matches!(dest, Destination::Bundle(_) | Destination::Transport(..));
        let shown = match dest {
            Destination::Transport(path, _) => path.display().to_string(),
            _ => String::new(),
        };
        let dest = match dest {
            Destination::Token(name) | Destination::Bundle(name) => tokens::Dest::Token(name),
            Destination::File(f) => tokens::Dest::File(*f),
            Destination::Transport(_, t) => tokens::Dest::Transport(t, &shown),
        };
        let target_token = match dest {
            tokens::Dest::Token(name) => Some(name),
            _ => None,
        };
        let file_format = match dest {
            tokens::Dest::File(format) => Some(format),
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
        let mut moves = tokens::plan_moves(&self.lock, opener.registry, &req, &open, notes)?;
        for p in &mut moves.plans {
            if let Some(spec) = no_export(cfg, &p.object, from) {
                p.ready = false;
                p.reasons.insert(0, format!("migrate.noExport in spec '{spec}': it never leaves '{from}'"));
            }
            // A move lands only on a pair that says `origin = "import"`: an object realised on
            // the target by no such pair cannot move there, whatever else would carry it.
            if let (false, Some(to)) = (bundle, target_token)
                && let Some(why) = no_import_pair(cfg, &p.object, to)
            {
                p.ready = false;
                p.reasons.insert(0, why);
            }
            match target_token {
                Some(to) => match import_target(cfg, &p.object, to, spec_for(cfg, specs, &p.object), MOVE) {
                    Ok(landing) => landing_checks(p, &landing, &moves.source, moves.target.as_ref(), opener.registry),
                    // A move must pick its landing pair now: several, and no `--spec` naming
                    // one, is refused by the run, so by the plan. (An object with none is
                    // blocked already, by `no_import_pair`.) A bundle lands later, under the
                    // pair its import picks.
                    Err(e) if p.ready && !bundle => {
                        p.ready = false;
                        p.reasons.push(e.to_string());
                    }
                    Err(_) => {}
                },
                // Nothing lands on a token here: the source's export is all the run makes.
                None => {
                    if let (true, Some(method)) = (p.ready, &p.method) {
                        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
                        if let Err(why) = tokens::source_refusal(method, exposure, &moves.source, opener.registry) {
                            p.ready = false;
                            p.reasons.push(why);
                        }
                    }
                }
            }
        }
        // A sealed move wraps under the transport key's spec in keys.toml: one the lock still
        // names and keys.toml no longer has is said here, where the move itself would stop.
        if let Some(to) = target_token
            && let Ok(spec) = tokens::transport_spec(&self.lock, to, transport_key)
            && !cfg.specs.contains_key(spec)
        {
            let sealed = |p: &plan::Plan| matches!(p.method, Some(Method::RsaOaepAesKwp(_) | Method::RsaOaep(_)));
            for p in moves.plans.iter_mut().filter(|p| p.ready && sealed(p)) {
                p.ready = false;
                p.reasons.push(format!("the transport key's spec '{spec}' is gone from keys.toml"));
            }
        }
        match file_format {
            Some(format) => self.limit_file_plans(&mut moves.plans, format, from),
            None if bundle => limit_bundle_plans(&mut moves.plans),
            None => {}
        }
        if show {
            show_plans(from, &moves, how.json)?;
        }
        Ok(moves)
    }
}

/// What an import's dry run asks of the open `target` before it says ready, as the import asks
/// before it creates anything: the capability check of the record that follows
/// (`ops::check_import`), and the target's provider about the templates `method` sends there
/// ([`tokens::target_refusal`]).
///
/// # Errors
///
/// What `ops::check_import` refuses; the provider's refusal (15).
fn import_checks(
    dst: &Target,
    target: &cakeys_pkcs11::Token,
    method: &Method,
    registry: &Registry,
    notes: &mut Notes,
) -> cakeys_core::Result<()> {
    cakeys_pkcs11::ops::check_import(dst, target)?;
    match tokens::target_refusal(dst, method, &tokens::side(target)?, registry) {
        Ok(None) => Ok(()),
        Ok(Some(note)) => {
            notes.note(format_args!("{note}"));
            Ok(())
        }
        Err(why) => Err(KmError::Unsupported(why.into())),
    }
}

/// What a ready plan `p` must still pass where it lands on `to`, said in the plan since the run
/// would refuse it: the target's `lock` must prove possession of a private key the way its spec
/// says; the providers must take the templates the move sends (`Provider::template`, refused
/// before anything is created); an imported key is never attested where the provider attests
/// only what the device made (PIV, docs/CAMIGRATE.md D8), the check the import itself makes.
/// `dst` is the landing pair, the one `--spec` names.
fn landing_checks(
    p: &mut plan::Plan,
    dst: &Target,
    source: &cakeys_core::migrate::Side,
    target: Option<&cakeys_core::migrate::Side>,
    registry: &Registry,
) {
    let block = |p: &mut plan::Plan, why: String| {
        p.ready = false;
        p.reasons.push(why);
    };
    if let (true, Some(target)) = (p.ready, target)
        && let Some(why) = unprovable(dst, target)
    {
        block(p, why);
    }
    if let (true, Some(method), Some(target)) = (p.ready, p.method.clone(), target) {
        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
        match tokens::template_refusal(dst, &method, exposure, source, target, registry) {
            Ok(None) => {}
            Ok(Some(note)) => p.notes.push(note),
            Err(why) => block(p, why),
        }
    }
    if let (true, Some(target)) = (p.ready, target)
        && let Ok(Some(provider)) = registry.named(&target.provider)
        && let Err(why) = cakeys_pkcs11::ops::check_imported_attestation(dst, provider.as_ref())
    {
        block(p, why);
    }
}

/// Whether a bundle carries what `method` moves: sealed keys and public objects.
fn in_bundle(method: &Method) -> bool {
    matches!(method, Method::RsaOaepAesKwp(_) | Method::RsaOaep(_) | Method::Public)
}

/// A bundle carries sealed keys and public objects only: a move the plan sends another way
/// (through the host, a provider's own method) is `migrate`'s, said in the plan, since the
/// export would refuse it.
fn limit_bundle_plans(plans: &mut [plan::Plan]) {
    for p in plans.iter_mut().filter(|p| p.ready) {
        if let Some(method) = p.method.as_ref().filter(|m| !in_bundle(m)) {
            p.ready = false;
            p.reasons.push(format!(
                "a bundle carries sealed keys and public objects, not {}: move it with `camigrate migrate`",
                method.name()
            ));
        }
    }
}

/// Print the plans of one invocation, as a table or as JSON.
fn show_plans(from: &str, moves: &tokens::Moves, json: bool) -> anyhow::Result<()> {
    let (to_name, plans) = (&moves.to, &moves.plans);
    let (source_from, target_from) = (moves.source_from.name(), moves.target_from.name());
    if json {
        return print(&serde_json::json!({
            "from": from,
            "to": to_name,
            "capabilities": { "from": source_from, "to": target_from },
            "plans": plans,
        }));
    }
    println!("{from} -> {to_name} (capabilities: {from} from the {source_from}, {to_name} from the {target_from})");
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
    Ok(())
}

/// Why `object` cannot move to `to`: specs realise it there, and none says `origin = "import"`.
fn no_import_pair(cfg: &Config, object: &str, to: &str) -> Option<String> {
    let origins: Vec<KeyOrigin> = cfg
        .specs
        .values()
        .filter(|s| s.object == object)
        .filter_map(|s| s.tokens.get(to).map(SpecTokenCfg::key_origin))
        .collect();
    (!origins.is_empty() && !origins.contains(&KeyOrigin::Import)).then(|| {
        format!(
            "no spec realises '{object}' on '{to}' with origin = \"import\": a move lands only where keys.toml \
             says origin = \"import\""
        )
    })
}

/// The source of `object` on `from`: the spec of a realisation the lock records there.
fn source_target<'a>(cfg: &'a Config, lock: &Lock, object: &str, from: &'a str) -> cakeys_core::Result<Target<'a>> {
    realised_target(cfg, lock, object, from, "object")
}

/// The spec `--spec` names for `object`, if one does.
fn spec_for<'a>(cfg: &Config, specs: &'a [String], object: &str) -> Option<&'a str> {
    specs.iter().map(String::as_str).find(|s| cfg.specs.get(*s).is_some_and(|c| c.object == object))
}

/// Every `--spec` must select something: a spec keys.toml names, of one of the `objects` being
/// moved, on `token`. A name that selects nothing is refused (17), never ignored.
fn specs_select<'a>(
    cfg: &Config,
    specs: &[String],
    objects: impl Iterator<Item = &'a str>,
    token: &str,
    landing: &[KeyOrigin],
) -> cakeys_core::Result<()> {
    let objects: Vec<&str> = objects.collect();
    for name in specs {
        let Some(spec) = cfg.specs.get(name) else {
            return Err(KmError::Validation(format!("--spec '{name}': keys.toml has no such spec").into()));
        };
        if !spec.tokens.contains_key(token) || !objects.contains(&spec.object.as_str()) {
            return Err(KmError::Validation(
                format!(
                    "--spec '{name}' selects nothing: it realises '{}', which is not being moved to '{token}' under it",
                    spec.object
                )
                .into(),
            ));
        }
    }
    specs_import(cfg, specs, token, landing)
}

/// The pairs a move from another token lands on.
const MOVE: &[KeyOrigin] = &[KeyOrigin::Import];
/// The pairs an object from its own file lands on (docs/FILE.md F6).
const FROM_FILE: &[KeyOrigin] = &[KeyOrigin::File];
/// The pairs a key file given by `--in` lands on: a move's, or a pair born in a file.
const KEY_FILE: &[KeyOrigin] = &[KeyOrigin::Import, KeyOrigin::File];

/// `origin = "import"`, or each of `landing` so, joined by "or".
fn landing_names(landing: &[KeyOrigin]) -> String {
    landing.iter().map(|o| format!("origin = \"{o}\"")).collect::<Vec<_>>().join(" or ")
}

/// Every `--spec` that realises its object on `token` says one of `landing` there: a move lands
/// on no other pair (17). Checked by the dry run too, which plans without the names.
fn specs_import(cfg: &Config, specs: &[String], token: &str, landing: &[KeyOrigin]) -> cakeys_core::Result<()> {
    for name in specs {
        if let Some(on) = cfg.specs.get(name).and_then(|s| s.tokens.get(token))
            && !landing.contains(&on.key_origin())
        {
            return Err(KmError::Validation(
                format!(
                    "--spec '{name}' realises its object on '{token}' with origin = \"{}\": a move lands only where \
                 keys.toml says {}",
                    on.key_origin(),
                    landing_names(landing)
                )
                .into(),
            ));
        }
    }
    Ok(())
}

/// Where `object` goes on `to`: its one spec there whose origin is one of `landing`, or the one
/// `--spec` names. A pair that says the key is created or adopted there is never a target.
fn import_target<'a>(
    cfg: &'a Config,
    object: &str,
    to: &'a str,
    spec: Option<&str>,
    landing: &[KeyOrigin],
) -> cakeys_core::Result<Target<'a>> {
    let on_to = |s: &'a SpecCfg| s.tokens.get(to).filter(|_| s.object == object);
    let named = |name: &str| spec.is_none_or(|n| n == name);
    let specs: Vec<&str> = cfg
        .specs
        .iter()
        .filter(|(name, s)| named(name) && on_to(s).is_some_and(|t| landing.contains(&t.key_origin())))
        .map(|(name, _)| name.as_str())
        .collect();
    let elsewhere =
        cfg.specs.iter().find_map(|(name, s)| on_to(s).filter(|_| named(name)).map(|t| (name, t.key_origin())));
    match specs.as_slice() {
        [one] => Target::new(cfg, one, to),
        [] => Err(KmError::Validation(match (spec, elsewhere) {
            (_, Some((name, origin))) => format!(
                "spec '{name}' realises object '{object}' on token '{to}' with origin = \"{origin}\": a move lands \
                 only where keys.toml says {}",
                landing_names(landing)
            )
            .into(),
            (Some(n), None) => format!("spec '{n}' does not realise object '{object}' on token '{to}'").into(),
            (None, None) => {
                format!("keys.toml has no spec of object '{object}' on token '{to}' to import it under").into()
            }
        })),
        several => Err(KmError::Validation(
            format!("object '{object}' has several specs on token '{to}' ({}); pass --spec", several.join(", ")).into(),
        )),
    }
}

/// Why the target could not prove possession of a private key moved to `dst` the way its spec
/// says (`cakeys_pkcs11` would refuse after the key was created): `None` when it can, or the
/// object is no private key. The proof's own check (`cakeys_pkcs11::token::proof_refusal`), on
/// what the plan knows of the target.
fn unprovable(dst: &Target, target: &cakeys_core::migrate::Side) -> Option<String> {
    let binding = cakeys_core::plan::expected_binding(dst)?;
    let side = cakeys_pkcs11::token::ProofSide {
        token: &target.token,
        profile: None,
        has: Box::new(|m| target.mechanisms.contains(&m.to_string())),
        unwraps: target.unwraps,
    };
    match cakeys_pkcs11::token::proof_refusal(dst.object, binding, &side) {
        Ok(None) => None,
        Ok(Some(why)) => Some(format!("{dst} could not prove possession of the key once there: {why}")),
        Err(e) => Some(format!("{dst} could not prove possession of the key once there: {e}")),
    }
}

/// The spec that keeps `object` on `from` (`noExport`), if one does.
fn no_export<'a>(cfg: &'a Config, object: &str, from: &str) -> Option<&'a str> {
    cfg.specs
        .iter()
        .find(|(_, s)| s.migrate.no_export && s.object == object && s.tokens.contains_key(from))
        .map(|(name, _)| name.as_str())
}

impl Run<'_> {
    /// `export --to-file`: one private key, through the host (`Token::extract`), into a
    /// passphrase-protected file (docs/CAMIGRATE.md D2 `file`): encrypted PKCS#8, or PKCS#12 with the
    /// certificate the lock pairs with it on the source. Written whole or not at all, mode 0600.
    #[expect(clippy::too_many_arguments, reason = "the export command's parts, as the CLI hands them over")]
    fn export_file(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Destination,
        out: &Path,
        pass: &Path,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let moves = self.plan(objects, from, dest, &[], how, false, notes)?;
        moves.ready()?;
        let [p] = moves.plans.as_slice() else {
            return Err(KmError::Validation(
                format!("a key file holds one key, and {} are planned: name the one to export", moves.plans.len())
                    .into(),
            )
            .into());
        };
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let pass = read_passphrase(pass)?;
        let src = source_target(cfg, &self.lock, &p.object, from)?;
        let source = opener.open(from, Access::Scratch, notes)?;
        cakeys_pkcs11::ops::verify(&src, &source, &self.lock, notes)?;
        let h = source
            .find_key(src.object, &src.on_token.locator, false)?
            .ok_or_else(|| KmError::NotFound(src.to_string().into()))?;
        let kwp = sealed::rfc5649(&source)
            .ok_or_else(|| source.unsupported(format!("'{from}' offers no RFC 5649 key wrap to hand the key over")))?;
        let pkcs8 = source.extract(h, &kwp)?;
        let bytes = match p.method {
            Some(Method::Pkcs12) => {
                let cert = self.paired_certificate(&p.object, from, &source, notes)?;
                let id = self
                    .lock
                    .objects
                    .get(&p.object)
                    .and_then(|o| o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()))
                    .cloned()
                    .unwrap_or_default();
                file::write_pkcs12(&pkcs8, &cert, &pass, id.as_bytes())?
            }
            _ => file::write_pkcs8(&pkcs8, &pass)?.into_bytes(),
        };
        drop(pkcs8);
        write_whole(out, &bytes, 0o600)?;
        let method = p.method.as_ref().map_or_else(String::new, Method::name);
        notes.say(format!("wrote {} ({} by {method}, file)", out.display(), p.object));
        Ok(())
    }

    /// The certificate the lock pairs with `object` (`pairs`), as realised on `from`.
    fn paired_certificate_target(&self, object: &str, from: &'_ str) -> Option<String> {
        let pairs = self.lock.objects.get(object).map(|o| o.pairs.clone()).unwrap_or_default();
        pairs.into_iter().find(|pair| {
            let is_cert = self.lock.objects.get(pair).and_then(|o| o.object_type.as_ref()).map(|t| t.class)
                == Some(cakeys_core::types::ObjectClass::Certificate);
            is_cert && source_target(&self.opener.cfg, &self.lock, pair, from).is_ok()
        })
    }

    /// That certificate's DER, read and verified on the open source `tok`.
    fn paired_certificate(
        &self,
        object: &str,
        from: &str,
        tok: &cakeys_pkcs11::Token,
        notes: &mut Notes,
    ) -> anyhow::Result<Vec<u8>> {
        let pair = self.paired_certificate_target(object, from).ok_or_else(|| {
            KmError::PreconditionFailed(format!("the lock pairs no certificate with '{object}' on '{from}'").into())
        })?;
        let t = source_target(&self.opener.cfg, &self.lock, &pair, from)?;
        Ok(public::material(&t, tok, &self.lock, notes)?)
    }

    /// `import --in <key file> --passphrase-file`: decrypt the file, find the locked object by
    /// its key's identity (`rfc7093m4` of its public key), and create it under the spec that
    /// realises that object on `token` (`--spec` when several), with the certificate a PKCS#12
    /// carries when the lock pairs one with the object there too. Recorded with where it came
    /// from: a `file`.
    fn import_file(
        &mut self,
        token: &str,
        specs: &[String],
        input: &Path,
        pass: &Path,
        dry_run: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let pass = read_passphrase(pass)?;
        let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
        let read = file::read(&bytes, &pass)?;
        drop(pass);
        let spki = cakeys_core::id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(&read.pkcs8)?)?;
        let id = cakeys_core::id::sri(&spki);
        let object = self
            .lock
            .objects
            .iter()
            .find(|(_, o)| {
                o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()) == Some(&id)
                    && o.object_type.as_ref().is_some_and(|t| t.class == cakeys_core::types::ObjectClass::PrivateKey)
            })
            .map(|(name, _)| name.clone())
            .ok_or_else(|| {
                KmError::PreconditionFailed(
                    format!("{}: the lock pins no private key with this key's identity ({id})", input.display()).into(),
                )
            })?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let pairs = self.lock.objects.get(&object).map(|o| o.pairs.clone()).unwrap_or_default();
        let objects = std::iter::once(object.as_str()).chain(pairs.iter().map(String::as_str));
        specs_select(cfg, specs, objects, token, KEY_FILE)?;
        let spec_for = |o: &str| spec_for(cfg, specs, o);
        let dst = import_target(cfg, &object, token, spec_for(&object), KEY_FILE)?;
        // The certificate a PKCS#12 carries for its key goes where the lock pairs one with the key
        // on this token.
        let cert_target = pairs.iter().find_map(|o| import_target(cfg, o, token, spec_for(o), KEY_FILE).ok());
        let certificate = keyfile::key_certificate(&read.certificates, &spki);
        if dry_run {
            // Everything the import checks before it creates anything, and nothing more.
            let target = opener.open(token, Access::Read, notes)?;
            if public::already_there(&dst, &target, &self.lock, notes)? {
                notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
            } else {
                host::free_locator(&dst, &target, Some(&spki))?;
                import_checks(&dst, &target, &read.method, opener.registry, notes)?;
                println!("{dst}: {object} by {} (file) from {}: ready", read.method, input.display());
            }
            match (&certificate, &cert_target) {
                (Some(cert), Some(t)) if !public::already_there(t, &target, &self.lock, notes)? => {
                    public::preflight(t, &target, cert)?;
                    import_checks(t, &target, &Method::Public, opener.registry, notes)?;
                    println!("{t}: its certificate: ready");
                }
                (Some(_), None) => notes.note(format_args!(
                    "the file's certificate would not be imported: the lock pairs no certificate with '{object}' on \
                     '{token}'"
                )),
                _ => {}
            }
            return Ok(());
        }
        let target = opener.open(token, Access::Write, notes)?;
        let origin = cakeys_core::config::Origin {
            from: "file".into(),
            method: read.method.name(),
            exposure: Exposure::File,
            declared: false,
        };
        let moved = host::create_and_record(&dst, &target, &mut self.lock, &read.pkcs8, Some(&spki), origin, notes)?;
        let mut changed = matches!(moved, public::Moved::Imported);
        match moved {
            public::Moved::Imported => {
                self.record(&dst)?;
                notes.say(format!("imported {object} from {} into {dst}", input.display()));
            }
            public::Moved::AlreadyThere => {
                notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
            }
        }
        // The certificate a PKCS#12 carries, where the lock pairs one with the key on this token.
        // Its failure ends the run only after the lock is saved: the key is on the token by now.
        let mut failed = None;
        if let Some(cert) = &certificate {
            match cert_target {
                Some(t) => match public::create(&t, &target, cert, "file", &mut self.lock, notes) {
                    Ok(public::Moved::Imported) => {
                        changed = true;
                        notes.say(format!("imported its certificate into {t}"));
                    }
                    Ok(public::Moved::AlreadyThere) => {}
                    Err(e) => {
                        notes.say(format!("{t}: its certificate is not imported: {e}"));
                        failed = Some(e);
                    }
                },
                None => notes.note(format_args!(
                    "the file's certificate is not imported: the lock pairs no certificate with '{object}' on '{token}'"
                )),
            }
        }
        self.save(changed, notes)?;
        failed.map_or(Ok(()), |e| Err(e.into()))
    }

    /// `import` without `--in` (docs/FILE.md F6): each object a pair on `token` says is born in a
    /// file (`origin = "file"`), or each of `objects`, from its object's `migrate.file`. Keys
    /// first, so a public key object finds the public half its key's import made. Each on its
    /// own, as a bundle's entries: one that fails leaves nothing, the others still import, the
    /// lock records them, and the run exits with the first failure.
    fn import_files(
        &mut self,
        token: &str,
        objects: &[String],
        specs: &[String],
        how: &FileImport,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let cfg = &self.opener.cfg;
        let from_file = |o: &str| {
            cfg.specs
                .values()
                .any(|s| s.object == o && s.tokens.get(token).is_some_and(|t| t.key_origin() == KeyOrigin::File))
        };
        for o in objects {
            if !cfg.objects.contains_key(o) {
                return Err(KmError::Validation(format!("unknown object '{o}'").into()).into());
            }
            if !from_file(o) {
                return Err(KmError::Validation(format!(
                    "no spec realises '{o}' on '{token}' with origin = \"file\": nothing brings it from its file there"
                ).into())
                .into());
            }
        }
        let mut wanted: Vec<&str> = cfg
            .objects
            .keys()
            .map(String::as_str)
            .filter(|o| from_file(o) && (objects.is_empty() || objects.iter().any(|n| n == o)))
            .collect();
        if wanted.is_empty() {
            return Err(KmError::Validation(format!("no pair on '{token}' says origin = \"file\"").into()).into());
        }
        // Keys first: a public key object then finds the public half its key's import made.
        wanted.sort_by_key(|o| !cfg.objects[*o].class.is_key() || cfg.objects[*o].class == Class::PublicKey);
        specs_select(cfg, specs, wanted.iter().copied(), token, FROM_FILE)?;
        let access = if how.dry_run { Access::Read } else { Access::Write };
        let target = self.opener.open(token, access, notes)?;
        let (mut changed, mut failed) = (false, None);
        for object in wanted {
            let dst = match import_target(cfg, object, token, spec_for(cfg, specs, object), FROM_FILE) {
                Ok(dst) => dst,
                Err(err) => {
                    notes.say(format!("{object}: not imported: {err}"));
                    failed.get_or_insert(err);
                    continue;
                }
            };
            match from_its_file((cfg, self.opener.registry), &dst, &target, &mut self.lock, how, notes) {
                Ok(None) => {}
                Ok(Some(public::Moved::Imported)) => {
                    changed = true;
                    self.record(&dst)?;
                    notes.say(format!("imported {object} from its file into {dst}"));
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
        self.save(changed, notes)?;
        failed.map_or(Ok(()), |e| Err(e.into()))
    }

    /// `transport --trusted`: the source's SO makes a `CKA_TRUSTED` copy of the transport key
    /// realised as `spec` on `token`, from the public key the lock records (so the lock vouches
    /// for it, never a file). Nothing to do when the source already trusts it; any other trusted
    /// object there is warned about, since `enforced` is only as narrow as the trusted set.
    fn trust(&self, spec: &str, token: &str, source: &str, notes: &mut Notes) -> anyhow::Result<()> {
        let spec =
            tokens::transport_spec(&self.lock, token, Some(spec)).map_err(|e| KmError::PreconditionFailed(e.into()))?;
        let spki = self.locked_spki(spec, token).ok_or_else(|| {
            KmError::PreconditionFailed(
                format!(
                    "the lock records no public key for transport key '{spec}' on '{token}': lock it there with \
                 migrate.transportWith naming it"
                )
                .into(),
            )
        })?;
        let tok = self.opener.open(source, Access::Write, notes)?;
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

/// The passphrase in `path` (its first line), zeroized when dropped. Never empty.
fn read_passphrase(path: &Path) -> cakeys_core::Result<Zeroizing<String>> {
    let text =
        Zeroizing::new(std::fs::read_to_string(path).map_err(KmError::io(format_args!("reading {}", path.display())))?);
    let line = Zeroizing::new(text.lines().next().unwrap_or_default().to_owned());
    if line.is_empty() {
        return Err(KmError::Validation(format!("{}: the passphrase is empty", path.display()).into()));
    }
    Ok(line)
}

/// How `import` without `--in` reads the objects' files.
struct FileImport<'a> {
    /// `--passphrase-file`: every encrypted file's passphrase, over keys.toml's.
    pass: Option<&'a Path>,
    /// `--allow-host-plaintext`.
    plaintext: bool,
    /// `--dry-run`.
    dry_run: bool,
}

/// The passphrase of `object`'s file: `--passphrase-file`, else its `migrate.passphraseEnv`,
/// else its `migrate.passphraseFile`; `None` when none is given.
fn file_passphrase(cfg: &Config, object: &str, over: Option<&Path>) -> cakeys_core::Result<Option<Zeroizing<String>>> {
    if let Some(path) = over {
        return read_passphrase(path).map(Some);
    }
    if let Some(var) = cfg.object_migrate.get(object).and_then(|m| m.passphrase_env.as_deref()) {
        let value = std::env::var(var).map_err(|_| {
            KmError::Validation(
                format!("object '{object}': migrate.passphraseEnv names {var}, which is not set").into(),
            )
        })?;
        return Ok(Some(Zeroizing::new(value)));
    }
    cfg.object_passphrase_file(object, &|name| std::env::var(name).ok())?.map(|p| read_passphrase(&p)).transpose()
}

/// One object from its file, as `import` without `--in` takes it (docs/FILE.md F3, F6): read
/// and typed on the host, checked against the IDs the lock pins (10 before anything is
/// written), then created on `to` and recorded with `from = "file"`. When the lock pins
/// nothing yet, the file is the object's first use: the IDs the host computes from it are put
/// in the lock first, so the token must show exactly them, and the lock is left as it was if it
/// does not. `None` when the dry run found it ready.
fn from_its_file(
    (cfg, registry): (&Config, &Registry),
    dst: &Target,
    to: &cakeys_pkcs11::Token,
    lock: &mut Lock,
    how: &FileImport,
    notes: &mut Notes,
) -> cakeys_core::Result<Option<public::Moved>> {
    if public::already_there(dst, to, lock, notes)? {
        return Ok(Some(public::Moved::AlreadyThere));
    }
    let class = dst.object.class;
    let private_data = class == Class::Data && dst.spec.flag("CKA_PRIVATE") == Some(true);
    if (matches!(class, Class::PrivateKey | Class::SecretKey) || private_data) && !how.plaintext {
        return Err(KmError::Unsupported(
            format!(
                "{dst}: its file's {class} passes through this process's memory as plaintext; pass \
             --allow-host-plaintext (docs/CAMIGRATE.md D2, file)"
            )
            .into(),
        ));
    }
    let env = |name: &str| std::env::var(name).ok();
    let path = cfg
        .object_file(dst.object_name, &env)?
        .ok_or_else(|| KmError::Validation(format!("object '{}' names no migrate.file", dst.object_name).into()))?;
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(KmError::io(format_args!("reading {}", path.display())))?);
    // A certificate or public key beside a private key is found by decoding that key.
    if keyfile::holds_private_key(&bytes) && !how.plaintext {
        return Err(KmError::Unsupported(
            format!(
                "{dst}: {} holds a private key, which reading its {class} decodes in this process's memory; pass \
             --allow-host-plaintext (docs/CAMIGRATE.md D2, file)",
                path.display()
            )
            .into(),
        ));
    }
    let pass = file_passphrase(cfg, dst.object_name, how.pass)?;
    let encoding = cfg.object_migrate.get(dst.object_name).and_then(|m| m.encoding);
    let m =
        keyfile::read(&bytes, dst.object, private_data, pass.as_ref().map(|p| p.as_str()), encoding).map_err(|e| {
            match e {
                KmError::Validation(why) => KmError::Validation(format!("{}: {why}", path.display()).into()),
                other => other,
            }
        })?;
    drop(bytes);
    let ids = keyfile::host_ids(dst.object, &m);
    let locked = lock.objects.get(dst.object_name).map(|o| &o.ids);
    for (scheme, got) in &ids {
        if let Some(want) = locked.and_then(|l| l.get(scheme.name()))
            && want != got
        {
            return Err(KmError::HashMismatch {
                what: format!("{dst}: the material in {}", path.display()),
                expected: want.clone(),
                got: got.clone(),
            });
        }
    }
    let first_use = locked.is_none_or(BTreeMap::is_empty);
    if how.dry_run {
        match class {
            Class::PrivateKey | Class::SecretKey => {
                host::free_locator(dst, to, m.spki.as_deref())?;
            }
            _ => {
                public::preflight(dst, to, &m.bytes)?;
            }
        }
        import_checks(dst, to, &m.method, registry, notes)?;
        let first = if first_use { "; its first use, the lock pins it from the file" } else { "" };
        println!("{dst}: {} by {} ({}) from {}: ready{first}", dst.object_name, m.method, m.exposure, path.display());
        return Ok(None);
    }
    let before = lock.clone();
    if first_use && !ids.is_empty() {
        let entry = lock.objects.entry(dst.object_name.to_owned()).or_default();
        entry.object_type = Some(dst.object.clone());
        entry.ids.extend(ids.iter().map(|(s, v)| (s.name().to_owned(), v.clone())));
    }
    let origin = Origin { from: "file".into(), method: m.method.name(), exposure: m.exposure, declared: false };
    let moved = match class {
        Class::PrivateKey | Class::SecretKey => {
            host::create_and_record(dst, to, lock, &m.bytes, m.spki.as_deref(), origin, notes)
        }
        _ => public::create_as(dst, to, &m.bytes, origin, lock, notes),
    };
    if moved.is_err() {
        *lock = before;
    }
    moved.map(Some)
}

/// The transport key to seal to on `to`: `--transport-key`, else the token's `transportWith`.
fn transport_choice<'a>(cfg: &'a Config, to: &str, how: &'a MoveArgs) -> Option<&'a str> {
    how.transport_key.as_deref().or_else(|| cfg.tokens.get(to).and_then(|t| t.migrate.transport_with.as_deref()))
}

/// The target `token`'s transport key, as a target: the spec `tokens::transport_spec` finds.
fn transport_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    token: &'a str,
    chosen: Option<&str>,
) -> cakeys_core::Result<Target<'a>> {
    let spec = tokens::transport_spec(lock, token, chosen).map_err(|e| KmError::PreconditionFailed(e.into()))?;
    let spec = cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()).ok_or_else(|| {
        KmError::PreconditionFailed(format!("the transport key's spec '{spec}' is gone from keys.toml").into())
    })?;
    Target::new(cfg, spec, token)
}

/// The realisation of `object` on `token` the lock records, as a target; `what` names the
/// object in the refusal (a bundle's transport key names its object).
fn realised_target<'a>(
    cfg: &'a Config,
    lock: &Lock,
    object: &str,
    token: &'a str,
    what: &str,
) -> cakeys_core::Result<Target<'a>> {
    let spec = lock
        .realisations
        .iter()
        .find(|(_, by_token)| by_token.get(token).is_some_and(|r| r.object == object))
        .and_then(|(spec, _)| cfg.specs.get_key_value(spec).map(|(name, _)| name.as_str()))
        .ok_or_else(|| {
            KmError::PreconditionFailed(
                format!("{what} '{object}' has no realisation on '{token}' under a spec keys.toml still names").into(),
            )
        })?;
    Target::new(cfg, spec, token)
}

/// A move into `token` must see everything under the target locator, which only a logged-in
/// session does (docs/CAMIGRATE.md D6): a token keys.toml gives no user PIN is refused before
/// any plan, by the dry run alike.
fn needs_login(cfg: &Config, token: &str) -> cakeys_core::Result<()> {
    match cfg.tokens.get(token) {
        Some(t) if t.pin_file.is_none() && t.pin_env.is_none() => Err(KmError::Unavailable(
            format!(
                "token '{token}' has no user PIN, and a session without login cannot tell a target locator is free; \
             configure pinFile or pinEnv"
            )
            .into(),
        )),
        _ => Ok(()),
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
