//! The `camigrate` command line (README.md, "Three tools"): it moves keys between tokens
//! (docs/CAMIGRATE.md). It is the only tool that handles key material: it plans a move
//! (`--dry-run`), then makes it exactly as planned. A library, so a downstream binary can link
//! extra provider crates: `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

pub mod bundle;
mod file;
mod file_verbs;
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
use cakeys_pkcs11::ops::{Notes, Target};
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{Registry, Token};
use clap::{Parser, Subcommand};
use file_verbs::FileImport;
use plan::FileFormat;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use transport::Transport;
use zeroize::Zeroizing;

pub use cakeys_cli_common::default_registry;

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/bundle.rs`, `key_file.rs`): what
/// camigrate reads from the files it is handed, on arbitrary input (review D9).
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    use cakeys_core::config::ObjectCfg;
    use cakeys_core::types::{KeyType, ObjectClass as Class};

    /// A bundle's text: read or refused as invalid (17), never a panic; and a bundle that reads
    /// is read back from its own writing as it was: what `export` writes, `import` reads.
    ///
    /// # Panics
    ///
    /// When either does not hold.
    pub fn bundle_round_trips(text: &str) {
        let path = std::path::Path::new("bundle.toml");
        let bundle = match crate::bundle::Bundle::parse(text, path) {
            Ok(b) => b,
            Err(e) => return assert_eq!(e.exit_code(), 17, "{e}"),
        };
        let written = bundle.to_toml().expect("a bundle that reads serializes");
        let again = crate::bundle::Bundle::parse(&written, path).unwrap_or_else(|e| panic!("{e}\n{written}"));
        assert_eq!(again, bundle, "the bundle read back differs:\n{written}");
    }

    /// A key file's bytes as each kind of object reads them, with the fixtures' passphrase: read
    /// or refused as invalid (17) or unsupported (15), never a panic; and a private key read from
    /// a file is one the shape scan (`holds_private_key`) says the file holds, the scan that
    /// keeps a certificate's import from decoding a key without `--allow-host-plaintext`.
    ///
    /// # Panics
    ///
    /// When either does not hold.
    pub fn key_file(bytes: &[u8]) {
        let p256 = |class| ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(class, Some(KeyType::Ec)) };
        let aes = ObjectCfg { value_len: Some(32), ..ObjectCfg::new(Class::SecretKey, Some(KeyType::Aes)) };
        let objects = [
            p256(Class::PrivateKey),
            p256(Class::PublicKey),
            ObjectCfg::new(Class::Certificate, None),
            aes,
            ObjectCfg::new(Class::Data, None),
        ];
        for object in &objects {
            match crate::keyfile::read(bytes, object, false, Some("pass phrase"), None) {
                Ok(_) if object.class == Class::PrivateKey => {
                    assert!(
                        crate::keyfile::holds_private_key(bytes),
                        "a key read from a file the scan says holds none"
                    );
                }
                Ok(_) => {}
                Err(e) => assert!(matches!(e.exit_code(), 15 | 17), "{object}: {e}"),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        /// The fixtures, every key file and the sample bundle: random bytes rarely read.
        #[test]
        fn the_fixtures_hold_the_properties() {
            let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            super::bundle_round_trips(&std::fs::read_to_string(fixtures.join("sample.bundle.toml")).unwrap());
            for file in std::fs::read_dir(fixtures.join("keyfiles")).unwrap() {
                super::key_file(&std::fs::read(file.unwrap().path()).unwrap());
            }
        }
    }
}

/// Move keys between PKCS#11 tokens, checked against keys.lock (docs/CAMIGRATE.md).
///
/// Exit codes: 0 ok, 10 the material differs from the lock, 11 not found, 12 ambiguous, 13
/// the target refused (a tampered bundle, an occupied locator), 14 precondition failed, 15
/// unsupported (an object cannot move as invoked), 16 unavailable, 17 invalid input, 21 the
/// lock cannot be written, 1 other.
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
        /// others warned about, except a spec's `noExport` and a token's transport key).
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
    /// `transportWith`. A transport file must name that key of its token.
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

/// A verb's run over its objects (review D8: `import`, `migrate` and `import` from files each
/// kept their own): each object on its own, so one that fails leaves nothing and the others
/// still move. Whether any changed the lock, and the first failure, which the run exits with
/// once the lock is saved.
#[derive(Default)]
struct Tally {
    changed: bool,
    failed: Option<KmError>,
}

impl Tally {
    /// An object written: the lock changed.
    fn moved(&mut self) {
        self.changed = true;
    }

    /// `what` failed with `err`: said now, and kept when it is the run's first failure.
    fn fail(&mut self, what: impl std::fmt::Display, err: KmError, notes: &mut Notes) {
        notes.say(format!("{what}: {err}"));
        self.failed.get_or_insert(err);
    }

    /// Save the lock if anything moved, then exit with the first failure.
    fn finish(self, run: &Run<'_>, notes: &mut Notes) -> anyhow::Result<()> {
        run.save(self.changed, notes)?;
        self.failed.map_or(Ok(()), |e| Err(e.into()))
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
        let source = self.opener.open(from, Access::Read, notes);
        let (moves, _) = self.plan(objects, from, dest, specs, how, true, source, notes)?;
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
        // The source is opened once, for the plan and the wrap; so is a bundle's token, for the
        // plan and its transport key (review lib.rs F5).
        let source = self.opener.open(from, Access::Scratch, notes);
        let (moves, source, planned_target) =
            self.plan_opening(objects, from, dest, &[], how, false, source, Access::Read, notes)?;
        // Named objects are all or nothing; without names, whatever can move does, and what
        // cannot (a key made non-extractable, ...) is warned about and left out.
        if !objects.is_empty() {
            moves.ready()?;
        }
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let mut items = Vec::new();
        for p in &moves.plans {
            if !p.ready {
                // What is meant never to leave is not planned at all (`plan`).
                notes.warn(format_args!("{}: left out of the bundle: {}", p.object, p.reasons.join("; ")));
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
        let source = self.source(from, source, notes)?;
        let wraps = items.iter().any(|i| i.method != Method::Public);
        let transport = match dest {
            _ if !wraps => None,
            Destination::Bundle(to) => {
                let tr = transport_target(cfg, &self.lock, to, transport_choice(cfg, to, how))?;
                Some(if let Some(key) = tokens::locked_transport(&tr, &self.lock, notes)? {
                    key
                } else {
                    let target = match planned_target {
                        Some(t) => t,
                        None => opener.open(to, Access::Read, notes)?,
                    };
                    notes.note(format_args!(
                        "{tr}: the lock records no public key for it yet; lock it again to export without '{to}'"
                    ));
                    tokens::transport(&tr, &target, &self.lock, notes)?.key()?
                })
            }
            // The plan checked this same parsed file against the lock; sealing checks it again,
            // so nothing wraps to a key the lock does not pin, whatever the plan let through.
            Destination::Transport(path, t) => {
                tokens::pinned(&self.lock, t, transport_choice(cfg, &t.token, how))
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
        bundle.check_source(cfg)?;
        specs_select(cfg, specs, bundle.keys.iter().map(|e| e.object.as_str()), token, MOVE)?;
        let tr = match &bundle.transport {
            Some(t) => Some(realised_target(cfg, &self.lock, &t.object, token, "the bundle's transport key")?),
            None => None,
        };
        let access = if dry_run { Access::Read } else { Access::Write };
        let target = opener.open(token, access, notes)?;
        let mut tally = Tally::default();
        // Keys first: a public key object then finds the public half its key's import made.
        let public = Method::Public.name();
        let entries =
            bundle.keys.iter().filter(|e| e.method != public).chain(bundle.keys.iter().filter(|e| e.method == public));
        for e in entries {
            let dst = match import_target(cfg, &e.object, token, spec_for(cfg, specs, &e.object), MOVE) {
                Ok(dst) => dst,
                Err(err) => {
                    tally.fail(format_args!("{}: not imported", e.object), err, notes);
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
                    tally.moved();
                    self.record(&dst)?;
                    notes.say(format!(
                        "imported {} from {} ({}) into {dst}",
                        e.object, bundle.source.token, bundle.source.provider
                    ));
                }
                Ok(Some(public::Moved::AlreadyThere)) => {
                    notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                }
                Err(err) => tally.fail(format_args!("{dst}: not imported"), err, notes),
            }
        }
        tally.finish(self, notes)
    }

    /// `migrate` for real: plan and print as `--dry-run` does, refuse (15) before anything moves
    /// when an object cannot move or needs a method not built yet, then move each object and
    /// record it: a public object as it is (phase 2), a key sealed to the target's transport key,
    /// the bundle in memory (phase 3). Each object on its own: one that fails is undone and
    /// said, the others still move and are recorded, and the run exits with the first failure
    /// (it stopped there until review D8). Never a copy left on the target without its
    /// realisation.
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
        // Each side is opened once, for the plan and the moves: the target read-write, as the
        // moves write there (review lib.rs F5).
        let source = self.opener.open(from, Access::Scratch, notes);
        let dest = Destination::Token(to);
        let (moves, source, planned) =
            self.plan_opening(object.as_slice(), from, &dest, specs, how, true, source, Access::Write, notes)?;
        // The plan blocked a method not built yet, and checked every --spec (`plan_opening`).
        moves.ready()?;
        let source = self.source(from, source, notes)?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        // The one the plan opened; else opened now, which says why it does not open.
        let mut target = Some(match planned {
            Some(t) => t,
            None => opener.open(to, Access::Write, notes)?,
        });
        // tpm2-pkcs11 sees what `tpm2_ptool` imported only once opened again: the old one first.
        let reopen = |t: &mut Option<cakeys_pkcs11::Token>, notes: &mut Notes| -> cakeys_core::Result<()> {
            *t = None;
            *t = Some(opener.open(to, Access::Write, notes)?);
            Ok(())
        };
        let mut tally = Tally::default();
        // The transport key every sealed move wraps to, checked on the target once
        // (`tokens::transport` verifies it, its proof included); after a failure, the next
        // sealed move asks again and fails on its own.
        let mut sealing: Option<(Target, sealed::TransportKey)> = None;
        for p in &moves.plans {
            let pair = source_target(cfg, &self.lock, &p.object, from)
                .and_then(|src| Ok((src, import_target(cfg, &p.object, to, spec_for(cfg, specs, &p.object), MOVE)?)));
            let lock = &mut self.lock;
            let target = &mut target;
            let sealing = &mut sealing;
            let outcome = pair.and_then(|(src, dst)| {
                if p.method == Some(Method::Tpm2Ptool) {
                    return host::import_ptool(&src, &source, &dst, target, &reopen, lock, notes);
                }
                let target = target
                    .as_ref()
                    .ok_or_else(|| KmError::Unavailable(format!("the target token '{to}' is not open").into()))?;
                match &p.method {
                    Some(method @ (Method::RsaOaepAesKwp(_) | Method::RsaOaep(_))) => {
                        if sealing.is_none() {
                            let tr = transport_target(cfg, lock, to, transport_choice(cfg, to, how))?;
                            let key = tokens::transport(&tr, target, lock, notes)?.key()?;
                            *sealing = Some((tr, key));
                        }
                        let Some((tr, key)) = sealing.as_ref() else { unreachable!("set just above") };
                        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
                        let item = sealed::Item { src, method: method.clone(), exposure };
                        let bundle = sealed::export(&[item], &source, lock, Some(key), notes)?;
                        sealed::import(&bundle, &bundle.keys[0], &dst, target, Some(tr), lock, notes)
                    }
                    Some(method @ (Method::HostPkcs8 | Method::HostRaw | Method::PivImport)) => {
                        host::import(&src, &source, &dst, target, lock, method, notes)
                    }
                    _ => public::import(&src, &source, &dst, target, lock, notes),
                }
            });
            match outcome {
                Ok(public::Moved::Imported) => {
                    tally.moved();
                    self.record(&format_args!("'{}' on token '{to}'", p.object))?;
                    let how = p.method.as_ref().map_or_else(String::new, Method::name);
                    notes.say(format!("moved {} from {from} to {to} ({how})", p.object));
                }
                Ok(public::Moved::AlreadyThere) => {
                    notes.note(format_args!("{} is already on {to} and verifies; nothing to move", p.object));
                }
                Err(e) => tally.fail(format_args!("{}: not moved", p.object), e, notes),
            }
        }
        tally.finish(self, notes)
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
        source: cakeys_core::Result<Token>,
        notes: &mut Notes,
    ) -> anyhow::Result<(tokens::Moves, Option<Token>)> {
        let planned = self.plan_opening(objects, from, dest, specs, how, show, source, Access::Read, notes)?;
        Ok((planned.0, planned.1))
    }

    /// [`Self::plan`], opening a target token with `target` access, and handing it back, when it
    /// opened, beside the source: a `migrate` that writes there opens it once, read-write (review
    /// lib.rs F5: read-only for the plan, then again for the run).
    #[expect(clippy::too_many_arguments, reason = "the move command's parts, as the CLI hands them over")]
    fn plan_opening(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Destination,
        specs: &[String],
        how: &MoveArgs,
        show: bool,
        source: cakeys_core::Result<Token>,
        target: Access,
        notes: &mut Notes,
    ) -> anyhow::Result<(tokens::Moves, Option<Token>, Option<Token>)> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let open = |name: &str, notes: &mut Notes| opener.open(name, target, notes);
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
        // A transport file is held to its token's transport key, as a target token is (review
        // 2026-11-23 C-1): the one --transport-key or keys.toml's transportWith names.
        let transport_key = match dest {
            tokens::Dest::Token(name) => transport_choice(cfg, name, how),
            tokens::Dest::Transport(t, _) => transport_choice(cfg, &t.token, how),
            tokens::Dest::File(_) => how.transport_key.as_deref(),
        };
        let spki = match &dest {
            // No transport key named is the plan's own reason (`plan_moves`); a recorded one that
            // does not decode is an error.
            tokens::Dest::Token(name) => match tokens::transport_spec(&self.lock, name, transport_key) {
                Ok(spec) => locked_spki(&self.lock, spec, name)?,
                Err(_) => None,
            },
            tokens::Dest::Transport(t, _) => t.spki().ok(),
            tokens::Dest::File(_) => None,
        };
        // Whether the source's SO made a trusted copy of that key (`transport --trusted`). A
        // source that did not open is planned from the lock, which records no trusted copy; a
        // lookup that fails on an open one is its own error, never "no copy".
        let trusted_transport = match (spki, &source) {
            (Some(spki), Ok(tok)) => tok.trusted(&spki)?.0.is_some(),
            _ => false,
        };
        let req = tokens::Request {
            objects,
            from,
            dest,
            host_plaintext: how.allow_host_plaintext,
            transport_key,
            trusted_transport,
        };
        let (mut moves, source, target) = tokens::plan_moves(&self.lock, opener.registry, &req, source, &open, notes)?;
        // Without names, what is kept home is left out quietly; named, it is refused (15).
        if objects.is_empty() {
            moves.plans.retain(|p| no_export(cfg, &p.object, from).is_none());
        }
        for p in &mut moves.plans {
            if let Some(why) = no_export(cfg, &p.object, from) {
                p.ready = false;
                p.reasons.insert(0, format!("{why}: it never leaves '{from}'"));
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
            None => limit_token_plans(&mut moves.plans),
        }
        if show {
            show_plans(from, &moves, how.json)?;
        }
        // Every --spec selects an object moving to the token, checked where the run checked it:
        // once nothing is blocked (15 first). Here, so the dry run exits as the run does (D9;
        // review 2026-11-23 C-2: it said ready for a --spec the run refused).
        if let (false, Some(to)) = (bundle, target_token)
            && moves.plans.iter().all(|p| p.ready)
        {
            specs_select(cfg, specs, moves.plans.iter().map(|p| p.object.as_str()), to, MOVE)?;
        }
        Ok((moves, source, target))
    }

    /// The source token `from` a real run planned with ([`Self::plan`]): the one opened for the
    /// plan, else opened now, which says why it does not open.
    fn source(&self, from: &str, planned: Option<Token>, notes: &mut Notes) -> cakeys_core::Result<Token> {
        planned.map_or_else(|| self.opener.open(from, Access::Scratch, notes), Ok)
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

/// The methods a move onto a token runs today: a public object, a sealed key, the host path, a
/// `tpm2_ptool` or PIV import. A vendor's own method is a later docs/CAMIGRATE.md phase.
fn built(method: &Method) -> bool {
    matches!(
        method,
        Method::Public
            | Method::RsaOaepAesKwp(_)
            | Method::RsaOaep(_)
            | Method::HostPkcs8
            | Method::HostRaw
            | Method::Tpm2Ptool
            | Method::PivImport
    )
}

/// A move onto a token runs only a [`built`] method: another blocks the plan, so the dry run
/// says what the run refuses (D9; review 2026-11-23 C-2: only the run refused it).
fn limit_token_plans(plans: &mut [plan::Plan]) {
    for p in plans.iter_mut().filter(|p| p.ready) {
        if !p.method.as_ref().is_some_and(built) {
            let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
            p.ready = false;
            p.reasons.push(format!(
                "moving by {method} is a later docs/CAMIGRATE.md phase; public objects, sealed keys and the host \
                 path into PKCS#11 tokens move"
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

/// What keeps `object` on `from`, if anything does: a spec's `noExport`, or being a token's
/// transport key (`transportWith`), which never leaves by default. A transport key is
/// non-extractable already (keys.toml refuses one that does not say so), so it cannot move;
/// this says why plainly and keeps a move without names from stopping at it.
fn no_export(cfg: &Config, object: &str, from: &str) -> Option<String> {
    let realises = |s: &SpecCfg| s.object == object && s.tokens.contains_key(from);
    if let Some((name, _)) = cfg.specs.iter().find(|(_, s)| s.migrate.no_export && realises(s)) {
        return Some(format!("migrate.noExport in spec '{name}'"));
    }
    cfg.tokens.iter().find_map(|(token, t)| {
        let spec = t.migrate.transport_with.as_deref()?;
        realises(cfg.specs.get(spec)?)
            .then(|| format!("the transport key of token '{token}' (migrate.transportWith = \"{spec}\")"))
    })
}

impl Run<'_> {
    /// `transport --trusted`: the source's SO makes a `CKA_TRUSTED` copy of the transport key
    /// realised as `spec` on `token`, from the public key the lock records (so the lock vouches
    /// for it, never a file). Nothing to do when the source already trusts it; any other trusted
    /// object there is warned about, since `enforced` is only as narrow as the trusted set.
    fn trust(&self, spec: &str, token: &str, source: &str, notes: &mut Notes) -> anyhow::Result<()> {
        let spec =
            tokens::transport_spec(&self.lock, token, Some(spec)).map_err(|e| KmError::PreconditionFailed(e.into()))?;
        let spki = locked_spki(&self.lock, spec, token)?.ok_or_else(|| {
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
}

/// The public key `lock` records for the transport key realised as `spec` on `token`, if any.
///
/// # Errors
///
/// `Validation` (17) for a recorded public key that is not base64: never read as none.
fn locked_spki(lock: &Lock, spec: &str, token: &str) -> cakeys_core::Result<Option<Vec<u8>>> {
    use base64::Engine as _;
    let Some(key) =
        lock.realisation(spec, token).and_then(|r| lock.objects.get(&r.object)).and_then(|o| o.public_key.as_ref())
    else {
        return Ok(None);
    };
    base64::engine::general_purpose::STANDARD.decode(key).map(Some).map_err(|e| {
        KmError::Validation(format!("the lock's publicKey of transport key '{spec}' on '{token}': {e}").into())
    })
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
            "the patched cryptoki is linked without camigrate's `kwp` feature (nix/package-common.nix features)"
        );
    }

    /// The transport key's recorded public key: none where the lock records none, the bytes
    /// where it does, and 17 for one that does not decode, never "none" (review lib.rs F10).
    #[test]
    fn a_locked_public_key_that_does_not_decode_is_invalid() {
        use cakeys_core::config::{Lock, LockObject};
        let text = "version = 1\n[objects.t]\npublicKey = \"AAEC\"\n\
                    [realisations.tr.tok]\nobject = \"t\"\nspecDigest = \"sha256-x\"\nmode = \"direct\"\n\
                    schemes = []\nlocator = { CKA_LABEL = \"t\" }\npolicy = {}\n";
        let mut lock: Lock = toml::from_str(text).unwrap();
        assert_eq!(super::locked_spki(&lock, "tr", "tok").unwrap(), Some(vec![0, 1, 2]));
        assert_eq!(super::locked_spki(&lock, "tr", "other").unwrap(), None);
        lock.objects.insert("t".into(), LockObject { public_key: Some("!".into()), ..LockObject::default() });
        let e = super::locked_spki(&lock, "tr", "tok").unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("publicKey"), "{e}");
    }

    /// The numbers of a text that are whole words: what an exit-code list names.
    fn codes(text: &str) -> std::collections::BTreeSet<u8> {
        text.split(|c: char| !c.is_ascii_alphanumeric()).filter_map(|w| w.parse().ok()).collect()
    }

    /// `--help` lists the exit codes camigrate returns, as docs/CAMIGRATE.md does (review lib.rs
    /// F8: it left out 10, 12, 13 and 21).
    #[test]
    fn the_help_lists_the_documented_exit_codes() {
        let help = super::command().get_long_about().map(ToString::to_string).unwrap_or_default();
        let help = &help[help.find("Exit codes:").expect("the help lists exit codes")..];
        assert_eq!(codes(help), [0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 21].into(), "{help}");
    }
}
