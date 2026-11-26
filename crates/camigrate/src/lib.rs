//! The `camigrate` command line (README.md, "Three tools"): it moves keys between tokens
//! (docs/CAMIGRATE.md). It is the only tool that handles key material: it plans a move
//! (`--dry-run`), then makes it exactly as planned. A library, so a downstream binary can link
//! extra provider crates: `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

pub(crate) mod bundle;
mod file;
mod file_verbs;
mod host;
mod keyfile;
mod landing;
mod plan;
mod public;
mod sealed;
mod side;
mod tokens;
mod transport;
mod trust;

use anyhow::Context as _;
use bundle::Bundle;
use cakeys_cli_common::{Opener, print, read_lock};
use cakeys_core::KmError;
use cakeys_core::config::{
    ALLOW_NIX_STORE_KEYS, Config, KeyOrigin, Lock, Origin, in_nix_build, save_lock, write_whole,
};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_pkcs11::ops::{Notes, Target};
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{Registry, Token};
use clap::{Parser, Subcommand};
use file_verbs::FileImport;
use landing::{
    FROM_FILE, KEY_FILE, MOVE, import_checks, import_target, in_bundle, source_target, spec_for, specs_import,
    specs_select,
};
use plan::FileFormat;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use trust::{BoundBundle, BoundTransport};
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
        let claimed = match crate::bundle::Bundle::parse(text, path) {
            Ok(b) => b,
            Err(e) => return assert_eq!(e.exit_code(), 17, "{e}"),
        };
        let bundle = claimed.unverified();
        let written = bundle.to_toml().expect("a bundle that reads serializes");
        let again = crate::bundle::Bundle::parse(&written, path).unwrap_or_else(|e| panic!("{e}\n{written}"));
        assert_eq!(again.unverified(), bundle, "the bundle read back differs:\n{written}");
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

/// Move keys between PKCS#11 tokens, checked against keys.lock (docs/CAMIGRATE.md). Every verb
/// names its direction: `--from` the token the objects are on, `--to` where they go.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Declarative input (keys.toml).
    #[arg(short, long, env = "CAKEYS_CONFIG")]
    config: PathBuf,
    /// Lock file (keys.lock); defaults to the config path with a `.lock` extension. It must
    /// exist, unless --new-lock.
    #[arg(short, long, env = "CAKEYS_LOCK")]
    lock: Option<PathBuf>,
    /// Override a token's PKCS#11 module: `<token>=<path>` (repeatable).
    #[arg(long = "module", value_name = "TOKEN=PATH")]
    modules: Vec<String>,
    /// Start a lock where none is: without it, a lock that is not there is refused (17), so a
    /// mistyped --lock never becomes a second lock.
    #[arg(long, global = true)]
    new_lock: bool,
    /// Print the reports (the --dry-run plans of `export` and `migrate`) as JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Export objects realised on --from, shaped for where they go: a bundle for `import` on
    /// --to (the keys sealed to its transport key, the public objects as they are), the same
    /// sealed to the key of --to's transport file, or one key in a passphrase-protected key file.
    /// With --dry-run, per object the method, how exposed the material is on the way, and why
    /// not when it cannot move. Named objects are all or nothing: one that cannot move fails
    /// the export and nothing is written.
    #[command(group(clap::ArgGroup::new("destination").args(["to", "to_key_file"]).required(true)))]
    Export {
        /// The objects to export; default: every object realised on --from that can move (the
        /// others warned about, except a spec's `noExport` and a token's transport key).
        objects: Vec<String>,
        /// The token the objects are on.
        #[arg(long)]
        from: String,
        /// The token in keys.toml the bundle is for: its capabilities are read from the open
        /// token, else from what the lock recorded there, else from its transport file.
        #[arg(long)]
        to: Option<String>,
        /// The transport file (`camigrate transport`) of --to, a token this host cannot reach:
        /// it must be that token's, naming the transport key the lock pins there.
        #[arg(long, value_name = "FILE", requires = "to")]
        to_transport_file: Option<PathBuf>,
        /// One key, to a passphrase-protected key file (needs --out and --passphrase-file).
        #[arg(long, value_enum)]
        to_key_file: Option<FileArg>,
        /// Where to write the bundle (default: stdout), or the key file.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The passphrase the key file is encrypted under, read from this file (one line).
        #[arg(long, value_name = "FILE", requires = "to_key_file")]
        passphrase_file: Option<PathBuf>,
        /// The transport key's spec on the destination token; default: its `transportWith`.
        #[arg(long, value_name = "SPEC", conflicts_with = "to_key_file")]
        transport_spec: Option<String>,
        /// Allow the key's plaintext in this process's memory, which a key file needs.
        #[arg(long, requires = "to_key_file")]
        allow_host_plaintext: bool,
        /// Print the plan and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Import onto --to: a bundle (`export`'s), each key under the spec that realises its object
    /// there, unwrapped with the transport key realised there; or a key file, the object the lock
    /// pins with its key's identity; or, without --in, each object a pair on --to says is born
    /// in a file (`origin = "file"`), from its object's `migrate.file` (docs/FILE.md). Each
    /// checked against the lock before the token is touched and recorded with where it came
    /// from, each on its own: one that fails leaves nothing, the others still import, and the
    /// run exits with the first failure. Prints each object's outcome, as a JSON array.
    Import {
        /// Without --in: the objects to import from their files; default: every one a pair on
        /// --to says `origin = "file"` for.
        #[arg(conflicts_with = "input")]
        objects: Vec<String>,
        /// The token they go to.
        #[arg(long)]
        to: String,
        /// The spec to realise an object under, when it has several on --to (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        /// A bundle, or a key file (told apart by what the file holds).
        #[arg(long = "in", value_name = "FILE")]
        input: Option<PathBuf>,
        /// A bundle's transport key, by its spec on --to, as its export named it; default: --to's
        /// `transportWith`. A bundle sealed to any other key is refused.
        #[arg(long, value_name = "SPEC", requires = "input")]
        transport_spec: Option<String>,
        /// The passphrase of an encrypted key file, read from this file; without --in, of every
        /// encrypted file, over keys.toml's.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
        /// Allow a key file's plaintext in this process's memory, which a key file needs.
        #[arg(long)]
        allow_host_plaintext: bool,
        /// Check each object against the lock and the token, and import nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move objects from --from to --to, both reachable from this host: each is created on --to
    /// and recorded in the lock with where it came from. Public objects move as they are; keys
    /// sealed to --to's transport key, through the host only wrapped. Each on its own: one that
    /// fails is undone, the others still move. Prints each object's outcome, as a JSON array
    /// (with --dry-run, the plan).
    Migrate {
        /// The objects to move; default: every object realised on --from.
        objects: Vec<String>,
        /// The token they are on.
        #[arg(long)]
        from: String,
        /// The token they go to.
        #[arg(long)]
        to: String,
        /// The spec to realise an object under on --to, when it has several there (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Write the transport file of a token's transport key: an RSA private key there that may
    /// unwrap, realised and locked. Exports to the token seal to it. With --trust-on, instead
    /// make that token's security officer trust it, so its keys marked wrap-with-trusted wrap
    /// under it and nothing else.
    Transport {
        /// The transport key's object; default: the token's `migrate.transportWith`.
        object: Option<String>,
        /// The transport key's spec, where the object has several on --token.
        #[arg(long)]
        spec: Option<String>,
        /// The token the transport key is on.
        #[arg(long)]
        token: String,
        /// Where to write the transport file; default: stdout.
        #[arg(long, conflicts_with = "trust_on")]
        out: Option<PathBuf>,
        /// The source token whose security officer marks a copy of the transport key
        /// `CKA_TRUSTED` (with its `soCredentialFile`/`soCredentialEnv`), from the public key
        /// the lock records.
        #[arg(long, value_name = "SOURCE")]
        trust_on: Option<String>,
    },
}

/// How `migrate` may move material; `export` takes the same flags.
#[derive(clap::Args)]
struct MoveArgs {
    /// Print the plan and move nothing.
    #[arg(long)]
    dry_run: bool,
    /// The transport key's spec on --to; default: its `transportWith`.
    #[arg(long, value_name = "SPEC")]
    transport_spec: Option<String>,
    /// `--json`, the global flag: the plan as JSON.
    #[arg(skip)]
    json: bool,
    /// Allow the `host` and `file` methods, which put plaintext in this process's memory.
    #[arg(long)]
    allow_host_plaintext: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum FileArg {
    Pkcs8,
    Pkcs12,
}

/// The command line's definition: its verbs and flags, with the exit codes after its help, for
/// parsing and for the test that every flag is used by an integration test
/// (`tests/common/surface.rs`).
#[must_use]
pub fn command() -> clap::Command {
    cakeys_cli_common::with_exit_codes(<Cli as clap::CommandFactory>::command())
}

/// Run the command line with the given providers; maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parse the arguments, then load keys.toml and the lock — refusing up front a run that writes a
/// lock it cannot (docs/CAMIGRATE.md D8: never inside a Nix build) — and run the verb.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let mut cli: Cli = cakeys_cli_common::parse(command());
    if let Cmd::Migrate { how, .. } = &mut cli.cmd {
        how.json = cli.json;
    }
    let opener = Opener::load(&cli.config, &cli.modules, registry, notes)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    // A key file given to `import --in` is told from a bundle by what it holds (review 2026-11-23
    // C-6), before anything else is decided by it.
    let key_file = match &cli.cmd {
        Cmd::Import { input: Some(path), .. } => {
            let bytes = std::fs::read(path).map_err(KmError::io(format_args!("reading {}", path.display())))?;
            (!Bundle::is_bundle(&bytes)).then_some(path.as_path())
        }
        _ => None,
    };
    // A real `migrate` or `import` writes the lock; it holds the advisory sidecar lock across load
    // and save, as cakeys' writing verbs do. A real `export` is an admin operation too (D8).
    let writes = matches!(&cli.cmd, Cmd::Migrate { how, .. } if !how.dry_run)
        || matches!(&cli.cmd, Cmd::Import { dry_run: false, .. });
    let exports = matches!(&cli.cmd, Cmd::Export { dry_run: false, .. });
    // A key file is decrypted into this process's memory, also to check it (--dry-run); so is
    // an object's own file, without --in.
    let reads_key_file = key_file.is_some() || matches!(&cli.cmd, Cmd::Import { input: None, .. });
    let trusts = matches!(&cli.cmd, Cmd::Transport { trust_on: Some(_), .. });
    refuse_admin_in_nix_build(exports, reads_key_file, trusts)?;
    if let Cmd::Migrate { to: target, .. } | Cmd::Import { to: target, .. } = &cli.cmd {
        needs_login(&opener.cfg, target)?;
    }
    let instead = "run it outside a Nix build sandbox, or pass --dry-run";
    let (lock, _update_guard) = read_lock(&lock_path, cli.new_lock, writes, instead)?;
    let mut run = Run { opener, lock, lock_path };
    match &cli.cmd {
        Cmd::Export { .. } => run.export_verb(&cli.cmd, cli.json, notes),
        Cmd::Import { objects, to, spec, input: None, dry_run, passphrase_file, allow_host_plaintext, .. } => {
            let how =
                FileImport { pass: passphrase_file.as_deref(), plaintext: *allow_host_plaintext, dry_run: *dry_run };
            run.import_files(to, objects, spec, &how, notes)
        }
        Cmd::Import {
            to,
            spec,
            input: Some(input),
            dry_run,
            passphrase_file,
            allow_host_plaintext,
            transport_spec,
            ..
        } if key_file.is_some() => {
            key_file_flags(input, *allow_host_plaintext, transport_spec.as_deref())?;
            run.import_file(to, spec, input, passphrase_file.as_deref(), *dry_run, notes)
        }
        Cmd::Import { to, spec, input: Some(input), dry_run, passphrase_file, transport_spec, .. } => {
            if passphrase_file.is_some() {
                return Err(KmError::Validation(
                    format!("{} is a bundle, which takes no passphrase: its keys are sealed", input.display()).into(),
                )
                .into());
            }
            run.import(to, spec, input, transport_spec.as_deref(), *dry_run, notes)
        }
        Cmd::Migrate { objects, from, to, spec, how } if how.dry_run => {
            specs_import(&run.opener.cfg, spec, to, MOVE)?;
            let objects: Vec<&str> = objects.iter().map(String::as_str).collect();
            let dest = tokens::Dest::Token(to);
            run.plan_moves(&MoveCtx { objects: &objects, from, dest: &dest, specs: spec, how }, notes)
        }
        Cmd::Migrate { objects, from, to, spec, how } => {
            let objects: Vec<&str> = objects.iter().map(String::as_str).collect();
            run.migrate(&objects, from, to, spec, how, notes)
        }
        Cmd::Transport { object, spec, token, trust_on: Some(source), .. } => {
            let spec = transport_named(&run.opener.cfg, object.as_deref(), spec.as_deref(), token)?;
            run.trust(&spec, token, source, notes)
        }
        Cmd::Transport { object, spec, token, out, trust_on: None } => {
            let cfg = &run.opener.cfg;
            let spec = transport_named(cfg, object.as_deref(), spec.as_deref(), token)?;
            let bound = BoundTransport::from_lock(cfg, &run.lock, token, Some(&spec))?;
            let tok = run.opener.open(token, Access::Read, notes)?;
            let bound = bound.read(cfg, &tok, &run.lock, notes)?;
            bound.warn_decrypting(&run.lock, notes);
            let text = bound.transport_file(&tok)?.to_toml()?;
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

impl Run<'_> {
    /// `export`: a plan (`--dry-run`), a bundle for a token or a transport file, or one key file.
    fn export_verb(&mut self, cmd: &Cmd, json: bool, notes: &mut Notes) -> anyhow::Result<()> {
        let Cmd::Export {
            objects,
            from,
            to,
            to_transport_file,
            to_key_file,
            out,
            passphrase_file,
            transport_spec,
            allow_host_plaintext,
            dry_run,
        } = cmd
        else {
            unreachable!("export_verb is called for export only")
        };
        let dest = match (to, to_transport_file, to_key_file) {
            (_, _, Some(FileArg::Pkcs8)) => tokens::Dest::File(FileFormat::Pkcs8),
            (_, _, Some(FileArg::Pkcs12)) => tokens::Dest::File(FileFormat::Pkcs12),
            (Some(to), Some(path), None) => tokens::Dest::transport(path, to)?,
            (Some(to), None, None) => tokens::Dest::Bundle(to),
            (None, _, None) => unreachable!("clap requires --to or --to-key-file, and --to with --to-transport-file"),
        };
        let how = MoveArgs {
            dry_run: *dry_run,
            transport_spec: transport_spec.clone(),
            json,
            allow_host_plaintext: *allow_host_plaintext,
        };
        let objects: Vec<&str> = objects.iter().map(String::as_str).collect();
        let ctx = MoveCtx { objects: &objects, from, dest: &dest, specs: &[], how: &how };
        if how.dry_run {
            return self.plan_moves(&ctx, notes);
        }
        if json {
            return Err(KmError::Validation(
                "--json is the plan's form: a real export writes the bundle or the key file".into(),
            )
            .into());
        }
        if let tokens::Dest::File(_) = &dest {
            let (Some(out), Some(pass)) = (out, passphrase_file) else {
                return Err(KmError::Validation("writing a key file needs --out and --passphrase-file".into()).into());
            };
            return self.export_file(&ctx, out, pass, notes);
        }
        self.export(&ctx, out.as_deref(), notes)
    }
}

/// An admin operation (a real export, a key file read, a trust grant) is refused inside a Nix build
/// as cakeys refuses a writing run there, with the same code (review 2026-11-23 C-12).
fn refuse_admin_in_nix_build(exports: bool, reads_key_file: bool, trusts: bool) -> cakeys_core::Result<()> {
    if !((exports || reads_key_file || trusts) && in_nix_build()) {
        return Ok(());
    }
    let (verb, instead) = match (exports, reads_key_file) {
        (true, _) => ("export", ", or pass --dry-run to plan it"),
        (_, true) => ("an import of a key file", ""),
        _ => ("transport --trust-on", ""),
    };
    Err(KmError::LockUnwritable(
        format!(
            "{verb} is an admin operation (docs/CAMIGRATE.md D8), refused inside a Nix build: run it outside \
             the sandbox{instead} ({ALLOW_NIX_STORE_KEYS}=1 runs it as outside, for throwaway keys only)"
        )
        .into(),
    ))
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

/// What `import --in` of a key file needs of its flags: `--allow-host-plaintext`, since its key
/// passes through this process's memory, and no `--transport-spec`, since nothing in it is sealed.
///
/// # Errors
///
/// `Unsupported` (15) without the flag; `Validation` (17) with a transport key named.
fn key_file_flags(input: &Path, allow_host_plaintext: bool, transport_spec: Option<&str>) -> cakeys_core::Result<()> {
    if transport_spec.is_some() {
        return Err(KmError::Validation(
            format!("{} is a key file, which takes no --transport-spec: nothing in it is sealed", input.display())
                .into(),
        ));
    }
    if !allow_host_plaintext {
        return Err(KmError::Unsupported(
            format!(
                "{} is a key file: its key passes through this process's memory as plaintext; pass \
                 --allow-host-plaintext (docs/CAMIGRATE.md D2, file)",
                input.display()
            )
            .into(),
        ));
    }
    Ok(())
}

/// What a verb works with once the arguments are parsed: keys.toml, the lock, and how tokens
/// are opened.
struct Run<'a> {
    opener: Opener<'a>,
    lock: Lock,
    lock_path: PathBuf,
}

/// One move command's parts, as the CLI hands them over: what moves, from where, to where,
/// under which `--spec`s, and how (review 2026-11-23 C-23: four functions took them one by
/// one).
struct MoveCtx<'a> {
    /// The objects named; empty: every one realised on `from`.
    objects: &'a [&'a str],
    /// The source token.
    from: &'a str,
    dest: &'a tokens::Dest<'a>,
    /// `--spec`: the pairs objects land on, on a target token.
    specs: &'a [String],
    how: &'a MoveArgs,
}

impl MoveCtx<'_> {
    /// What the run takes of its plans, the dry run's verdict and the run's.
    fn take(&self) -> tokens::Take {
        tokens::Take::of(self.objects, self.dest)
    }
}

/// A verb's run over its objects (review D8: `import`, `migrate` and `import` from files each
/// kept their own): each object on its own, so one that fails leaves nothing and the others
/// still move. Each object's outcome, printed as the run's result (review 2026-11-23 C-7);
/// whether any changed the lock; and the first failure, which the run exits with once the lock
/// is saved. A row is cakeys' ([`cakeys_cli_common::Outcome`]: its exit, the rule that refused it
/// and whether the device failed), with the method the object moved by beside it.
#[derive(Default)]
struct Tally {
    changed: bool,
    failed: Option<KmError>,
    results: Vec<cakeys_cli_common::Outcome>,
}

/// Which object an outcome is of: its name, the spec it lands under (once known) and the token.
#[derive(Clone, Copy)]
struct Of<'a> {
    object: &'a str,
    spec: Option<&'a str>,
    token: &'a str,
}

impl<'a> Of<'a> {
    /// The object a pair realises.
    fn pair(t: &'a Target<'a>) -> Of<'a> {
        Of { object: t.object_name, spec: Some(t.spec_name), token: t.token_name }
    }

    /// An object before its landing pair is known.
    fn object(object: &'a str, token: &'a str) -> Of<'a> {
        Of { object, spec: None, token }
    }

    /// Its row, passed with `outcome` (no spec yet: empty).
    fn row(self, outcome: &str) -> cakeys_cli_common::Outcome {
        cakeys_cli_common::Outcome::passed(self.object, self.spec.unwrap_or_default(), self.token, outcome)
    }
}

impl Tally {
    /// `of`'s outcome (`imported`, `moved`, `already-there`, `ready`), and the method it moved
    /// by, if it did.
    fn done(&mut self, of: Of<'_>, outcome: &str, method: Option<&str>) {
        let mut row = of.row(outcome);
        row.more.insert("method".into(), method.into());
        self.results.push(row);
    }

    /// `of` ready to move by `method`, but for `deferred`: the rules only its run decides, which
    /// the row names so that a run ending with one keeps the dry run's promise (§1.4).
    fn ready(&mut self, of: Of<'_>, method: &str, deferred: &[(&str, &str)]) {
        self.done(of, "ready", Some(method));
        if let Some(row) = self.results.last_mut() {
            row.deferred = deferred
                .iter()
                .map(|(rule, why)| cakeys_cli_common::DeferredRow { rule: (*rule).to_owned(), why: (*why).to_owned() })
                .collect();
        }
    }

    /// `of` written (`outcome`, by `method`): the lock changed.
    fn moved(&mut self, of: Of<'_>, outcome: &str, method: Option<&str>) {
        self.changed = true;
        self.done(of, outcome, method);
    }

    /// `of` failed with `err` (`what` says how): said now, and kept when it is the run's first
    /// failure.
    fn fail(&mut self, of: Of<'_>, what: impl std::fmt::Display, err: KmError, notes: &mut Notes) {
        notes.say(format!("{what}: {err}"));
        let mut row = of.row("failed").refused_by(Some(&err));
        // 10 names no rule of its own: the material is not the one the lock pins.
        if matches!(err, KmError::HashMismatch { .. }) && row.rule.is_none() {
            row.rule = Some(sealed::IDENTITY.to_owned());
        }
        self.results.push(cakeys_cli_common::Outcome { error: Some(err.to_string()), ..row });
        self.failed.get_or_insert(err);
    }

    /// `of` written (`outcome`, by `method`), and recorded at once, before the run touches
    /// another object (the save is atomic): a run killed or failing later never leaves an object
    /// on a token the lock does not record, and on ykcs11 cakeys cannot remove it. A save that
    /// fails is the object's failure, 21 (`lock-writable`), saying how to record it once the lock
    /// can be written (`hint`: [`public::unrecorded_hint`]); `false` then, and the run moves
    /// nothing more. [`Tally::finish`] still prints every row and exits with the first failure
    /// (review 2026-11-24 D-9: a failed save returned before it, the rows and an earlier
    /// object's failure lost).
    fn record(
        &mut self,
        run: &Run<'_>,
        of: Of<'_>,
        (outcome, method): (&str, Option<&str>),
        hint: &str,
        notes: &mut Notes,
    ) -> bool {
        match save_lock(&run.lock_path, &run.lock) {
            Ok(()) => {
                self.moved(of, outcome, method);
                true
            }
            Err(e) => {
                let what = format!("'{}' on token '{}'", of.object, of.token);
                let e = KmError::LockUnwritable(
                    format!(
                        "{what} is on the token, but the lock could not record it ({e}), and the run stops here. {hint}"
                    )
                    .into(),
                );
                self.fail(of, format_args!("{what}: not recorded"), cakeys_cli_common::lock_rule(e), notes);
                false
            }
        }
    }

    /// Print each object's outcome, say the lock was written if anything moved, then exit with
    /// the first failure. Each move saved it already ([`Tally::record`]): never a second write
    /// only to say so (review 2026-11-23 C-21).
    fn finish(self, run: &Run<'_>, notes: &mut Notes) -> anyhow::Result<()> {
        print(&self.results)?;
        if self.changed {
            notes.lock_written(&run.lock_path);
        }
        self.failed.map_or(Ok(()), |e| Err(e.into()))
    }
}

impl Run<'_> {
    /// `--dry-run`: plan each object's move from `from` to `dest` and print it (docs/CAMIGRATE.md
    /// D9), and end with the real run's own verdict ([`tokens::Moves::verdict`]): an export
    /// without names takes what can move, and fails only when nothing can. A `migrate` writes on
    /// its target, so its dry run opens that token as the dry run of a write: a write-protected
    /// one is refused (15) as the run's open refuses it (review 2026-11-24 L4a-3), and a target
    /// the plan took from the lock is opened after the verdict, as the run opens it.
    fn plan_moves(&self, ctx: &MoveCtx, notes: &mut Notes) -> anyhow::Result<()> {
        let source = self.opener.open(ctx.from, Access::Read, notes);
        let target = if let tokens::Dest::Token(_) = ctx.dest { Access::DryWrite } else { Access::Read };
        let (moves, _, opened) = self.plan(ctx, Show::Stdout, source, target, notes)?;
        moves.verdict(ctx.take(), ctx.from)?;
        if let (tokens::Dest::Token(to), None) = (ctx.dest, opened) {
            self.opener.open(to, target, notes)?;
        }
        Ok(())
    }

    /// `export` for real: plan as `--dry-run` does, then wrap every key to the target's
    /// transport key — the one the lock records for the token, else the open token's, or a
    /// transport file the lock pins — and write them as one bundle. Public objects need no
    /// transport key, and a bundle of them alone is made without one. Named objects are all or
    /// nothing: one that cannot move fails the export before anything is wrapped. Without names,
    /// every key that can move is exported and the others are warned about. The bundle is
    /// written whole or not at all; nothing on either token changes.
    fn export(&self, ctx: &MoveCtx, out: Option<&Path>, notes: &mut Notes) -> anyhow::Result<()> {
        let MoveCtx { from, dest, how, .. } = *ctx;
        // The source is opened once, for the plan and the wrap; so is a bundle's token, for the
        // plan and its transport key (review lib.rs F5).
        let source = self.opener.open(from, Access::Scratch, notes);
        let (moves, source, planned_target) = self.plan(ctx, Show::No, source, Access::Read, notes)?;
        // Named objects are all or nothing; without names, whatever can move does, and what
        // cannot (a key made non-extractable, ...) is warned about and left out. (What is meant
        // never to leave is not planned at all: `landing::block`.)
        let take = ctx.take();
        if take == tokens::Take::WhatCanGo {
            for p in moves.plans.iter().filter(|p| !p.ready) {
                notes.warn(format_args!("{}: left out of the bundle: {}", p.object, p.reasons.join("; ")));
            }
        }
        moves.verdict(take, from)?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let mut items = Vec::new();
        for p in moves.plans.iter().filter(|p| p.ready) {
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
        let source = self.source(from, source, notes)?;
        let wraps = items.iter().any(|i| i.method != Method::Public);
        // The transport key bound to the target named, as the plan bound it; sealing binds it
        // again, so nothing wraps to a key the lock does not bind there, whatever the plan let
        // through (review 2026-11-24 D-1).
        let spec = how.transport_spec.as_deref();
        let transport = match dest {
            _ if !wraps => None,
            tokens::Dest::Bundle(to) => {
                let bound = BoundTransport::from_lock(cfg, &self.lock, to, spec)?;
                Some(if bound.spki().is_some() {
                    bound
                } else {
                    let target = match planned_target {
                        Some(t) => t,
                        None => opener.open(to, Access::Read, notes)?,
                    };
                    notes.note(format_args!(
                        "transport key '{}' of '{to}': the lock records no public key for it yet; lock it again to \
                         export without '{to}'",
                        bound.object()
                    ));
                    bound.read(cfg, &target, &self.lock, notes)?
                })
            }
            tokens::Dest::Transport(path, to, t) => {
                Some(BoundTransport::from_file(t, path, cfg, &self.lock, to, spec)?)
            }
            tokens::Dest::Token(_) | tokens::Dest::File(_) => {
                unreachable!("an export makes a bundle or a key file, and a file plan is never sealed")
            }
        };
        if let Some(bound) = &transport {
            bound.warn_decrypting(&self.lock, notes);
        }
        let Some(to) = dest.to() else { unreachable!("a bundle is for the token --to names") };
        let bundle = sealed::export(&items, &source, &self.lock, to, transport.as_ref(), notes)?;
        let text = bundle.to_toml()?;
        let what = bundle.keys.iter().map(|k| format!("{} by {}", k.object, k.method)).collect::<Vec<_>>().join(", ");
        match out {
            Some(path) => {
                write_whole(path, text.as_bytes(), 0o644)?;
                notes.say(format!("wrote {} for '{to}' ({what})", path.display()));
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
        transport_spec: Option<&str>,
        dry_run: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let text = std::fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        // Made for `token`, from a source keys.toml names, sealed to `token`'s transport key as
        // the lock binds it: never to whichever key the file names (review 2026-11-24 D-8).
        let bound = BoundBundle::from_file(Bundle::parse(&text, input)?, cfg, &self.lock, token, transport_spec, notes)
            .map_err(|e| e.prefixed(input.display()))?;
        let bundle = bound.bundle();
        specs_select(cfg, specs, bundle.keys.iter().map(|e| e.object.as_str()), token, MOVE)?;
        let access = if dry_run { Access::DryWrite } else { Access::Write };
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
                    tally.fail(Of::object(&e.object, token), format_args!("{}: not imported", e.object), err, notes);
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
                    return sealed::import(&bound, e, &dst, &target, lock, notes).map(Some);
                }
                sealed::preflight(&bound, e, &dst, &target, lock, notes)?;
                let method = e.method().map_err(|e| KmError::Validation(e.into()))?;
                import_checks(&dst, &target, &method, opener.registry, notes).map(|()| None)
            });
            match outcome {
                Ok(None) => {
                    notes.say(format!(
                        "{dst}: {} by {} ({}) from {}: ready",
                        e.object, e.method, e.exposure, bundle.source.token
                    ));
                    // A blob is unwrapped, and what it holds known, only by the import itself.
                    let sealed: &[(&str, &str)] = &[
                        (sealed::UNWRAPS, "only the target's unwrap shows the blob is intact"),
                        (sealed::IDENTITY, "only the unwrapped key shows it is the one the lock pins"),
                    ];
                    tally.ready(Of::pair(&dst), &e.method, if e.method == public { &[] } else { sealed });
                }
                Ok(Some(public::Moved::Imported)) => {
                    let hint = public::unrecorded_hint(&dst);
                    if !tally.record(self, Of::pair(&dst), ("imported", Some(&e.method)), &hint, notes) {
                        break;
                    }
                    notes.say(format!(
                        "imported {} from {} ({}) into {dst}",
                        e.object, bundle.source.token, bundle.source.provider
                    ));
                }
                Ok(Some(public::Moved::AlreadyThere)) => {
                    notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                    tally.done(Of::pair(&dst), "already-there", None);
                }
                Err(err) => tally.fail(Of::pair(&dst), format_args!("{dst}: not imported"), err, notes),
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
        objects: &[&str],
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
        let dest = tokens::Dest::Token(to);
        let ctx = MoveCtx { objects, from, dest: &dest, specs, how };
        let (moves, source, planned) = self.plan(&ctx, Show::Notes, source, Access::Write, notes)?;
        // The plan blocked a method not built yet, and checked every --spec (`plan`).
        moves.verdict(ctx.take(), from)?;
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
        // The transport key every sealed move wraps to, bound to `to` and checked on the target
        // once (`BoundTransport::read` verifies it, its proof included); after a failure, the
        // next sealed move asks again and fails on its own.
        let mut sealing: Option<BoundTransport> = None;
        for p in &moves.plans {
            let pair = source_target(cfg, &self.lock, &p.object, from)
                .and_then(|src| Ok((src, import_target(cfg, &p.object, to, spec_for(cfg, specs, &p.object), MOVE)?)));
            let hint = pair.as_ref().map(|(_, dst)| public::unrecorded_hint(dst)).unwrap_or_default();
            let landed = pair.as_ref().ok().map(|(_, dst)| dst.spec_name.to_owned());
            let of = Of { object: &p.object, spec: landed.as_deref(), token: to };
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
                            let bound = BoundTransport::from_lock(cfg, lock, to, how.transport_spec.as_deref())?;
                            let bound = bound.read(cfg, target, lock, notes)?;
                            bound.warn_decrypting(lock, notes);
                            *sealing = Some(bound);
                        }
                        let Some(bound) = sealing.as_ref() else { unreachable!("set just above") };
                        let exposure = p.exposure.unwrap_or(Exposure::Sealed);
                        let item = sealed::Item { src, method: method.clone(), exposure };
                        let bundle = sealed::export(&[item], &source, lock, to, Some(bound), notes)?;
                        let bundle = BoundBundle::made(bundle, bound, cfg)?;
                        sealed::import(&bundle, &bundle.bundle().keys[0], &dst, target, lock, notes)
                    }
                    Some(method @ (Method::HostPkcs8 | Method::HostRaw | Method::PivImport)) => {
                        host::import(&src, &source, &dst, target, lock, method, notes)
                    }
                    _ => public::import(&src, &source, &dst, target, lock, notes),
                }
            });
            let method = p.method.as_ref().map(Method::name);
            match outcome {
                Ok(public::Moved::Imported) => {
                    if !tally.record(self, of, ("moved", method.as_deref()), &hint, notes) {
                        break;
                    }
                    let how = method.unwrap_or_default();
                    notes.say(format!("moved {} from {from} to {to} ({how})", p.object));
                }
                Ok(public::Moved::AlreadyThere) => {
                    notes.note(format_args!("{} is already on {to} and verifies; nothing to move", p.object));
                    tally.done(of, "already-there", None);
                }
                Err(e) => tally.fail(of, format_args!("{}: not moved", p.object), e, notes),
            }
        }
        tally.finish(self, notes)
    }

    /// Whether the source's SO made a trusted copy (`transport --trust-on`) of the transport key
    /// `dest` seals to. A source that did not open is planned from the lock, which records no
    /// trusted copy; a lookup that fails on an open one is its own error, never "no copy".
    fn trusted_transport(
        &self,
        dest: &tokens::Dest<'_>,
        transport_spec: Option<&str>,
        source: &cakeys_core::Result<Token>,
    ) -> anyhow::Result<bool> {
        let (cfg, lock) = (&self.opener.cfg, &self.lock);
        // No transport key bound is the plan's own reason (`plan_moves`); a malformed one (a
        // recorded key that does not decode, or is too small) is an error.
        let bound = match dest {
            tokens::Dest::Token(name) | tokens::Dest::Bundle(name) => {
                trust::planned(BoundTransport::from_lock(cfg, lock, name, transport_spec))?.ok()
            }
            tokens::Dest::Transport(path, to, t) => {
                trust::planned(BoundTransport::from_file(t, path, cfg, lock, to, transport_spec))?.ok()
            }
            tokens::Dest::File(_) => None,
        };
        let spki = bound.as_ref().and_then(BoundTransport::spki);
        Ok(match (spki, source) {
            (Some(spki), Ok(tok)) => tok.trusted(spki)?.0.is_some(),
            _ => false,
        })
    }

    /// Plan each object's move, block what the run would refuse ([`landing::block`]), and show
    /// the plans where `show` says (an export that writes the bundle to stdout shows none: stdout
    /// is the bundle). A target token is opened with `target` access and handed back, when it
    /// opened, beside the source: a `migrate` that writes there opens it once, read-write
    /// (review lib.rs F5: read-only for the plan, then again for the run).
    fn plan(
        &self,
        ctx: &MoveCtx,
        show: Show,
        source: cakeys_core::Result<Token>,
        target: Access,
        notes: &mut Notes,
    ) -> anyhow::Result<(tokens::Moves, Option<Token>, Option<Token>)> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let open = |name: &str, notes: &mut Notes| opener.open(name, target, notes);
        // The transport key is the one the lock binds to the token the operator named (`--to`),
        // a transport file's included (review 2026-11-24 D-1): --transport-spec, else that
        // token's transportWith.
        let transport_spec = ctx.how.transport_spec.as_deref();
        let trusted_transport = self.trusted_transport(ctx.dest, transport_spec, &source)?;
        let req = tokens::Request {
            objects: ctx.objects,
            from: ctx.from,
            dest: ctx.dest,
            host_plaintext: ctx.how.allow_host_plaintext,
            cfg,
            transport_spec,
            trusted_transport,
        };
        let (mut moves, source, target) = tokens::plan_moves(&self.lock, opener.registry, &req, source, &open, notes)?;
        landing::block(self, ctx, &mut moves, target.as_ref());
        match show {
            Show::No => {}
            Show::Stdout => show_plans(ctx.from, &moves, ctx.how.json)?,
            Show::Notes => {
                for line in plan_lines(ctx.from, &moves) {
                    notes.say(line);
                }
            }
        }
        // Every --spec selects an object moving to the token, checked where the run checked it:
        // once nothing is blocked (15 first). Here, so the dry run exits as the run does (D9;
        // review 2026-11-23 C-2: it said ready for a --spec the run refused).
        if let (false, Some(to)) = (ctx.dest.bundle(), ctx.dest.to())
            && moves.plans.iter().all(|p| p.ready)
        {
            specs_select(cfg, ctx.specs, moves.plans.iter().map(|p| p.object.as_str()), to, MOVE)?;
        }
        Ok((moves, source, target))
    }

    /// The source token `from` a real run planned with ([`Self::plan`]): the one opened for the
    /// plan, else opened now, which says why it does not open.
    fn source(&self, from: &str, planned: Option<Token>, notes: &mut Notes) -> cakeys_core::Result<Token> {
        planned.map_or_else(|| self.opener.open(from, Access::Scratch, notes), Ok)
    }
}

/// Where a plan is shown: nowhere (a real export), on stdout as the dry run's result, or with
/// the notes, on stderr (a real `migrate`, whose stdout is each object's outcome).
#[derive(Clone, Copy)]
enum Show {
    No,
    Stdout,
    Notes,
}

/// Print the plans of one invocation, as a table or as JSON.
fn show_plans(from: &str, moves: &tokens::Moves, json: bool) -> anyhow::Result<()> {
    if json {
        return print(&serde_json::json!({
            "from": from,
            "to": moves.to,
            "capabilities": { "from": moves.source_from.name(), "to": moves.target_from.name() },
            "plans": moves.plans,
        }));
    }
    for line in plan_lines(from, moves) {
        println!("{line}");
    }
    Ok(())
}

/// The plans of one invocation as a table, line by line.
fn plan_lines(from: &str, moves: &tokens::Moves) -> Vec<String> {
    let (to_name, plans) = (&moves.to, &moves.plans);
    let (source_from, target_from) = (moves.source_from.name(), moves.target_from.name());
    let mut lines = vec![format!(
        "{from} -> {to_name} (capabilities: {from} from the {source_from}, {to_name} from the {target_from})"
    )];
    for p in plans {
        let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
        let exposure = p.exposure.map_or("-", Exposure::name);
        let status = if p.ready { "ready" } else { "blocked" };
        lines.push(format!("  {:<24} {method:<26} {exposure:<9} {status}", p.object));
        lines.extend(p.reasons.iter().map(|r| format!("      - {r}")));
        lines.extend(p.notes.iter().map(|n| format!("      note: {n}")));
    }
    lines
}

impl Run<'_> {
    /// `transport --trust-on`: the source's SO makes a `CKA_TRUSTED` copy of the transport key
    /// realised as `spec` on `token`, from the public key the lock records (so the lock vouches
    /// for it, never a file), held to the transport key's rule as every other path is
    /// (`BoundTransport`; review 2026-11-24 D-10). Nothing to do when the source already trusts
    /// it; any other trusted object there is warned about, since `enforced` is only as narrow as
    /// the trusted set.
    fn trust(&self, spec: &str, token: &str, source: &str, notes: &mut Notes) -> anyhow::Result<()> {
        let bound = BoundTransport::from_lock(&self.opener.cfg, &self.lock, token, Some(spec))?;
        let spki = bound.spki().ok_or_else(|| bound.no_public_key())?;
        let tok = self.opener.open(source, Access::Write, notes)?;
        let (copy, others) = tok.trusted(spki)?;
        if copy.is_some() {
            notes.note(format_args!("'{source}' already trusts transport key '{spec}' of '{token}'"));
        } else {
            let (n, e) = sealed::rsa_parts(spki)?;
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
        )
        .with_rule(cakeys_pkcs11::ops::Rule::NeedsLogin.name())),
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

    /// The numbers of a text that are whole words: what an exit-code list names.
    fn codes(text: &str) -> std::collections::BTreeSet<u8> {
        text.split(|c: char| !c.is_ascii_alphanumeric()).filter_map(|w| w.parse().ok()).collect()
    }

    /// `--help` lists every exit code, from the one table (review lib.rs F8: it left out 10, 12,
    /// 13 and 21; review 2026-11-23 C-10: each tool had its own list).
    #[test]
    fn the_help_lists_the_documented_exit_codes() {
        let help = super::command().render_help().to_string();
        let help = &help[help.find("Exit codes").expect("the help lists exit codes")..];
        let all: std::collections::BTreeSet<u8> = cakeys_core::EXIT_CODES.iter().map(|(c, _)| *c).collect();
        assert_eq!(codes(help), all, "{help}");
    }
}
