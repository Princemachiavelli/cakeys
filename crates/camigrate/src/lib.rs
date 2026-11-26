//! The `camigrate` command line (README.md, "Three tools"). It moves keys between tokens
//! (docs/CAMIGRATE.md), and it is the only tool that handles key material. It plans a move
//! (`--dry-run`), and the real run then makes the move exactly as planned. The crate is a library
//! so that a downstream binary can link extra provider crates:
//! `camigrate::main(&camigrate::default_registry().with(MyProvider))`.

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
use cakeys_core::config::{
    ALLOW_NIX_STORE_KEYS, Config, KeyOrigin, Lock, Origin, in_nix_build, save_lock, write_whole,
};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{Check, KmError};
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

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/bundle.rs`, `key_file.rs`). They run the
/// code that reads the files camigrate is given (bundles and key files) on arbitrary input
/// (review D9).
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    use cakeys_core::config::ObjectCfg;
    use cakeys_core::types::{KeyType, ObjectClass as Class};

    /// Checks two properties of a bundle's text. First, `Bundle::parse` either reads the text or
    /// refuses it as invalid (exit 17), and it never panics. Second, when the text reads, the
    /// bundle is written again with `to_toml`, and that text reads back as the same bundle, so
    /// `import` reads whatever `export` writes.
    ///
    /// # Panics
    ///
    /// When either property does not hold.
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

    /// Reads a key file's bytes once for each kind of object (a P-256 private key, a P-256 public
    /// key, a certificate, an AES key and a data object), with the fixtures' passphrase. Each read
    /// either succeeds or is refused as invalid (exit 17) or unsupported (exit 15), and it never
    /// panics. When a private key reads, the shape scan `holds_private_key` must also report that
    /// the bytes hold a private key. That scan keeps the import of a certificate from decoding a
    /// key without `--allow-host-plaintext`.
    ///
    /// # Panics
    ///
    /// When either property does not hold.
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
        /// Runs both checks on the fixtures: the sample bundle and every key file. The fuzzer's
        /// random bytes rarely form a file that reads, so the fixtures cover what random input
        /// seldom reaches.
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

/// Move keys between PKCS#11 tokens, and check them against keys.lock (docs/CAMIGRATE.md). Every
/// verb names its direction: `--from` names the token that holds the objects, and `--to` names the
/// token that they go to.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Declarative input (keys.toml).
    #[arg(short, long, env = "CAKEYS_CONFIG")]
    config: PathBuf,
    /// The lock file (keys.lock). It defaults to the config path with a `.lock` extension. It must
    /// exist, unless --new-lock is given.
    #[arg(short, long, env = "CAKEYS_LOCK")]
    lock: Option<PathBuf>,
    /// Override a token's PKCS#11 module: `<token>=<path>` (repeatable).
    #[arg(long = "module", value_name = "TOKEN=PATH")]
    modules: Vec<String>,
    /// Start a new lock file when none exists. Without this flag, a missing lock file is refused
    /// (exit 17), so a mistyped --lock path never creates a second lock.
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
    /// Export objects that are realised on --from, in the form that the destination needs. The
    /// output is a bundle for `import` on --to, in which the keys are sealed to the transport key
    /// of --to and the public objects are copied as they are. With --to-transport-file, the keys
    /// are sealed to the key in that transport file instead. With --to-key-file, the output is one
    /// key in a passphrase-protected key file. With --dry-run, print for each object the method,
    /// the exposure of the material during the move, and the reason when the object cannot move.
    /// Named objects export all or nothing: if one of them cannot move, the export fails and
    /// writes nothing.
    #[command(group(clap::ArgGroup::new("destination").args(["to", "to_key_file"]).required(true)))]
    Export {
        /// The objects to export. The default is every object realised on --from that can move.
        /// The export warns about each object that cannot move, except an object whose spec sets
        /// `noExport` and a token's transport key.
        objects: Vec<String>,
        /// The token the objects are on.
        #[arg(long)]
        from: String,
        /// The token in keys.toml that the bundle is for. Its capabilities are read from the open
        /// token, or else from what the lock recorded for the token, or else from its transport
        /// file.
        #[arg(long)]
        to: Option<String>,
        /// The transport file (written by `camigrate transport`) of --to, for a token that this
        /// host cannot reach. The file must belong to that token, and it must name the transport
        /// key that the lock pins on that token.
        #[arg(long, value_name = "FILE", requires = "to")]
        to_transport_file: Option<PathBuf>,
        /// Export one key to a passphrase-protected key file of this format. This needs --out and
        /// --passphrase-file.
        #[arg(long, value_enum)]
        to_key_file: Option<FileArg>,
        /// The file to write the bundle to (the default is stdout), or the key file to write.
        #[arg(long)]
        out: Option<PathBuf>,
        /// A file that holds the passphrase (one line) under which the key file is encrypted.
        #[arg(long, value_name = "FILE", requires = "to_key_file")]
        passphrase_file: Option<PathBuf>,
        /// The spec of the transport key on the destination token. The default is that token's
        /// `transportWith`.
        #[arg(long, value_name = "SPEC", conflicts_with = "to_key_file")]
        transport_spec: Option<String>,
        /// Allow the key's plaintext in this process's memory. A key file needs this flag.
        #[arg(long, requires = "to_key_file")]
        allow_host_plaintext: bool,
        /// Print the plan and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Import objects onto --to. With --in and a bundle that `export` wrote, import each key under
    /// the spec that realises its object on --to, and unwrap it with the transport key that is
    /// realised there. With --in and a key file, import its key as the object that the lock pins
    /// with that key's identity. Without --in, import each object for which a pair on --to says
    /// `origin = "file"`, from its object's `migrate.file` (docs/FILE.md). Each object is checked
    /// against the lock before the token is touched, and it is recorded in the lock with its
    /// origin. Each object is handled on its own: an object that fails leaves nothing on the
    /// token, and the other objects still import. The run exits with the code of the first
    /// failure, or with 22 if it recorded any object in the lock. The row of each failed object
    /// shows that object's exit code. Print the outcome of each object as a JSON array.
    Import {
        /// Without --in, the objects to import from their files. The default is every object for
        /// which a pair on --to says `origin = "file"`.
        #[arg(conflicts_with = "input")]
        objects: Vec<String>,
        /// The token they go to.
        #[arg(long)]
        to: String,
        /// The spec under which to realise an object, when the object has several specs on --to
        /// (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        /// A bundle or a key file. camigrate tells them apart by the content of the file.
        #[arg(long = "in", value_name = "FILE")]
        input: Option<PathBuf>,
        /// The spec on --to of the bundle's transport key, as the export named it. The default is
        /// the `transportWith` of --to. A bundle sealed to any other key is refused.
        #[arg(long, value_name = "SPEC", requires = "input")]
        transport_spec: Option<String>,
        /// A file that holds the passphrase of an encrypted key file. Without --in, the passphrase
        /// applies to every encrypted file, and it overrides the passphrase that keys.toml names.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
        /// Allow a key file's plaintext in this process's memory. A key file needs this flag.
        #[arg(long)]
        allow_host_plaintext: bool,
        /// Check each object against the lock and the token, and import nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move objects from --from to --to. Both tokens must be reachable from this host. Each object
    /// is created on --to and recorded in the lock with its origin. Public objects are copied as
    /// they are. Keys are sealed to the transport key of --to, so they pass through the host only
    /// in wrapped form. Each object is handled on its own: an object that fails is undone, and the
    /// other objects still move. Print the outcome of each object as a JSON array, or print the
    /// plan with --dry-run.
    Migrate {
        /// The objects to move. The default is every object realised on --from.
        objects: Vec<String>,
        /// The token they are on.
        #[arg(long)]
        from: String,
        /// The token they go to.
        #[arg(long)]
        to: String,
        /// The spec under which to realise an object on --to, when the object has several specs
        /// there (repeatable).
        #[arg(long)]
        spec: Vec<String>,
        #[command(flatten)]
        how: MoveArgs,
    },
    /// Write the transport file of a token's transport key. The transport key is an RSA private
    /// key on that token that may unwrap, and it is realised and locked. Exports to the token seal
    /// their keys to it. With --trust-on, instead make the security officer of the --trust-on
    /// token trust the transport key, so that the keys on that token that are marked
    /// wrap-with-trusted can be wrapped under this key and under nothing else.
    Transport {
        /// The object of the transport key. The default is the token's `migrate.transportWith`.
        object: Option<String>,
        /// The spec of the transport key, when the object has several specs on --token.
        #[arg(long)]
        spec: Option<String>,
        /// The token the transport key is on.
        #[arg(long)]
        token: String,
        /// The file to write the transport file to. The default is stdout.
        #[arg(long, conflicts_with = "trust_on")]
        out: Option<PathBuf>,
        /// The source token on which the security officer creates a copy of the transport key
        /// that is marked `CKA_TRUSTED`. The SO logs in with the token's `soCredentialFile` or
        /// `soCredentialEnv`, and the copy is made from the public key that the lock records.
        #[arg(long, value_name = "SOURCE")]
        trust_on: Option<String>,
    },
}

/// The flags that control how `migrate` may move material. `export` takes the same flags.
#[derive(clap::Args)]
struct MoveArgs {
    /// Print the plan and move nothing.
    #[arg(long)]
    dry_run: bool,
    /// The spec of the transport key on --to. The default is the `transportWith` of --to.
    #[arg(long, value_name = "SPEC")]
    transport_spec: Option<String>,
    /// The value of the global `--json` flag, which prints the plan as JSON.
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

/// Returns the definition of the command line: its verbs and flags, with the table of exit codes
/// after the help. It is used for parsing, and by the test that checks that an integration test
/// uses every flag (`tests/common/surface.rs`).
#[must_use]
pub fn command() -> clap::Command {
    cakeys_cli_common::with_exit_codes(<Cli as clap::CommandFactory>::command())
}

/// Runs the command line with the given providers, and maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parses the arguments, loads keys.toml and the lock, and runs the verb. Before the verb runs,
/// it refuses a run that would write a lock that it cannot write, and an admin operation inside a
/// Nix build, where camigrate never writes (docs/CAMIGRATE.md D8).
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let mut cli: Cli = cakeys_cli_common::parse(command());
    if let Cmd::Migrate { how, .. } = &mut cli.cmd {
        how.json = cli.json;
    }
    let opener = Opener::load(&cli.config, &cli.modules, registry, notes)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    // The file given to `import --in` is read first, to tell a key file from a bundle by its
    // content (review 2026-11-23 C-6). The decisions below depend on which kind of file it is.
    let key_file = match &cli.cmd {
        Cmd::Import { input: Some(path), .. } => {
            let bytes = std::fs::read(path).map_err(KmError::io(format_args!("reading {}", path.display())))?;
            (!Bundle::is_bundle(&bytes)).then_some(path.as_path())
        }
        _ => None,
    };
    // A real `migrate` or `import` writes the lock. Such a run holds the advisory sidecar lock
    // from the load to the save, as cakeys' writing verbs do. A real `export` does not write the
    // lock, but it is also an admin operation (D8).
    let writes = matches!(&cli.cmd, Cmd::Migrate { how, .. } if !how.dry_run)
        || matches!(&cli.cmd, Cmd::Import { dry_run: false, .. });
    let exports = matches!(&cli.cmd, Cmd::Export { dry_run: false, .. });
    // A key file is decrypted into this process's memory, even when the run only checks it
    // (--dry-run). An `import` without --in also decrypts each object's own file.
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
    /// Runs `export`. It prints a plan (`--dry-run`), writes a bundle for a token or for a
    /// transport file, or writes one key file.
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

/// Refuses an admin operation inside a Nix build. The admin operations are a real export, the read
/// of a key file and a trust grant. cakeys refuses a writing run inside a Nix build in the same
/// way, with the same exit code, 21 (review 2026-11-23 C-12).
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

/// Returns the spec of the transport key that the `transport` verb names on `token`. When the
/// object or `--spec` is given, the spec is the pair that this address selects, as cakeys' verbs
/// select it (`[<object>] [--spec]`). Otherwise, the spec is the token's `migrate.transportWith`.
///
/// # Errors
///
/// `Validation` (17) for a name that keys.toml does not contain, for an address that matches no
/// pair on `token`, or for a token that names no transport key when the address is left out.
/// `Ambiguous` (12) for an object that has several specs on `token`.
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

/// Checks the flags of an `import --in` of a key file. The import needs `--allow-host-plaintext`,
/// because the key passes through this process's memory. It takes no `--transport-spec`, because
/// nothing in a key file is sealed.
///
/// # Errors
///
/// `Unsupported` (15) without `--allow-host-plaintext`. `Validation` (17) when `--transport-spec`
/// is given.
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

/// The state that a verb works with after the arguments are parsed: keys.toml and the token
/// opener, the lock, and the lock's path.
struct Run<'a> {
    opener: Opener<'a>,
    lock: Lock,
    lock_path: PathBuf,
}

/// The parts of one move command, as the command line provides them: the objects that move, the
/// source, the destination, the `--spec` values, and the move flags. Before review 2026-11-23
/// C-23, four functions took these parts as separate arguments.
struct MoveCtx<'a> {
    /// The named objects. An empty list means every object realised on `from`.
    objects: &'a [&'a str],
    /// The source token.
    from: &'a str,
    dest: &'a tokens::Dest<'a>,
    /// The `--spec` values: the pairs under which objects are realised on a target token.
    specs: &'a [String],
    how: &'a MoveArgs,
}

impl MoveCtx<'_> {
    /// Returns which of its plans the run takes ([`tokens::Take`]). The dry run and the real run
    /// base their verdicts on the same value.
    fn take(&self) -> tokens::Take {
        tokens::Take::of(self.objects, self.dest)
    }
}

/// The record of a verb's run over its objects. `import`, `migrate` and `import` from files share
/// it; before review D8, each verb kept its own. Each object is handled on its own, so an object
/// that fails leaves nothing behind and the other objects still move. The record holds the
/// outcome of each object, which is printed as the run's result (review 2026-11-23 C-7), whether
/// any object changed the lock, and the first failure. The run exits with the code of the first
/// failure, unless it changed the lock. In that case, it exits with 22, and the failure's code
/// appears only in that object's row. A row is cakeys' row ([`cakeys_cli_common::Outcome`]: its
/// exit code, the rule that refused it and whether the device failed), with the method by which
/// the object moved added to it.
#[derive(Default)]
struct Tally {
    changed: bool,
    failed: Option<KmError>,
    results: Vec<cakeys_cli_common::Outcome>,
}

/// The object that an outcome belongs to: its name, the spec under which it is realised on the
/// target (once that is known), and the token.
#[derive(Clone, Copy)]
struct Of<'a> {
    object: &'a str,
    spec: Option<&'a str>,
    token: &'a str,
}

impl<'a> Of<'a> {
    /// Returns the object that the pair `t` realises.
    fn pair(t: &'a Target<'a>) -> Of<'a> {
        Of { object: t.object_name, spec: Some(t.spec_name), token: t.token_name }
    }

    /// Returns an object whose target pair is not known yet.
    fn object(object: &'a str, token: &'a str) -> Of<'a> {
        Of { object, spec: None, token }
    }

    /// Returns the object's row, marked as passed with `outcome`. The spec is empty when it is
    /// not known yet.
    fn row(self, outcome: &str) -> cakeys_cli_common::Outcome {
        cakeys_cli_common::Outcome::passed(self.object, self.spec.unwrap_or_default(), self.token, outcome)
    }
}

impl Tally {
    /// Records the outcome of `of` (`imported`, `moved`, `already-there` or `ready`), and the
    /// method by which it moved, if it moved.
    fn done(&mut self, of: Of<'_>, outcome: &str, method: Option<&str>) {
        let mut row = of.row(outcome);
        row.more.insert("method".into(), method.into());
        self.results.push(row);
    }

    /// Records that `of` is ready to move by `method`, except for the checks in `deferred`, which
    /// only the real run decides. The row names these checks, so that a real run that fails one
    /// of them still matches what the dry run reported
    /// (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4).
    fn ready(&mut self, of: Of<'_>, method: &str, deferred: &[(&str, &str)]) {
        self.done(of, "ready", Some(method));
        if let Some(row) = self.results.last_mut() {
            row.deferred = deferred
                .iter()
                .map(|(rule, why)| cakeys_cli_common::DeferredRow { rule: (*rule).to_owned(), why: (*why).to_owned() })
                .collect();
        }
    }

    /// Records that `of` was written (with `outcome`, by `method`), and that the lock changed.
    fn moved(&mut self, of: Of<'_>, outcome: &str, method: Option<&str>) {
        self.changed = true;
        self.done(of, outcome, method);
    }

    /// Records that `of` failed with `err`. It prints the failure now, after `what`, and it keeps
    /// `err` when it is the run's first failure.
    fn fail(&mut self, of: Of<'_>, what: impl std::fmt::Display, err: KmError, notes: &mut Notes) {
        notes.say(format!("{what}: {err}"));
        // A material mismatch (exit 10, check `identity.material`) is reported as
        // `import.identity`, which is the name under which the dry run defers this check to the
        // real run.
        let err = if err.check() == Some(Check::IdentityMaterial) { err.with_check(sealed::IDENTITY) } else { err };
        let row = of.row("failed").refused_by(Some(&err));
        self.results.push(cakeys_cli_common::Outcome { error: Some(err.to_string()), ..row });
        self.failed.get_or_insert(err);
    }

    /// Records that `of` was written (with `outcome`, by `method`), and saves the lock at once,
    /// before the run touches another object. The save is atomic. Therefore, a run that is killed
    /// or that fails later never leaves an object on a token without a record in the lock. This
    /// matters because cakeys cannot remove an object from a ykcs11 token. The function returns
    /// `true` when the save succeeds. When the save fails, the failure becomes the object's
    /// failure, with exit code 21 and the rule `lock-writable`, and its message says how to
    /// record the object once the lock can be written (`hint`, from [`public::unrecorded_hint`]).
    /// The function then returns `false`, and the run moves nothing more. [`Tally::finish`] still
    /// prints every row, and the run exits with the code of the first failure, or with 22 if an
    /// earlier object was recorded in the lock. Before review 2026-11-24 D-9, a failed save
    /// returned early and lost the rows and the failure of an earlier object.
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

    /// Prints the outcome of each object, says that the lock was written if any object moved, and
    /// then returns the first failure. `cakeys_cli_common::main` turns that failure into exit 22
    /// if any object moved, because the lock was then written. Each move has already saved the
    /// lock ([`Tally::record`]), so this function does not write it again (review 2026-11-23
    /// C-21).
    fn finish(self, run: &Run<'_>, notes: &mut Notes) -> anyhow::Result<()> {
        print(&self.results)?;
        if self.changed {
            notes.lock_written(&run.lock_path);
        }
        self.failed.map_or(Ok(()), |e| Err(e.into()))
    }
}

/// Prints the rows of a run that ends with the error `e` before it moves its first object. Each of
/// `objects` on `token` gets one failed row, with the exit code, the rule or check, and the reason
/// of `e`. The function then returns `e`, and the run exits with it. Before review 2026-11-24
/// L4b-1, the refusal appeared only on stderr, and no row named the objects.
fn unmoved(objects: &[impl AsRef<str>], token: &str, e: anyhow::Error) -> anyhow::Result<()> {
    let rows: Vec<cakeys_cli_common::Outcome> =
        objects.iter().map(|object| cakeys_cli_common::Outcome::failed(object.as_ref(), "", token, &e)).collect();
    print(&rows)?;
    Err(e)
}

/// Prints the rows of a `migrate` whose plans the verdict (`Moves::verdict`) refused with `e`
/// before anything moved. The row of a blocked plan's object fails with that plan's own refusal
/// ([`plan::Plan::refusal`]). The row of a ready plan's object says `ready`, not moved, because
/// named objects move all or none. The function then returns `e`, and the run exits with it
/// (review 2026-11-24 L4b-1).
fn refused_plans(moves: &tokens::Moves, token: &str, e: KmError) -> anyhow::Result<()> {
    let mut tally = Tally::default();
    for p in &moves.plans {
        let of = Of::object(&p.object, token);
        if p.ready {
            tally.done(of, "ready", p.method.as_ref().map(Method::name).as_deref());
        } else {
            let refusal = p.refusal(format!("{}: {}", p.object, p.reasons.join("; ")));
            let row = of.row("failed").refused_by(Some(&refusal));
            tally.results.push(cakeys_cli_common::Outcome { error: Some(refusal.to_string()), ..row });
        }
    }
    print(&tally.results)?;
    Err(e.into())
}

impl Run<'_> {
    /// Runs `--dry-run`. It plans the move of each object from `from` to `dest`, prints the plans
    /// (docs/CAMIGRATE.md D9), and ends with the same verdict as the real run
    /// ([`tokens::Moves::verdict`]). An export without names takes the objects that can move, and
    /// it fails only when no object can move. A `migrate` writes on its target, so its dry run
    /// opens that token with the access of a dry-run write. A write-protected target is therefore
    /// refused (15), as the real run's open refuses it (review 2026-11-24 L4a-3). When a token did
    /// not open and the plan took its capabilities from the lock, the dry run opens the token
    /// again after the verdict, as the real run opens it, and fails as the real run fails. Before
    /// review 2026-11-24 L4b-4, a source that did not open was planned as ready, and its real run
    /// exited 16.
    fn plan_moves(&self, ctx: &MoveCtx, notes: &mut Notes) -> anyhow::Result<()> {
        let source = self.opener.open(ctx.from, Access::Read, notes);
        let target = if let tokens::Dest::Token(_) = ctx.dest { Access::DryWrite } else { Access::Read };
        let (moves, source, opened) = self.plan(ctx, Show::Stdout, source, target, notes)?;
        moves.verdict(ctx.take(), ctx.from)?;
        if source.is_none() {
            self.opener.open(ctx.from, Access::Read, notes)?;
        }
        if let (tokens::Dest::Token(to), None) = (ctx.dest, opened) {
            self.opener.open(to, target, notes)?;
        }
        Ok(())
    }

    /// Runs a real `export`. It plans as `--dry-run` does, wraps every key to the target's
    /// transport key, and writes the keys as one bundle. The transport key's public key comes from
    /// the lock's record for the token, or else from the open token, or from a transport file that
    /// the lock pins. Public objects need no transport key, and a bundle of public objects alone
    /// is made without one. Named objects export all or nothing: an object that cannot move fails
    /// the export before anything is wrapped. Without names, every key that can move is exported,
    /// and the export warns about the others. The bundle is written whole or not at all, and
    /// nothing changes on either token.
    fn export(&self, ctx: &MoveCtx, out: Option<&Path>, notes: &mut Notes) -> anyhow::Result<()> {
        let MoveCtx { from, dest, how, .. } = *ctx;
        // The source is opened once, for both the plan and the wrap. A bundle's target token is
        // also opened once, for both the plan and the read of its transport key (review lib.rs
        // F5).
        let source = self.opener.open(from, Access::Scratch, notes);
        let (moves, source, planned_target) = self.plan(ctx, Show::No, source, Access::Read, notes)?;
        // Named objects export all or nothing. Without names, every object that can move is
        // exported, and each object that cannot move (for example, a key made non-extractable) is
        // left out with a warning. An object that is meant never to leave its token is removed
        // from the plans without a warning (`landing::block`).
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
            // A ready plan always has a method that a bundle can carry (`limit_bundle_plans`).
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
        // The transport key is the key that the lock binds to the named target, as in the plan.
        // The sealing code binds the key again, so no key is wrapped to a key that the lock does
        // not bind to that target, whatever the plan allowed (review 2026-11-24 D-1).
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

    /// Runs `import` of a bundle. It reads the bundle and then handles each key on its own. It
    /// checks the key against the lock and the token. Without --dry-run, it then imports the key
    /// under the spec that realises its object on `token`, and it records the key in the lock. A
    /// key that fails leaves nothing behind and is reported, and the other keys still import and
    /// are recorded. The run exits with the code of the first failure, or with 22 if it recorded
    /// any key in the lock.
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
        let parsed = Bundle::parse(&text, input)?;
        // An import that ends before its first key still prints a row for each key of the
        // bundle, with the exit code and the reason. Before review 2026-11-24 L4b-1, the refusal
        // appeared only on stderr. The rows use the object names that the file contains. These
        // names are not verified yet, and the rows use them only as names.
        let objects: Vec<String> = parsed.unverified().keys.iter().map(|e| e.object.clone()).collect();
        let ready = (|| -> anyhow::Result<_> {
            // The bundle must be made for `token`, from a source that keys.toml names, and it must
            // be sealed to the transport key that the lock binds to `token`. A bundle is never
            // accepted because it is sealed to the key that the file itself names (review
            // 2026-11-24 D-8).
            let bound = BoundBundle::from_file(parsed, cfg, &self.lock, token, transport_spec, notes)
                .map_err(|e| e.prefixed(input.display()))?;
            specs_select(cfg, specs, bound.bundle().keys.iter().map(|e| e.object.as_str()), token, MOVE)?;
            let access = if dry_run { Access::DryWrite } else { Access::Write };
            Ok((bound, opener.open(token, access, notes)?))
        })();
        let (bound, target) = match ready {
            Ok(ready) => ready,
            Err(e) => return unmoved(&objects, token, e),
        };
        let bundle = bound.bundle();
        let mut tally = Tally::default();
        // Keys are imported before public objects, so that a public key object finds the public
        // half that the import of its private key created.
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
            // The dry run checks a key as the import does. A key that is already realised on the
            // token is verified, and it is not refused because it occupies its own locator. A key
            // that the import would create must be a key that a bundle file can carry under the
            // key's binding.
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
                    // Only the real import unwraps a blob and learns which key the blob holds.
                    let sealed: &[(&str, &str)] = &[
                        (sealed::UNWRAPS.name(), "only the target's unwrap shows the blob is intact"),
                        (sealed::IDENTITY.name(), "only the unwrapped key shows it is the one the lock pins"),
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

    /// Runs a real `migrate`. It plans and prints the plans as `--dry-run` does. Before anything
    /// moves, it refuses the run when an object cannot move or needs a method that is not built
    /// yet, with the exit code of the first blocked plan's refusal (15, or the code of the rule
    /// that blocked the plan). It then moves each object and records it. A public object is copied
    /// as it is (phase 2). A key is sealed to the target's transport key, with the bundle in memory
    /// (phase 3), or it passes through the host on a host method (phase 4). Each object is handled
    /// on its own: an object that fails is undone and reported, and the other objects still move
    /// and are recorded. Before review D8, the run stopped at the first failure. The run exits
    /// with the code of the first failure, or with 22 if it recorded any object in the lock. A
    /// copy is never left on the target without its realisation in the lock.
    fn migrate(
        &mut self,
        objects: &[&str],
        from: &str,
        to: &str,
        specs: &[String],
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let dest = tokens::Dest::Token(to);
        let ctx = MoveCtx { objects, from, dest: &dest, specs, how };
        // A run that ends before its first move still prints a row for each object, with the exit
        // code and the reason. Before review 2026-11-24 L4b-1, the refusal appeared only on
        // stderr.
        let planned = specs_import(&self.opener.cfg, specs, to, MOVE).map_err(anyhow::Error::from).and_then(|()| {
            // The --spec values are checked before the plan, as the dry run checks them, so both
            // refuse a --spec whose pair on the target is not an import pair. Each token is opened
            // once, for both the plan and the moves. The target is opened read-write, because the
            // moves write there (review lib.rs F5).
            let source = self.opener.open(from, Access::Scratch, notes);
            self.plan(&ctx, Show::Notes, source, Access::Write, notes)
        });
        let (moves, source, planned) = match planned {
            Ok(planned) => planned,
            Err(e) => return unmoved(&self.named_or_locked(objects, from), to, e),
        };
        // The plan has already blocked each method that is not built yet, and `plan` has checked
        // every --spec.
        if let Err(e) = moves.verdict(ctx.take(), from) {
            return refused_plans(&moves, to, e);
        }
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        // Use the tokens that the plan opened. A token that the plan did not open is opened now,
        // so that the error says why it does not open.
        let sides = self.source(from, source, notes).and_then(|source| {
            let target = match planned {
                Some(t) => t,
                None => opener.open(to, Access::Write, notes)?,
            };
            Ok((source, target))
        });
        let (source, target) = match sides {
            Ok(sides) => sides,
            Err(e) => {
                let objects: Vec<String> = moves.plans.iter().map(|p| p.object.clone()).collect();
                return unmoved(&objects, to, e.into());
            }
        };
        let mut target = Some(target);
        // tpm2-pkcs11 sees an object that `tpm2_ptool` imported only after the token is opened
        // again. The closure drops the old token before it opens the new one.
        let reopen = |t: &mut Option<cakeys_pkcs11::Token>, notes: &mut Notes| -> cakeys_core::Result<()> {
            *t = None;
            *t = Some(opener.open(to, Access::Write, notes)?);
            Ok(())
        };
        let mut tally = Tally::default();
        // The transport key to which every sealed move wraps. It is bound to `to` and checked on
        // the target once (`BoundTransport::read` verifies it, including its proof of
        // possession). When the check fails, `sealing` stays empty, so the next sealed move checks
        // the key again and fails on its own.
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

    /// Returns whether the source's SO made a trusted copy (`transport --trust-on`) of the
    /// transport key to which `dest` seals. A source that did not open is planned from the lock,
    /// which records no trusted copy, so the result is then `false`. A lookup that fails on an
    /// open source is returned as an error, and it is never treated as "no copy".
    fn trusted_transport(
        &self,
        dest: &tokens::Dest<'_>,
        transport_spec: Option<&str>,
        source: &cakeys_core::Result<Token>,
    ) -> anyhow::Result<bool> {
        let (cfg, lock) = (&self.opener.cfg, &self.lock);
        // When no transport key is bound, the plan gives that as its own reason (`plan_moves`),
        // and the result here is `false`. A malformed transport key (a recorded key that does not
        // decode, or that is too small) is an error.
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

    /// Plans the move of each object, blocks each move that the run would refuse
    /// ([`landing::block`]), and shows the plans where `show` says. A real export shows no plan,
    /// because it may write the bundle to stdout. The target token is opened with `target`
    /// access. When it opens, it is returned together with the source, so a `migrate` that
    /// writes there opens it only once, read-write. Before review lib.rs F5, the target was
    /// opened read-only for the plan and then again for the run. A dry run also reads the object
    /// of each ready plan on the source, as the run reads it ([`landing::search`]). When the
    /// planning fails before the plans exist, the plan of each object is shown as blocked, with
    /// the failure as its reason, and the failure is returned. Before review 2026-11-24 L4b-1,
    /// such a dry run printed no plan.
    fn plan(
        &self,
        ctx: &MoveCtx,
        show: Show,
        source: cakeys_core::Result<Token>,
        target: Access,
        notes: &mut Notes,
    ) -> anyhow::Result<(tokens::Moves, Option<Token>, Option<Token>)> {
        let (mut moves, source, target) = match self.plans(ctx, source, target, notes) {
            Ok(planned) => planned,
            Err(e) => {
                let why = format!("{e:#}");
                let plans: Vec<plan::Plan> = self
                    .named_or_locked(ctx.objects, ctx.from)
                    .iter()
                    .map(|object| plan::Plan::unplanned(object, why.clone()))
                    .collect();
                let unknown = tokens::KnownFrom::Nowhere;
                let to = ctx.dest.name();
                let shown = Shown { from: ctx.from, to: &to, sides: [unknown, unknown], plans: &plans };
                shown.show(show, ctx.how.json, notes)?;
                return Err(e);
            }
        };
        // Whether the run refuses a --spec is decided from the plans as they were before the
        // search, so whether every plan is ready is computed here, before the search.
        let all_ready = moves.plans.iter().all(|p| p.ready);
        let searched = match (&source, ctx.how.dry_run) {
            (Some(tok), true) => landing::search(self, ctx, &mut moves, tok, notes),
            _ => Ok(()),
        };
        Shown::of(ctx.from, &moves).show(show, ctx.how.json, notes)?;
        // Every --spec must select an object that moves to the token. This is checked where the
        // run checks it: only when no plan is blocked, so that the 15 of a blocked plan comes
        // first. The check is here so that the dry run exits as the run does (D9). Before review
        // 2026-11-23 C-2, the dry run said ready for a --spec that the run refused.
        if let (false, Some(to), true) = (ctx.dest.bundle(), ctx.dest.to(), all_ready) {
            specs_select(&self.opener.cfg, ctx.specs, moves.plans.iter().map(|p| p.object.as_str()), to, MOVE)?;
        }
        searched?;
        Ok((moves, source, target))
    }

    /// Returns the plans of [`Self::plan`] before they are shown. It plans the move of each
    /// object ([`tokens::plan_moves`]) and blocks each move that the run would refuse
    /// ([`landing::block`]).
    fn plans(
        &self,
        ctx: &MoveCtx,
        source: cakeys_core::Result<Token>,
        target: Access,
        notes: &mut Notes,
    ) -> anyhow::Result<(tokens::Moves, Option<Token>, Option<Token>)> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let open = |name: &str, notes: &mut Notes| opener.open(name, target, notes);
        // The transport key is the key that the lock binds to the token that the operator named
        // with `--to`, also when the key comes from a transport file (review 2026-11-24 D-1). It
        // is the key that --transport-spec names, or else that token's transportWith.
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
        Ok((moves, source, target))
    }

    /// Returns the objects that a run names, or else every object that the lock realises on
    /// `from`. A run that fails before its plans exist shows a plan or a row for each of these
    /// objects (review 2026-11-24 L4b-1). The list is empty when the lock realises nothing on
    /// `from`.
    fn named_or_locked(&self, objects: &[&str], from: &str) -> Vec<String> {
        if !objects.is_empty() {
            return objects.iter().map(|o| (*o).to_owned()).collect();
        }
        tokens::materials(&self.lock, from, &[])
            .map(|found| found.iter().map(|m| m.object.to_owned()).collect())
            .unwrap_or_default()
    }

    /// Returns the source token `from` for a real run. It is the token that [`Self::plan`]
    /// opened, or else the token is opened now, so that the error says why it does not open.
    fn source(&self, from: &str, planned: Option<Token>, notes: &mut Notes) -> cakeys_core::Result<Token> {
        planned.map_or_else(|| self.opener.open(from, Access::Scratch, notes), Ok)
    }
}

/// Where the plans are shown: nowhere (a real export), on stdout as the dry run's result, or with
/// the notes on stderr (a real `migrate`, whose stdout holds the outcome of each object).
#[derive(Clone, Copy)]
enum Show {
    No,
    Stdout,
    Notes,
}

/// The plans of one invocation as they are shown: the source token, the destination, where the
/// capabilities of each side came from, and the plans.
struct Shown<'a> {
    from: &'a str,
    to: &'a str,
    sides: [tokens::KnownFrom; 2],
    plans: &'a [plan::Plan],
}

impl<'a> Shown<'a> {
    /// Returns the plans of `moves`, from the token `from`.
    fn of(from: &'a str, moves: &'a tokens::Moves) -> Shown<'a> {
        Shown { from, to: &moves.to, sides: [moves.source_from, moves.target_from], plans: &moves.plans }
    }

    /// Shows the plans where `show` says: as a table or as JSON (`json`) on stdout, or as a table
    /// with the notes.
    fn show(&self, show: Show, json: bool, notes: &mut Notes) -> anyhow::Result<()> {
        match show {
            Show::No => {}
            Show::Stdout if json => {
                let [source, target] = self.sides;
                print(&serde_json::json!({
                    "from": self.from,
                    "to": self.to,
                    "capabilities": { "from": source.name(), "to": target.name() },
                    "plans": self.plans,
                }))?;
            }
            Show::Stdout => {
                for line in self.lines() {
                    println!("{line}");
                }
            }
            Show::Notes => {
                for line in self.lines() {
                    notes.say(line);
                }
            }
        }
        Ok(())
    }

    /// Returns the plans as a table, as a list of lines.
    fn lines(&self) -> Vec<String> {
        let (from, to_name) = (self.from, self.to);
        let [source_from, target_from] = self.sides.map(tokens::KnownFrom::name);
        let mut lines = vec![format!(
            "{from} -> {to_name} (capabilities: {from} from the {source_from}, {to_name} from the {target_from})"
        )];
        for p in self.plans {
            let method = p.method.as_ref().map_or_else(|| "-".to_owned(), Method::name);
            let exposure = p.exposure.map_or("-", Exposure::name);
            let status = if p.ready { "ready" } else { "blocked" };
            lines.push(format!("  {:<24} {method:<26} {exposure:<9} {status}", p.object));
            lines.extend(p.reasons.iter().map(|r| format!("      - {r}")));
            lines.extend(p.notes.iter().map(|n| format!("      note: {n}")));
        }
        lines
    }
}

impl Run<'_> {
    /// Runs `transport --trust-on`. The source's SO creates a `CKA_TRUSTED` copy of the transport
    /// key that is realised as `spec` on `token`. The copy is made from the public key that the
    /// lock records, so the lock authenticates the key, and a file never does. The key must pass
    /// the same transport-key checks as on every other path (`BoundTransport`; review 2026-11-24
    /// D-10). When the source already trusts the key, nothing is done. The function warns about
    /// any other trusted object on the source, because a `CKA_WRAP_WITH_TRUSTED` key can be
    /// wrapped under any trusted object, so `enforced` is only as narrow as that set of objects.
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

/// Refuses a move into `token` when keys.toml gives the token no user PIN. A move must see every
/// object under the target locator, and only a logged-in session sees them all (docs/CAMIGRATE.md
/// D6). The refusal comes before any plan, in the dry run as in the real run.
fn needs_login(cfg: &Config, token: &str) -> cakeys_core::Result<()> {
    match cfg.tokens.get(token) {
        Some(t) if t.pin_file.is_none() && t.pin_env.is_none() => Err(KmError::Unavailable(
            format!(
                "token '{token}' has no user PIN, and a session without login cannot tell a target locator is free; \
             configure pinFile or pinEnv"
            )
            .into(),
        )
        .with_rule(cakeys_pkcs11::ops::Rule::NeedsLogin)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    /// Checks that a build with the patched binding, which names `CKM_AES_KEY_WRAP_KWP` (the Nix
    /// build uses this binding), also enables the `kwp` feature that uses that mechanism. With the
    /// patch but without the feature, camigrate would plan a method that the run cannot perform.
    #[test]
    fn the_kwp_feature_comes_with_the_patched_binding() {
        assert!(
            !cakeys_pkcs11::binding::patched() || cfg!(feature = "kwp"),
            "the patched cryptoki is linked without camigrate's `kwp` feature (nix/package-common.nix features)"
        );
    }

    /// Checks that the row of a failed pair names the check that refused it when no rule refused
    /// it. Before review 2026-11-24 L4b, the rows of `migrate` with exit 12 named nothing. A
    /// material that is not the locked one (exit 10) names `import.identity`, the name under which
    /// a dry run defers that check, and a transport key mismatch keeps its own check.
    #[test]
    fn a_refused_row_names_its_check() {
        use cakeys_core::{Check, KmError, Reason};
        let mut tally = super::Tally::default();
        let mut notes = cakeys_core::reconcile::Notes::default();
        let of = super::Of::object("o", "t");
        let several = KmError::Ambiguous(Reason::check(Check::LocatorUnique, "2 objects under the locator"));
        tally.fail(of, "o", several, &mut notes);
        let mismatch = KmError::HashMismatch {
            what: "o".into(),
            expected: "sha256-a".into(),
            got: "sha256-b".into(),
            check: Check::IdentityMaterial,
        };
        tally.fail(of, "o", mismatch, &mut notes);
        let transport = KmError::HashMismatch {
            what: "transport key".into(),
            expected: "sha256-a".into(),
            got: "sha256-b".into(),
            check: Check::ImportTransport,
        };
        tally.fail(of, "o", transport, &mut notes);
        let rows: Vec<(u8, Option<&str>)> = tally.results.iter().map(|r| (r.exit, r.rule.as_deref())).collect();
        assert_eq!(
            rows,
            [(12, Some("locator.unique")), (10, Some("import.identity")), (10, Some("import.transport"))],
            "{:?}",
            tally.results
        );
    }

    /// Returns the numbers in `text` that are whole words, which are the codes that an exit-code
    /// list names.
    fn codes(text: &str) -> std::collections::BTreeSet<u8> {
        text.split(|c: char| !c.is_ascii_alphanumeric()).filter_map(|w| w.parse().ok()).collect()
    }

    /// Checks that `--help` lists every exit code from the one shared table. Review lib.rs F8
    /// found that the help left out 10, 12, 13 and 21, and review 2026-11-23 C-10 found that each
    /// tool had its own list.
    #[test]
    fn the_help_lists_the_documented_exit_codes() {
        let help = super::command().render_help().to_string();
        let help = &help[help.find("Exit codes").expect("the help lists exit codes")..];
        let all: std::collections::BTreeSet<u8> = cakeys_core::EXIT_CODES.iter().map(|(c, _)| *c).collect();
        assert_eq!(codes(help), all, "{help}");
    }
}
