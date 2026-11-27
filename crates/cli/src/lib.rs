//! The `cakeys` command line (README.md, "Three tools"), which pins and verifies the identity of
//! PKCS#11 objects. It is built as a library, so that a downstream binary can link extra provider
//! crates: `cakeys::main(&cakeys::default_registry().with(MyProvider))`.

use cakeys_cli_common::{DeferredRow, Opener, Outcome, print, read_lock, refused, save_changed, token_cfg};
use cakeys_core::KmError;
use cakeys_core::config::{Config, Lock, gc, save_lock};
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::Registry;
use cakeys_pkcs11::ops::{self, LockWrite, Notes, Target};
use cakeys_pkcs11::token::{Access, pin_ref, provider_pem, with_query};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

pub use cakeys_cli_common::default_registry;

/// Content-addressed identity for PKCS#11 objects (docs/CAKEYS.md).
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Declarative input (keys.toml).
    #[arg(short, long, env = "CAKEYS_CONFIG")]
    config: PathBuf,
    /// Lock file (default: the config path with `.lock`).
    #[arg(short, long, env = "CAKEYS_LOCK")]
    lock: Option<PathBuf>,
    /// Override a token's PKCS#11 module (repeatable).
    #[arg(long = "module", value_name = "TOKEN=PATH")]
    modules: Vec<String>,
    /// Start a new lock file when none exists, instead of exiting 17.
    #[arg(long, global = true, help_heading = "Global options")]
    new_lock: bool,
    /// Print the `validate` and `gc` reports as JSON.
    #[arg(long, global = true, help_heading = "Global options")]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

/// The verbs. The first paragraph of each doc comment is the one line that `cakeys --help` and
/// `-h` show; `cakeys <verb> --help` shows every paragraph.
#[derive(Subcommand)]
enum Cmd {
    /// Check keys.toml statically, without opening any token.
    ///
    /// Check each spec's identity modes, opt-ins and types.
    Validate,
    /// Find an object by its locator, and print its identity as JSON.
    ///
    /// Never write to the lock or to the token.
    Resolve {
        #[command(flatten)]
        at: Address,
    },
    /// Compare objects with the lock, and record what the lock lacks.
    ///
    /// Find each object and compare it with the lock. Record what the lock lacks (missing
    /// hashes, realisation details) and what changed around the object, but never overwrite a
    /// hash. Never create an object; `create` does that.
    ///
    /// Print each object's identity as a JSON array.
    Lock {
        #[command(flatten)]
        at: Addresses,
        /// Compare with the lock only, and write nothing.
        ///
        /// A first use then exits 18, and its message shows the identity after `got:`.
        #[arg(long)]
        dry_run: bool,
    },
    /// Create the keys that keys.toml declares, and record them in the lock.
    ///
    /// No other verb creates keys; `lock` creates only the TPM Attestation Key that a realisation
    /// needs. For every selected (spec, token) pair with origin = "create" whose object the lock
    /// does not pin yet, create the object, and then record it as `lock` does. A pair whose object
    /// the lock already pins is verified as `check` verifies it, and is otherwise left alone. The
    /// other pairs are skipped with a note.
    ///
    /// When nothing is named, every pair is selected. When one pair is named (an object or
    /// --spec, and --token), create or verify it, or say why not.
    ///
    /// Before any token is opened, each pair is checked against the capability profiles. If the
    /// profiles say that a pair cannot be created, the whole run is refused (exit 15), and nothing
    /// is created. If a key that the lock does not pin already exists under the pair's locator,
    /// the run stops (exit 19); `lock` records such a key.
    ///
    /// Print the created objects as JSON.
    Create {
        #[command(flatten)]
        at: Addresses,
        /// Print what would be done and why, as JSON, and write nothing.
        ///
        /// Each pair would be created, verified, skipped or refused. The tokens are opened
        /// read-only. Exit 15 when a pair is refused (0 with --skip-unsupported).
        #[arg(long)]
        dry_run: bool,
        /// Create the pairs that the profiles allow, and warn about the pairs that they refuse,
        /// instead of refusing the whole run.
        #[arg(long)]
        skip_unsupported: bool,
        /// Create the keys, but record nothing in the lock.
        ///
        /// The run is then a first use, which a person can review before `lock` records it.
        #[arg(long, conflicts_with = "dry_run")]
        no_update_lock: bool,
    },
    /// Delete objects that hold the expected identity.
    ///
    /// Delete each object by its locator if it holds the expected identity, and remove its
    /// realisation from the lock. An absent object counts as success.
    ///
    /// Print what happened to each object as a JSON array.
    Delete {
        #[command(flatten)]
        at: Addresses,
        /// Expected CA-ID of the one object named. It defaults to the CA-ID that the lock pins.
        #[arg(long)]
        if_match: Option<String>,
        /// Identify each object and check it as a delete would; destroy and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the lock entries whose spec or object is gone from keys.toml.
    ///
    /// Print each entry that is removed.
    Gc {
        /// Print the stale entries, and remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify an object against the lock, and print its URI.
    ///
    /// Verify the object before it is used, in a read-only session. Never write to the lock or to
    /// the token. `<object>.id.<scheme>` asks for one identity scheme, which the lock must pin.
    ///
    /// With --token alone (no object and no --spec), check every object that keys.toml places on
    /// that token, and print the token's module file. When any object fails, write each failure to
    /// stderr with its own exit code, and exit 20.
    Check {
        #[command(flatten)]
        at: Address,
        /// The output format.
        #[arg(long, value_enum, default_value_t = Format::Uri)]
        format: Format,
        /// Add `module-path=` with the module file that the check loaded.
        ///
        /// p11-kit and libp11 read it; pkcs11-provider takes its module from its own
        /// configuration.
        #[arg(long)]
        uri_module: bool,
        /// Add the user PIN.
        #[arg(long, value_enum)]
        uri_pin: Option<UriPin>,
        #[command(flatten)]
        validity: ValidityArgs,
    },
}

/// The time at which a key's attestation chain must be valid under `check` (ISSUES.md B8).
/// Every certificate of the chain, from the slot's certificate to the pinned root, must be
/// within its validity period at that time.
#[derive(clap::Args)]
struct ValidityArgs {
    /// Check the attestation chain's dates at this time instead of now.
    ///
    /// The dates are those of the chain's certificates. The format is RFC 3339 in UTC:
    /// YYYY-MM-DDTHH:MM:SSZ. It is meant for a host clock that is wrong, or for the time at which
    /// the lock was recorded.
    #[arg(long, value_name = "TIME", conflicts_with = "ignore_validity")]
    at: Option<String>,
    /// Do not check the attestation chain's certificate dates; a note says so.
    #[arg(long)]
    ignore_validity: bool,
}

impl ValidityArgs {
    /// Returns the time against which the chain's dates are checked: the `--at` time, or else
    /// the system clock's time (never `SOURCE_DATE_EPOCH`). With `--ignore-validity`, it adds a
    /// note and returns `Unchecked`.
    fn chain_time(&self, notes: &mut Notes) -> cakeys_core::Result<cakeys_pkcs11::ChainTime> {
        if self.ignore_validity {
            notes.note(format_args!("check: the attestation chain's certificate dates are not checked"));
            return Ok(cakeys_pkcs11::ChainTime::Unchecked);
        }
        self.at.as_deref().map_or_else(|| Ok(cakeys_pkcs11::ChainTime::now()), cakeys_pkcs11::ChainTime::parse)
    }
}

/// The target of a verb with one result (docs/CAKEYS.md): an object, narrowed by the spec and
/// the token when keys.toml realises it more than once. A name that keys.toml lacks is refused
/// with exit 17.
#[derive(clap::Args)]
struct Address {
    /// The object (`[objects.<name>]`), which may be left out when --spec names it.
    ///
    /// `check` also takes `<object>.id.<scheme>`. A `check` of every object on --token leaves the
    /// object out.
    object: Option<String>,
    /// The spec that realises the object, when several specs do.
    #[arg(long)]
    spec: Option<String>,
    /// The token that holds the object, when several tokens do.
    #[arg(long)]
    token: Option<String>,
}

impl Address {
    /// Returns the one (spec, token) pair that the address names. Only `check` accepts
    /// `.id.<scheme>`, so this function refuses it.
    fn pair(&self, cfg: &Config) -> Result<(String, String), KmError> {
        cfg.address(plain(self.object.as_deref())?, self.spec.as_deref(), self.token.as_deref())
    }
}

/// The targets of `lock`, `create` and `delete`: several objects, each narrowed by the specs
/// that realise it and by the token. Each one is the same kind of address as an [`Address`].
#[derive(clap::Args)]
struct Addresses {
    /// The objects (`[objects.<name>]`). They may be left out when --spec names them.
    objects: Vec<String>,
    /// A spec that realises one of the objects (repeatable).
    ///
    /// Name one when the object has several specs. When no object is named, the spec selects its
    /// own object.
    #[arg(long)]
    spec: Vec<String>,
    /// The token that holds the objects, when several tokens do.
    #[arg(long)]
    token: Option<String>,
}

/// An object and one of its specs, either of which may be left out (`Addresses::units`).
type Unit<'a> = (Option<&'a str>, Option<&'a str>);

impl Addresses {
    /// Returns each object with the specs named for it, or each spec alone when no object is
    /// named, or `(None, None)` when nothing is named. A spec that realises none of the named
    /// objects is refused with exit 17.
    fn units<'a>(&'a self, cfg: &Config) -> Result<Vec<Unit<'a>>, KmError> {
        for o in &self.objects {
            plain(Some(o))?;
        }
        if self.objects.is_empty() {
            if self.spec.is_empty() {
                return Ok(vec![(None, None)]);
            }
            return Ok(self.spec.iter().map(|s| (None, Some(s.as_str()))).collect());
        }
        let mut units = Vec::new();
        for o in &self.objects {
            let mut specs = self.spec.iter().filter(|s| cfg.specs.get(s.as_str()).is_some_and(|c| c.object == *o));
            match specs.next() {
                None => units.push((Some(o.as_str()), None)),
                Some(first) => {
                    units.push((Some(o.as_str()), Some(first.as_str())));
                    units.extend(specs.map(|s| (Some(o.as_str()), Some(s.as_str()))));
                }
            }
        }
        // A --spec that realises none of the named objects is refused. An unknown spec gets the
        // error that `Config::address` gives for it, as the pair of that spec alone would.
        if let Some(s) = self.spec.iter().find(|s| !units.iter().any(|(_, u)| *u == Some(s.as_str()))) {
            let Some(c) = cfg.specs.get(s.as_str()) else {
                cfg.address(None, Some(s), self.token.as_deref())?;
                return Err(KmError::Validation(format!("unknown spec '{s}'").into()));
            };
            let named: Vec<String> = self.objects.iter().map(|o| format!("'{o}'")).collect();
            return Err(KmError::Validation(
                format!("spec '{s}' realises '{}', not {}", c.object, named.join(" or ")).into(),
            ));
        }
        Ok(units)
    }

    /// Returns the (spec, token) pair of each unit ([`Config::address`]), without duplicates.
    fn pairs(&self, cfg: &Config) -> Result<Vec<(String, String)>, KmError> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (object, spec) in self.units(cfg)? {
            let pair = cfg.address(object, spec, self.token.as_deref())?;
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
        }
        Ok(pairs)
    }
}

/// Checks `object` in the form that every verb except `check` takes: a plain name, never
/// `<object>.id.<scheme>`.
fn plain(object: Option<&str>) -> Result<Option<&str>, KmError> {
    match object {
        Some(o) if ops::split_reference(o).1.is_some() => {
            Err(KmError::Validation(format!("'{o}': only check takes <object>.id.<scheme>").into()))
        }
        object => Ok(object),
    }
}

/// What `check` prints. `check --help` lists each value with its doc comment.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    /// The PKCS#11 URI.
    Uri,
    /// pkcs11-provider's key file that wraps the URI (the file that its `uri2pem.py` writes), for
    /// programs that take a private key only as a PEM file and load it through OpenSSL with
    /// pkcs11-provider.
    Pkcs11ProviderPem,
}

/// How `check` puts the user PIN in the URI. `check --help` lists each value with its doc comment.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum UriPin {
    /// Refer to keys.toml's pinEnv (`pin-source=env:`, a pkcs11-provider extension) or pinFile
    /// (`pin-source=file:`).
    Source,
    /// Write the PIN itself (`pin-value=`) into the output, wherever the output goes.
    Value,
}

/// Returns the command line's definition: its verbs and flags, with the exit codes after its
/// help. It is used for parsing, and by the test that checks that an integration test uses every
/// flag (`tests/common/surface.rs`).
#[must_use]
pub fn command() -> clap::Command {
    cakeys_cli_common::with_exit_codes(<Cli as clap::CommandFactory>::command())
}

/// Runs the command line with the given providers, and maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parses the arguments, loads keys.toml and the lock, and runs the verb. Before any token is
/// opened, it refuses a run that would write a lock that it cannot write, and it refuses a
/// missing lock file unless --new-lock is given.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli: Cli = cakeys_cli_common::parse(command());
    let mut opener = Opener::load(&cli.config, &cli.modules, registry, notes)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    let (writes, instead) = match &cli.cmd {
        Cmd::Create { dry_run, no_update_lock, .. } => {
            (!dry_run && !no_update_lock, "pass --no-update-lock to create without recording, or --dry-run")
        }
        Cmd::Lock { dry_run, .. } | Cmd::Delete { dry_run, .. } | Cmd::Gc { dry_run } => {
            (!dry_run, "pass --dry-run to compare without writing")
        }
        _ => (false, ""),
    };
    // The update guard is held until the end of the run.
    let (lock, _update_guard) = read_lock(&lock_path, cli.new_lock, writes, instead)?;
    // `create`'s gate and its generation decide by what earlier runs on the token itself
    // demonstrated (the observations in the lock), as `validate` does. No other verb's verdict
    // uses an observation (docs/LOCK.md).
    if matches!(cli.cmd, Cmd::Create { .. }) {
        opener.recall(&lock);
    }
    Run { opener, lock, lock_path, json: cli.json }.verb(&cli.cmd, notes)
}

/// The state that a verb works with after the arguments are parsed: keys.toml, the lock, the path
/// where the lock is saved, and the way in which tokens are opened.
struct Run<'a> {
    opener: Opener<'a>,
    lock: Lock,
    lock_path: PathBuf,
    /// `--json`: print the reports as JSON.
    json: bool,
}

impl Run<'_> {
    fn verb(&mut self, cmd: &Cmd, notes: &mut Notes) -> anyhow::Result<()> {
        match cmd {
            Cmd::Validate => self.validate(notes),
            Cmd::Resolve { at } => {
                let (spec, token) = at.pair(&self.opener.cfg)?;
                let t = Target::new(&self.opener.cfg, &spec, &token)?;
                let tok = self.opener.open(&token, Access::Read, notes)?;
                let r = ops::resolve(&t, &tok, &self.lock, notes)?
                    .ok_or_else(|| KmError::NotFound(format!("{} on {token}", t.object_name).into()))?;
                print(&r)
            }
            Cmd::Lock { at, dry_run } => {
                let write = if *dry_run { LockWrite::Compare } else { LockWrite::Record };
                let mut locked = Vec::new();
                let result = self.each(at, &mut locked, notes, |opener, lock, t, notes| {
                    // `lock` never creates an object. It opens the token read-write where the
                    // token allows it, because a wrap-rebind copy or a proof creates session
                    // objects, and read-only on a write-protected token.
                    let tok = opener.open(t.token_name, Access::Scratch, notes)?;
                    let (r, changed) = ops::lock(t, &tok, lock, write, notes)?;
                    let word = if *dry_run { "compared" } else { "locked" };
                    Ok((Outcome::passed(t.object_name, t.spec_name, t.token_name, word).with(&r)?, changed))
                });
                print(&locked)?;
                result
            }
            Cmd::Create { at, dry_run, skip_unsupported, no_update_lock } => {
                let write = if *no_update_lock { LockWrite::Compare } else { LockWrite::Record };
                let how = CreateHow { dry_run: *dry_run, skip_unsupported: *skip_unsupported, write };
                self.create(at, how, notes)
            }
            Cmd::Delete { at, if_match, dry_run } => {
                if if_match.is_some() && at.pairs(&self.opener.cfg)?.len() > 1 {
                    return Err(KmError::Validation(
                        "--if-match is one object's identity: name one object, or leave it out to expect each \\
                         one's locked identity"
                            .into(),
                    )
                    .into());
                }
                let access = if *dry_run { Access::DryWrite } else { Access::Write };
                let mut deleted = Vec::new();
                let result = self.each(at, &mut deleted, notes, |opener, lock, t, notes| {
                    let tok = opener.open(t.token_name, access, notes)?;
                    let (outcome, changed) = ops::delete(t, &tok, lock, if_match.as_deref(), *dry_run, notes)?;
                    Ok((Outcome::passed(t.object_name, t.spec_name, t.token_name, outcome.name()), changed))
                });
                print(&deleted)?;
                result
            }
            Cmd::Gc { dry_run } => {
                let stale = gc(&self.opener.cfg, &mut self.lock, !dry_run);
                if self.json {
                    print(&stale)?;
                } else {
                    for entry in &stale {
                        println!("{entry}");
                    }
                }
                if stale.is_empty() {
                    notes.note("gc: nothing to collect: every lock entry is named by the config");
                } else if *dry_run {
                    notes.note(format_args!("gc: {} stale entries; run without --dry-run to remove them", stale.len()));
                } else {
                    notes.say(format!("gc: removed {} stale entries", stale.len()));
                }
                self.save(!dry_run && !stale.is_empty(), notes)
            }
            Cmd::Check { at, format, uri_module, uri_pin, validity } => {
                let when = validity.chain_time(notes)?;
                self.check(at, *format, *uri_module, *uri_pin, when, notes)
            }
        }
    }

    /// `check`: prints the verified URI in the form that the consumer asked for. The lock's URI
    /// stays the bare locator. The module path and the PIN are added only here, and only on
    /// request.
    fn check(
        &self,
        at: &Address,
        format: Format,
        uri_module: bool,
        uri_pin: Option<UriPin>,
        when: cakeys_pkcs11::ChainTime,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let (reference, spec, token) = (at.object.as_deref(), at.spec.as_deref(), at.token.as_deref());
        if let (None, None, Some(token)) = (reference, spec, token) {
            if format != Format::Uri || uri_module || uri_pin.is_some() {
                return Err(KmError::Validation(
                    "check --token alone prints the module file, not a URI: --format, --uri-module and --uri-pin \
                     need an object"
                        .into(),
                )
                .into());
            }
            return self.check_token(token, when, notes);
        }
        // These checks refuse a bad address, and an output format that cannot hold the result,
        // before any token is opened.
        let object = reference.map(|r| ops::split_reference(r).0);
        let (spec_name, token_name) = cfg.address(object, spec, token)?;
        let object = &cfg.specs[&spec_name].object;
        let key_file = format == Format::Pkcs11ProviderPem;
        if key_file && cfg.objects.get(object).is_some_and(|o| o.class != ObjectClass::PrivateKey) {
            return Err(KmError::Unsupported(
                format!(
                    "--format pkcs11-provider-pem for '{object}': pkcs11-provider's key files name private keys only"
                )
                .into(),
            )
            .into());
        }
        let pin = match uri_pin {
            None => None,
            Some(how) => Some(pin_ref(&token_name, token_cfg(cfg, &token_name)?, how == UriPin::Value)?),
        };
        let open = |name: &str, access| opener.open_quiet(name, access, when);
        // Pass the pair that was resolved above, so that `check_open` cannot choose another pair.
        let (spec, token) = (Some(spec_name.as_str()), Some(token_name.as_str()));
        let (r, tok) = ops::check_open(cfg, reference, spec, token, open, &self.lock, notes)?;
        let uri = with_query(&r.uri, uri_module.then_some(tok.module.path.as_str()), pin.as_ref());
        if !key_file {
            println!("{uri}");
            return Ok(());
        }
        // pkcs11-provider finds a private key's public half by CKA_ID alone. Without a CKA_ID, a
        // module whose private key holds no public point (SoftHSM) gives OpenSSL no public key.
        let t = Target::new(cfg, &r.spec, &r.token)?;
        if tok.key_id(&t.object, &t.on_token.locator, t.on_token.public_only)?.is_none() {
            notes.warn(format!(
                "'{object}' on '{}' has no CKA_ID: pkcs11-provider finds a private key's public half by \
                 CKA_ID, so unless the module puts the public key on the private object, OpenSSL cannot \
                 get the public key from this key file (to match a certificate, or `openssl pkey -pubout`)",
                r.token
            ));
        }
        print!("{}", provider_pem(&uri)?);
        Ok(())
    }

    /// `check --token`: checks every object that keys.toml places on the token, in one session.
    /// If all objects pass, it prints the module file that the check loaded on stdout. If any
    /// object fails, it prints nothing on stdout, prints each failure on stderr after its own
    /// exit code, and exits 20.
    fn check_token(&self, token: &str, when: cakeys_pkcs11::ChainTime, notes: &mut Notes) -> anyhow::Result<()> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let open = |name: &str, access| opener.open_quiet(name, access, when);
        let (checked, tok) = ops::check_token(cfg, token, open, &self.lock, notes)?;
        let failed: Vec<(&ops::PairCheck, &KmError)> =
            checked.iter().filter_map(|c| c.result.as_ref().err().map(|e| (c, e))).collect();
        if failed.is_empty() {
            println!("{}", tok.module.path);
            return Ok(());
        }
        for (c, e) in &failed {
            eprintln!("exit {}: '{}' (spec '{}'): {e}", e.exit_code(), c.object, c.spec);
        }
        Err(KmError::ObjectsFailed(
            format!("{} of {} on token '{token}', each listed above with its exit code", failed.len(), checked.len())
                .into(),
        )
        .into())
    }

    /// Save the lock if the verb changed it.
    fn save(&self, changed: bool, notes: &mut Notes) -> anyhow::Result<()> {
        save_changed(&self.lock_path, &self.lock, changed, notes)
    }

    /// Runs `verb` on each pair that `at` names, in order. For each pair, it pushes the pair's
    /// row to `out`, and it saves the lock if the verb changed it, before it moves to the next
    /// pair. The first failure ends the run, after the work on the earlier pairs, and the failed
    /// pair's row is pushed too ([`Outcome::failed`]). The caller therefore prints every pair's
    /// outcome in the same form, whatever ended the run (review 2026-11-23 C-7, 2026-11-24 C-1).
    /// If an earlier pair wrote the lock and a later pair fails, the run exits 22, and the failed
    /// pair's row holds the failure's code (`cakeys_cli_common::main`, review 2026-11-24 L5).
    fn each(
        &mut self,
        at: &Addresses,
        out: &mut Vec<Outcome>,
        notes: &mut Notes,
        mut verb: impl FnMut(&Opener<'_>, &mut Lock, &Target, &mut Notes) -> anyhow::Result<(Outcome, bool)>,
    ) -> anyhow::Result<()> {
        let Run { opener, lock, lock_path, .. } = self;
        for (spec, token) in at.pairs(&opener.cfg)? {
            let t = Target::new(&opener.cfg, &spec, &token)?;
            let done = verb(opener, lock, &t, notes).and_then(|(v, changed)| {
                save_changed(lock_path, lock, changed, notes)?;
                Ok(v)
            });
            match done {
                Ok(v) => out.push(v),
                Err(e) => {
                    out.push(Outcome::failed(t.object_name, &spec, &token, &e));
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// `validate`: checks each token's options (for a token with a named provider), and then runs
    /// the static gate (docs/CAPROBE.md). The gate checks each target's needs against its token's
    /// capability profiles, which are resolved from keys.toml and the lock. No token is opened.
    /// Each pair's mode is printed on stdout only when the run passes.
    fn validate(&self, notes: &mut Notes) -> anyhow::Result<()> {
        for (name, t) in &self.opener.cfg.tokens {
            let Some(p) = t.named_provider() else { continue };
            // A named provider also checks the token's options here. An auto-detected provider is
            // known only after the token is opened, so it can check the options only then.
            let provider = self.opener.registry.named(p)?.ok_or_else(|| {
                KmError::Validation(
                    format!(
                        "token '{name}': unknown provider '{p}' (registered: generic, {})",
                        self.opener.registry.names().join(", ")
                    )
                    .into(),
                )
            })?;
            provider.check_options(name, &t.options)?;
        }
        // A token whose stack does not resolve also goes through the gate. Each pair on it defers
        // its rules by name and says why (review 2026-11-24 B-1).
        let mut stacks = BTreeMap::new();
        for (name, t) in &self.opener.cfg.tokens {
            stacks.insert(name.as_str(), cakeys_pkcs11::gate::stack(name, t, &self.lock)?);
        }
        let (mut refusals, mut modes) = (Vec::new(), Vec::new());
        for (spec_name, spec) in &self.opener.cfg.specs {
            for token in spec.tokens.keys() {
                let t = Target::new(&self.opener.cfg, spec_name, token)?;
                let mode = ops::plan_mode(&t)?;
                modes.push((spec_name, token, mode.to_string()));
                let verb = ops::Verb::of(&t, &self.lock);
                let v = cakeys_pkcs11::gate::check(&t, mode, &stacks[token.as_str()], self.opener.registry, verb)?;
                for d in ops::deferred_lines(&v.deferred) {
                    notes.note(format_args!("validate: {d}"));
                }
                refusals.extend(v.refusals.into_iter().map(KmError::from));
            }
        }
        for (name, stack) in stacks.iter().filter_map(|(name, s)| Some((name, s.as_ref().ok()?))) {
            for n in &stack.resolved.notes {
                notes.note(format_args!("validate: token '{name}' ({}): {n}", stack.source));
            }
        }
        // stdout holds only the result: the modes of a run that passes, and nothing for a run
        // that fails.
        if refusals.is_empty() {
            if self.json {
                let rows: Vec<serde_json::Value> = modes
                    .iter()
                    .map(|(spec, token, mode)| serde_json::json!({"spec": spec, "token": token, "mode": mode}))
                    .collect();
                return print(&rows);
            }
            for (spec, token, mode) in &modes {
                println!("{spec} on {token}: mode {mode}");
            }
            return Ok(());
        }
        // The exit code is the refusal's own code when there is one refusal, or 20 when there are
        // several, and then each refusal is listed with its code.
        Err(refused(refusals, "refusals by the static gate").map_or_else(|| anyhow::anyhow!("no refusal"), Into::into))
    }

    /// `create`: decides what each selected pair gets before any token is opened
    /// ([`ops::plan_create`]). A pair that the profiles refuse ends the run at that point, unless
    /// `--skip-unsupported` is given. Then it creates or verifies the pairs. The lock file
    /// records each key as soon as it is created, so a later pair's failure, a failed save or a
    /// killed run never loses a key that was made earlier.
    fn create(&mut self, at: &Addresses, how: CreateHow, notes: &mut Notes) -> anyhow::Result<()> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let mut planned: Vec<ops::Planned> = Vec::new();
        for (object, spec) in at.units(cfg)? {
            for p in ops::plan_create(cfg, object, spec, at.token.as_deref(), &self.lock, opener.registry)? {
                if !planned.iter().any(|q| q.spec == p.spec && q.token == p.token) {
                    planned.push(p);
                }
            }
        }
        let refusing = planned.iter().filter(|p| p.action == ops::Action::Refuse).count();
        let stopped = refusing > 0 && !how.skip_unsupported;
        for p in &planned {
            for r in &p.reasons() {
                match p.action {
                    ops::Action::Skip => notes.note(format_args!(
                        "create: skipped '{}' (spec '{}') on token '{}': {r}",
                        p.object, p.spec, p.token
                    )),
                    ops::Action::Create | ops::Action::Verify => notes.note(format_args!("create: {r}")),
                    ops::Action::Refuse if how.skip_unsupported => {
                        notes.warn(format!("create: skipped, unsupported: {r}"));
                    }
                    // A refusal is reported once: as the run's error, or as one line with its
                    // code for each refusal ([`refused`]).
                    ops::Action::Refuse => {}
                }
            }
        }
        if how.dry_run {
            // The dry run also checks what the run would refuse after a token opens. For each
            // pair that the run would create or verify, it opens the token read-only, refuses it
            // where the write's open would refuse it (a write-protected token, 15: L4a-3), and
            // asks the token the same questions that the write asks (review 2026-11-24 C-4). A
            // run that the profiles stop opens no token, and neither does its dry run. A token
            // that fails (at its open, a login or a search) ends the dry run at that pair, as it
            // would end the run (16), and the pair's row says so (review 2026-11-24 L4a-2).
            if !stopped {
                let open = |name: &str, notes: &mut Notes| opener.open(name, Access::DryWrite, notes);
                ops::plan_on_tokens(cfg, &mut planned, &open, &self.lock, notes);
            }
            let rows: Vec<Outcome> = planned.iter().map(dry_row).collect::<anyhow::Result<_>>()?;
            print(&rows)?;
            if let Some(e) = planned.iter_mut().find_map(|p| p.failed.take()) {
                return Err(e.into());
            }
        }
        if stopped {
            let one = refusing == 1;
            notes.note(format_args!(
                "create: {refusing} pair{} cannot be created, as the capability profiles say{}; pass \
                 --skip-unsupported to create the others",
                if one { "" } else { "s" },
                if how.dry_run { "" } else { ": nothing was created" }
            ));
            let errors = planned.into_iter().flat_map(|p| p.refusals).map(KmError::from).collect();
            return Err(refused(errors, "refusals").map_or_else(|| anyhow::anyhow!("no refusal"), Into::into));
        }
        if how.dry_run {
            // The first refusal that the run would meet ends the dry run with its own exit code.
            // The other refusals are printed on stderr.
            let mut on_token = planned.into_iter().filter(|p| p.on_token).flat_map(|p| p.refusals);
            let first = on_token.next();
            for r in on_token {
                eprintln!("{r}");
            }
            return first.map_or(Ok(()), |r| Err(KmError::from(r).into()));
        }
        let ready: Vec<ops::Ready> = planned.iter().filter_map(ops::Planned::ready).collect();
        let open = |name: &str, notes: &mut Notes| opener.open(name, Access::Write, notes);
        // Each created key is recorded before the next pair is touched. What was created is
        // printed whatever ended the run, because that output is the only machine-readable
        // record of it.
        let lock_path = &self.lock_path;
        let mut persist = |lock: &Lock| save_lock(lock_path, lock).map_err(cakeys_cli_common::lock_rule);
        let done = ops::create_selected(cfg, &ready, &open, &mut self.lock, how.write, &mut persist, notes);
        if done.changed {
            notes.lock_written(lock_path);
        }
        // One row for each pair that the run reached, including the pair that failed (review
        // 2026-11-24 C-1).
        let (mut rows, mut failure) = (Vec::new(), None);
        for r in done.reached {
            let object = Target::new(cfg, r.spec, r.token)?.object_name;
            let mut row = match &r.made {
                Some(ops::Made::Created(res, _)) => Outcome::passed(object, r.spec, r.token, "created").with(res)?,
                Some(ops::Made::Verified(res)) => Outcome::passed(object, r.spec, r.token, "verified").with(res)?,
                None => Outcome::passed(object, r.spec, r.token, "failed"),
            };
            if let Some(e) = r.failed {
                let e = anyhow::Error::from(e);
                row = Outcome { more: row.more, ..Outcome::failed(object, r.spec, r.token, &e) };
                failure = Some(e);
            }
            rows.push(row);
        }
        print(&rows)?;
        failure.map_or(Ok(()), Err)
    }
}

/// Builds a `create --dry-run` row. The row holds what the run would do with the pair. When a
/// refusal applies, it holds the first refusal's exit code, rule and message. When the pair's
/// token failed, it holds `failed` with the failure's exit code, rule and device bit, as the
/// run's row would. It also holds the rules that only the run decides.
fn dry_row(p: &ops::Planned<'_>) -> anyhow::Result<Outcome> {
    let mut row = Outcome::passed(p.object, p.spec, p.token, p.action.name());
    if let Some(r) = p.refusals.first() {
        row = Outcome { error: Some(r.error.to_string()), ..row.refused_by(Some(&r.error)) };
    }
    if let Some(e) = &p.failed {
        row = Outcome { outcome: "failed".to_owned(), error: Some(e.to_string()), ..row.refused_by(Some(e)) };
    }
    row.deferred =
        p.deferred.iter().map(|d| DeferredRow { rule: d.rule.name().to_owned(), why: d.why.clone() }).collect();
    let refusals: Vec<serde_json::Value> = p
        .refusals
        .iter()
        .map(|r| serde_json::json!({"rule": r.rule.name(), "exit": r.error.exit_code(), "error": r.error.to_string()}))
        .collect();
    row.with(&serde_json::json!({"action": p.action.name(), "reasons": p.reasons(), "refusals": refusals}))
}

/// How `create` runs: its flags.
#[derive(Clone, Copy)]
struct CreateHow {
    dry_run: bool,
    skip_unsupported: bool,
    write: LockWrite,
}
