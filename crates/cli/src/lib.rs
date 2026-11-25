//! The `cakeys` command line (README.md, "Three tools"): it pins and verifies. As a
//! library so a downstream binary can link extra provider crates:
//! `cakeys::main(&cakeys::default_registry().with(MyProvider))`.

use cakeys_cli_common::{Opener, print, read_lock, save_changed, token_cfg};
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
    /// Print the reports (`validate`, `gc`) as JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the spec statically (identity modes, opt-ins, types). Touches no token.
    Validate,
    /// Find the object by its locator and print its identity as JSON. Never writes.
    Resolve {
        #[command(flatten)]
        at: Address,
    },
    /// Find each object and compare it with the lock, recording what it lacks (missing hashes,
    /// realisation details) and what changed around it; never overwriting a hash. Never creates
    /// an object: `create` does. Prints each object's identity, as a JSON array.
    Lock {
        #[command(flatten)]
        at: Addresses,
        /// Compare with the lock only; write nothing (a first use is then exit 18, with `got:`).
        #[arg(long)]
        dry_run: bool,
    },
    /// Create keys, the one verb that does: every selected (spec, token) pair with origin =
    /// "create" whose object the lock does not pin yet, then record them like `lock`; a pair
    /// whose object the lock pins is verified as `check` verifies it and left alone; the other
    /// pairs are skipped with a note. Nothing named selects every pair. Before any token is
    /// opened, each is checked against the capability profiles: a pair they say cannot be made
    /// refuses the whole run (15), and nothing is created. Naming one pair (an object or --spec,
    /// and --token) creates or verifies it, or says why not. A key the lock does not pin already
    /// under its locator stops the run (19): `lock` records it. Prints the created objects as
    /// JSON.
    Create {
        #[command(flatten)]
        at: Addresses,
        /// Print what would be created, verified, skipped or refused, and why, as JSON; open no
        /// token and write nothing. Exits 15 when a pair is refused (0 with --skip-unsupported).
        #[arg(long)]
        dry_run: bool,
        /// Create the pairs the profiles allow and warn about the ones they refuse, instead of
        /// refusing the run.
        #[arg(long)]
        skip_unsupported: bool,
        /// Create, but record nothing: a first use to review before `lock` records it.
        #[arg(long, conflicts_with = "dry_run")]
        no_update_lock: bool,
    },
    /// Delete each object by its locator if it holds the expected identity, and remove its
    /// realisation from the lock. Absent is success. Prints what happened to each, as a JSON
    /// array.
    Delete {
        #[command(flatten)]
        at: Addresses,
        /// Expected CA-ID of the one object named; defaults to the locked one.
        #[arg(long)]
        if_match: Option<String>,
        /// Identify each object and check it as a delete would; destroy and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the lock entries whose spec or object is gone from the config, printing each.
    Gc {
        /// Print them; remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify the object against the lock before it is used, in a read-only session, and print
    /// its URI. `<object>.id.<scheme>` asks for one identity scheme, which the lock must pin.
    /// Never writes, the lock or the token. With --token alone (no object, no --spec), checks
    /// every object keys.toml places on that token and prints the token's module file; when any
    /// fails, each failure goes to stderr with its own exit code and the run exits 20.
    Check {
        #[command(flatten)]
        at: Address,
        /// `uri`, or `pkcs11-provider-pem`: pkcs11-provider's key file (what its `uri2pem.py`
        /// writes) wrapping the URI, for programs that take a private key only as a PEM file
        /// and load it through OpenSSL with pkcs11-provider.
        #[arg(long, value_enum, default_value_t = Format::Uri)]
        format: Format,
        /// Add `module-path=` with the module file the check loaded (read by p11-kit and libp11;
        /// pkcs11-provider takes its module from its own configuration).
        #[arg(long)]
        uri_module: bool,
        /// Add the user PIN: `source` refers to keys.toml's pinEnv (`pin-source=env:`, a
        /// pkcs11-provider extension) or pinFile (`pin-source=file:`); `value` writes the PIN
        /// itself (`pin-value=`) into the output, wherever that goes.
        #[arg(long, value_enum)]
        uri_pin: Option<UriPin>,
        #[command(flatten)]
        validity: ValidityArgs,
    },
}

/// When a key's attestation chain must be valid under `check` (ISSUES.md B8): every
/// certificate of it, from the slot's to the pinned root, within its validity period.
#[derive(clap::Args)]
struct ValidityArgs {
    /// Judge the attestation chain's certificate dates at this time, not now (a host clock that
    /// is wrong, or the time the lock was recorded): RFC 3339 in UTC, YYYY-MM-DDTHH:MM:SSZ.
    #[arg(long, value_name = "TIME", conflicts_with = "ignore_validity")]
    at: Option<String>,
    /// Do not check the attestation chain's certificate dates; a note says so.
    #[arg(long)]
    ignore_validity: bool,
}

impl ValidityArgs {
    /// The time the chain is held to: the system clock's, never `SOURCE_DATE_EPOCH`.
    fn chain_time(&self, notes: &mut Notes) -> cakeys_core::Result<cakeys_pkcs11::ChainTime> {
        if self.ignore_validity {
            notes.note(format_args!("check: the attestation chain's certificate dates are not checked"));
            return Ok(cakeys_pkcs11::ChainTime::Unchecked);
        }
        self.at.as_deref().map_or_else(|| Ok(cakeys_pkcs11::ChainTime::now()), cakeys_pkcs11::ChainTime::parse)
    }
}

/// What a verb with one result acts on (docs/CAKEYS.md): an object, narrowed by the spec and the
/// token when keys.toml realises it more than once. A name keys.toml lacks is 17.
#[derive(clap::Args)]
struct Address {
    /// The object (`[objects.<name>]`); `check` also takes `<object>.id.<scheme>`. May be left
    /// out when --spec names it, or for `check` of every object on --token.
    object: Option<String>,
    /// The spec realising it, when several do.
    #[arg(long)]
    spec: Option<String>,
    /// The token it is on, when it is on several.
    #[arg(long)]
    token: Option<String>,
}

impl Address {
    /// The one (spec, token) pair named; `.id.<scheme>` is `check`'s alone.
    fn pair(&self, cfg: &Config) -> Result<(String, String), KmError> {
        cfg.address(plain(self.object.as_deref())?, self.spec.as_deref(), self.token.as_deref())
    }
}

/// What `lock`, `create` and `delete` act on: objects, each narrowed by the specs that realise
/// it and by the token, the same address as [`Address`], several times.
#[derive(clap::Args)]
struct Addresses {
    /// The objects (`[objects.<name>]`); may be left out when --spec names them.
    objects: Vec<String>,
    /// A spec realising one of the objects, where it has several (repeatable); with no object
    /// named, the spec's own object.
    #[arg(long)]
    spec: Vec<String>,
    /// The token they are on, when they are on several.
    #[arg(long)]
    token: Option<String>,
}

/// An object and a spec of it, either left out (`Addresses::units`).
type Unit<'a> = (Option<&'a str>, Option<&'a str>);

impl Addresses {
    /// Each object with the specs named for it, or each spec alone when no object is named;
    /// `(None, None)` when nothing is. A spec that realises none of the objects named is 17.
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
        // A --spec that is no named object's: said as the pair it would have been is.
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

    /// The (spec, token) pair of each unit ([`Config::address`]), each once.
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

/// `object` as every verb but `check` takes it: a name, never `<object>.id.<scheme>`.
fn plain(object: Option<&str>) -> Result<Option<&str>, KmError> {
    match object {
        Some(o) if ops::split_reference(o).1.is_some() => {
            Err(KmError::Validation(format!("'{o}': only check takes <object>.id.<scheme>").into()))
        }
        object => Ok(object),
    }
}

/// What `check` prints.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    Uri,
    Pkcs11ProviderPem,
}

/// How `check` puts the user PIN in the URI.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum UriPin {
    Source,
    Value,
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

/// Parse the arguments, then load keys.toml and the lock — refusing up front a run that may write
/// a lock it cannot, and a lock that is not there unless --new-lock — and run the verb.
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
    // Held to the end of the run.
    let (lock, _update_guard) = read_lock(&lock_path, cli.new_lock, writes, instead)?;
    // `create`'s gate and generation decide by what the token's own runs demonstrated, as
    // `validate` does; no other verb's verdict takes an observation (docs/LOCK.md).
    if matches!(cli.cmd, Cmd::Create { .. }) {
        opener.recall(&lock);
    }
    Run { opener, lock, lock_path, json: cli.json }.verb(&cli.cmd, notes)
}

/// What a verb works with once the arguments are parsed: keys.toml, the lock and where it is
/// saved, and how tokens are opened.
struct Run<'a> {
    opener: Opener<'a>,
    lock: Lock,
    lock_path: PathBuf,
    /// `--json`: the reports as JSON.
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
                    // Never creates: read-write where the token allows (the session objects a
                    // wrap-rebind copy or a proof makes), read-only on a write-protected one.
                    let tok = opener.open(t.token_name, Access::Scratch, notes)?;
                    let (r, changed) = ops::lock(t, &tok, lock, write, notes)?;
                    Ok((serde_json::to_value(r)?, changed))
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
                let access = if *dry_run { Access::Read } else { Access::Write };
                let mut deleted = Vec::new();
                let result = self.each(at, &mut deleted, notes, |opener, lock, t, notes| {
                    let tok = opener.open(t.token_name, access, notes)?;
                    let (outcome, changed) = ops::delete(t, &tok, lock, if_match.as_deref(), *dry_run, notes)?;
                    let row = serde_json::json!({
                        "object": t.object_name, "spec": t.spec_name, "token": t.token_name, "outcome": outcome.name(),
                    });
                    Ok((row, changed))
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

    /// `check`: the verified URI as the consumer asked for it. The lock's URI stays the bare
    /// locator; the module and PIN are only ever added here, on request.
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
        // Refused before any token is opened: the address, and what the output cannot carry.
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
        // The pair resolved above, so `check_open` cannot settle on another one.
        let (spec, token) = (Some(spec_name.as_str()), Some(token_name.as_str()));
        let (r, tok) = ops::check_open(cfg, reference, spec, token, open, &self.lock, notes)?;
        let uri = with_query(&r.uri, uri_module.then_some(tok.module.path.as_str()), pin.as_ref());
        if !key_file {
            println!("{uri}");
            return Ok(());
        }
        // pkcs11-provider finds a private key's public half by CKA_ID alone: without one, a
        // module whose private key carries no public point (SoftHSM) gives OpenSSL no public key.
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

    /// `check --token`: every object keys.toml places on the token, in one session. All pass:
    /// the module file the check loaded, on stdout. Any fails: nothing on stdout, each failure on
    /// stderr led by its own exit code, and 20.
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

    /// `verb` on each pair `at` names, in order, its result pushed to `out` and the lock saved
    /// when it changed it, before the next pair; the first failure ends the run, after what was
    /// done before it, and is pushed too (its object, spec, token, exit code and message), so the
    /// caller prints every pair's outcome whatever ended the run (review 2026-11-23 C-7).
    fn each(
        &mut self,
        at: &Addresses,
        out: &mut Vec<serde_json::Value>,
        notes: &mut Notes,
        mut verb: impl FnMut(&Opener<'_>, &mut Lock, &Target, &mut Notes) -> anyhow::Result<(serde_json::Value, bool)>,
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
                    let code = e.downcast_ref::<KmError>().map_or(1, KmError::exit_code);
                    out.push(serde_json::json!({
                        "object": t.object_name, "spec": spec, "token": token, "outcome": "failed",
                        "exit": code, "error": format!("{e:#}"),
                    }));
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// `validate`: each token's options (with a named provider), then the static gate
    /// (docs/CAPROBE.md) — each target's needs against its token's capability
    /// profiles, resolved from keys.toml and the lock. No token is opened. Each pair's mode goes
    /// to stdout only when the run passes.
    fn validate(&self, notes: &mut Notes) -> anyhow::Result<()> {
        for (name, t) in &self.opener.cfg.tokens {
            let Some(p) = t.named_provider() else { continue };
            // A named provider checks the token's options here too; an auto-detected one
            // can only be known, and check them, once the token is opened.
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
        let mut stacks = BTreeMap::new();
        for (name, t) in &self.opener.cfg.tokens {
            match cakeys_pkcs11::gate::stack(name, t, &self.lock)? {
                Ok(stack) => {
                    stacks.insert(name.as_str(), stack);
                }
                Err(why) => notes.note(format_args!("validate: {why}")),
            }
        }
        let (mut refusals, mut modes) = (Vec::new(), Vec::new());
        for (spec_name, spec) in &self.opener.cfg.specs {
            for token in spec.tokens.keys() {
                let t = Target::new(&self.opener.cfg, spec_name, token)?;
                let mode = ops::plan_mode(&t)?;
                modes.push((spec_name, token, mode.to_string()));
                if let Some(stack) = stacks.get(token.as_str()) {
                    let creates = ops::creates(&t, &self.lock);
                    let v = cakeys_pkcs11::gate::check(&t, mode, stack, self.opener.registry, creates)?;
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
        // stdout carries the result only: the modes of a run that passes, nothing of one that fails.
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
        for r in &refusals {
            eprintln!("{r}");
        }
        let one = refusals.len() == 1;
        Err(KmError::Unsupported(
            format!(
                "{} target{} need{} what the capability profiles say the token cannot do",
                refusals.len(),
                if one { "" } else { "s" },
                if one { "s" } else { "" }
            )
            .into(),
        )
        .into())
    }

    /// `create`: what each selected pair gets is decided before any token is opened
    /// ([`ops::plan_create`]); a pair the profiles refuse ends the run there unless
    /// `--skip-unsupported`. Then the pairs to create or verify; the lock file records each key
    /// as it is created, so a later pair's failure, a failed save or a killed run never loses
    /// one made before.
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
        let refused: Vec<&ops::Planned> = planned.iter().filter(|p| p.action == ops::Action::Refuse).collect();
        for p in &planned {
            for r in &p.reasons {
                match p.action {
                    ops::Action::Skip => notes.note(format_args!(
                        "create: skipped '{}' (spec '{}') on token '{}': {r}",
                        p.object, p.spec, p.token
                    )),
                    ops::Action::Create | ops::Action::Verify => notes.note(format_args!("create: {r}")),
                    ops::Action::Refuse if how.skip_unsupported => {
                        notes.warn(format!("create: skipped, unsupported: {r}"));
                    }
                    ops::Action::Refuse => eprintln!("{r}"),
                }
            }
        }
        if how.dry_run {
            let rows: Vec<serde_json::Value> = planned
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "spec": p.spec, "token": p.token, "object": p.object,
                        "action": p.action.name(), "reasons": p.reasons,
                    })
                })
                .collect();
            print(&rows)?;
        }
        if !refused.is_empty() && !how.skip_unsupported {
            let one = refused.len() == 1;
            return Err(KmError::Unsupported(
                format!(
                    "{} pair{} cannot be created, as the capability profiles say{}; pass --skip-unsupported to create \
                 the others",
                    refused.len(),
                    if one { "" } else { "s" },
                    if how.dry_run { "" } else { ": nothing was created" }
                )
                .into(),
            )
            .into());
        }
        if how.dry_run {
            return Ok(());
        }
        let pairs: Vec<(&str, &str)> = planned.iter().filter(|p| p.action.runs()).map(|p| (p.spec, p.token)).collect();
        let open = |name: &str, notes: &mut Notes| opener.open(name, Access::Write, notes);
        // Each created key is recorded before the next pair is touched; what was created is
        // printed whatever ended the run, the only machine-readable record of it.
        let lock_path = &self.lock_path;
        let mut persist = |lock: &Lock| save_lock(lock_path, lock);
        let done = ops::create_selected(cfg, &pairs, &open, &mut self.lock, how.write, &mut persist, notes);
        print(&done.created)?;
        if done.changed {
            notes.lock_written(lock_path);
        }
        done.failed.map_or(Ok(()), |e| Err(e.into()))
    }
}

/// How `create` runs: its flags.
#[derive(Clone, Copy)]
struct CreateHow {
    dry_run: bool,
    skip_unsupported: bool,
    write: LockWrite,
}
