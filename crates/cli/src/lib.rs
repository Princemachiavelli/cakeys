//! The `cakeys` command line (README.md, "Three tools"): it pins and verifies. As a
//! library so a downstream binary can link extra provider crates:
//! `cakeys::main(&cakeys::default_registry().with(MyProvider))`.

use cakeys_cli_common::{Opener, print, read_lock, save_changed, token_cfg};
use cakeys_core::KmError;
use cakeys_core::config::{Config, Lock, gc, save_lock};
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::ops::{self, LockWrite, Notes, Target};
use cakeys_pkcs11::token::{Access, pin_ref, provider_pem, with_query};
use cakeys_pkcs11::{Registry, Token};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

pub use cakeys_cli_common::default_registry;

/// Content-addressed identity for PKCS#11 objects.
///
/// Exit codes: 0 ok, 10 hash mismatch, 11 not found,
/// 12 ambiguous, 13 conflict, 14 precondition failed, 15 unsupported, 16 unavailable,
/// 17 invalid spec, 18 first use (nothing pinned yet: record the `got:` hash), 19 already
/// exists (`create` on a key that is there and not pinned), 20 objects failed (`check --token`: each failure
/// listed with its own code), 1 other.
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
        #[command(flatten)]
        at: Address,
    },
    /// Find the object and compare it with the lock, recording what it lacks (missing hashes,
    /// realisation details) and what changed around it unless --no-update-lock; never
    /// overwriting a hash. Never creates the object: `create` does.
    Lock {
        #[command(flatten)]
        at: Address,
        #[command(flatten)]
        write: LockWriteArgs,
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
        at: Address,
        /// Print what would be created, verified, skipped or refused, and why, as JSON; open no
        /// token and write nothing. Exits 15 when a pair is refused (0 with --skip-unsupported).
        #[arg(long)]
        dry_run: bool,
        /// Create the pairs the profiles allow and warn about the ones they refuse, instead of
        /// refusing the run.
        #[arg(long)]
        skip_unsupported: bool,
        #[command(flatten)]
        write: LockWriteArgs,
    },
    /// Delete by locator if it holds the expected identity, and remove its realisation from the
    /// lock unless --no-update-lock. Absent is success.
    Delete {
        #[command(flatten)]
        at: Address,
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
    /// Pseudo-FOD pre-use check (also `verify`): verifies the object against the lock in a
    /// read-only session and prints its URI on stdout. `<object>.id.<scheme>` asks for one
    /// identity scheme, which the lock must pin. Never writes, the lock or the token. With
    /// --token alone (no object, no --spec), checks every object keys.toml places on that token
    /// and prints the token's module file; when any fails, each failure goes to stderr with its
    /// own exit code and the run exits 20.
    #[command(visible_alias = "verify")]
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

/// What a verb acts on, the same for every verb (docs/CAKEYS.md): an object, narrowed by the
/// spec and the token when keys.toml realises it more than once. A name keys.toml lacks is 17.
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
    /// The object named, for every verb but `check`: a name, never `<object>.id.<scheme>`.
    fn plain_object(&self) -> Result<Option<&str>, KmError> {
        match self.object.as_deref() {
            Some(o) if ops::split_reference(o).1.is_some() => {
                Err(KmError::Validation(format!("'{o}': only check takes <object>.id.<scheme>").into()))
            }
            object => Ok(object),
        }
    }

    /// The one (spec, token) pair named; `.id.<scheme>` is `check`'s alone.
    fn pair(&self, cfg: &Config) -> Result<(String, String), KmError> {
        cfg.address(self.plain_object()?, self.spec.as_deref(), self.token.as_deref())
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

/// Whether `lock`/`delete` write the lock: by default they do, like `nix build` with
/// `flake.lock`. Where the lock cannot be written (a Nix build sandbox, a read-only lock or
/// directory) the run is refused up front unless `--no-update-lock` says so explicitly.
#[derive(clap::Args)]
struct LockWriteArgs {
    /// Compare with the lock only; never write it (first use is then exit 18 with `got:`).
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

/// A token `check` opened, holding attestation chains to `when` ([`ValidityArgs`]).
fn checked_open(tok: cakeys_core::Result<Token>, when: cakeys_pkcs11::ChainTime) -> cakeys_core::Result<Token> {
    tok.map(|mut tok| {
        tok.chain_time = when;
        tok
    })
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

/// Parse the arguments, then load keys.toml and the lock — refusing up front a run that may write
/// a lock it cannot — and run the verb.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let opener = Opener::load(&cli.config, &cli.modules, registry, notes)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    let writes = match &cli.cmd {
        Cmd::Create { dry_run: true, .. } => false,
        Cmd::Lock { write, .. } | Cmd::Create { write, .. } | Cmd::Delete { write, .. } => {
            write.mode() == LockWrite::Record
        }
        Cmd::Gc { apply } => *apply,
        _ => false,
    };
    let opt_out = if matches!(cli.cmd, Cmd::Gc { .. }) { "drop --apply" } else { "pass --no-update-lock" };
    // Held to the end of the run.
    let (lock, _update_guard) = read_lock(&lock_path, writes, &format!("{opt_out} to compare without writing"))?;
    Run { opener, lock, lock_path }.verb(&cli.cmd, notes)
}

/// What a verb works with once the arguments are parsed: keys.toml, the lock and where it is
/// saved, and how tokens are opened.
struct Run<'a> {
    opener: Opener<'a>,
    lock: Lock,
    lock_path: PathBuf,
}

impl Run<'_> {
    fn verb(&mut self, cmd: &Cmd, notes: &mut Notes) -> anyhow::Result<()> {
        match cmd {
            Cmd::Validate => self.validate(notes),
            Cmd::Resolve { at } => {
                let (spec, token) = at.pair(&self.opener.cfg)?;
                let t = Target::new(&self.opener.cfg, &spec, &token)?;
                let tok = self.opener.open(&token, Access::Read, notes)?;
                let r = ops::resolve(&t, &tok, &self.lock)?
                    .ok_or_else(|| KmError::NotFound(format!("{} on {token}", t.object_name).into()))?;
                print(&r)
            }
            Cmd::Lock { at, write } => {
                let (spec, token) = at.pair(&self.opener.cfg)?;
                let t = Target::new(&self.opener.cfg, &spec, &token)?;
                // Never creates: read-write where the token allows (the session objects a
                // wrap-rebind copy or a proof makes), read-only on a write-protected one.
                let tok = self.opener.open(&token, Access::Scratch, notes)?;
                let (r, changed) = ops::lock(&t, &tok, &mut self.lock, write.mode(), notes)?;
                self.save(changed, notes)?;
                print(&r)
            }
            Cmd::Create { at, dry_run, skip_unsupported, write } => {
                let how = CreateHow { dry_run: *dry_run, skip_unsupported: *skip_unsupported, write: write.mode() };
                self.create(at, how, notes)
            }
            Cmd::Delete { at, if_match, write } => {
                let (spec, token) = at.pair(&self.opener.cfg)?;
                let t = Target::new(&self.opener.cfg, &spec, &token)?;
                let tok = self.opener.open(&token, Access::Write, notes)?;
                let changed = ops::delete(&t, &tok, &mut self.lock, if_match.as_deref(), write.mode(), notes)?;
                self.save(changed, notes)
            }
            Cmd::Gc { apply } => {
                let stale = gc(&self.opener.cfg, &mut self.lock, *apply);
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
            Cmd::Check { at, format, uri_module, uri_pin, validity } => {
                let when = validity.chain_time(notes)?;
                self.check(at, *format, *uri_module, *uri_pin, when, notes)
            }
        }
    }

    /// `check`: the verified URI as the consumer asked for it. The lock's URI stays the bare
    /// locator; the module and PIN are only ever added here, on request.
    fn check(
        &mut self,
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
        let open = |name: &str, access| checked_open(opener.open_quiet(name, access), when);
        let (r, tok) = ops::check_open(cfg, reference, spec, token, open, &self.lock, notes)?;
        let uri = with_query(&r.uri, uri_module.then_some(tok.module.path.as_str()), pin.as_ref());
        if !key_file {
            println!("{uri}");
            return Ok(());
        }
        // pkcs11-provider finds a private key's public half by CKA_ID alone: without one, a
        // module whose private key carries no public point (SoftHSM) gives OpenSSL no public key.
        let t = Target::new(cfg, &r.spec, &r.token)?;
        if tok.key_id(t.object, &t.on_token.locator, t.on_token.public_only)?.is_none() {
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
        let open = |name: &str, access| checked_open(opener.open_quiet(name, access), when);
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

    /// `validate`: each token's options (with a named provider), then the static gate
    /// (docs/CAPROBE.md) — each target's needs against its token's capability
    /// profiles, resolved from keys.toml and the lock. No token is opened.
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
        let mut refusals = Vec::new();
        for (spec_name, spec) in &self.opener.cfg.specs {
            for token in spec.tokens.keys() {
                let t = Target::new(&self.opener.cfg, spec_name, token)?;
                let mode = ops::plan_mode(&t)?;
                println!("{spec_name} on {token}: mode {mode}");
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
        if refusals.is_empty() {
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
    fn create(&mut self, at: &Address, how: CreateHow, notes: &mut Notes) -> anyhow::Result<()> {
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let (object, spec, token) = (at.plain_object()?, at.spec.as_deref(), at.token.as_deref());
        let planned = ops::plan_create(cfg, object, spec, token, &self.lock, opener.registry)?;
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
            notes.say(format!("updated {}", lock_path.display()));
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
