//! The `cakeys` command line, as a library so a downstream binary can link extra provider
//! crates: `cakeys::main(&cakeys::default_registry().with(MyProvider))`.

use anyhow::Context;
use cakeys_core::KmError;
use cakeys_core::config::{Config, gc, load_config, load_lock, lock_for_update, lock_unwritable, save_lock};
use cakeys_core::migrate::{Exposure, Method, Side, Transport};
use cakeys_pkcs11::migrate::{self, Allow, FileFormat, Plan, To};
use cakeys_pkcs11::ops::{self, LockWrite, Notes, Target};
use cakeys_pkcs11::{Registry, Token, providers};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

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
    /// Print a token's provider and usable mechanisms as JSON.
    Caps {
        #[arg(long)]
        token: String,
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
    /// Ask the capability profiles what a vendor SO version supports (docs/PROVIDERS.md):
    /// pure data, no token touched. NAME is a mechanism (`CKM_*`), key type (`CKK_*`),
    /// parameter set (`CKP_*`) or curve; `--bits` asks for an RSA size; `--class` lists a
    /// baseline class; `--oaep` lists the wrap hashes. Exit 0 yes, 15 no, 16 unknown.
    Supports {
        /// What to ask about: `CKM_*`, `CKK_*`, `CKP_*` or a curve name.
        #[arg(required_unless_present_any = ["class", "oaep"])]
        name: Option<String>,
        /// The module profile, e.g. softhsm/2.7 (or its family, when only one is loaded).
        #[arg(long, conflicts_with = "token")]
        profile: Option<String>,
        /// The token in keys.toml whose `provider` names the profile family.
        #[arg(long)]
        token: Option<String>,
        /// A delta layer on top, repeatable: p11-kit/0.26, cryptoki/0.12-unpatched, swtpm.
        #[arg(long = "layer")]
        layers: Vec<String>,
        /// List the members of a baseline class (pq, hmac, key-wrap, oaep) with verdicts.
        #[arg(long)]
        class: Option<String>,
        /// List the RSA-OAEP hashes usable for wrapping.
        #[arg(long)]
        oaep: bool,
        /// An RSA modulus size to ask about (with a `CKK_RSA` query).
        #[arg(long)]
        bits: Option<u32>,
        /// A directory of extra or replacement profile files, read recursively (D11).
        #[arg(long = "profiles")]
        profiles_dir: Option<PathBuf>,
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

/// The providers this build links, in detection order. Built through the same public API a
/// third party uses; `tpm2` and `ykcs11` are cargo features (both on by default).
#[must_use]
pub fn default_registry() -> Registry {
    let registry = Registry::new().with(providers::SoftHsm).with(providers::Kryoptic);
    #[cfg(feature = "ykcs11")]
    let registry = registry.with(cakeys_ykcs11::Ykcs11);
    #[cfg(feature = "tpm2")]
    let registry = registry.with(cakeys_tpm2_pkcs11::Tpm2Pkcs11);
    registry.with(providers::P11Kit)
}

/// Run the CLI with the given providers; maps errors to the documented exit codes.
pub fn main(registry: &Registry) -> ExitCode {
    match run(registry) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(e.downcast_ref::<KmError>().map_or(1, KmError::exit_code))
        }
    }
}

fn open_token(
    cfg: &Config,
    modules: &BTreeMap<String, String>,
    registry: &Registry,
    name: &str,
) -> Result<Token, KmError> {
    let tcfg = cfg.tokens.get(name).ok_or_else(|| KmError::Validation(format!("unknown token '{name}'")))?;
    Token::open(name, tcfg, modules.get(name).map(String::as_str), registry)
}

/// What the `supports` query resolved and answered.
struct Support {
    /// The resolved module profile's name ("(none)" without one).
    module: String,
    /// The stack's layer names, the binding layer first.
    layers: Vec<String>,
    /// One verdict per asked name.
    verdicts: Vec<(String, cakeys_profile::Verdict)>,
}

/// Resolve what the `supports` query asks (docs/PROVIDERS.md): the embedded profiles plus
/// any `--profiles` directory, the module profile (named, or through a token's `provider`),
/// the delta layers on top, and the answers.
#[allow(clippy::too_many_arguments)] // one parameter per CLI flag: grouping them buys nothing
fn supports(
    cfg: &Config,
    profile: Option<&str>,
    token: Option<&str>,
    layers: &[String],
    class: Option<&str>,
    oaep: bool,
    name: Option<&str>,
    bits: Option<u32>,
    profiles_dir: Option<&std::path::Path>,
) -> anyhow::Result<Support> {
    let validation = |e: String| -> anyhow::Error { KmError::Validation(e).into() };
    let mut set =
        cakeys_profile::Set::embedded().map_err(validation).with_context(|| "the embedded profiles do not parse")?;
    if let Some(dir) = profiles_dir {
        set = set.with_dir(dir).map_err(validation).with_context(|| format!("--profiles {}", dir.display()))?;
    }
    let module = match (profile, token) {
        (Some(p), _) => Some(set.find(p).map_err(validation)?),
        (None, Some(t)) => {
            let tcfg = cfg.tokens.get(t).ok_or_else(|| KmError::Validation(format!("unknown token '{t}'")))?;
            let family = tcfg.provider.as_deref().ok_or_else(|| {
                KmError::Validation(format!("token '{t}' names no provider; set tokens.{t}.provider or pass --profile"))
            })?;
            Some(set.find(family).map_err(validation)?)
        }
        (None, None) => None,
    };
    // The cryptoki binding layer is always in the stack (docs/PROVIDERS.md phase 2): what it
    // subtracts is decided by the build this binary runs against, so an explicit `--layer
    // cryptoki/0.12` adds nothing it has not already decided.
    let mut resolved: Vec<cakeys_profile::Profile> = vec![cakeys_pkcs11::binding::layer().map_err(validation)?];
    for l in layers {
        let p = set.find(l).map_err(validation)?.clone();
        if p.profile == "cryptoki/0.12" {
            continue;
        }
        resolved.push(p);
    }
    let stack: Vec<&cakeys_profile::Profile> = resolved.iter().collect();
    let baseline = set.baseline().map_err(validation)?;
    let eff = cakeys_profile::Effective::new(baseline, module, &stack);
    let verdicts = if let Some(class) = class {
        eff.class(class).ok_or_else(|| {
            KmError::Validation(format!(
                "no class '{class}' in baseline {} (classes: {})",
                baseline.baseline,
                baseline.class.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        })?
    } else if oaep {
        eff.oaep()
    } else if let Some(name) = name {
        vec![(name.to_owned(), eff.query(name, bits))]
    } else {
        unreachable!("clap requires a name, --class or --oaep")
    };
    let module_name = module.map_or_else(|| "(none)".to_owned(), |m| m.profile.clone());
    let stack_names: Vec<String> = resolved.iter().map(|p| p.profile.clone()).collect();
    Ok(Support { module: module_name, layers: stack_names, verdicts })
}

fn run(registry: &Registry) -> anyhow::Result<()> {
    let mut notes = Notes::default();
    let result = dispatch(registry, &mut notes);
    // Before the error line, if any: what the run noticed on the way is never lost to a failure.
    for line in notes.lines() {
        eprintln!("{line}");
    }
    result
}

#[allow(clippy::too_many_lines)] // one match over the verbs; splitting it buys nothing
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;
    let lock_path = cli.lock.clone().unwrap_or_else(|| cli.config.with_extension("lock"));
    // A run that may write the lock holds its advisory sidecar lock across load and save (M3),
    // so concurrent updaters queue instead of losing each other's writes. Held to the end of run.
    let writes = match &cli.cmd {
        Cmd::Realise { write, .. } | Cmd::Delete { write, .. } => write.mode() == LockWrite::Record,
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
    let mut lock = load_lock(&lock_path)?;
    let modules: BTreeMap<String, String> = cli
        .modules
        .iter()
        .map(|m| m.split_once('=').map(|(t, p)| (t.to_owned(), p.to_owned())))
        .collect::<Option<_>>()
        .context("--module expects TOKEN=PATH")?;

    match &cli.cmd {
        Cmd::Validate => {
            for (name, t) in &cfg.tokens {
                let Some(p) = t.provider.as_deref() else { continue };
                // A named provider checks the token's options here too; an auto-detected one
                // can only be known, and check them, once the token is opened.
                let provider = registry.named(p).ok_or_else(|| {
                    KmError::Validation(format!(
                        "token '{name}': unknown provider '{p}' (registered: generic, {})",
                        registry.names().join(", ")
                    ))
                })?;
                provider.check_options(name, &t.options)?;
            }
            for (spec_name, spec) in &cfg.specs {
                for token in spec.tokens.keys() {
                    let t = Target::new(&cfg, spec_name, token)?;
                    let mode = ops::plan_mode(&t)?;
                    let note = if mode.needs_opt_in() { " (opted in)" } else { "" };
                    println!("{spec_name} on {token}: mode {mode}{note}");
                }
            }
        }
        Cmd::Resolve { spec, token } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            let r = ops::resolve(&t, &tok, &lock)?.ok_or_else(|| KmError::NotFound(format!("{spec} on {token}")))?;
            print(&r);
        }
        Cmd::Verify { spec, token } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            println!("{}", ops::verify(&t, &tok, &lock, notes)?.uri);
        }
        Cmd::Realise { spec, token, write } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            let (r, changed) = ops::realise(&t, &tok, &mut lock, write.mode(), notes)?;
            if changed {
                save_lock(&lock_path, &lock)?;
                notes.say(format!("updated {}", lock_path.display()));
            }
            print(&r);
        }
        Cmd::Delete { spec, token, if_match, write } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            if ops::delete(&t, &tok, &mut lock, if_match.as_deref(), write.mode(), notes)? {
                save_lock(&lock_path, &lock)?;
                notes.say(format!("updated {}", lock_path.display()));
            }
        }
        Cmd::Gc { apply } => {
            let stale = gc(&cfg, &mut lock, *apply);
            for entry in &stale {
                println!("{entry}");
            }
            if stale.is_empty() {
                eprintln!("nothing to collect: every lock entry is named by the config");
            } else if *apply {
                save_lock(&lock_path, &lock)?;
                eprintln!("updated {} ({} entries removed)", lock_path.display(), stale.len());
            } else {
                eprintln!("{} stale entries; pass --apply to remove them", stale.len());
            }
        }
        Cmd::Check { reference, token, spec } => {
            let open = |name: &str| open_token(&cfg, &modules, registry, name);
            let r = ops::check(&cfg, reference, spec.as_deref(), token.as_deref(), open, &mut lock, notes)?;
            println!("{}", r.uri);
        }
        Cmd::Caps { token } => {
            let tok = open_token(&cfg, &modules, registry, token)?;
            print(&serde_json::json!({
                "token": token,
                "provider": tok.provider.name(),
                "profiles": {
                    "module": tok.profiles.module_name(),
                    "layers": tok.profiles.layer_names(),
                },
                "mechanisms": tok.mechanism_names(),
            }));
        }
        Cmd::Export { object, token, target, transport, to_file, how } => {
            let dest = match (target, transport, to_file) {
                (_, _, Some(FileArg::Pkcs8)) => Dest::File(FileFormat::Pkcs8),
                (_, _, Some(FileArg::Pkcs12)) => Dest::File(FileFormat::Pkcs12),
                (_, Some(path), None) => Dest::Transport(path),
                (Some(t), None, None) => Dest::Token(t),
                (None, None, None) => unreachable!("clap requires one of --target, --transport, --to-file"),
            };
            let moves = Moves { cfg: &cfg, modules: &modules, registry, lock: &lock };
            moves.plan(object.as_deref(), token, &dest, how, notes)?;
        }
        Cmd::Migrate { object, from, to, how } => {
            let moves = Moves { cfg: &cfg, modules: &modules, registry, lock: &lock };
            moves.plan(object.as_deref(), from, &Dest::Token(to), how, notes)?;
        }
        Cmd::Transport { spec, token, out } => {
            let t = Target::new(&cfg, spec, token)?;
            let tok = open_token(&cfg, &modules, registry, token)?;
            let text = migrate::transport(&t, &tok, &lock, notes)?.to_toml();
            match out {
                Some(path) => {
                    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
                    notes.say(format!("wrote {}", path.display()));
                }
                None => print!("{text}"),
            }
        }
        Cmd::Supports { name, profile, token, layers, class, oaep, bits, profiles_dir } => {
            let eff = supports(
                &cfg,
                profile.as_deref(),
                token.as_deref(),
                layers,
                class.as_deref(),
                *oaep,
                name.as_deref(),
                *bits,
                profiles_dir.as_deref(),
            )?;
            notes.note(format_args!(
                "profiles: module {}, layers [{}] (docs/PROVIDERS.md)",
                eff.module,
                eff.layers.join(", ")
            ));
            for (n, v) in &eff.verdicts {
                println!("{n}: {v}");
            }
            let any_no = eff.verdicts.iter().any(|(_, v)| matches!(v, cakeys_profile::Verdict::No { .. }));
            let any_unknown = eff.verdicts.iter().any(|(_, v)| matches!(v, cakeys_profile::Verdict::Unknown { .. }));
            if any_no {
                let names: Vec<&str> = eff
                    .verdicts
                    .iter()
                    .filter(|(_, v)| matches!(v, cakeys_profile::Verdict::No { .. }))
                    .map(|(n, _)| n.as_str())
                    .collect();
                return Err(KmError::Unsupported(format!("not supported: {}", names.join(", "))).into());
            }
            if any_unknown {
                return Err(KmError::Unavailable(
                    "the profiles do not decide this: run the probe (PROVIDERS.md phase 3) or a fuller profile".into(),
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Where `export` or `migrate` sends the material.
enum Dest<'a> {
    Token(&'a str),
    Transport(&'a std::path::Path),
    File(FileFormat),
}

/// What planning a move reads: keys.toml for the tokens, the lock for the objects.
struct Moves<'a> {
    cfg: &'a Config,
    modules: &'a BTreeMap<String, String>,
    registry: &'a Registry,
    lock: &'a cakeys_core::config::Lock,
}

impl Moves<'_> {
    /// Plan each object's move from `from` to `dest` and print it (MIGRATE.md D9); 15 when any
    /// object cannot move as invoked. Moving is not implemented yet: without --dry-run, refused.
    fn plan(
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
        let materials = migrate::materials(self.lock, from, object)?;
        let (source, source_from) = self.side(from, notes)?;
        let mut allow = Allow { host_plaintext: how.allow_host_plaintext, ..Allow::default() };
        let (target, target_from, to_name) = match dest {
            Dest::Token(name) => {
                let (side, from) = self.side(name, notes)?;
                (Some(side), from, (*name).to_owned())
            }
            Dest::Transport(path) => {
                let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
                let t = Transport::parse(&text, path)?;
                // Phase 3b sets this only after the source's SO marked the key trusted there.
                allow.trusted_transport = t.trusted;
                let side = migrate::side_from_transport(&t, self.registry)
                    .ok_or_else(|| {
                        KmError::Unsupported(format!(
                            "{}: provider '{}' is not in this build",
                            path.display(),
                            t.provider
                        ))
                    })?
                    .map_err(|e| KmError::Validation(format!("{}: {e}", path.display())))?;
                (Some(side), "transport file", t.token)
            }
            Dest::File(f) => (None, "-", format!("{f:?} file").to_lowercase()),
        };
        let to = target.as_ref().map_or_else(
            || To::File(if let Dest::File(f) = dest { *f } else { unreachable!("only a file has no side") }),
            To::Token,
        );
        let plans: Vec<Plan> = materials.iter().map(|m| migrate::plan(m, &source, &to, allow)).collect();
        if how.json {
            print(&serde_json::json!({
                "from": from,
                "to": to_name,
                "capabilities": { "from": source_from, "to": target_from },
                "plans": plans,
            }));
        } else {
            println!(
                "{from} -> {to_name} (capabilities: {from} from the {source_from}, {to_name} from the {target_from})"
            );
            for p in &plans {
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
        let blocked = plans.iter().filter(|p| !p.ready).count();
        if blocked > 0 {
            return Err(
                KmError::Unsupported(format!("{blocked} of {} objects cannot move as invoked", plans.len())).into()
            );
        }
        Ok(())
    }

    /// A token's capabilities: from the open token, else from what the lock recorded there.
    fn side(&self, name: &str, notes: &mut Notes) -> Result<(Side, &'static str), KmError> {
        match open_token(self.cfg, self.modules, self.registry, name) {
            Ok(tok) => Ok((migrate::side(&tok)?, "token")),
            Err(e) => match migrate::side_from_lock(name, self.lock, self.registry) {
                Some(side) => {
                    notes.note(format_args!(
                        "capabilities of '{name}' come from the lock: the token did not open ({e})"
                    ));
                    Ok((side?, "lock"))
                }
                None => Err(e),
            },
        }
    }
}

fn print<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}
