//! The `caprobe` command line (docs/SCOPE.md, "Three tools"): it measures PKCS#11 modules. It
//! probes a token into a capability profile and compares it with a committed one, answers what
//! the profiles say a module supports, and prints what a token offers. It is the only tool that
//! creates and destroys scratch objects (`probe --write`), and it never reads keys.lock. A
//! library, so a downstream binary can link extra provider crates:
//! `caprobe::main(&caprobe::default_registry().with(MyProvider))`.

#[cfg(test)]
mod baseline;
mod diff;
mod emit;
mod probe;
mod supports;

use anyhow::Context as _;
use cakeys_cli_common::{module_overrides, open_token, print, token_cfg};
use cakeys_core::KmError;
use cakeys_core::config::{Config, load_config};
use cakeys_pkcs11::Registry;
use cakeys_pkcs11::ops::Notes;
use cakeys_pkcs11::token::Access;
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub use cakeys_cli_common::default_registry;

/// Measure PKCS#11 modules: capability profiles, and what a token offers.
///
/// Exit codes: 0 ok, 15 unsupported (a profile's no; drift from --diff), 16 unavailable (a
/// profile's unknown), 17 invalid spec, 1 other.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Declarative input (keys.toml): the tokens. Every verb needs it except `supports
    /// --profile`, which reads only the capability profiles.
    #[arg(short, long, env = "CAKEYS_CONFIG")]
    config: Option<PathBuf>,
    /// Override a token's PKCS#11 module: `<token>=<path>` (repeatable).
    #[arg(long = "module", value_name = "TOKEN=PATH")]
    modules: Vec<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a token's provider, resolved capability profiles and usable mechanisms as JSON.
    Caps {
        #[arg(long)]
        token: String,
    },
    /// Ask the capability profiles what a vendor SO version supports (docs/PROVIDERS.md):
    /// pure data, no token touched. NAME is a mechanism (`CKM_*`), key type (`CKK_*`),
    /// parameter set (`CKP_*`) or curve; `--bits` asks for an RSA size; `--class` lists a
    /// baseline class; `--oaep` lists the wrap hashes. Exit 0 yes, 15 no, 16 unknown.
    Supports(SupportsArgs),
    /// Generate the token's capability profile by probing it (docs/PROVIDERS.md phase 3):
    /// read-only probes always; with --write, the probes that generate, wrap, unwrap and
    /// delete — only on a token keys.toml marks scratch, refused (17) on any other. With
    /// --diff, the result is compared against a committed profile: any difference is
    /// printed and the exit is 15.
    Probe(ProbeArgs),
}

/// The `supports` query.
#[derive(clap::Args)]
struct SupportsArgs {
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
}

/// What `probe` probes, and where the result goes.
#[derive(clap::Args)]
struct ProbeArgs {
    #[arg(long)]
    token: String,
    /// Also run the write probes, against a scratch token only.
    #[arg(long)]
    write: bool,
    /// Write the generated profile here; default: stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Name the generated profile, e.g. `tpm2-pkcs11/1.10+swtpm` for a module on one kind of
    /// hardware; default: the claimed profile's name with --diff, else `<provider>/<version>`.
    #[arg(long)]
    name: Option<String>,
    /// Diff against this profile (name or family), from the embedded set or --profiles.
    #[arg(long)]
    diff: Option<String>,
    #[arg(long = "profiles")]
    profiles_dir: Option<PathBuf>,
}

/// Run the command line with the given providers; maps errors to the documented exit codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    cakeys_cli_common::main(|notes| dispatch(registry, notes))
}

/// Parse the arguments, load keys.toml, and run the verb.
fn dispatch(registry: &Registry, notes: &mut Notes) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = match (&cli.config, &cli.cmd) {
        (Some(path), _) => load_config(path)?,
        // Pure data over the profiles (docs/PROVIDERS.md): nothing in keys.toml to read.
        (None, Cmd::Supports(a)) if a.token.is_none() => Config::default(),
        (None, _) => {
            use clap::CommandFactory as _;
            Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "--config <CONFIG> (or CAKEYS_CONFIG) is required: only `supports --profile` runs without a keys.toml",
                )
                .exit()
        }
    };
    let modules = module_overrides(&cli.modules)?;
    match &cli.cmd {
        Cmd::Caps { token } => {
            let tok = open_token(&cfg, &modules, registry, token, Access::Read, notes)?;
            print(&serde_json::json!({
                "token": token,
                "provider": tok.provider.name(),
                "profiles": {
                    "module": tok.profiles.module_name(),
                    "layers": tok.profiles.layer_names(),
                },
                "mechanisms": tok.mechanism_names(),
            }))
        }
        Cmd::Supports(a) => run_supports(&cfg, a, notes),
        Cmd::Probe(a) => run_probe(&cfg, &modules, registry, a, notes),
    }
}

/// The embedded capability profiles, plus any `--profiles` directory (D11).
fn profile_set(dir: Option<&Path>) -> anyhow::Result<cakeys_profile::Set> {
    let set =
        cakeys_profile::Set::embedded().map_err(KmError::Validation).context("the embedded profiles do not parse")?;
    match dir {
        Some(dir) => Ok(set
            .with_dir(dir)
            .map_err(KmError::Validation)
            .with_context(|| format!("--profiles {}", dir.display()))?),
        None => Ok(set),
    }
}

/// The `supports` verb: answers from the capability profiles alone (docs/PROVIDERS.md), so it
/// runs with an empty `cfg` when there is no keys.toml and no `--token` to look up.
fn run_supports(cfg: &Config, a: &SupportsArgs, notes: &mut Notes) -> anyhow::Result<()> {
    let set = profile_set(a.profiles_dir.as_deref())?;
    let q = supports::Query {
        name: a.name.as_deref(),
        profile: a.profile.as_deref(),
        token: a.token.as_deref(),
        layers: &a.layers,
        class: a.class.as_deref(),
        oaep: a.oaep,
        bits: a.bits,
    };
    let s = supports::supports(cfg, &set, &q)?;
    notes.note(format_args!("profiles: module {}, layers [{}] (docs/PROVIDERS.md)", s.module, s.layers.join(", ")));
    for (n, v) in &s.verdicts {
        println!("{n}: {v}");
    }
    Ok(s.outcome()?)
}

/// `probe`: generate the token's capability profile, print or write it, and diff it against
/// a committed one.
fn run_probe(
    cfg: &Config,
    modules: &BTreeMap<String, String>,
    registry: &Registry,
    a: &ProbeArgs,
    notes: &mut Notes,
) -> anyhow::Result<()> {
    let tcfg = token_cfg(cfg, &a.token)?;
    let set = profile_set(a.profiles_dir.as_deref())?;
    let claimed = a.diff.as_deref().map(|name| set.find(name).map_err(KmError::Validation)).transpose()?;
    let access = if a.write { Access::Write } else { Access::Read };
    let tok = open_token(cfg, modules, registry, &a.token, access, notes)?;
    let req =
        probe::Request { write: a.write, name: a.name.as_deref(), claimed, kept: a.out.is_some() || a.diff.is_some() };
    let mut profile = probe::generate(&tok, tcfg, &req, notes)?;
    match &a.out {
        Some(path) => write_profile(path, &mut profile, a.write, notes)?,
        None => print!("{}", emit::profile(&profile)),
    }
    let Some(claimed) = claimed else { return Ok(()) };
    let name = &claimed.profile;
    let lines = probe::drift(&profile, claimed, a.write);
    if lines.is_empty() {
        notes.say(format!("{}: the profile conforms to {name}", tok.name));
        return Ok(());
    }
    // stderr: stdout may be carrying the generated profile.
    for line in &lines {
        eprintln!("{line}");
    }
    Err(KmError::Unsupported(format!(
        "{}: {} row{} differ from profile {name}",
        tok.name,
        lines.len(),
        if lines.len() == 1 { "" } else { "s" }
    ))
    .into())
}

/// Write a generated profile to `path`, keeping the one section the probe does not generate:
/// the file's [migration] claims (MIGRATE.md evidence, never probe-observable). Refused onto
/// an existing file that does not parse (regenerating it would silently drop those claims),
/// and onto any existing file from a read-only probe (it would drop every write-probe row).
fn write_profile(
    path: &Path,
    profile: &mut cakeys_profile::Profile,
    write: bool,
    notes: &mut Notes,
) -> anyhow::Result<()> {
    if let Ok(text) = std::fs::read_to_string(path) {
        probe::keep_claims(profile, &text, &path.display().to_string(), write)?;
    }
    std::fs::write(path, emit::profile(profile)).with_context(|| format!("writing {}", path.display()))?;
    notes.say(format!("wrote {}", path.display()));
    Ok(())
}
