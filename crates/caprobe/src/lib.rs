//! The `caprobe` command line (README.md, "Three tools"): it measures PKCS#11 modules. It
//! probes a token into a capability profile and compares it with a committed one, answers what
//! the profiles say a module supports, and prints what a token offers. It is the only tool that
//! creates and destroys scratch objects (`probe --write`), and it never reads keys.lock. A
//! library, so a downstream binary can link extra provider crates:
//! `caprobe::main(&caprobe::default_registry().with(MyProvider))`.

#[cfg(test)]
mod baseline;
#[cfg(test)]
mod coverage;
mod diff;
mod emit;
mod probe;
mod supports;

use anyhow::Context as _;
use cakeys_cli_common::{module_overrides, open_token, print, token_cfg};
use cakeys_core::KmError;
use cakeys_core::config::{Config, load_config};
use cakeys_pkcs11::ops::Notes;
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{ChainTime, Registry};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub use cakeys_cli_common::default_registry;

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/profile.rs`): the profile emitter on
/// whatever the profile parser reads.
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    /// `text` as a profile: one the parser reads is emitted, and the emitted text reads back as
    /// the same profile and emits to the same text, the round trip a regenerated profile takes.
    ///
    /// Before that, every quoted string in `text` that reads as a row key is the key its
    /// capability writes back. The round trip compares parsed profiles, so it cannot see a key
    /// parse that takes two spellings to one row (review profile.rs F1: `generate.CKK_RSA.02048`
    /// read as `…2048`); this does, on the input's own keys. A string that is no row key is
    /// passed over, so the check holds whatever the TOML around it is.
    ///
    /// # Panics
    ///
    /// When it does not: what the fuzz target looks for.
    pub fn profile_round_trip(text: &str) {
        for key in text.split(['"', '\'']) {
            if let Ok(c) = cakeys_profile::Capability::parse(key) {
                assert_eq!(c.to_string(), key, "the row key {key:?} is written back as another");
            }
        }
        let Ok(profile) = cakeys_profile::Profile::from_toml(text) else { return };
        let emitted = crate::emit::profile(&profile);
        let back = cakeys_profile::Profile::from_toml(&emitted)
            .unwrap_or_else(|e| panic!("the emitted profile does not read back: {e}\n{emitted}"));
        assert_eq!(back, profile, "the emitted profile reads back as another\n{emitted}");
        assert_eq!(crate::emit::profile(&back), emitted, "the emitted profile emits to another text");
    }

    #[cfg(test)]
    mod tests {
        /// Every committed profile passes, and so does each with its sizes respelt (`02048`,
        /// `+2048`): the parser refuses those keys rather than reading them as another's row.
        /// Were it to read one, the key check above fails here, not only under the fuzzer.
        #[test]
        fn the_committed_profiles_pass_with_their_sizes_respelt() {
            // The quoted row keys ending in `.<digits>`, with `prefix` before the digits.
            let respell = |text: &str, prefix: &str| {
                let mut parts: Vec<String> = text.split('"').map(str::to_owned).collect();
                for part in parts.iter_mut().skip(1).step_by(2) {
                    if let Some((head, n)) = part.rsplit_once('.')
                        && cakeys_profile::Capability::parse(part).is_ok()
                        && !n.is_empty()
                        && n.bytes().all(|b| b.is_ascii_digit())
                    {
                        *part = format!("{head}.{prefix}{n}");
                    }
                }
                parts.join("\"")
            };
            let mut respelt_any = false;
            for (path, text) in cakeys_profile::embedded::PROFILE_FILES {
                super::profile_round_trip(text);
                for prefix in ["0", "+"] {
                    let variant = respell(text, prefix);
                    if variant != *text {
                        respelt_any = true;
                        assert!(cakeys_profile::Profile::from_toml(&variant).is_err(), "{path}: {prefix}");
                    }
                    super::profile_round_trip(&variant);
                }
            }
            assert!(respelt_any, "no committed profile has a sized row");
        }
    }
}

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
    /// Ask the capability profiles what a vendor SO version supports (docs/CAPROBE.md):
    /// pure data, no token touched. NAME is a mechanism (`CKM_*`), key type (`CKK_*`),
    /// parameter set (`CKP_*`) or curve; `--bits` asks for an RSA size; `--class` lists a
    /// baseline class; `--oaep` lists the wrap hashes. Exit 0 yes, 15 no, 16 unknown.
    Supports(SupportsArgs),
    /// Generate the token's capability profile by probing it (docs/CAPROBE.md):
    /// read-only probes always; with --write, the probes that generate, wrap, unwrap and
    /// delete — only on a token keys.toml marks scratch (`[tokens.<t>] probe = { scratch =
    /// true }`, or `probe.scratchId` for the one slot of a token, such as a `YubiKey`, whose
    /// real keys sit beside it), refused (17) on any other. With
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
    /// Also run the write probes, against a scratch token only: `[tokens.<t>] probe = {
    /// scratch = true }`, or `probe.scratchId` naming one slot (a `YubiKey`'s).
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
    /// A directory of extra or replacement profile files, read recursively (D11), for the
    /// --diff lookup: the token is probed unprofiled, whatever the directory holds.
    #[arg(long = "profiles")]
    profiles_dir: Option<PathBuf>,
    /// The largest RSA key the write probes generate, in bits: every size up to 16384 by
    /// default, whatever the module reports. A smaller one probes faster (the test suites pass
    /// 4096: 16384 bits take a software token over a minute).
    #[arg(long, default_value_t = probe::RSA_SIZES[probe::RSA_SIZES.len() - 1])]
    rsa_max_bits: u32,
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
    main_from(registry, std::env::args_os())
}

/// [`main`] on `args`, the program name first, instead of the process's: caprobe run in-process
/// by a binary or a test. It never exits the process: `--help` and `--version` print and return
/// 0, a usage error prints and returns clap's 2. The profile set is built once per process
/// (`activate`): a later call reuses it when it names the same profile directories, and is
/// refused (17) when it names others.
#[must_use]
pub fn main_from<I, T>(registry: &Registry, args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args).and_then(Cli::with_config) {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version on stdout, a usage error on stderr, as clap's own exit does.
            let _ = e.print();
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    cakeys_cli_common::main(|notes| dispatch(registry, &cli, notes))
}

impl Cli {
    /// `self`, when it has the keys.toml its verb needs: every verb but `supports --profile`
    /// (pure data over the profiles, docs/CAPROBE.md) reads one.
    fn with_config(self) -> Result<Cli, clap::Error> {
        if self.config.is_some() || matches!(&self.cmd, Cmd::Supports(a) if a.token.is_none()) {
            return Ok(self);
        }
        Err(<Cli as clap::CommandFactory>::command().error(
            clap::error::ErrorKind::MissingRequiredArgument,
            "--config <CONFIG> (or CAKEYS_CONFIG) is required: only `supports --profile` runs without a keys.toml",
        ))
    }
}

/// The profile directories this process's set was built from (keys.toml's `profileDirs`, then
/// `--profiles`), once [`activate`] has built it.
static ACTIVATED: std::sync::Mutex<Option<(Vec<PathBuf>, Option<PathBuf>)>> = std::sync::Mutex::new(None);

/// Activate the profile set from `cfg`'s `profileDirs` and `replacing` (`--profiles`), once per
/// process: `Set::activate` builds it once, so a second in-process run ([`main_from`]) reuses it
/// when it names the same directories.
///
/// # Errors
///
/// What [`cakeys_cli_common::activate_profiles`] refuses; `Validation` (17) for a run that
/// names other directories than the set was built from.
fn activate(cfg: &Config, replacing: Option<&Path>, notes: &mut Notes) -> Result<(), KmError> {
    let wanted = (cfg.profile_dirs.clone(), replacing.map(Path::to_path_buf));
    let mut activated = ACTIVATED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    match &*activated {
        None => {
            cakeys_cli_common::activate_profiles(cfg, replacing, notes)?;
            *activated = Some(wanted);
            Ok(())
        }
        Some(was) if *was == wanted => Ok(()),
        Some((dirs, from)) => Err(KmError::Validation(
            format!(
                "this process's profile set was built from profileDirs {dirs:?} and --profiles {from:?}, \
                 not {:?} and {:?}: it is built once per process, so run caprobe in a process of its own",
                wanted.0, wanted.1
            )
            .into(),
        )),
    }
}

/// Load keys.toml, and run the verb.
fn dispatch(registry: &Registry, cli: &Cli, notes: &mut Notes) -> anyhow::Result<()> {
    let cfg = match &cli.config {
        Some(path) => load_config(path)?,
        // `supports --profile` ([`Cli::with_config`]): nothing in keys.toml to read.
        None => Config::default(),
    };
    // One profile set, as the verbs activate it, with `--profiles` loaded over it.
    let replacing = match &cli.cmd {
        Cmd::Supports(a) => a.profiles_dir.as_deref(),
        Cmd::Probe(a) => a.profiles_dir.as_deref(),
        Cmd::Caps { .. } => None,
    };
    activate(&cfg, replacing, notes)?;
    let modules = module_overrides(&cli.modules, &cfg)?;
    match &cli.cmd {
        Cmd::Caps { token } => {
            let tok = open_token(&cfg, &modules, registry, token, Access::Read, ChainTime::Unchecked, notes)?;
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

/// The active profile set: the embedded profiles, keys.toml's `profileDirs` and any
/// `--profiles` (D11), activated once in `dispatch` as every verb activates it (review D4).
fn profile_set() -> anyhow::Result<&'static cakeys_profile::Set> {
    Ok(cakeys_profile::Set::active().map_err(|e| KmError::Validation(e.into()))?)
}

/// The `supports` verb: answers from the capability profiles alone (docs/CAPROBE.md), so it
/// runs with an empty `cfg` when there is no keys.toml and no `--token` to look up.
fn run_supports(cfg: &Config, a: &SupportsArgs, notes: &mut Notes) -> anyhow::Result<()> {
    let set = profile_set()?;
    let ask = match (a.class.as_deref(), a.oaep, a.name.as_deref()) {
        (Some(class), _, _) => supports::Ask::Class(class),
        (None, true, _) => supports::Ask::Oaep,
        (None, false, Some(name)) => supports::Ask::Name(name),
        (None, false, None) => unreachable!("clap requires a name, --class or --oaep"),
    };
    let q = supports::Query {
        ask,
        profile: a.profile.as_deref(),
        token: a.token.as_deref(),
        layers: &a.layers,
        bits: a.bits,
    };
    let s = supports::supports(cfg, set, &q)?;
    for n in &s.notes {
        notes.note(n);
    }
    notes.note(format_args!("profiles: module {}, layers [{}] (docs/CAPROBE.md)", s.module, s.layers.join(", ")));
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
    let set = profile_set()?;
    let claimed =
        a.diff.as_deref().map(|name| set.find(name).map_err(|e| KmError::Validation(e.into()))).transpose()?;
    let access = if a.write { Access::Write } else { Access::Read };
    // Unprofiled: what the probe measures must not be what the committed profile says.
    let tok = open_token(cfg, modules, registry, &a.token, access, ChainTime::Unchecked, notes)?.unprofiled()?;
    let req = probe::Request {
        write: a.write,
        name: a.name.as_deref(),
        claimed,
        kept: a.out.is_some() || a.diff.is_some(),
        rsa_max_bits: a.rsa_max_bits,
    };
    let mut profile = probe::generate(&tok, tcfg, &req, notes)?;
    match &a.out {
        Some(path) => write_profile(path, &mut profile, a.write, a.name.is_some(), notes)?,
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
    Err(KmError::Unsupported(
        format!(
            "{}: {} row{} differ from profile {name}",
            tok.name,
            lines.len(),
            if lines.len() == 1 { "" } else { "s" }
        )
        .into(),
    )
    .into())
}

/// Write a generated profile to `path`, keeping the one section the probe does not generate:
/// the file's `[migration]` claims (docs/CAMIGRATE.md evidence, never probe-observable). Refused onto
/// an existing file that does not parse (regenerating it would silently drop those claims),
/// onto any existing file from a read-only probe (it would drop every write-probe row), and onto
/// another profile's file (`probe::keep_claims`; `renamed`: `--name` was given).
fn write_profile(
    path: &Path,
    profile: &mut cakeys_profile::Profile,
    write: bool,
    renamed: bool,
    notes: &mut Notes,
) -> anyhow::Result<()> {
    // Only a file that is not there has nothing to keep: one that cannot be read may hold claims.
    match std::fs::read_to_string(path) {
        Ok(text) => probe::keep_claims(profile, &text, &path.display().to_string(), write, renamed)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {} to keep its claims", path.display())),
    }
    cakeys_core::config::write_whole(path, emit::profile(profile).as_bytes(), 0o666)?;
    notes.say(format!("wrote {}", path.display()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> ExitCode {
        main_from(&default_registry(), std::iter::once("caprobe").chain(args.iter().copied()))
    }

    /// `main_from` returns what clap would exit with, never exiting the process the test runs
    /// in, and runs again in one process: the same profile directories reuse the set, others
    /// are refused (17) (review lib F2). One test: the set is the process's.
    #[test]
    fn main_from_returns_and_runs_again_in_one_process() {
        assert_eq!(run(&["--help"]), ExitCode::SUCCESS);
        assert_eq!(run(&["--version"]), ExitCode::SUCCESS);
        assert_eq!(run(&["probe"]), ExitCode::from(2), "--token is required");
        if std::env::var_os("CAKEYS_CONFIG").is_none() {
            assert_eq!(run(&["caps", "--token", "t"]), ExitCode::from(2), "--config is required");
        }
        let ask = ["supports", "--profile", "softhsm/2.7", "CKM_AES_KEY_WRAP"];
        assert_eq!(run(&ask), ExitCode::SUCCESS);
        assert_eq!(run(&ask), ExitCode::SUCCESS, "a second run in the process");
        let dir = std::env::temp_dir().join(format!("caprobe-main-from-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let other =
            run(&["supports", "--profiles", dir.to_str().unwrap(), "--profile", "softhsm/2.7", "CKM_AES_KEY_WRAP"]);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(other, ExitCode::from(17), "other directories than the set was built from");
    }
}
