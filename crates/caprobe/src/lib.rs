//! The `caprobe` command line (README.md, "Three tools") measures PKCS#11 modules. It probes a
//! token into a capability profile and compares that profile with a committed one, answers what
//! the profiles say that a module supports, and prints what a token offers. It is the only tool
//! that creates and destroys scratch objects (`probe --write-probes`), and it never reads
//! keys.lock. The command line is a library, so that a downstream binary can link extra provider
//! crates: `caprobe::main(&caprobe::default_registry().with(MyProvider))`.

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

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/profile.rs`), which run the profile
/// emitter on whatever the profile parser reads.
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing {
    /// Checks the round trip of `text` as a profile. When the parser reads `text`, the function
    /// emits the profile, and the emitted text must read back as the same profile and must emit
    /// to the same text. This is the round trip that a regenerated profile takes.
    ///
    /// Before the round trip, every quoted string in `text` that parses as a row key must be
    /// written back by its capability as the same key. The round trip compares parsed profiles,
    /// so it cannot detect a key parser that maps two spellings to one row (review profile.rs
    /// F1: `generate.CKK_RSA.02048` was read as `…2048`). This check detects that on the input's
    /// own keys. A string that is not a row key is skipped, so the check holds whatever the
    /// surrounding TOML is.
    ///
    /// # Panics
    ///
    /// Panics when either check fails, which is what the fuzz target looks for.
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
        /// Every committed profile passes, and so does each profile with its sizes spelled
        /// differently (`02048`, `+2048`). The parser refuses those keys instead of reading them
        /// as the row of another key. If the parser read one, the key check above would fail
        /// here, and not only under the fuzzer.
        #[test]
        fn the_committed_profiles_pass_with_their_sizes_respelt() {
            // Rewrites each quoted row key that ends in `.<digits>`, with `prefix` placed before
            // the digits.
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

/// Measure PKCS#11 modules: capability profiles, and what a token offers (docs/CAPROBE.md).
/// `supports` exits 0 for yes, 15 for no and 16 for unknown, and `probe --diff` exits 15 on
/// drift.
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
    /// A directory of extra or replacement profile files, read recursively, which are loaded
    /// over the built-in profiles and the `profileDirs` of keys.toml. `probe` still probes the
    /// token without a profile, and uses the directory only for its --diff.
    #[arg(long = "profiles", value_name = "DIR", global = true)]
    profiles_dir: Option<PathBuf>,
    /// Print the verdicts of `supports` as JSON. `caps` always prints JSON, and `probe` prints a
    /// profile.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a token's provider, resolved capability profiles and usable mechanisms as JSON.
    Caps {
        /// The token in keys.toml to read.
        #[arg(long)]
        token: String,
    },
    /// Ask the capability profiles what a module version supports (docs/CAPROBE.md). The
    /// query reads only data and touches no token. NAME is a mechanism (`CKM_*`), a key type
    /// (`CKK_*`), a parameter set (`CKP_*`) or a curve. `--bits` asks about an RSA size,
    /// `--class` lists a baseline class, and `--oaep` lists the wrap hashes. The exit code is 0
    /// for yes, 15 for no and 16 for unknown.
    Supports(SupportsArgs),
    /// Generate the token's capability profile by probing it (docs/CAPROBE.md). The read-only
    /// probes always run. With --write-probes, the probes that generate, wrap, unwrap and
    /// delete also run, but only on a token that keys.toml marks as scratch
    /// (`[tokens.<t>] probe = { scratch = true }`, or `probe.scratchId` for the one slot of a
    /// token, such as a `YubiKey`, that also holds real keys). On any other token, the write
    /// probes are refused with exit code 17. With --diff, the result is compared with a
    /// committed profile, each difference is printed, and the exit code is 15.
    Probe(ProbeArgs),
    /// Regenerate a committed module profile. This runs `probe` with the write probes, RSA up
    /// to 4096 bits, and the profile's name, with a diff against the profile when the profile
    /// set has it. It writes the file as `probe --out` writes it: beside a file that differs, as
    /// `<file>.new`, unless --accept is given. Every regeneration runs this one command
    /// (profiles/LEDGER.toml, `[regen]`), so the flags belong to this command and not to each
    /// script. The exit code is 15 on drift.
    Regenerate(RegenerateArgs),
}

/// The `supports` query.
#[derive(clap::Args)]
struct SupportsArgs {
    /// What to ask about: `CKM_*`, `CKK_*`, `CKP_*` or a curve name.
    #[arg(required_unless_present_any = ["class", "oaep"], conflicts_with_all = ["class", "oaep"])]
    name: Option<String>,
    /// The module profile, for example softhsm/2.7 (or its family, when only one profile of the
    /// family is loaded).
    #[arg(long, conflicts_with = "token")]
    profile: Option<String>,
    /// The token in keys.toml whose `provider` names the profile family.
    #[arg(long)]
    token: Option<String>,
    /// A delta layer to put on top (repeatable): p11-kit/0.26, swtpm, or a layer from
    /// --profiles. The cryptoki binding layer is always applied as this build decides it, so
    /// `--layer cryptoki/0.12` adds nothing.
    #[arg(long = "layer")]
    layers: Vec<String>,
    /// List the members of a baseline class (pq, hmac, key-wrap, oaep) with verdicts.
    #[arg(long, conflicts_with = "oaep")]
    class: Option<String>,
    /// List the RSA-OAEP hashes usable for wrapping.
    #[arg(long)]
    oaep: bool,
    /// An RSA modulus size to ask about, with NAME `CKK_RSA`.
    #[arg(long, requires = "name")]
    bits: Option<u32>,
}

/// What `probe` probes, and where the result goes.
#[derive(clap::Args)]
struct ProbeArgs {
    /// The token in keys.toml to probe.
    #[arg(long)]
    token: String,
    /// Also run the probes that create and delete objects. They run only on a scratch token:
    /// `[tokens.<t>] probe = { scratch = true }`, or `probe.scratchId`, which names one slot (of
    /// a `YubiKey`, for example).
    #[arg(long)]
    write_probes: bool,
    /// Write the generated profile to this file instead of stdout. An existing file that differs
    /// is replaced only with --accept. Otherwise, the profile is written beside it as
    /// `<file>.new`, to be reviewed first (docs/DEVELOPMENT.md, "Golden files").
    #[arg(long)]
    out: Option<PathBuf>,
    /// Replace the --out file with the regenerated profile, rather than writing `<file>.new`.
    #[arg(long, requires = "out")]
    accept: bool,
    /// Name the generated profile, for example `tpm2-pkcs11/1.10+swtpm` for a module on one
    /// kind of hardware. The default is the claimed profile's name with --diff, and otherwise
    /// `<provider>/<version>`.
    #[arg(long)]
    name: Option<String>,
    /// Diff against this profile (name or family), from the embedded set or --profiles.
    #[arg(long)]
    diff: Option<String>,
    /// The largest RSA key that the write probes generate, in bits. By default, the probes try
    /// every size up to 16384, whatever the module reports. A smaller limit probes faster: the
    /// test suites pass 4096, because a software token takes over a minute for 16384 bits.
    #[arg(long, requires = "write_probes", default_value_t = probe::RSA_SIZES[probe::RSA_SIZES.len() - 1])]
    rsa_max_bits: u32,
}

/// The largest RSA key that a regeneration generates, in bits (profiles/LEDGER.toml, `[regen]`;
/// `checks.ledger` checks that the ledger matches this value). Every path that regenerates a
/// committed profile probes the same sizes, because the sizes belong to the `regenerate` command
/// (review 2026-11-24 E-8). A software token takes over a minute for each 16384-bit key.
pub const REGENERATE_RSA_MAX_BITS: u32 = 4096;

/// What `regenerate` regenerates: one committed module profile, from one token, into one file.
#[derive(clap::Args)]
struct RegenerateArgs {
    /// The profile, by its full name (`softhsm/2.7`, `tpm2-pkcs11/1.10+swtpm`). The file gets
    /// this name, and the result is compared with this profile when the profile set has it.
    profile: String,
    /// The token in keys.toml to probe, which must be a scratch token (`probe.scratch` or
    /// `probe.scratchId`).
    #[arg(long)]
    token: String,
    /// The profile's file. It is written whether or not the profile drifts, and its
    /// `[migration]` and `[manual]` sections are kept. Beside a file that differs, it is written
    /// as `<file>.new` unless --accept is given (`cakeys_profile::regenerate::write`;
    /// docs/DEVELOPMENT.md, "Golden files").
    #[arg(long)]
    out: PathBuf,
    /// Replace the --out file with the regenerated profile, rather than writing `<file>.new`.
    #[arg(long)]
    accept: bool,
}

impl RegenerateArgs {
    /// Returns the `probe` arguments that this regeneration runs, with the flags that every
    /// regeneration shares.
    ///
    /// # Errors
    ///
    /// Returns `Validation` (17) for a family name, or for any name that is not a full profile
    /// name (`<family>/<version>`).
    fn probe(&self, set: &cakeys_profile::Set) -> Result<ProbeArgs, KmError> {
        if !self.profile.contains('/') {
            return Err(KmError::Validation(
                format!("regenerate names a profile in full, <family>/<version> (softhsm/2.7), not '{}'", self.profile)
                    .into(),
            ));
        }
        Ok(ProbeArgs {
            token: self.token.clone(),
            write_probes: true,
            out: Some(self.out.clone()),
            name: Some(self.profile.clone()),
            // A full name finds only that profile (`Set::find`), and the first probe of a
            // profile has none to compare with.
            diff: set.find(&self.profile).is_ok().then(|| self.profile.clone()),
            rsa_max_bits: REGENERATE_RSA_MAX_BITS,
            accept: self.accept,
        })
    }
}

/// Returns the definition of the command line: its verbs and flags, with the exit codes after
/// its help. The definition is used for parsing and by the test that checks that an
/// integration test uses every flag (`tests/common/surface.rs`).
#[must_use]
pub fn command() -> clap::Command {
    cakeys_cli_common::with_exit_codes(<Cli as clap::CommandFactory>::command())
}

/// Runs the command line with the given providers, and maps errors to the documented exit
/// codes.
#[must_use]
pub fn main(registry: &Registry) -> ExitCode {
    main_from(registry, std::env::args_os())
}

/// Runs [`main`] on `args` (with the program name first) instead of the process's arguments,
/// so that a binary or a test can run caprobe in its own process. It never exits the process:
/// `--help` and `--version` print and return 0, and a usage error prints and returns clap's 2.
/// The profile set is built once per process (`activate`). A later call reuses the set when it
/// names the same profile directories, and is refused with 17 when it names other ones.
#[must_use]
pub fn main_from<I, T>(registry: &Registry, args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let parsed = command().try_get_matches_from(args).and_then(|m| <Cli as clap::FromArgMatches>::from_arg_matches(&m));
    let cli = match parsed.and_then(Cli::with_config) {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version go to stdout, and a usage error goes to stderr, as clap's own
            // exit does.
            let _ = e.print();
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    cakeys_cli_common::main(|notes| dispatch(registry, &cli, notes))
}

impl Cli {
    /// Returns `self` when it has the keys.toml that its verb needs. Every verb except
    /// `supports --profile` reads a keys.toml; `supports --profile` reads only the profiles
    /// (docs/CAPROBE.md).
    fn with_config(self) -> Result<Cli, clap::Error> {
        if self.config.is_some() || matches!(&self.cmd, Cmd::Supports(a) if a.token.is_none()) {
            return Ok(self);
        }
        Err(command().error(
            clap::error::ErrorKind::MissingRequiredArgument,
            "--config <CONFIG> (or CAKEYS_CONFIG) is required: only `supports --profile` runs without a keys.toml",
        ))
    }
}

/// The profile directories from which this process's set was built (the `profileDirs` of
/// keys.toml, and then `--profiles`), after [`activate`] has built the set.
static ACTIVATED: std::sync::Mutex<Option<(Vec<PathBuf>, Option<PathBuf>)>> = std::sync::Mutex::new(None);

/// Activates the profile set from the `profileDirs` of `cfg` and from `replacing`
/// (`--profiles`), once per process. `Set::activate` builds the set only once, so a second run
/// in the same process ([`main_from`]) reuses the set when it names the same directories.
///
/// # Errors
///
/// Returns what [`cakeys_cli_common::activate_profiles`] refuses, and `Validation` (17) for a
/// run that names other directories than the ones the set was built from.
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

/// Loads keys.toml and runs the verb.
fn dispatch(registry: &Registry, cli: &Cli, notes: &mut Notes) -> anyhow::Result<()> {
    let cfg = match &cli.config {
        Some(path) => load_config(path)?,
        // This is `supports --profile` ([`Cli::with_config`]), which reads nothing from
        // keys.toml.
        None => Config::default(),
    };
    // There is one profile set, activated as the verbs activate it, with `--profiles` loaded
    // over it.
    activate(&cfg, cli.profiles_dir.as_deref(), notes)?;
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
        Cmd::Supports(a) => run_supports(&cfg, a, cli.json, notes),
        Cmd::Probe(_) | Cmd::Regenerate(_) if cli.json => {
            Err(KmError::Validation("--json: `probe` prints a profile, which is TOML".into()).into())
        }
        Cmd::Probe(a) => run_probe(&cfg, &modules, registry, a, notes),
        Cmd::Regenerate(a) => run_probe(&cfg, &modules, registry, &a.probe(profile_set()?)?, notes),
    }
}

/// Returns the active profile set: the embedded profiles, the `profileDirs` of keys.toml, and
/// any `--profiles` (D11). `dispatch` activates the set once, as every verb activates it (review
/// D4).
fn profile_set() -> anyhow::Result<&'static cakeys_profile::Set> {
    Ok(cakeys_profile::Set::active().map_err(|e| KmError::Validation(e.into()))?)
}

/// Runs the `supports` verb. It answers from the capability profiles alone (docs/CAPROBE.md),
/// so it runs with an empty `cfg` when there is no keys.toml and no `--token` to look up.
fn run_supports(cfg: &Config, a: &SupportsArgs, json: bool, notes: &mut Notes) -> anyhow::Result<()> {
    // A size applies only to an RSA key. A size given with any other name would be dropped
    // without a message, so it is refused.
    if let (Some(bits), Some(name)) = (a.bits, a.name.as_deref())
        && name != "CKK_RSA"
    {
        return Err(KmError::Validation(
            format!("--bits {bits} asks for an RSA size: NAME is CKK_RSA, not {name}").into(),
        )
        .into());
    }
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
    if json {
        let rows: Vec<serde_json::Value> =
            s.verdicts.iter().map(|(n, v)| serde_json::json!({"name": n, "verdict": v.to_string()})).collect();
        print(&rows)?;
    } else {
        for (n, v) in &s.verdicts {
            println!("{n}: {v}");
        }
    }
    Ok(s.outcome()?)
}

/// Runs `probe`: generates the token's capability profile, prints or writes it, and compares it
/// with a committed profile.
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
    let access = if a.write_probes { Access::Write } else { Access::Read };
    // The token is opened without a profile, so that the committed profile cannot affect what
    // the probe measures.
    let tok = open_token(cfg, modules, registry, &a.token, access, ChainTime::Unchecked, notes)?.unprofiled()?;
    let req = probe::Request {
        write: a.write_probes,
        name: a.name.as_deref(),
        claimed,
        kept: a.out.is_some() || a.diff.is_some(),
        rsa_max_bits: a.rsa_max_bits,
    };
    let mut profile = probe::generate(&tok, tcfg, &req, notes)?;
    match &a.out {
        Some(path) => write_profile(path, &mut profile, a.write_probes, a.name.is_some(), a.accept, notes)?,
        None => print!("{}", emit::profile(&profile)),
    }
    let Some(claimed) = claimed else { return Ok(()) };
    let name = &claimed.profile;
    let lines = probe::drift(&profile, claimed, a.write_probes);
    if lines.is_empty() {
        notes.say(format!("{}: the profile conforms to {name}", tok.name));
        return Ok(());
    }
    // The lines go to stderr, because stdout may carry the generated profile.
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

/// Writes a generated profile to `path`, and keeps the two sections of the existing file that
/// the probe does not generate: the `[migration]` claims (the docs/CAMIGRATE.md evidence, which
/// no probe can observe) and the `[manual]` findings. The write is refused onto an existing file
/// that does not parse (regenerating it would silently drop those sections), onto any existing
/// file from a read-only probe (the result would drop every write-probe row), and onto another
/// profile's file (`probe::keep_claims`; `renamed` is true when `--name` was given). The file is
/// written as every golden file is (`cakeys_profile::regenerate`): over a file that differs only
/// when `accept` is true, and otherwise beside it as `<file>.new` (review 2026-11-24 C-8).
fn write_profile(
    path: &Path,
    profile: &mut cakeys_profile::Profile,
    write: bool,
    renamed: bool,
    accept: bool,
    notes: &mut Notes,
) -> anyhow::Result<()> {
    // Only a file that does not exist has nothing to keep. A file that cannot be read may hold
    // claims, so a read error other than "not found" is an error.
    match std::fs::read_to_string(path) {
        Ok(text) => probe::keep_claims(profile, &text, &path.display().to_string(), write, renamed)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {} to keep its claims", path.display())),
    }
    let written = cakeys_profile::regenerate::write_with(path, &emit::profile(profile), accept, |p, text| {
        anyhow::Ok(cakeys_core::config::write_whole(p, text.as_bytes(), 0o666)?)
    })?;
    notes.say(written.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> ExitCode {
        main_from(&default_registry(), std::iter::once("caprobe").chain(args.iter().copied()))
    }

    /// `main_from` returns the code that clap would exit with, and never exits the process that
    /// the test runs in. It also runs again in the same process: the same profile directories
    /// reuse the set, and other directories are refused with 17 (review lib F2). This is one
    /// test, because the set belongs to the process.
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

    /// `regenerate` is `probe` with the flags that every regeneration shares: the write probes,
    /// RSA up to the ledger's size, the profile's name, and a diff only against that same
    /// profile (the first probe of a profile has nothing to compare with). A family name is
    /// refused and is never resolved to one of its versions.
    #[test]
    fn regenerating_is_the_one_probe_every_regeneration_runs() {
        // The test activates the process's set as `main_from` does.
        activate(&Config::default(), None, &mut Notes::default()).unwrap();
        let set = profile_set().unwrap();
        let regen = |profile: &str, accept| RegenerateArgs {
            profile: profile.into(),
            token: "t".into(),
            out: "p.toml".into(),
            accept,
        };
        for (profile, diff, accept) in [("softhsm/2.7", Some("softhsm/2.7"), false), ("softhsm/9.9", None, true)] {
            let p = regen(profile, accept).probe(set).unwrap();
            assert!(p.write_probes && p.token == "t" && p.out.as_deref() == Some(Path::new("p.toml")), "{profile}");
            // The file is written through `regenerate::write`, as `probe --out` writes it: as
            // `.new` unless the change is accepted.
            assert_eq!(p.accept, accept, "{profile}");
            assert_eq!((p.name.as_deref(), p.diff.as_deref()), (Some(profile), diff));
            assert_eq!(p.rsa_max_bits, REGENERATE_RSA_MAX_BITS, "the ledger's [regen] size, checks.ledger holds it");
        }
        assert_eq!(regen("softhsm", false).probe(set).err().map(|e| e.exit_code()), Some(17));
    }
}
