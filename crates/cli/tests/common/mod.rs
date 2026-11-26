//! Helpers shared by the integration tests of `cakeys`, `caprobe` and `camigrate` (each package
//! includes this file). The helpers run the package's own binary, write the token headers of each
//! suite's keys.toml, and provide the cross-reference harness ([`xref`]), the check of what a run
//! must leave unchanged ([`state`]), the runner of the liar matrix ([`liars`]), CLI output parsing
//! and an independent DER oracle.
#![allow(dead_code, reason = "each test binary uses a subset")]
#![expect(unreachable_pub, reason = "its crate is a test binary: pub and pub(crate) say the same")]

pub mod liars;
pub mod state;
pub mod surface;
#[path = "../../../test-skip.rs"]
pub(crate) mod test_skip;
pub mod xref;

pub(crate) use test_skip::{REQUIRE_ALL, TPM_BUILT, required, required_here, skip};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The binary under test, which is the binary of the package that includes this file (Cargo sets
/// `CARGO_BIN_EXE_<name>` only for the package's own binaries).
pub const BIN: &str = match (
    option_env!("CARGO_BIN_EXE_cakeys"),
    option_env!("CARGO_BIN_EXE_caprobe"),
    option_env!("CARGO_BIN_EXE_camigrate"),
) {
    (Some(b), _, _) | (None, Some(b), _) | (None, None, Some(b)) => b,
    (None, None, None) => panic!("included by a package with no cakeys, caprobe or camigrate binary"),
};

/// The variables that the tools read from the environment when no flag sets the value: a
/// developer's real keys.toml and lock (review common/mod.rs F1), and the Nix build markers, which
/// a run should see only when a test sets them. The per-test runner (nix/test-tokens.sh) also
/// unsets the first two for every test.
pub const SCRUBBED: [&str; 4] = ["CAKEYS_CONFIG", "CAKEYS_LOCK", "NIX_BUILD_TOP", "IN_NIX_SHELL"];

/// Returns a command that runs `bin` from a test, with none of the variables in [`SCRUBBED`].
/// Every run of a tool in a test starts here.
pub fn tool(bin: impl AsRef<OsStr>) -> Command {
    let mut c = Command::new(bin);
    for var in SCRUBBED {
        c.env_remove(var);
    }
    c
}

/// A run of a tool on a keys.toml: [`tool`] with `--config`, plus the environment that a test
/// gives it (variables set and removed). The run's output is logged in the test's output. Every
/// helper that runs a tool against a keys.toml builds a `Run` (review D9: each helper had its own
/// copy, and the copies removed different variables).
pub struct Run {
    command: Command,
    /// The name of the run in the log: the binary, and a note (the reference, for xref).
    name: String,
}

impl Run {
    /// Returns a run of `bin --config <config>`.
    pub fn new(bin: impl AsRef<OsStr>, config: &Path) -> Run {
        let bin = bin.as_ref();
        let mut command = tool(bin);
        command.arg("--config").arg(config);
        Run { command, name: Path::new(bin).file_name().unwrap_or(bin).to_string_lossy().into_owned() }
    }

    pub fn env(mut self, var: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Run {
        self.command.env(var, value);
        self
    }

    pub fn envs<K: AsRef<OsStr>, V: AsRef<OsStr>>(mut self, vars: impl IntoIterator<Item = (K, V)>) -> Run {
        self.command.envs(vars);
        self
    }

    pub fn env_remove(mut self, var: impl AsRef<OsStr>) -> Run {
        self.command.env_remove(var);
        self
    }

    /// Adds `note` next to the binary's name in the log.
    pub fn note(mut self, note: &str) -> Run {
        self.name = format!("{} ({note})", self.name);
        self
    }

    /// Returns the command with `args`, for a test that controls the process itself.
    pub fn command(mut self, args: &[&str]) -> Command {
        self.command.args(args);
        self.command
    }

    /// Runs with `args` until the process exits.
    pub fn output(mut self, args: &[&str]) -> Output {
        let out = self.command.args(args).output().unwrap();
        log_run(&self.name, args, &out);
        out
    }

    /// Runs with `args`, with a time limit, so that on hardware a touch or PIN prompt fails the
    /// test instead of making it wait forever.
    ///
    /// # Panics
    ///
    /// When the run takes longer than `limit`.
    pub fn within(mut self, args: &[&str], limit: Duration) -> Output {
        self.command.args(args);
        let out = output_within(self.command, limit).unwrap_or_else(|| {
            panic!(
                "{} {} did not finish within {limit:?}: user presence (touch or PIN) needed?",
                self.name,
                args.join(" ")
            )
        });
        log_run(&self.name, args, &out);
        out
    }
}

fn log_run(name: &str, args: &[&str], out: &Output) {
    eprintln!(
        "$ {name} {}\n  exit={:?}\n  stdout={}\n  stderr={}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

/// Returns `command`'s output, or `None` (after the child is killed) when it runs longer than
/// `limit`. Both pipes are read while the child runs, because a child that writes more than a
/// pipe holds blocks until someone reads. When the pipes were read only after the child exited,
/// the child never exited (review common/mod.rs F3).
pub fn output_within(mut command: Command, limit: Duration) -> Option<Output> {
    fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    }
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (stdout, stderr) = (drain(child.stdout.take().unwrap()), drain(child.stderr.take().unwrap()));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stderr) = (stdout.join().unwrap(), stderr.join().unwrap());
    status.map(|status| Output { status, stdout, stderr })
}

/// Returns the path of another binary of this workspace, next to [`BIN`] in the target directory.
/// Cargo gives a test only the binaries of its own package, but `cargo test --workspace` (the Nix
/// check phase) builds all of them before any test runs.
///
/// # Panics
///
/// Panics when that binary is not built (for example, after `cargo test -p <package>` alone).
/// Build the workspace first.
pub fn sibling(name: &str) -> PathBuf {
    let path = Path::new(BIN).with_file_name(name);
    assert!(path.exists(), "{} is not built: run `cargo build --workspace` first", path.display());
    path
}

/// Returns the value of `var` (a module path), or `None` when it is unset. When the run requires
/// the variable ([`required`]: `require` is set, or `CAKEYS_REQUIRE_ALL` is set), a missing value
/// is a failure instead. Every suite's gate reads its module through this function (review D9).
///
/// # Panics
///
/// Panics when `var` is missing and required.
pub fn required_var(var: &str, require: &str) -> Option<String> {
    let v = std::env::var(var).ok();
    if let (None, Some(because)) = (&v, required_here(require)) {
        panic!("{var} is required ({because})");
    }
    v
}

/// Works like [`required_var`] for the suite that `test` belongs to. `None` means that the test is
/// skipped ([`skip`]).
pub fn suite_var(var: &str, require: &str, test: &str) -> Option<String> {
    let v = std::env::var(var).ok();
    if v.is_none() {
        skip(test, require, &format!("{var} not set"));
    }
    v
}

/// A hardware suite's opt-in: its variables, which must be all set or all unset, and the variable
/// that makes the suite required (a run that intends to run the suite, such as
/// `scripts/coverage-full.sh`, sets it together with them).
#[derive(Clone, Copy)]
pub struct OptIn<const N: usize> {
    pub vars: [&'static str; N],
    pub require: &'static str,
}

/// The opt-in of the ftpm suites: the module and its pair profile, both set or neither set.
pub const FTPM_OPT_IN: OptIn<2> =
    OptIn { vars: ["CAKEYS_FTPM_MODULE", "CAKEYS_FTPM_PROFILE"], require: "CAKEYS_FTPM_REQUIRE" };
/// The opt-in of the `YubiKey` suites that log in: the PIN file and the management-key file, both
/// set or neither set. The module variable alone opts in only the read-only probe (caprobe).
pub const YUBIKEY_OPT_IN: OptIn<2> =
    OptIn { vars: ["CAKEYS_TEST_YUBIKEY_PIN", "CAKEYS_TEST_YUBIKEY_MGM"], require: "CAKEYS_YUBIKEY_REQUIRE" };

/// Returns the module, the PIN file and the management-key file for a `YubiKey` suite that logs
/// in, opted in by [`YUBIKEY_OPT_IN`]. When the opt-in variables are set, a missing module is a
/// failure.
pub fn yubikey_opted_in(test: &str) -> Option<[String; 3]> {
    let [pin, mgm] = opted_in(test, YUBIKEY_OPT_IN)?;
    let module = std::env::var("CAKEYS_TEST_YUBIKEY_MODULE")
        .unwrap_or_else(|_| panic!("{test}: the PIN and management key are set, CAKEYS_TEST_YUBIKEY_MODULE is not"));
    Some([module, pin, mgm])
}

/// Reads a hardware suite's opt-in (review D9) through `env`. When every one of its variables is
/// set, it returns their values. When none is set, it returns `None` (the suite is skipped),
/// unless the suite's require variable is set. When some but not all are set, it returns an error
/// that names the missing ones, because setting any of them shows that the run wants the suite,
/// and a half-set opt-in must not pass without running anything. The require variable alone,
/// without the opt-in variables, is also an error (review ftpm.rs F2: a run that intended the
/// suite, without its variables, passed after running nothing).
///
/// # Errors
///
/// Returns the message for a half-set opt-in, or for a required opt-in that is not set.
pub fn opt_in<const N: usize>(
    o: OptIn<N>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<[String; N]>, String> {
    let got = o.vars.map(env);
    let missing: Vec<&str> = o.vars.iter().zip(&got).filter(|(_, v)| v.is_none()).map(|(n, _)| *n).collect();
    let required = env(o.require).is_some();
    match missing.len() {
        0 => Ok(Some(got.map(Option::unwrap_or_default))),
        n if n == N && !required => Ok(None),
        _ => {
            let why = if required { format!("; {} is set", o.require) } else { String::new() };
            Err(format!("{} not set: the opt-in is {}, all or none{why}", missing.join(", "), o.vars.join(", ")))
        }
    }
}

/// Calls [`opt_in`] on the process's environment. It returns `None` when the suite is skipped
/// ([`skip`]), and it panics when the opt-in is half set or required but not set.
pub fn opted_in<const N: usize>(test: &str, o: OptIn<N>) -> Option<[String; N]> {
    match opt_in(o, &|v| std::env::var(v).ok()) {
        Ok(Some(values)) => Some(values),
        Ok(None) => {
            skip(test, o.require, &format!("{} not set", o.vars.join(", ")));
            None
        }
        Err(e) => panic!("{test}: {e}"),
    }
}

/// Returns the reference suite's tokens. `ref` is a scratch token: it is created for the run and
/// discarded afterward, which is what the probe's write probes require (docs/CAPROBE.md).
/// `ref-anon` is the same token without a PIN, so it sees only public objects, like a PIV token
/// that is used without a login.
pub fn reference_tokens(module: &str, dir: &Path) -> String {
    format!(
        "[tokens.ref]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprobe = {{ scratch = true }}\n\n\
         [tokens.ref-anon]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n\n",
        dir.join("pin").display(),
    )
}

/// Returns the tpm2-pkcs11 tokens on swtpm: `tpm` (logged in, and a scratch token, because the
/// swtpm token is created for the run), `tpm-anon` (no PIN) and `tpm-generic` (logged in, but
/// without the fix-ups of the tpm2-pkcs11 provider). The native attestation path finds the TPM
/// in the same way as the module, through `$TPM2_PKCS11_TCTI`, which the harness exports in the
/// TCTI library-path form, and it finds the store through `$TPM2_PKCS11_STORE`.
pub fn tpm2_tokens(module: &str, dir: &Path) -> String {
    let pin = dir.join("pin");
    let token =
        |name: &str, extra: &str| format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n{extra}\n");
    token("tpm", &format!("pinFile = \"{}\"\nprobe = {{ scratch = true }}", pin.display()))
        + &token("tpm-anon", "")
        + &token("tpm-generic", &format!("pinFile = \"{}\"\nprovider = \"generic\"", pin.display()))
}

/// Returns the tpm2-pkcs11 store of the TPM harnesses (nix/tpm2-test-env.sh,
/// nix/ftpm-test-env.sh).
pub fn tpm2_store() -> String {
    std::env::var("TPM2_PKCS11_STORE").expect("TPM2_PKCS11_STORE: the TPM harness's store")
}

/// Runs `tpm2_ptool <args> --path <store>`, which must succeed.
pub fn ptool_in(store: &str, args: &[&str]) {
    let out = Command::new("tpm2_ptool").args(args).arg(format!("--path={store}")).output().unwrap();
    assert!(out.status.success(), "tpm2_ptool {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// Runs `tpm2_ptool <args>` on the harness's token `kmtest` ([`tpm2_store`], user PIN 1234).
pub fn ptool(args: &[&str]) {
    ptool_in(&tpm2_store(), &[args, &["--label=kmtest", "--userpin=1234"]].concat());
}

/// Returns the token on the host's real TPM: `ftpm` (logged in, and a scratch token, because the
/// harness's store is made for the run).
pub fn ftpm_tokens(module: &str, dir: &Path) -> String {
    format!(
        "[tokens.ftpm]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprobe = {{ scratch = true }}\n\n",
        dir.join("pin").display()
    )
}

/// Returns the tokens for p11-kit forwarding: `fwd` (through p11-kit), `fwd-anon` (no PIN),
/// `fwd-softhsm` (with the provider named), `fwd-other` (a token that the server does not export)
/// and `direct` (`SoftHSM` itself).
pub fn p11kit_tokens(client: &str, direct: &str, dir: &Path) -> String {
    let pin = format!("pinFile = \"{}\"", dir.join("pin").display());
    let token = |name: &str, module: &str, label: &str, extra: &str| {
        format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"\n{extra}\n\n")
    };
    token("fwd", client, "kmp11", &pin)
        + &token("fwd-anon", client, "kmp11", "")
        + &token("fwd-softhsm", client, "kmp11", &format!("{pin}\nprovider = \"softhsm\""))
        + &token("fwd-other", client, "kmtest", &pin)
        + &token("direct", direct, "kmp11", &pin)
}

/// A `YubiKey` test's turn at the device. Only one test at a time uses the device, across every
/// test process (through an exclusive lock on a file in the shared target tmpdir), and no test
/// uses it after a login failed. The PIN has three tries, and the hardware rule is to stop after
/// one failed login (docs/DEVELOPMENT.md, "Hardware rules"). Two tests that logged in at the same
/// time with a wrong PIN file used two tries (review yubikey.rs F1). Take the turn before the
/// test's first run, and pass each run's output through [`YubikeyTurn::checked`].
pub struct YubikeyTurn {
    _lock: std::fs::File,
}

/// Returns the path of the file that a failed `YubiKey` login leaves. Every later `YubiKey` test
/// refuses to run until a person has fixed the credential and removed the file.
pub fn yubikey_latch() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("yubikey-login-failed")
}

impl YubikeyTurn {
    /// Waits for the device, and then refuses to continue if a login has failed since the latch
    /// was cleared.
    ///
    /// # Panics
    ///
    /// Panics when the latch is set.
    pub fn take() -> YubikeyTurn {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(&dir).unwrap();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("yubikey.turn"))
            .unwrap();
        file.lock().unwrap();
        let turn = YubikeyTurn { _lock: file };
        turn.refuse_if_latched();
        turn
    }

    /// Refuses to continue if a login has failed since the latch was cleared.
    ///
    /// # Panics
    ///
    /// Panics when a login has failed since then.
    #[expect(clippy::unused_self, reason = "asked only by the test holding the turn")]
    pub fn refuse_if_latched(&self) {
        let latch = yubikey_latch();
        assert!(
            !latch.exists(),
            "a YubiKey login failed in an earlier test: no further login is tried until the credential is \
             fixed and {} is removed",
            latch.display()
        );
    }

    /// Returns `out`. If the run's login failed (any `CKR_PIN_*`), it first sets the latch, which
    /// stops every later `YubiKey` test.
    ///
    /// # Panics
    ///
    /// Panics when the run's login failed.
    #[expect(clippy::unused_self, reason = "a run is checked by the test holding the turn")]
    pub fn checked(&self, out: Output) -> Output {
        if let Some(rv) = failed_login(&String::from_utf8_lossy(&out.stderr)) {
            std::fs::write(yubikey_latch(), format!("{rv}\n")).unwrap();
            panic!(
                "a YubiKey login failed ({rv}): latched off at {}; stop and fix the credential",
                yubikey_latch().display()
            );
        }
        out
    }
}

/// Returns the `CKR_PIN_*` that a run's stderr reports, if its login failed. The tools name a
/// login's return value by its constant (cryptoki's own message text names no constant), and
/// `cli/tests/fault.rs` checks that they do.
pub fn failed_login(said: &str) -> Option<String> {
    let at = said.find("CKR_PIN_")?;
    Some(said[at..].chars().take_while(|c| c.is_ascii_uppercase() || *c == '_').collect())
}

/// Returns the token table for a real `YubiKey`, with both credentials (file paths) and with
/// `extra` added.
pub fn yubikey_token(module: &str, pin: &str, mgm: &str, extra: &str) -> String {
    format!(
        "[tokens.yubikey]\nmodule = \"{module}\"\ntokenLabel = \"{}\"\npinFile = \"{pin}\"\nsoCredentialFile = \"{mgm}\"\n{extra}\n",
        yubikey_label(module)
    )
}

/// Returns the label of the first `YubiKey` that the module sees, so that the config names the
/// right token.
pub fn yubikey_label(module: &str) -> String {
    let ctx = Module::open(module);
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().model().starts_with("YubiKey"))
        .unwrap();
    ctx.get_token_info(slot).unwrap().label().to_string()
}

/// Runs the binary on `config` with a time limit ([`Run::within`]).
///
/// # Panics
///
/// Panics when the run takes longer than `limit`.
pub fn run_within(config: &Path, args: &[&str], limit: Duration) -> Output {
    Run::new(BIN, config).within(args, limit)
}

/// Returns whether the linked cryptoki has the HMAC key type fix (nix/patches/), which the Nix
/// build has. Without the fix, tests that need SHA-224/384/512 HMAC keys skip, unless `require` is
/// true, in which case they fail. A suite that may skip names the variable that requires it
/// through [`hmac_types_fixed`]. Pass `true` for a suite that never skips (a hardware suite, after
/// it is opted in).
///
/// # Panics
///
/// Panics when `require` is true and the fix is missing.
pub fn cryptoki_hmac_types_fixed(require: bool) -> bool {
    let fixed = std::os::raw::c_ulong::from(cryptoki::object::KeyType::SHA384_HMAC) == 0x2c;
    assert!(fixed || !require, "cryptoki lacks the HMAC key type fix (nix/patches/cryptoki-hmac-key-types.patch)");
    fixed
}

/// Calls [`cryptoki_hmac_types_fixed`], and skips ([`skip`]) when the fix is missing, unless the run
/// requires the suite through `require_var` (review common/mod.rs F7: callers that computed the
/// flag themselves passed `false`, or another suite's variable).
pub fn hmac_types_fixed(require_var: &str) -> bool {
    let fixed = cryptoki_hmac_types_fixed(false);
    if !fixed {
        skip("", require_var, "cryptoki lacks the HMAC key type fix; run through the Nix build");
    }
    fixed
}

/// A software PKCS#11 token that the shared suite (`tests/reference/`) runs against. The struct
/// holds the facts that the suite needs about the token, so that its tests assert the same
/// results on every reference.
pub struct Reference {
    /// The variable that holds the path of the module. The suite skips when it is unset.
    pub module_var: &'static str,
    /// The variable that, when set, makes a missing module fail instead of skip.
    pub require_var: &'static str,
    /// The variable that names the module's own configuration file.
    pub conf_var: &'static str,
    /// The provider cakeys detects from `C_GetInfo`.
    pub provider: &'static str,
    /// `C_GetInfo` manufacturer and `C_GetTokenInfo` model, as recorded in provenance.
    pub manufacturer: &'static str,
    pub model: &'static str,
    /// The curves (by their `keys.toml` names) that the module cannot generate. They are refused
    /// as unsupported (15).
    pub missing_curves: &'static [&'static str],
    /// Whether the module implements Triple DES (`CKM_DES3_ECB`, `CKM_DES3_KEY_GEN`). Without it,
    /// a `CKK_DES3` spec is refused as unsupported (15).
    pub des3: bool,
    /// Whether the module generates the HMAC key types that are bound to a hash (PKCS#11 3.0's
    /// `CKM_SHA*_KEY_GEN`).
    pub hmac_key_gen: bool,
    /// The module's committed capability profile: its name, and its path under profiles/.
    pub profile: (&'static str, &'static str),
    /// Returns the module's configuration (the file in `conf_var`) with one mechanism hidden.
    pub hide_mechanism: fn(conf: &str, mechanism: &str) -> String,
    /// Whether the suite loads the module through `p11-fault` (`P11_FAULT_MODULE` names the
    /// module) with no fault plan. The shim must then forward every call without a change.
    pub through_fault_shim: bool,
}

pub const SOFTHSM: Reference = Reference {
    module_var: "CAKEYS_TEST_MODULE",
    require_var: "CAKEYS_TEST_REQUIRE",
    conf_var: "SOFTHSM2_CONF",
    provider: "softhsm",
    manufacturer: "SoftHSM",
    model: "SoftHSM v2",
    missing_curves: &[],
    des3: true,
    hmac_key_gen: false,
    profile: ("softhsm/2.7", "modules/softhsm/2.7.toml"),
    hide_mechanism: |conf, m| format!("{conf}\nslots.mechanisms = -{m}\n"),
    through_fault_shim: false,
};

/// kryoptic 1.5.4 (with its `OpenSSL` backend) generates neither secp256k1 nor the brainpool
/// curves, and it has no DES mechanism (`pkcs11-tool -M` \[run\], 2026-11-15). The harness
/// (nix/package-common.nix) ends `KRYOPTIC_CONF` with the token's `[[slots]]` table, so a key that
/// is appended to the file belongs to that table.
pub const KRYOPTIC: Reference = Reference {
    module_var: "CAKEYS_KRYOPTIC_MODULE",
    require_var: "CAKEYS_KRYOPTIC_REQUIRE",
    conf_var: "KRYOPTIC_CONF",
    provider: "kryoptic",
    manufacturer: "Kryoptic",
    model: "v1",
    missing_curves: &["secp256k1", "brainpoolP256r1", "brainpoolP384r1"],
    des3: false,
    hmac_key_gen: true,
    profile: ("kryoptic/1.5", "modules/kryoptic/1.5.toml"),
    hide_mechanism: |conf, m| format!("{conf}\nmechanisms = [\"DENY\", \"{m}\"]\n"),
    through_fault_shim: false,
};

/// `SoftHSM` behind `p11-fault` (`docs/FAULT_SHIM.md`) with no fault plan. The whole suite runs a
/// third time through the shim, and it must pass as it does directly. The per-test runner
/// (nix/test-tokens.sh) points `P11_FAULT_MODULE` at the test's own `SoftHSM` token, and the
/// token's module is the shim.
pub const FAULT: Reference = Reference {
    module_var: "P11_FAULT_MODULE",
    require_var: "CAKEYS_FAULT_REQUIRE",
    through_fault_shim: true,
    ..SOFTHSM
};

/// Returns the path of `libp11_fault.so`. It is next to the binaries after a build of the
/// workspace, and otherwise among the dependencies of the tests (`deps/`), where every test build
/// puts it because the `cakeys` tests have a dev-dependency on `p11-fault`.
///
/// # Panics
///
/// Panics when the library is in neither place.
pub fn fault_shim() -> String {
    let beside = Path::new(BIN).with_file_name("libp11_fault.so");
    let path = if beside.exists() { beside } else { Path::new(BIN).with_file_name("deps").join("libp11_fault.so") };
    assert!(path.exists(), "libp11_fault.so is built neither beside {BIN} nor in deps/");
    path.to_str().unwrap().to_owned()
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// Returns the file of a committed capability profile (profiles/, docs/CAPROBE.md), which the
/// conformance tests regenerate and compare byte for byte.
pub fn committed_profile(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles").join(path)
}

/// The conformance check that every reference token runs (docs/CAPROBE.md). The committed module
/// profile `name` (at `path` under profiles/) must be exactly what a new probe of token `token`
/// observes, and regenerating it (the maintenance flow) must change no byte. `km` runs the CLI
/// against the test's keys.toml, and `scratch` is a file that the regeneration may write.
///
/// The check runs only one write probe, which compares and regenerates in the same run. A second
/// write probe would see what the first one left behind on modules that cannot destroy everything
/// they make (tpm2-pkcs11's sealed derived secrets: profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml,
/// `derive.destroy`).
///
/// The check uses `caprobe regenerate`, the command that every regeneration runs
/// (profiles/LEDGER.toml, `[regen]`). The verb sets the flags, so the test regenerates in the same
/// way as the scripts do.
pub fn assert_profile_conforms(
    km: impl Fn(&[&str]) -> Output,
    token: &str,
    name: &str,
    path: &str,
    scratch: &std::path::Path,
) {
    let committed = std::fs::read(committed_profile(path)).unwrap();
    std::fs::write(scratch, &committed).unwrap();
    let out = scratch.to_str().unwrap();
    // With `--accept`, the scratch copy is replaced, so the comparison below checks the bytes that
    // the probe made. Without `--accept`, a profile that drifted would be written next to the
    // copy, and the unchanged copy would then compare equal.
    let probe = km(&["regenerate", name, "--token", token, "--out", out, "--accept"]);
    assert_eq!(code(&probe), 0, "a fresh probe drifts from {name}: {}", String::from_utf8_lossy(&probe.stderr));
    assert!(
        std::fs::read(scratch).unwrap() == committed,
        "{path} is not what the probe generates: regenerate it as profiles/LEDGER.toml says for profiles/{path}, \
         never by hand"
    );
    // A read-only probe conforms on what it observes, and it may never overwrite the file (17).
    assert_eq!(code(&km(&["probe", "--token", token, "--diff", name])), 0);
    assert_eq!(code(&km(&["probe", "--token", token, "--out", out])), 17);
    assert_eq!(std::fs::read(scratch).unwrap(), committed, "a read-only probe overwrote the file");
}

/// Returns the writing form of a compare-only `lock` or `delete` argument list, which is the list
/// without `--dry-run`.
pub fn recording<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter().copied().filter(|a| *a != "--dry-run").collect()
}

/// Returns what a one-object `lock` run printed: the one row of the JSON array that `lock` prints
/// (one row per object, review 2026-11-23 C-7).
pub fn lock_result(o: &Output) -> serde_json::Value {
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&o.stdout).unwrap();
    let [row] = <[serde_json::Value; 1]>::try_from(rows).unwrap_or_else(|rows| panic!("not one lock result: {rows:?}"));
    row
}

pub fn got_hash(o: &Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    let line = err.lines().find(|l| l.trim_start().starts_with("got:")).expect("no got: line");
    line.split_whitespace().last().unwrap().to_owned()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A test's scratch directory, which holds keys.toml, keys.lock (empty, as `--new-lock` starts
/// one) and a PIN file that holds `1234`, and the runs of the tool against it. A token suite's test
/// holds one in its [`Suite`].
pub struct Workdir {
    pub dir: PathBuf,
}

/// A lock that pins nothing. `--new-lock` starts from it, and every test directory starts with it.
pub const EMPTY_LOCK: &str = "version = 1\n";

/// Returns the directory of one test under the integration tests' tmpdir, which every package and
/// test binary shares. The directory name includes both the package and the test binary, so
/// suites that run at the same time (and the shared reference suite, which two binaries run under
/// the same test names) never use the same directory.
pub fn test_dir(name: &str) -> PathBuf {
    let binary = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_CRATE_NAME"));
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{binary}-{name}"))
}

impl Workdir {
    /// Creates a new, empty directory `name` under the integration tests' tmpdir.
    pub fn new(name: &str) -> Workdir {
        let dir = test_dir(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pin"), "1234\n").unwrap();
        std::fs::write(dir.join("keys.lock"), EMPTY_LOCK).unwrap();
        Workdir { dir }
    }

    pub fn write_config(&self, text: &str) {
        std::fs::write(self.dir.join("keys.toml"), text).unwrap();
    }

    pub fn km(&self, args: &[&str]) -> Output {
        self.km_env(args, &[])
    }

    /// Runs `cakeys --config keys.toml <args>` with `envs` set, and logs the run in the test's
    /// output. The suites themselves run inside a Nix build, so `NIX_BUILD_TOP` is removed
    /// ([`SCRUBBED`]), and a run sees it only when a test sets it.
    pub fn km_env(&self, args: &[&str], envs: &[(&str, &Path)]) -> Output {
        self.run().envs(envs.iter().copied()).output(args)
    }

    /// Returns a run on this keys.toml ([`Run`]), for a run that removes a variable or has a time
    /// limit.
    pub fn run(&self) -> Run {
        Run::new(BIN, &self.dir.join("keys.toml"))
    }

    /// Returns the exit code of [`Self::km`].
    pub fn code(&self, args: &[&str]) -> i32 {
        code(&self.km(args))
    }

    pub fn lock(&self) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap()
    }

    /// Replaces keys.lock with `lock`. Tests edit the parsed TOML, never the text.
    pub fn write_lock(&self, lock: &toml::Value) {
        std::fs::write(self.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    }

    /// Returns the `observations` entry that the realisation of `spec` on `token` names.
    pub fn observation(&self, spec: &str, token: &str) -> toml::Value {
        let lock = self.lock();
        let key = lock["realisations"][spec][token]["observation"].as_str().unwrap().to_owned();
        lock["observations"][key.as_str()].clone()
    }

    pub fn locked_id(&self, object: &str, scheme: &str) -> String {
        self.lock()["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }
}

/// A token suite's test (review D9: each suite had its own copy): its [`Workdir`], the module that
/// its tokens load, and the token tables at the start of every keys.toml that it writes. A suite's
/// gate makes one after the module is known ([`suite_var`], [`opted_in`]). What only one suite
/// does with it is in an `impl Suite` in that suite.
pub struct Suite {
    w: Workdir,
    /// The module that the suite's tokens load, which the test also opens itself
    /// ([`Self::session`]).
    pub module: String,
    tokens: String,
    /// The check that every keys.toml goes through before the test writes it
    /// ([`Self::checking`]).
    check: fn(&str),
}

impl std::ops::Deref for Suite {
    type Target = Workdir;
    fn deref(&self) -> &Workdir {
        &self.w
    }
}

impl Suite {
    /// Returns the suite for test `name`, with a new [`Workdir`]. Every keys.toml that the suite
    /// writes through [`Self::config`] starts with `tokens(module, dir)`.
    pub fn new(name: &str, module: String, tokens: impl FnOnce(&str, &Path) -> String) -> Suite {
        let w = Workdir::new(name);
        let tokens = tokens(&module, &w.dir);
        Suite { w, module, tokens, check: |_| {} }
    }

    /// Returns the suite with `check`, which sees every keys.toml before it is written. The tpm2
    /// suite's check refuses an attestation (a persistent TPM object) anywhere except on its swtpm.
    pub fn checking(self, check: fn(&str)) -> Suite {
        Suite { check, ..self }
    }

    /// Writes keys.toml with the suite's tokens followed by `body`.
    pub fn config(&self, body: &str) {
        self.write_config(&(self.tokens.clone() + body));
    }

    /// Writes keys.toml as `text`, after the check of [`Self::checking`] has seen it (this method
    /// shadows [`Workdir::write_config`]).
    pub fn write_config(&self, text: &str) {
        (self.check)(text);
        self.w.write_config(text);
    }

    /// Returns a logged-in session on the suite's token `kmtest` (PIN 1234).
    pub fn session(&self) -> TestSession {
        open_session(&self.module, "kmtest", "1234")
    }
}

pub fn sri(bytes: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes)))
}

/// A minimal DER writer for the test oracle, which is independent of the crates that the tool
/// uses.
pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 0x80 {
        v.push(u8::try_from(n).unwrap());
    } else {
        let len: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        v.push(0x80 | u8::try_from(len.len()).unwrap());
        v.extend(len);
    }
    v.extend_from_slice(body);
    v
}

/// Parses one DER element and returns (tag, contents, rest). It is independent of the crates that
/// cakeys uses.
pub fn der(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let (tag, first) = (input[0], input[1]);
    let (len, off) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        (input[2..2 + n].iter().fold(0, |acc, b| (acc << 8) | usize::from(*b)), 2 + n)
    };
    (tag, &input[off..off + len], &input[off + len..])
}

/// Returns the DER inside a PEM file.
pub fn pem_der(path: &str) -> Vec<u8> {
    use base64::Engine;
    let text = std::fs::read_to_string(path).unwrap();
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

/// Parses a PKCS#8 EC key and returns (curve OID as DER, private scalar, uncompressed public
/// point).
pub fn ec_fixture(pkcs8: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, alg, rest) = der(rest);
    let (_, _, curve) = der(alg); // id-ecPublicKey
    let curve_len = curve.len() - der(curve).2.len();
    let (_, inner, _) = der(rest); // OCTET STRING { ECPrivateKey }
    let (_, ec, _) = der(inner);
    let (_, _, rest) = der(ec); // version
    let (_, scalar, mut rest) = der(rest);
    loop {
        let (tag, body, next) = der(rest);
        if tag == 0xa1 {
            let (_, bits, _) = der(body);
            return (curve[..curve_len].to_vec(), scalar.to_vec(), bits[1..].to_vec());
        }
        rest = next;
    }
}

/// Returns the 32-byte seed of a PKCS#8 Ed25519 key (RFC 8410).
pub fn ed25519_fixture(pkcs8: &[u8]) -> Vec<u8> {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, _, rest) = der(rest); // algorithm
    let (_, inner, _) = der(rest); // OCTET STRING { CurvePrivateKey }
    der(inner).1.to_vec()
}

/// Parses a PKCS#8 RSA key and returns the modulus, the public and private exponents, the primes,
/// the CRT exponents and the coefficient.
pub fn rsa_fixture(pkcs8: &[u8]) -> Vec<Vec<u8>> {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, _, rest) = der(rest); // algorithm
    let (_, inner, _) = der(rest);
    let (_, key, _) = der(inner);
    let (_, _, mut rest) = der(key); // version
    let mut ints = Vec::new();
    while !rest.is_empty() {
        let (_, int, next) = der(rest);
        ints.push(int.iter().copied().skip_while(|b| *b == 0).collect());
        rest = next;
    }
    ints
}

/// Returns the token object template for a fixture certificate (`SoftHSM` requires
/// `CKA_SUBJECT`).
pub fn cert_object(der: &[u8], label: &[u8], id: Option<u8>) -> Vec<Attribute> {
    let der = der.to_vec();
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&der).unwrap();
    let subject = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject()).unwrap();
    let mut t = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(cryptoki::object::CertificateType::X_509),
        Attribute::Token(true),
        Attribute::Label(label.to_vec()),
        Attribute::Subject(subject),
        Attribute::Value(der),
    ];
    t.extend(id.map(|i| Attribute::Id(vec![i])));
    t
}

pub fn der_uint(b: &[u8]) -> Vec<u8> {
    let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    let mut body = if b[0] & 0x80 != 0 { vec![0] } else { vec![] };
    body.extend(b);
    tlv(0x02, &body)
}

pub fn spki(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(key);
    tlv(0x30, &[tlv(0x30, algorithm), tlv(0x03, &bits)].concat())
}

/// Returns the point inside a `CKA_EC_POINT` value, which is a DER OCTET STRING around the point.
pub fn unwrap_octets(v: &[u8]) -> Vec<u8> {
    assert_eq!(v[0], 0x04);
    let (len, off) = match v[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 => (v[2] as usize, 3),
        n => panic!("length form {n:#x}"),
    };
    assert_eq!(v.len(), off + len, "{v:02x?}");
    v[off..].to_vec()
}

/// The DER OID of an EC public key (`id-ecPublicKey`). The constants after it are the
/// `CKA_EC_PARAMS` (the curve's OID, DER) of each curve that the tests name.
pub const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
pub const P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
pub const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
pub const ED448: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];

/// Replaces the private key under `label` with another key of the same kind, as a token that
/// swapped the key would hold (review reference/mod.rs F2: this code was written five times). The
/// function generates a pair with `mechanism` from `public` (the curve or modulus) and `private`
/// (usage and policy). The new public half is a session object, so the public key object under
/// the label is still the original's. The original private key is destroyed, and the new private
/// key takes the label, together with `extra` (for example, a forged `CKA_PUBLIC_KEY_INFO`).
pub fn swap_private_key(
    s: &Session,
    label: &str,
    mechanism: &Mechanism,
    public: &[Attribute],
    private: &[Attribute],
    extra: &[Attribute],
) {
    let labelled = Attribute::Label(label.as_bytes().to_vec());
    let original = s.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), labelled.clone()]).unwrap();
    assert_eq!(original.len(), 1, "one private key under {label}");
    let public = [&[Attribute::Token(false)], public].concat();
    let private = [&[Attribute::Token(true)], private].concat();
    let (_, other) = s.generate_key_pair(mechanism, &public, &private).unwrap();
    s.destroy_object(original[0]).unwrap();
    s.update_attributes(other, &[&[labelled], extra].concat()).unwrap();
}

/// Returns the SPKI of the public key object under `label`, built from its raw PKCS#11
/// attributes.
pub fn oracle_spki(s: &Session, label: &str) -> Vec<u8> {
    oracle_spki_with(s, label, unwrap_octets)
}

/// Works like [`oracle_spki`], with a custom `CKA_EC_POINT` unwrapper (for a known bug of a
/// module).
#[expect(
    clippy::many_single_char_names,
    reason = "the DER-oracle bindings mirror the names in the specs they hand-roll"
)]
pub fn oracle_spki_with(s: &Session, label: &str, unwrap: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let h = s
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Label(label.as_bytes().to_vec())])
        .unwrap()[0];
    let a = s.get_attributes(h, &[AttributeType::KeyType]).unwrap();
    if let Attribute::KeyType(cryptoki::object::KeyType::RSA) = a[0] {
        let a = s.get_attributes(h, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap();
        let (Attribute::Modulus(n), Attribute::PublicExponent(e)) = (&a[0], &a[1]) else { panic!() };
        let rsa = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
        spki(&rsa, &tlv(0x30, &[der_uint(n), der_uint(e)].concat()))
    } else {
        let a = s.get_attributes(h, &[AttributeType::EcParams, AttributeType::EcPoint]).unwrap();
        let (Attribute::EcParams(p), Attribute::EcPoint(q)) = (&a[0], &a[1]) else { panic!() };
        // PKCS#11 3.2 stores Edwards points raw (kryoptic's default), and earlier modules wrap
        // them in an OCTET STRING. The raw form has the exact point length, which is two bytes
        // shorter than the wrapped form.
        let raw = match p.as_slice() {
            ED25519 => Some(32),
            ED448 => Some(57),
            _ => None,
        };
        let point = if raw == Some(q.len()) { q.clone() } else { unwrap(q) };
        match p.as_slice() {
            ED25519 | ED448 => spki(p, &point),
            _ => spki(&[EC_PUBLIC_KEY, p.as_slice()].concat(), &point),
        }
    }
}

/// The host oracle for the AES commitments (`cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) of a known
/// AES-128/192/256 key.
pub fn aes_commitment(key: &[u8], scheme: &str) -> String {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use cmac::Mac;
    let label = format!("key-management/v1/{scheme}/CKK_AES/{}", key.len() * 8);
    let digest = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes());
    let mut block = aes::Block::default();
    block.copy_from_slice(&digest[..16]);
    macro_rules! with_cipher {
        ($aes:ty, $kw:ty) => {
            match scheme {
                "cmac" => {
                    let mut m = <cmac::Cmac<$aes> as KeyInit>::new_from_slice(key).unwrap();
                    m.update(label.as_bytes());
                    m.finalize().into_bytes().to_vec()
                }
                "kcv-ecb" => {
                    <$aes>::new_from_slice(key).unwrap().encrypt_block(&mut block);
                    block.to_vec()
                }
                "kcv-ecb-dec" => {
                    <$aes>::new_from_slice(key).unwrap().decrypt_block(&mut block);
                    block.to_vec()
                }
                "kw" => {
                    let mut buf = [0u8; 40];
                    <$kw>::new_from_slice(key).unwrap().wrap_key(&digest, &mut buf).unwrap().to_vec()
                }
                s => panic!("{s}"),
            }
        };
    }
    let out = match key.len() {
        16 => with_cipher!(aes::Aes128, aes_kw::KwAes128),
        24 => with_cipher!(aes::Aes192, aes_kw::KwAes192),
        32 => with_cipher!(aes::Aes256, aes_kw::KwAes256),
        n => panic!("AES key of {n} bytes"),
    };
    sri(&out)
}

/// The host oracle of a DES3 check value (`kcv-ecb`, `kcv-ecb-dec`). It applies `RustCrypto`'s
/// `des` (three-key EDE) to the first 8 bytes of the SHA-256 of the commitment label.
pub fn des3_commitment(key: &[u8; 24], scheme: &str) -> String {
    use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    let label = format!("key-management/v1/{scheme}/CKK_DES3/192");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes());
    let mut block = des::cipher::Block::<des::TdesEde3>::default();
    block.copy_from_slice(&digest[..8]);
    let cipher = des::TdesEde3::new_from_slice(key).unwrap();
    match scheme {
        "kcv-ecb" => cipher.encrypt_block(&mut block),
        "kcv-ecb-dec" => cipher.decrypt_block(&mut block),
        s => panic!("{s}"),
    }
    sri(&block)
}

/// The test process's one initialized context for a module file, which every current holder
/// shares. (ISSUES.md: sessions on several test threads each initialized and finalized the
/// module, and one thread finalized it under another thread's session, which caused a SIGSEGV
/// under a plain parallel `cargo test`.) The last holder to drop it finalizes it, under the same
/// lock that initializes it, so a later holder initializes the module again. This matters because
/// tpm2-pkcs11 sees objects that other processes made only after a new `C_Initialize`
/// (cryptoki >= 0.11 no longer finalizes on drop).
pub struct Module {
    path: PathBuf,
    ctx: Pkcs11,
}

/// The contexts that are held now, by module file (its canonical path), with the number of
/// holders of each.
static MODULES: std::sync::Mutex<std::collections::BTreeMap<PathBuf, (Pkcs11, usize)>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

impl Module {
    /// Holds `path`'s context, and initializes the module if nothing holds it. The key is the file,
    /// not the name, because a module named in two ways (a symlink, a relative path) is one library
    /// in the process, and a second `C_Initialize` of it fails (review common/mod.rs F4).
    pub fn open(path: &str) -> Module {
        let file = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
        let mut held = MODULES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (ctx, count) = held.entry(file.clone()).or_insert_with(|| {
            let ctx = Pkcs11::new(&file).unwrap();
            ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
            (ctx, 0)
        });
        *count += 1;
        Module { path: file, ctx: ctx.clone() }
    }
}

impl std::ops::Deref for Module {
    type Target = Pkcs11;
    fn deref(&self) -> &Pkcs11 {
        &self.ctx
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        let mut held = MODULES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((ctx, count)) = held.get_mut(&self.path) {
            *count -= 1;
            if *count == 0 {
                let _ = ctx.clone().finalize();
                held.remove(&self.path);
            }
        }
    }
}

/// A logged-in session on the token `label`, on its module's shared context ([`Module`]).
pub struct TestSession {
    session: Option<Session>,
    ctx: Option<Module>,
}

impl std::ops::Deref for TestSession {
    type Target = Session;
    fn deref(&self) -> &Session {
        self.session.as_ref().unwrap()
    }
}

impl TestSession {
    /// Returns every object labelled `label`.
    pub fn labelled(&self, label: &str) -> Vec<cryptoki::object::ObjectHandle> {
        self.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap()
    }

    /// Destroys every object labelled with one of `labels`.
    pub fn clear(&self, labels: &[&str]) {
        for h in labels.iter().flat_map(|l| self.labelled(l)) {
            self.destroy_object(h).unwrap();
        }
    }
}

impl Drop for TestSession {
    fn drop(&mut self) {
        // Drop the session before the context on which it was opened.
        drop(self.session.take());
        drop(self.ctx.take());
    }
}

pub fn open_session(module: &str, label: &str, pin: &str) -> TestSession {
    let ctx = Module::open(module);
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label() == label)
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    // The login state belongs to the application (PKCS#11 §5.6), so another thread's session on
    // the shared context may have logged in already.
    match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
        Ok(()) | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => panic!("login to '{label}': {e}"),
    }
    TestSession { session: Some(session), ctx: Some(ctx) }
}

/// Opens a Security Officer session on the token `label` (SO PIN `so_pin`), on its module's shared
/// context ([`Module`]). It is for a test that plants an object that only the SO may make (a
/// `CKA_TRUSTED` key), without initializing and finalizing the module under another holder
/// (review camigrate `dry_run.rs` F2). No user session of the process may be logged in on the
/// token while this session is open (PKCS#11 §5.6).
pub fn open_so_session(module: &str, label: &str, so_pin: &str) -> TestSession {
    let ctx = Module::open(module);
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label() == label)
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    if let Err(e) = session.login(UserType::So, Some(&AuthPin::new(so_pin.into()))) {
        panic!("SO login to '{label}': {e}");
    }
    TestSession { session: Some(session), ctx: Some(ctx) }
}

/// Returns a reference whose material is made through its module (`C_CreateObject`) on token
/// `kmtest`, with no environment of its own. It is for a test that sets up its own references
/// ([`xref::Env::over`]).
pub fn created_ref(name: &'static str, module: String) -> xref::Ref {
    xref::Ref { name, module, token_label: "kmtest", env: &[], plant: xref::Plant::Create, eddsa: true }
}

/// Returns `vars` as the environment of an [`xref::Ref`], which must be `'static`. The function
/// leaks the values, and it is the only place that does so (review camigrate `dry_run.rs` F8,
/// `fault.rs` F4: each test leaked its own). An owned environment in `Ref` would remove the leak.
pub fn ref_env(vars: &[(&'static str, &str)]) -> &'static [(&'static str, &'static str)] {
    let leak = |v: &str| -> &'static str { Box::leak(v.to_owned().into_boxed_str()) };
    Box::leak(vars.iter().map(|(k, v)| (*k, leak(v))).collect::<Vec<_>>().into_boxed_slice())
}

impl xref::Env {
    /// Returns an environment over `refs` in the directory of test `name`'s new [`Workdir`]. It is
    /// for a test that needs references other than the two or more of [`xref::env`] (review
    /// camigrate `from_files.rs` F2, `fault.rs` F4).
    pub fn over(name: &str, refs: Vec<xref::Ref>) -> xref::Env {
        xref::Env { dir: Workdir::new(name).dir, refs }
    }

    /// Returns the references `names`, in that order, or `None` when the test is skipped
    /// ([`skip`]), with a message that names all of them (review camigrate `dry_run.rs` F3: each
    /// test had its own copy of the same lookup and skip). When the run requires a missing
    /// reference ([`xref::require_var_of`], [`required`]), the function fails instead, as
    /// [`suite_var`] does. [`xref::env`] already fails in that case, but [`Self::over`] or a test's
    /// own set of references does not.
    ///
    /// # Panics
    ///
    /// Panics when a missing reference is required, or when no reference has one of the `names`.
    pub fn needs<const N: usize>(&self, test: &str, names: [&str; N]) -> Option<[&xref::Ref; N]> {
        let found = self.needs_in(names, &|v| std::env::var_os(v).is_some()).unwrap_or_else(|e| panic!("{test}: {e}"));
        if let Err(missing) = found {
            skip(test, xref::require_var_of(missing), &format!("needs the {} references", names.join(" and ")));
        }
        found.ok()
    }

    /// Works like [`Self::needs`] in an environment where `set` says which variables are set. It
    /// returns the references, or the name of the first missing one (to skip), and `Err` for a
    /// missing reference that the run requires.
    pub fn needs_in<'a, const N: usize>(
        &self,
        names: [&'a str; N],
        set: &dyn Fn(&str) -> bool,
    ) -> Result<Result<[&xref::Ref; N], &'a str>, String> {
        let found = names.map(|n| self.refs.iter().find(|r| r.name == n));
        let missing: Vec<&str> = names.iter().zip(&found).filter(|(_, r)| r.is_none()).map(|(n, _)| *n).collect();
        let required: Vec<String> = missing
            .iter()
            .filter_map(|n| required(xref::require_var_of(n), TPM_BUILT, set).map(|why| format!("{n} ({why})")))
            .collect();
        if !required.is_empty() {
            return Err(format!("needs the references {}, required but not set up", required.join(", ")));
        }
        Ok(missing.first().map_or_else(|| Ok(found.map(Option::unwrap)), |n| Err(*n)))
    }
}
