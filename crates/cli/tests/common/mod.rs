//! Helpers shared by the integration tests of `cakeys`, `caprobe` and `camigrate` (each includes
//! this file): running the package's own binary, the token headers of each suite's keys.toml,
//! the cross-reference harness ([`xref`]), what a run must leave as it was ([`state`]), the liar
//! matrix's runner ([`liars`]), CLI output parsing and an independent DER oracle.
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

/// The binary under test: the including package's own (Cargo sets `CARGO_BIN_EXE_<name>` only
/// for the package's binaries).
pub const BIN: &str = match (
    option_env!("CARGO_BIN_EXE_cakeys"),
    option_env!("CARGO_BIN_EXE_caprobe"),
    option_env!("CARGO_BIN_EXE_camigrate"),
) {
    (Some(b), _, _) | (None, Some(b), _) | (None, None, Some(b)) => b,
    (None, None, None) => panic!("included by a package with no cakeys, caprobe or camigrate binary"),
};

/// What the tools read from the environment when no flag says it: a developer's real keys.toml
/// and lock (review common/mod.rs F1), and the Nix build markers, which only a test that sets
/// them means. The per-test runner (nix/test-tokens.sh) unsets the first two for every test too.
pub const SCRUBBED: [&str; 4] = ["CAKEYS_CONFIG", "CAKEYS_LOCK", "NIX_BUILD_TOP", "IN_NIX_SHELL"];

/// `bin` to run from a test, with none of [`SCRUBBED`]: every test's run of a tool starts here.
pub fn tool(bin: impl AsRef<OsStr>) -> Command {
    let mut c = Command::new(bin);
    for var in SCRUBBED {
        c.env_remove(var);
    }
    c
}

/// A run of a tool on a keys.toml: [`tool`] with `--config`, the environment a test gives it
/// (variables set and removed), its output logged for the test's own. Every helper that runs a
/// tool against a keys.toml builds one (review D9: each had its own copy, scrubbing differently).
pub struct Run {
    command: Command,
    /// What the log names the run by: the binary, and a note (xref's reference).
    name: String,
}

impl Run {
    /// `bin --config <config>`.
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

    /// `note` beside the binary's name in the log.
    pub fn note(mut self, note: &str) -> Run {
        self.name = format!("{} ({note})", self.name);
        self
    }

    /// The command with `args`, for a test that drives the process itself.
    pub fn command(mut self, args: &[&str]) -> Command {
        self.command.args(args);
        self.command
    }

    /// Run with `args` to the end.
    pub fn output(mut self, args: &[&str]) -> Output {
        let out = self.command.args(args).output().unwrap();
        log_run(&self.name, args, &out);
        out
    }

    /// Run with `args`, bounded in time: on hardware, a touch or PIN prompt fails the test
    /// instead of hanging it.
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

/// `command`'s output, or `None` (the child killed) when it runs longer than `limit`. Both pipes
/// are read while it runs: a child that writes more than a pipe holds blocks until someone reads,
/// and read only after it exited, it never did (review common/mod.rs F3).
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

/// Another binary of this workspace, beside [`BIN`] in the target directory. Cargo gives a test
/// only its own package's binaries; `cargo test --workspace` (the Nix check phase) builds them
/// all before any test runs.
///
/// # Panics
///
/// When that binary is not built (`cargo test -p <package>` alone): build the workspace first.
pub fn sibling(name: &str) -> PathBuf {
    let path = Path::new(BIN).with_file_name(name);
    assert!(path.exists(), "{} is not built: run `cargo build --workspace` first", path.display());
    path
}

/// The value of `var` (a module path), else `None` — unless the run requires it ([`required`]:
/// `require` set, or `CAKEYS_REQUIRE_ALL`), which makes a missing one a failure. Every suite's
/// gate reads its module through this (review D9).
///
/// # Panics
///
/// When `var` is missing and required.
pub fn required_var(var: &str, require: &str) -> Option<String> {
    let v = std::env::var(var).ok();
    if let (None, Some(because)) = (&v, required_here(require)) {
        panic!("{var} is required ({because})");
    }
    v
}

/// [`required_var`] for the suite `test` belongs to: `None` says it is skipped ([`skip`]).
pub fn suite_var(var: &str, require: &str, test: &str) -> Option<String> {
    let v = std::env::var(var).ok();
    if v.is_none() {
        skip(test, require, &format!("{var} not set"));
    }
    v
}

/// A hardware suite's opt-in: its variables, all set or none, and the variable that makes it
/// required (a run that means the suite, `scripts/coverage-full.sh`, sets it beside them).
#[derive(Clone, Copy)]
pub struct OptIn<const N: usize> {
    pub vars: [&'static str; N],
    pub require: &'static str,
}

/// The ftpm suites' opt-in: the module and its pair profile, both or neither.
pub const FTPM_OPT_IN: OptIn<2> =
    OptIn { vars: ["CAKEYS_FTPM_MODULE", "CAKEYS_FTPM_PROFILE"], require: "CAKEYS_FTPM_REQUIRE" };
/// The opt-in of the `YubiKey` suites that log in: the PIN and management-key files, both or
/// neither. The module alone is the read-only probe's (caprobe).
pub const YUBIKEY_OPT_IN: OptIn<2> =
    OptIn { vars: ["CAKEYS_TEST_YUBIKEY_PIN", "CAKEYS_TEST_YUBIKEY_MGM"], require: "CAKEYS_YUBIKEY_REQUIRE" };

/// A `YubiKey` suite that logs in: the module, the PIN file and the management-key file, opted
/// in by [`YUBIKEY_OPT_IN`]; with them, a missing module fails.
pub fn yubikey_opted_in(test: &str) -> Option<[String; 3]> {
    let [pin, mgm] = opted_in(test, YUBIKEY_OPT_IN)?;
    let module = std::env::var("CAKEYS_TEST_YUBIKEY_MODULE")
        .unwrap_or_else(|_| panic!("{test}: the PIN and management key are set, CAKEYS_TEST_YUBIKEY_MODULE is not"));
    Some([module, pin, mgm])
}

/// A hardware suite's opt-in (review D9), read through `env`: every one of its variables set,
/// their values; none, `None` (the suite is skipped), unless its require variable is set. Some
/// but not all is an error naming the missing ones: setting any says the run wants the suite,
/// and a half-set one must not pass empty; so does the require variable alone (review ftpm.rs
/// F2: a run that meant the suite, without its variables, passed having run nothing).
///
/// # Errors
///
/// The message for a half-set opt-in, or a required one not set.
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

/// [`opt_in`] on the process's environment: `None`, skipped ([`skip`]), or a failure when half
/// set or required.
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

/// The reference suite's tokens: `ref` (scratch: the token is created for the run and thrown
/// away, which is exactly what the probe's write probes demand, docs/CAPROBE.md) and
/// `ref-anon`, the same token without a PIN: it sees only public objects, like a PIV token used
/// without login.
pub fn reference_tokens(module: &str, dir: &Path) -> String {
    format!(
        "[tokens.ref]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprobe = {{ scratch = true }}\n\n\
         [tokens.ref-anon]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n\n",
        dir.join("pin").display(),
    )
}

/// tpm2-pkcs11 on swtpm: `tpm` (logged in, scratch: the swtpm token is created for the run),
/// `tpm-anon` (no PIN) and `tpm-generic` (logged in, but without the tpm2-pkcs11 provider's
/// fix-ups). The native attestation path finds the TPM the way the module does —
/// `$TPM2_PKCS11_TCTI`, which the harness exports in the TCTI library-path form — and the store
/// through `$TPM2_PKCS11_STORE`.
pub fn tpm2_tokens(module: &str, dir: &Path) -> String {
    let pin = dir.join("pin");
    let token =
        |name: &str, extra: &str| format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n{extra}\n");
    token("tpm", &format!("pinFile = \"{}\"\nprobe = {{ scratch = true }}", pin.display()))
        + &token("tpm-anon", "")
        + &token("tpm-generic", &format!("pinFile = \"{}\"\nprovider = \"generic\"", pin.display()))
}

/// The tpm2-pkcs11 store of the TPM harnesses (nix/tpm2-test-env.sh, nix/ftpm-test-env.sh).
pub fn tpm2_store() -> String {
    std::env::var("TPM2_PKCS11_STORE").expect("TPM2_PKCS11_STORE: the TPM harness's store")
}

/// `tpm2_ptool <args> --path <store>`, which must succeed.
pub fn ptool_in(store: &str, args: &[&str]) {
    let out = Command::new("tpm2_ptool").args(args).arg(format!("--path={store}")).output().unwrap();
    assert!(out.status.success(), "tpm2_ptool {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// `tpm2_ptool <args>` on the harness's token `kmtest` ([`tpm2_store`], user PIN 1234).
pub fn ptool(args: &[&str]) {
    ptool_in(&tpm2_store(), &[args, &["--label=kmtest", "--userpin=1234"]].concat());
}

/// The host's real TPM: `ftpm` (logged in, scratch: the harness's store is made for the run).
pub fn ftpm_tokens(module: &str, dir: &Path) -> String {
    format!(
        "[tokens.ftpm]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprobe = {{ scratch = true }}\n\n",
        dir.join("pin").display()
    )
}

/// p11-kit forwarding: `fwd` (through p11-kit), `fwd-anon` (no PIN), `fwd-softhsm` (provider
/// named), `fwd-other` (a token the server does not export) and `direct` (`SoftHSM` itself).
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

/// A `YubiKey` test's turn at the device: one test at a time across every test process (an
/// exclusive lock on a file in the shared target tmpdir), and none after a login failed. The
/// PIN has three tries, and the hardware rule is to stop after one failed login
/// (docs/DEVELOPMENT.md, "Hardware rules"): two tests logging in at once with a wrong PIN file
/// spent two (review yubikey.rs F1). Take it before the test's first run; pass each run's output
/// through [`YubikeyTurn::checked`].
pub struct YubikeyTurn {
    _lock: std::fs::File,
}

/// The file a failed `YubiKey` login leaves: every later `YubiKey` test refuses to run until a
/// person has fixed the credential and removed it.
pub fn yubikey_latch() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("yubikey-login-failed")
}

impl YubikeyTurn {
    /// Wait for the device, then refuse if a login has failed since the latch was cleared.
    ///
    /// # Panics
    ///
    /// When the latch is set.
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

    /// Refuse if a login has failed since the latch was cleared.
    ///
    /// # Panics
    ///
    /// When it has.
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

    /// `out`, after latching every later `YubiKey` test off if its login failed (any `CKR_PIN_*`).
    ///
    /// # Panics
    ///
    /// When it did.
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

/// The `CKR_PIN_*` a run's stderr reports, if its login failed: the tools name a login's return
/// value by its constant (cryptoki's prose names none), and `cli/tests/fault.rs` holds them to it.
pub fn failed_login(said: &str) -> Option<String> {
    let at = said.find("CKR_PIN_")?;
    Some(said[at..].chars().take_while(|c| c.is_ascii_uppercase() || *c == '_').collect())
}

/// A real `YubiKey`: the token with both credentials (file paths), `extra` added to it.
pub fn yubikey_token(module: &str, pin: &str, mgm: &str, extra: &str) -> String {
    format!(
        "[tokens.yubikey]\nmodule = \"{module}\"\ntokenLabel = \"{}\"\npinFile = \"{pin}\"\nsoCredentialFile = \"{mgm}\"\n{extra}\n",
        yubikey_label(module)
    )
}

/// The label of the first `YubiKey` the module sees, so the config names the right token.
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

/// The binary on `config`, bounded in time ([`Run::within`]).
///
/// # Panics
///
/// When the run takes longer than `limit`.
pub fn run_within(config: &Path, args: &[&str], limit: Duration) -> Output {
    Run::new(BIN, config).within(args, limit)
}

/// Whether the linked cryptoki has the HMAC key type fix (nix/patches/); the Nix build does.
/// Without it, tests needing SHA-224/384/512 HMAC keys skip, unless `require` (then they fail).
/// A suite that may skip says which variable requires it through [`hmac_types_fixed`];
/// `true` is for one that never skips (a hardware suite, once opted in).
///
/// # Panics
///
/// When `require` and the fix is missing.
pub fn cryptoki_hmac_types_fixed(require: bool) -> bool {
    let fixed = std::os::raw::c_ulong::from(cryptoki::object::KeyType::SHA384_HMAC) == 0x2c;
    assert!(fixed || !require, "cryptoki lacks the HMAC key type fix (nix/patches/cryptoki-hmac-key-types.patch)");
    fixed
}

/// [`cryptoki_hmac_types_fixed`], skipped ([`skip`]) unless the run requires the suite through
/// `require_var` (review common/mod.rs F7: callers computing the flag passed `false`, or another
/// suite's variable).
pub fn hmac_types_fixed(require_var: &str) -> bool {
    let fixed = cryptoki_hmac_types_fixed(false);
    if !fixed {
        skip("", require_var, "cryptoki lacks the HMAC key type fix; run through the Nix build");
    }
    fixed
}

/// A software PKCS#11 token the shared suite (`tests/reference/`) runs against: the facts the
/// suite needs about it, so its tests assert the same verdicts on every reference.
pub struct Reference {
    /// Path of the module; the suite skips when it is unset.
    pub module_var: &'static str,
    /// When set, a missing module fails instead of skipping.
    pub require_var: &'static str,
    /// The module's own configuration file.
    pub conf_var: &'static str,
    /// The provider cakeys detects from `C_GetInfo`.
    pub provider: &'static str,
    /// `C_GetInfo` manufacturer and `C_GetTokenInfo` model, as recorded in provenance.
    pub manufacturer: &'static str,
    pub model: &'static str,
    /// Curves (`keys.toml` names) it cannot generate: refused as unsupported (15).
    pub missing_curves: &'static [&'static str],
    /// Whether it implements Triple DES (`CKM_DES3_ECB`, `CKM_DES3_KEY_GEN`); without it a
    /// `CKK_DES3` spec is refused as unsupported (15).
    pub des3: bool,
    /// Whether it generates the hash-bound HMAC key types (PKCS#11 3.0's `CKM_SHA*_KEY_GEN`).
    pub hmac_key_gen: bool,
    /// Its committed capability profile: name, and path under profiles/.
    pub profile: (&'static str, &'static str),
    /// The module's configuration (`conf_var`'s file) with one mechanism hidden.
    pub hide_mechanism: fn(conf: &str, mechanism: &str) -> String,
    /// Whether the suite loads the module through `p11-fault` (`P11_FAULT_MODULE` names it), with no
    /// fault plan: the forwarder must be transparent.
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

/// kryoptic 1.5.4 (its `OpenSSL` backend) generates none of secp256k1 or the brainpool curves, and
/// has no DES mechanism at all (`pkcs11-tool -M` \[run\], 2026-11-15). The harness
/// (nix/package-common.nix) ends `KRYOPTIC_CONF` with the token's `[[slots]]` table, so an appended key
/// belongs to it.
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

/// `SoftHSM` behind `p11-fault` (`docs/FAULT_SHIM.md`) with no fault plan: the whole suite runs a
/// third time through the shim, and must pass as it does directly. The per-test runner
/// (nix/test-tokens.sh) points `P11_FAULT_MODULE` at the test's own `SoftHSM` token; the token's
/// module is the shim.
pub const FAULT: Reference = Reference {
    module_var: "P11_FAULT_MODULE",
    require_var: "CAKEYS_FAULT_REQUIRE",
    through_fault_shim: true,
    ..SOFTHSM
};

/// `libp11_fault.so`: beside the binaries after a build of the workspace, else among the
/// dependencies of the tests (`deps/`), where the `cakeys` tests' dev-dependency on `p11-fault`
/// has every test build put it.
///
/// # Panics
///
/// When it is in neither place.
pub fn fault_shim() -> String {
    let beside = Path::new(BIN).with_file_name("libp11_fault.so");
    let path = if beside.exists() { beside } else { Path::new(BIN).with_file_name("deps").join("libp11_fault.so") };
    assert!(path.exists(), "libp11_fault.so is built neither beside {BIN} nor in deps/");
    path.to_str().unwrap().to_owned()
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// A committed capability profile's file (profiles/, docs/CAPROBE.md): what the conformance
/// tests regenerate and compare byte for byte.
pub fn committed_profile(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles").join(path)
}

/// The conformance check every reference token runs (docs/CAPROBE.md): the committed
/// module profile `name` (at `path` under profiles/) is exactly what a fresh probe of token
/// `token` observes, and regenerating it — the maintenance flow — changes no byte. `km` runs
/// the CLI against the test's keys.toml; `scratch` is a file the regeneration may write.
///
/// One write probe only: it diffs and regenerates in the same run. A second would see what the
/// first left behind on modules that cannot destroy everything they make (tpm2-pkcs11's sealed
/// derived secrets: profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml, `derive.destroy`).
///
/// `caprobe regenerate`, the command every regeneration runs (profiles/LEDGER.toml, `[regen]`):
/// the flags are the verb's, so the test regenerates as the scripts do.
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
    // Accepted: the scratch copy is replaced, so the bytes below compare what the probe made
    // (without it a drifted profile would wait beside the copy, which would then compare equal).
    let probe = km(&["regenerate", name, "--token", token, "--out", out, "--accept"]);
    assert_eq!(code(&probe), 0, "a fresh probe drifts from {name}: {}", String::from_utf8_lossy(&probe.stderr));
    assert!(
        std::fs::read(scratch).unwrap() == committed,
        "{path} is not what the probe generates: regenerate it as profiles/LEDGER.toml says for profiles/{path}, \
         never by hand"
    );
    // A read-only probe conforms on what it observes; it may never overwrite the file.
    assert_eq!(code(&km(&["probe", "--token", token, "--diff", name])), 0);
    assert_eq!(code(&km(&["probe", "--token", token, "--out", out])), 17);
    assert_eq!(std::fs::read(scratch).unwrap(), committed, "a read-only probe overwrote the file");
}

/// The writing form of a compare-only `lock`/`delete` argument list: `--dry-run` dropped.
pub fn recording<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter().copied().filter(|a| *a != "--dry-run").collect()
}

/// What a one-object `lock` run printed: its one row of the JSON array `lock` prints (one per
/// object, review 2026-11-23 C-7).
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

/// A test's scratch directory — keys.toml, keys.lock (empty: as `--new-lock` starts one) and a
/// PIN file holding `1234` — and the
/// runs of the tool against it. A token suite's test holds one in its [`Suite`].
pub struct Workdir {
    pub dir: PathBuf,
}

/// A lock that pins nothing: what `--new-lock` starts from, and every test directory's first.
pub const EMPTY_LOCK: &str = "version = 1\n";

/// The directory of one test under the integration tests' tmpdir, which every package and test
/// binary shares: named for both, so suites that run at once (and the shared reference suite,
/// which two binaries run under the same test names) never meet in one.
pub fn test_dir(name: &str) -> PathBuf {
    let binary = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_CRATE_NAME"));
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{binary}-{name}"))
}

impl Workdir {
    /// A fresh directory `name` under the integration tests' tmpdir.
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

    /// `cakeys --config keys.toml <args>` with `envs` set, logged for the test's output. The
    /// suites themselves run in a Nix build: only a test that sets `NIX_BUILD_TOP` means it.
    pub fn km_env(&self, args: &[&str], envs: &[(&str, &Path)]) -> Output {
        self.run().envs(envs.iter().copied()).output(args)
    }

    /// A run on this keys.toml, for one that removes a variable or is bounded ([`Run`]).
    pub fn run(&self) -> Run {
        Run::new(BIN, &self.dir.join("keys.toml"))
    }

    /// The exit code of [`Self::km`].
    pub fn code(&self, args: &[&str]) -> i32 {
        code(&self.km(args))
    }

    pub fn lock(&self) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap()
    }

    /// Replace keys.lock with `lock`: an edit made on the TOML, never on its text.
    pub fn write_lock(&self, lock: &toml::Value) {
        std::fs::write(self.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    }

    /// The `observations` entry the realisation of `spec` on `token` names.
    pub fn observation(&self, spec: &str, token: &str) -> toml::Value {
        let lock = self.lock();
        let key = lock["realisations"][spec][token]["observation"].as_str().unwrap().to_owned();
        lock["observations"][key.as_str()].clone()
    }

    pub fn locked_id(&self, object: &str, scheme: &str) -> String {
        self.lock()["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }
}

/// A token suite's test (review D9: each suite had its own copy): its [`Workdir`], the module
/// its tokens load, and the token tables every keys.toml it writes starts with. A suite's gate
/// makes one once its module is known ([`suite_var`], [`opted_in`]); what one suite alone does
/// with it is an `impl Suite` in that suite.
pub struct Suite {
    w: Workdir,
    /// The module the suite's tokens load, which the test also opens itself ([`Self::session`]).
    pub module: String,
    tokens: String,
    /// What every keys.toml the test writes is shown first ([`Self::checking`]).
    check: fn(&str),
}

impl std::ops::Deref for Suite {
    type Target = Workdir;
    fn deref(&self) -> &Workdir {
        &self.w
    }
}

impl Suite {
    /// Test `name`'s fresh [`Workdir`], its keys.toml starting with `tokens(module, dir)`.
    pub fn new(name: &str, module: String, tokens: impl FnOnce(&str, &Path) -> String) -> Suite {
        let w = Workdir::new(name);
        let tokens = tokens(&module, &w.dir);
        Suite { w, module, tokens, check: |_| {} }
    }

    /// The suite with `check` shown every keys.toml before it is written: tpm2's refuses an
    /// attestation (a persistent TPM object) anywhere but its swtpm.
    pub fn checking(self, check: fn(&str)) -> Suite {
        Suite { check, ..self }
    }

    /// keys.toml: the suite's tokens and `body`.
    pub fn config(&self, body: &str) {
        self.write_config(&(self.tokens.clone() + body));
    }

    /// keys.toml as `text`, once [`Self::checking`]'s check has seen it (it shadows
    /// [`Workdir::write_config`]).
    pub fn write_config(&self, text: &str) {
        (self.check)(text);
        self.w.write_config(text);
    }

    /// A logged-in session on the suite's token `kmtest` (PIN 1234).
    pub fn session(&self) -> TestSession {
        open_session(&self.module, "kmtest", "1234")
    }
}

pub fn sri(bytes: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes)))
}

/// Minimal DER writer for the test oracle: independent of the crates the tool uses.
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

/// One DER element: (tag, contents, rest). Independent of the crates cakeys uses.
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

/// The DER inside a PEM file.
pub fn pem_der(path: &str) -> Vec<u8> {
    use base64::Engine;
    let text = std::fs::read_to_string(path).unwrap();
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

/// A PKCS#8 EC key: (curve OID as DER, private scalar, uncompressed public point).
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

/// A PKCS#8 Ed25519 key (RFC 8410): its 32-byte seed.
pub fn ed25519_fixture(pkcs8: &[u8]) -> Vec<u8> {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, _, rest) = der(rest); // algorithm
    let (_, inner, _) = der(rest); // OCTET STRING { CurvePrivateKey }
    der(inner).1.to_vec()
}

/// A PKCS#8 RSA key: modulus, public and private exponents, primes, CRT exponents, coefficient.
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

/// Token object template for a fixture certificate (`SoftHSM` requires `CKA_SUBJECT`).
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

/// `CKA_EC_POINT` is a DER OCTET STRING around the point.
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

/// `CKA_EC_PARAMS` (the curve's OID, DER) of each curve the tests name, and the EC key OID.
pub const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
pub const P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
pub const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
pub const ED448: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];

/// Replace the private key under `label` with another of its kind, as a token that swapped one
/// would hold (review reference/mod.rs F2: written five times): a pair generated by `mechanism`
/// from `public` (the curve or modulus) and `private` (usage and policy); its public half a
/// session object, so the public key object under the label stays the original's. The original
/// private key is destroyed and the new one takes the label, with `extra` (a forged
/// `CKA_PUBLIC_KEY_INFO`).
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

/// SPKI of the public key object under `label`, built from its raw PKCS#11 attributes.
pub fn oracle_spki(s: &Session, label: &str) -> Vec<u8> {
    oracle_spki_with(s, label, unwrap_octets)
}

/// As [`oracle_spki`], with a custom `CKA_EC_POINT` unwrapper (for a module's known bug).
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
        // PKCS#11 3.2 holds Edwards points raw (kryoptic's default); earlier modules wrap them
        // in an OCTET STRING. The raw length is exact, two bytes short of the wrapped form.
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

/// Host oracle for the AES commitments (`cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) of a known
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

/// The host oracle of a DES3 check value (`kcv-ecb`, `kcv-ecb-dec`): `RustCrypto`'s `des`
/// (three-key EDE) over the first 8 bytes of SHA-256 of the commitment label.
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

/// The test process's one initialized context for a module file, shared by every holder at once
/// (ISSUES.md: sessions on several test threads each initialized and finalized the module, and
/// one finalized it under another's session, SIGSEGV, under a plain parallel `cargo test`). The
/// last holder to go finalizes it, under the lock that initializes, so a holder that comes
/// after initializes afresh: tpm2-pkcs11 sees objects other processes made only after a new
/// `C_Initialize` (cryptoki >= 0.11 no longer finalizes on drop).
pub struct Module {
    path: PathBuf,
    ctx: Pkcs11,
}

/// The contexts held now, by module file (its canonical path), with how many hold each.
static MODULES: std::sync::Mutex<std::collections::BTreeMap<PathBuf, (Pkcs11, usize)>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

impl Module {
    /// Hold `path`'s context, initializing the module if nothing holds it. Keyed by the file, not
    /// the name: a module named two ways (a symlink, a relative path) is one library in the
    /// process, and a second `C_Initialize` of it fails (review common/mod.rs F4).
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

/// A logged-in session on `label`, on its module's shared context ([`Module`]).
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
    /// Every object labelled `label`.
    pub fn labelled(&self, label: &str) -> Vec<cryptoki::object::ObjectHandle> {
        self.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap()
    }

    /// Destroy every object labelled with one of `labels`.
    pub fn clear(&self, labels: &[&str]) {
        for h in labels.iter().flat_map(|l| self.labelled(l)) {
            self.destroy_object(h).unwrap();
        }
    }
}

impl Drop for TestSession {
    fn drop(&mut self) {
        // The session before the context it was opened on.
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
    // Login state is the application's (PKCS#11 §5.6): another thread's session on the shared
    // context may have logged in already.
    match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
        Ok(()) | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => panic!("login to '{label}': {e}"),
    }
    TestSession { session: Some(session), ctx: Some(ctx) }
}

/// A Security Officer session on `label` (SO PIN `so_pin`), on its module's shared context
/// ([`Module`]): for a test that plants what only the SO may make (a `CKA_TRUSTED` key), without
/// initializing and finalizing the module under another holder (review camigrate `dry_run.rs`
/// F2). No user session of the process may be logged in on the token meanwhile (PKCS#11 §5.6).
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

/// A reference whose material is made through its module (`C_CreateObject`) on token `kmtest`,
/// in no environment of its own: for a test that sets up its own references ([`xref::Env::over`]).
pub fn created_ref(name: &'static str, module: String) -> xref::Ref {
    xref::Ref { name, module, token_label: "kmtest", env: &[], plant: xref::Plant::Create, eddsa: true }
}

/// `vars` as an [`xref::Ref`]'s environment, which is `'static`: leaked, here alone (review
/// camigrate `dry_run.rs` F8, `fault.rs` F4: each test leaked its own). An owned environment in
/// `Ref` would remove the leak.
pub fn ref_env(vars: &[(&'static str, &str)]) -> &'static [(&'static str, &'static str)] {
    let leak = |v: &str| -> &'static str { Box::leak(v.to_owned().into_boxed_str()) };
    Box::leak(vars.iter().map(|(k, v)| (*k, leak(v))).collect::<Vec<_>>().into_boxed_slice())
}

impl xref::Env {
    /// Test `name`'s fresh [`Workdir`] over `refs`: for a test that needs other references than
    /// [`xref::env`]'s two or more (review camigrate `from_files.rs` F2, `fault.rs` F4).
    pub fn over(name: &str, refs: Vec<xref::Ref>) -> xref::Env {
        xref::Env { dir: Workdir::new(name).dir, refs }
    }

    /// The references `names`, in that order, or `None`: skipped ([`skip`]), naming them all
    /// (review camigrate `dry_run.rs` F3: the same lookup and skip, written once per test). A
    /// missing one the run requires ([`xref::require_var_of`], [`required`]) fails instead, as
    /// [`suite_var`] does: [`xref::env`] already fails then, but an [`Self::over`] or a test's own
    /// set of references does not.
    ///
    /// # Panics
    ///
    /// When a missing reference is required, or no reference has one of `names`.
    pub fn needs<const N: usize>(&self, test: &str, names: [&str; N]) -> Option<[&xref::Ref; N]> {
        let found = self.needs_in(names, &|v| std::env::var_os(v).is_some()).unwrap_or_else(|e| panic!("{test}: {e}"));
        if let Err(missing) = found {
            skip(test, xref::require_var_of(missing), &format!("needs the {} references", names.join(" and ")));
        }
        found.ok()
    }

    /// [`Self::needs`] in the environment `set` says which variables are set in: the references,
    /// or the first missing one's name (skip); `Err` for a missing reference the run requires.
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
