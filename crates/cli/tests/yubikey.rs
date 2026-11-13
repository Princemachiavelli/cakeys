//! End-to-end tests of the CLI against a real `YubiKey` (PIV, through ykcs11), read-write.
//!
//! Needs `CAKEYS_TEST_YUBIKEY_MODULE` (path to libykcs11.so), `CAKEYS_TEST_YUBIKEY_PIN` (path to
//! a file holding the PIV PIN) and `CAKEYS_TEST_YUBIKEY_MGM` (path to a file holding the admin
//! credential: the PIV management key in hex, or the PIN on a PIN-protected-management-key
//! device). The CLI uses it only for the SO step that generates the key, then logs the user back
//! in. Tests are skipped when any is unset — they never run in the Nix build — and the secrets
//! are only ever read by the CLI from these paths: never printed, never stored, never committed.
//!
//! The scratch slot is PIV Retired Key 20 (slot `0x95`, `CKA_ID 0x18`): production slots are
//! never touched. ykcs11 cannot erase a PIV key (its `C_DestroyObject` clears only the slot's
//! certificate), so `delete` is refused and the test adopts whatever a previous run left in the
//! slot; `ykman piv keys delete 95` empties it to exercise generation again. Every CLI run is
//! bounded in time: a touch or a PIN prompt would hang the run and fail the test instead of
//! waiting for a user.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
/// `YubiKey` operations are interactive hardware calls in the worst case; none of the tested ones
/// needs presence, and the bound turns a policy change (touch) into a test failure.
const RUN_LIMIT: Duration = Duration::from_secs(30);

struct Env {
    dir: PathBuf,
    module: String,
    pin: String,
    mgm: String,
}

fn env(name: &str) -> Option<Env> {
    let (Ok(module), Ok(pin), Ok(mgm)) = (
        std::env::var("CAKEYS_TEST_YUBIKEY_MODULE"),
        std::env::var("CAKEYS_TEST_YUBIKEY_PIN"),
        std::env::var("CAKEYS_TEST_YUBIKEY_MGM"),
    ) else {
        eprintln!("skipping {name}: CAKEYS_TEST_YUBIKEY_MODULE, _PIN and _MGM (file paths) not all set");
        return None;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(Env { dir, module, pin, mgm })
}

impl Env {
    /// The config: the token with both credentials, and an EC key in the scratch slot.
    fn config(&self) {
        let label = yubikey_label(&self.module);
        std::fs::write(
            self.dir.join("keys.toml"),
            format!(
                "[tokens.yubikey]\nmodule = \"{m}\"\ntokenLabel = \"{label}\"\n\
                 pinFile = \"{pin}\"\nmgmKeyFile = \"{mgm}\"\n\n\
                 [objects.rw-test]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                 [specs.rw-test-yubikey]\nobject = \"rw-test\"\nattributes = {{ CKA_SIGN = true }}\n\
                 tokens.yubikey = {{ locator = {{ CKA_ID = \"18\" }}, autoCreate = true, attestation = true }}\n",
                m = self.module,
                pin = self.pin,
                mgm = self.mgm,
            ),
        )
        .unwrap();
    }

    fn lock(&self) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap()
    }

    /// Run the CLI bounded in time: a touch or PIN prompt fails the test instead of hanging it.
    fn km(&self, args: &[&str]) -> Output {
        let mut child = Command::new(BIN)
            .env_remove("NIX_BUILD_TOP")
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                // The child is done; the pipes still hold (and now end) its output.
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut p) = child.stdout.take() {
                    std::io::Read::read_to_end(&mut p, &mut stdout).unwrap();
                }
                if let Some(mut p) = child.stderr.take() {
                    std::io::Read::read_to_end(&mut p, &mut stderr).unwrap();
                }
                eprintln!(
                    "$ cakeys {}\n  exit={:?}\n  stdout={}\n  stderr={}",
                    args.join(" "),
                    status.code(),
                    String::from_utf8_lossy(&stdout).trim(),
                    String::from_utf8_lossy(&stderr).trim()
                );
                return Output { status, stdout, stderr };
            }
            if started.elapsed() > RUN_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "cakeys {} did not finish within {:?}: user presence (touch or PIN) needed?",
                    args.join(" "),
                    RUN_LIMIT
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The label of the first `YubiKey` the module sees, so the config names the right token.
fn yubikey_label(module: &str) -> String {
    let ctx = Pkcs11::new(module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().model().starts_with("YubiKey"))
        .unwrap();
    ctx.get_token_info(slot).unwrap().label().to_string()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// Read-write on real hardware: generate into the scratch PIV slot under the SO (management-key)
/// credential, back in the user session attest it and prove possession by signing (no touch, no
/// prompt), record, verify; `delete` is refused (15) because ykcs11 would leave the key in the
/// slot, so the realisation stays and verifies.
#[test]
fn rw_lifecycle_generates_attests_proves_and_refuses_delete_without_touch() {
    let Some(e) = env("yubikey_rw") else { return };
    e.config();
    let r = ["realise", "rw-test-yubikey", "--token", "yubikey", "--no-update-lock"];
    let record = ["realise", "rw-test-yubikey", "--token", "yubikey", "--update-lock"];

    // First use: the key is generated (SO login) and identified; nothing is locked yet.
    let first = e.km(&r);
    assert_eq!(code(&first), 10, "{}", String::from_utf8_lossy(&first.stderr));
    let got = String::from_utf8_lossy(&first.stderr)
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("got:"))
        .map(str::trim)
        .expect("a got: hash")
        .to_owned();
    assert!(got.starts_with("sha256-"), "{got}");

    // Record it: the pop-sign proof and the attestation ran in the user session, and are recorded.
    let recorded = e.km(&record);
    assert_eq!(code(&recorded), 0, "{}", String::from_utf8_lossy(&recorded.stderr));
    let lock = e.lock();
    let real = &lock["realisations"]["rw-test-yubikey"]["yubikey"];
    assert_eq!(real["binding"].as_str(), Some("pop-sign"), "possession proven by signing, not asserted");
    assert_eq!(real["attestation"]["kind"].as_str(), Some("yubico-piv"), "generated on device, so attested");
    assert!(real["attestation"]["id"].as_str().is_some_and(|id| id.starts_with("sha256-")));
    assert!(lock["objects"]["rw-test"]["ids"].get("piv-attestation").is_none(), "the attestation is per realisation");
    assert_eq!(real["object"].as_str(), Some("rw-test"));
    assert_eq!(
        lock["objects"]["rw-test"]["ids"]["rfc7093m4"].as_str(),
        Some(got.as_str()),
        "the locked id is the first-use one"
    );
    assert_eq!(real["policy"]["CKA_SIGN"].as_bool(), Some(true));

    // Verify in a fresh process: the proof of possession runs again, unattended.
    let verify = ["verify", "rw-test-yubikey", "--token", "yubikey"];
    let verified = e.km(&verify);
    assert_eq!(code(&verified), 0, "{}", String::from_utf8_lossy(&verified.stderr));

    // Delete is refused: ykcs11 would clear only the slot's certificate and report success while
    // the key stays. Nothing changes — the lock keeps the realisation and it still verifies.
    let del = ["delete", "rw-test-yubikey", "--token", "yubikey", "--update-lock"];
    let deleted = e.km(&del);
    assert_eq!(code(&deleted), 15, "{}", String::from_utf8_lossy(&deleted.stderr));
    assert!(String::from_utf8_lossy(&deleted.stderr).contains("ykman piv keys delete 95"));
    assert!(e.lock()["realisations"]["rw-test-yubikey"]["yubikey"].is_table(), "the realisation stays");
    assert_eq!(code(&e.km(&verify)), 0);

    // Re-realising is idempotent: the same key, the same id, nothing generated.
    let again = e.km(&record);
    assert_eq!(code(&again), 0, "{}", String::from_utf8_lossy(&again.stderr));
    assert!(!String::from_utf8_lossy(&again.stderr).contains("created"), "nothing generated");
    assert_eq!(
        e.lock()["objects"]["rw-test"]["ids"]["rfc7093m4"].as_str(),
        Some(got.as_str()),
        "the key keeps its identity"
    );
}

/// The read-only probe of the device here (docs/PROVIDERS.md D10): ykcs11/2.7's match keys,
/// advertisement and reported RSA range are what this `YubiKey` shows, and the write probes are
/// refused even on a token marked scratch — ykcs11 creates only as SO, into device slots. Needs
/// only `CAKEYS_TEST_YUBIKEY_MODULE`: no PIN, nothing written; the diff only with the patched
/// cryptoki (the Nix build's). Another firmware than the
/// profile's drifts by design (exit 15, the rows named): probe it and record a new pair.
#[test]
fn the_read_only_probe_conforms() {
    let Ok(module) = std::env::var("CAKEYS_TEST_YUBIKEY_MODULE") else {
        eprintln!("skipping the_read_only_probe_conforms: CAKEYS_TEST_YUBIKEY_MODULE not set");
        return;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("yubikey-probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("keys.toml"),
        format!(
            "[tokens.yubikey]\nmodule = \"{module}\"\ntokenLabel = \"{}\"\nscratch = true\n",
            yubikey_label(&module)
        ),
    )
    .unwrap();
    // No credentials: the read-only probe needs none, and the write probes must not get far.
    let e = Env { dir, module, pin: String::new(), mgm: String::new() };
    let write = e.km(&["probe", "--token", "yubikey", "--write"]);
    assert_eq!(code(&write), 17);
    assert!(String::from_utf8_lossy(&write.stderr).contains("Security Officer"));
    // The diff needs the patched cryptoki (an unpatched one drops mechanisms it cannot name, and
    // the probe refuses to judge through it): a cargo build here has it only in the Nix build.
    // By hand: `nix build .#cakeys`, then `result/bin/cakeys probe --token <yk> --diff ykcs11/2.7`.
    if std::os::raw::c_ulong::from(cryptoki::object::KeyType::SHA384_HMAC) != 0x2c {
        eprintln!("skipping the ykcs11/2.7 diff: this build's cryptoki is unpatched");
        return;
    }
    let out = e.km(&["probe", "--token", "yubikey", "--diff", "ykcs11/2.7"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
}
