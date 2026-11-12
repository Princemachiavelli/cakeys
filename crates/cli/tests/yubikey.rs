//! End-to-end tests of the CLI against a real YubiKey (PIV, through ykcs11), read-write.
//!
//! Needs `CAKEYS_TEST_YUBIKEY_MODULE` (path to libykcs11.so), `CAKEYS_TEST_YUBIKEY_PIN` (path to
//! a file holding the PIV PIN) and `CAKEYS_TEST_YUBIKEY_MGM` (path to a file holding the admin
//! credential: the PIV management key in hex, or the PIN on a PIN-protected-management-key
//! device, which the SO login then also verifies as the PIN). Tests are skipped when any is
//! unset — they never run in the Nix build — and the secrets are only ever read by the CLI from
//! these paths: never printed, never stored, never committed.
//!
//! The scratch slot is PIV Retired Key 20 (slot `0x95`, `CKA_ID 0x18`): production slots are
//! never touched. A PIV key cannot be erased, so the test adopts whatever a previous run left
//! in the slot and only deletes the cert objects around it. Every CLI run is bounded in time:
//! a touch or a PIN prompt would hang the run and fail the test instead of waiting for a user.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
/// YubiKey operations are interactive hardware calls in the worst case; none of the tested ones
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
                 tokens.yubikey = {{ locator = {{ CKA_ID = \"18\" }}, autoCreate = true }}\n",
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

/// The label of the first YubiKey the module sees, so the config names the right token.
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
/// credential, prove possession by signing in the same run (no touch, no prompt), record, verify,
/// delete, and adopt whatever the slot still holds — PIV keys are not erasable, only their cert
/// objects are, and ykcs11 keeps attesting the key.
#[test]
fn rw_lifecycle_generates_proves_and_deletes_without_touch() {
    let Some(e) = env("yubikey_rw") else { return };
    e.config();
    let r = ["realise", "rw-test-yubikey", "--token", "yubikey"];
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

    // Record it: the pop-sign proof ran in the same (SO) session — the PIN-credential SO login
    // of a PIN-protected-management-key device also verifies the PIN — and is recorded.
    let recorded = e.km(&record);
    assert_eq!(code(&recorded), 0, "{}", String::from_utf8_lossy(&recorded.stderr));
    let lock = e.lock();
    let real = &lock["realisations"]["rw-test-yubikey"]["yubikey"];
    assert_eq!(real["binding"].as_str(), Some("pop-sign"), "possession proven by signing, not asserted");
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

    // Delete: the realisation goes, the object's id stays (delete keeps ids), and the PIV slot
    // keeps its key — ykcs11 attests it — so a verify is the honest precondition failure.
    let del = ["delete", "rw-test-yubikey", "--token", "yubikey", "--update-lock"];
    let deleted = e.km(&del);
    assert_eq!(code(&deleted), 0, "{}", String::from_utf8_lossy(&deleted.stderr));
    assert!(e.lock().get("realisations").and_then(|r| r.get("rw-test-yubikey")).is_none());
    assert_eq!(
        e.lock()["objects"]["rw-test"]["ids"]["rfc7093m4"].as_str(),
        Some(got.as_str()),
        "the object id survives the delete"
    );
    let after = e.km(&verify);
    assert_eq!(code(&after), 14, "material still matches, but the realisation is gone");

    // Re-realise adopts what the slot still holds: same key, same id, no new generation needed.
    let again = e.km(&record);
    assert_eq!(code(&again), 0, "{}", String::from_utf8_lossy(&again.stderr));
    assert_eq!(
        e.lock()["objects"]["rw-test"]["ids"]["rfc7093m4"].as_str(),
        Some(got.as_str()),
        "the leftover key keeps its identity"
    );
    assert_eq!(code(&e.km(&verify)), 0);
}
