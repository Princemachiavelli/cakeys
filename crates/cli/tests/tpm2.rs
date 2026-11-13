//! End-to-end tests against tpm2-pkcs11 on a software TPM (nix/tpm2-test-env.sh).
//!
//! Needs `CAKEYS_TPM_MODULE` (`libtpm2_pkcs11.so`), the `TPM2_PKCS11_*` environment from the harness,
//! a token `kmtest` with user PIN `1234`, and `tpm2_ptool` on PATH. Skipped when
//! `CAKEYS_TPM_MODULE` is unset, unless `CAKEYS_TPM_REQUIRE=1`.

mod common;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::Session;
use hmac::{Hmac, KeyInit, Mac};
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

struct Env {
    dir: PathBuf,
    module: String,
}

fn env(name: &str) -> Option<Env> {
    let Ok(module) = std::env::var("CAKEYS_TPM_MODULE") else {
        assert!(std::env::var("CAKEYS_TPM_REQUIRE").is_err(), "CAKEYS_TPM_MODULE is required");
        eprintln!("skipping {name}: CAKEYS_TPM_MODULE not set");
        return None;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tpm2-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, module })
}

impl Env {
    /// keys.toml with `tpm` (logged in), `tpm-anon` (no PIN) and `tpm-generic` (logged in, but
    /// without the tpm2-pkcs11 provider's fix-ups). The native attestation path finds the TPM
    /// the way the module does — `$TPM2_PKCS11_TCTI`, which the harness exports in the TCTI
    /// library-path form — and the store through `$TPM2_PKCS11_STORE`.
    fn config(&self, body: &str) {
        let pin = self.dir.join("pin");
        let token = |name: &str, extra: &str| {
            format!("[tokens.{name}]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\n{extra}\n", self.module)
        };
        // `tpm` is scratch: the swtpm token is created for the run (the probe's write probes).
        let head = token("tpm", &format!("pinFile = \"{}\"\nscratch = true", pin.display()))
            + &token("tpm-anon", "")
            + &token("tpm-generic", &format!("pinFile = \"{}\"\nprovider = \"generic\"", pin.display()));
        std::fs::write(self.dir.join("keys.toml"), head + body).unwrap();
    }

    fn km(&self, args: &[&str]) -> Output {
        let out = Command::new(BIN)
            .env_remove("NIX_BUILD_TOP")
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ cakeys {}\n  exit={:?}\n  stdout={}\n  stderr={}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    fn lock(&self) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap()
    }

    fn locked_id(&self, object: &str, scheme: &str) -> String {
        self.lock()["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }

    /// The attestation a realisation pins (§3.7: per realisation, never in the object's ids).
    fn locked_attestation(&self, spec: &str, token: &str) -> toml::Value {
        self.lock()["realisations"][spec][token]["attestation"].clone()
    }

    /// `tpm2_ptool <args> --label kmtest --userpin 1234 --path $TPM2_PKCS11_STORE`.
    #[allow(clippy::unused_self)] // the fixture helpers sit in an impl so the call sites read uniformly
    fn ptool(&self, args: &[&str]) {
        let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
        let out = Command::new("tpm2_ptool")
            .args(args)
            .args(["--label=kmtest", "--userpin=1234", &format!("--path={store}")])
            .output()
            .unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// A fresh session: tpm2-pkcs11 loads the object list when a session opens, so objects
    /// created by another process afterwards are invisible to it.
    fn session(&self) -> TestSession {
        open_session(&self.module, "kmtest", "1234")
    }
}

fn labelled(s: &Session, label: &str) -> usize {
    s.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap().len()
}

/// Like `unwrap_octets`, but also accepting tpm2-pkcs11's P-521 encoding `04 85 <133 bytes>`
/// (see cakeys-tpm2-pkcs11). The oracle's independence is in building the SPKI.
fn unwrap_tpm2(v: &[u8]) -> Vec<u8> {
    match v {
        [0x04, n, rest @ ..] if *n >= 0x80 && rest.len() == *n as usize => rest.to_vec(),
        _ => unwrap_octets(v),
    }
}

#[test]
fn tpm2_provider_refuses_what_the_module_cannot_do() {
    let Some(e) = env("refusals") else { return };
    e.ptool(&["addkey", "--algorithm=aes256", "--key-label=refusal-aes"]);
    e.config(
        r#"
[objects.aes-gen]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-gen]
object = "aes-gen"
attributes = { CKA_ENCRYPT = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes-gen" }, autoCreate = true }

[objects.hmac-gen]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA256_HMAC"
valueLen = 32

[specs.hmac-gen]
object = "hmac-gen"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-hmac-gen" }, autoCreate = true }

[objects.ed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC_EDWARDS"
curve = "edwards25519"

[specs.ed]
object = "ed"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-ed" }, autoCreate = true }

[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-mac]
object = "aes"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes" } }
"#,
    );
    let caps: serde_json::Value = serde_json::from_str(&stdout(&e.km(&["caps", "--token", "tpm"]))).unwrap();
    assert_eq!(caps["provider"], "tpm2-pkcs11");
    let mechs = caps["mechanisms"].to_string();
    assert!(mechs.contains("CKM_EC_KEY_PAIR_GEN") && !mechs.contains("CKM_AES_KEY_GEN"), "{mechs}");

    // Secret-key generation is refused up front, with the provider's advice, and creates nothing.
    for (spec, label) in [("aes-gen", "refusal-aes-gen"), ("hmac-gen", "refusal-hmac-gen")] {
        let o = e.km(&["realise", spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("tpm2_ptool addkey"), "{spec}");
        assert_eq!(labelled(&e.session(), label), 0, "{spec}");
    }
    assert_eq!(code(&e.km(&["realise", "ed", "--token", "tpm", "--no-update-lock"])), 15);
    // No CKM_AES_CMAC: a sign-only AES spec has no commitment here.
    assert_eq!(code(&e.km(&["realise", "aes-mac", "--token", "tpm", "--no-update-lock"])), 15);
}

#[test]
#[allow(clippy::format_push_string)] // the fixture TOML bodies are appended as += format!(...)
fn tpm2_generated_keys_match_der_oracle() {
    let Some(e) = env("generated") else { return };
    let kinds = [
        ("tpm-p256", "keyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
        ("tpm-p384", "keyType = \"CKK_EC\"\ncurve = \"secp384r1\""),
        ("tpm-p521", "keyType = \"CKK_EC\"\ncurve = \"secp521r1\""),
        ("tpm-rsa2048", "keyType = \"CKK_RSA\"\nmodulusBits = 2048"),
        ("tpm-rsa3072", "keyType = \"CKK_RSA\"\nmodulusBits = 3072"),
    ];
    let mut body = String::new();
    for (k, ty) in kinds {
        // tpm2-pkcs11 1.10.1 cannot sign with its P-521 keys: C_SignInit parses its own malformed
        // CKA_EC_POINT and fails (CKR_HOST_MEMORY; upstream/tpm2-pkcs11 fixes both).
        let binding = if k == "tpm-p521" { ", binding = \"token-asserted\"" } else { "" };
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}-gen]\nobject = \"{k}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"{k}\" }}, autoCreate = true{binding} }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.tpm-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, publicOnly = true }}\n\n"
        );
    }
    e.config(&body);
    for (k, _) in kinds {
        let spec = format!("{k}-gen");
        let first = e.km(&["realise", &spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&first), 10, "{k}");
        assert_eq!(
            got_hash(&e.km(&["realise", &spec, "--token", "tpm", "--no-update-lock"])),
            got_hash(&first),
            "{k}: no duplicate"
        );
        assert_eq!(code(&e.km(&["realise", &spec, "--token", "tpm", "--update-lock"])), 0, "{k}");
        // A session opened now: tpm2-pkcs11 sessions don't see objects created after they opened.
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki_with(&e.session(), k, unwrap_tpm2)), "{k}");
        let binding = if k == "tpm-p521" { "token-asserted" } else { "pop-sign" };
        assert_eq!(e.lock()["realisations"][&spec]["tpm"]["binding"].as_str(), Some(binding), "{k}");
        let pubs = format!("{k}-pub");
        assert_eq!(code(&e.km(&["realise", &pubs, "--token", "tpm-anon", "--update-lock"])), 0, "{k}");
    }
}

#[test]
fn tpm2_identity_failure_after_create_leaves_nothing() {
    let Some(e) = env("orphan") else { return };
    // Without the provider, tpm2-pkcs11's P-521 point is rejected after the key was generated.
    e.config(
        "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp521r1\"\n\n\
         [specs.p]\nobject = \"p\"\nattributes = { CKA_SIGN = true }\ntokens.tpm-generic = { locator = { CKA_LABEL = \"orphan-p521\" }, autoCreate = true }\n",
    );
    let o = e.km(&["realise", "p", "--token", "tpm-generic", "--no-update-lock"]);
    assert_eq!(code(&o), 13);
    assert!(String::from_utf8_lossy(&o.stderr).contains("removed 2 object(s) just created"));
    assert_eq!(labelled(&e.session(), "orphan-p521"), 0);
}

/// openssl-computed rfc7093m4 IDs of the import fixtures (test-only keys).
const IMPORT_P256: &str = "sha256-0ymh9vfz8P3lnbdlAXskvxwoDAfUJNEIbsv0KEupcSg=";
const IMPORT_RSA2048: &str = "sha256-kRE6YzH4EXmqqAKhbLhb0z6/57mcGvHKrm4F4omLIn4=";
const HMAC_VALUE: &[u8; 32] = b"key-management hmac test vector!";
const HMAC384_VALUE: &[u8; 48] = b"key-management hmac-sha384 test vector, 48 bytes";

#[test]
fn tpm2_imported_keys_match_openssl_and_host_hmac() {
    let Some(e) = env("imported") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    e.ptool(&[
        "import",
        "--algorithm=ecc",
        &format!("--privkey={FIXTURES}/tpm-import-p256.pem"),
        "--key-label=imp-p256",
    ]);
    e.ptool(&[
        "import",
        "--algorithm=rsa",
        &format!("--privkey={FIXTURES}/tpm-import-rsa2048.pem"),
        "--key-label=imp-rsa",
    ]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    e.ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=imp-hmac",
    ]);
    let hmac384_file = e.dir.join("hmac384.bin");
    std::fs::write(&hmac384_file, HMAC384_VALUE).unwrap();
    e.ptool(&[
        "import",
        "--algorithm=hmac:sha384",
        &format!("--privkey={}", hmac384_file.display()),
        "--key-label=imp-hmac384",
    ]);
    e.config(
        r#"
[objects.p256]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.p256]
object = "p256"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-p256" } }

[objects.rsa]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[specs.rsa]
object = "rsa"
tokens.tpm-anon = { locator = { CKA_LABEL = "imp-rsa" }, publicOnly = true }

[objects.hmac]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA256_HMAC"
valueLen = 32

# tpm2_ptool marks imported keys CKA_EXTRACTABLE = true; commitment (CKA_SIGN) is preferred.
[specs.hmac]
object = "hmac"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-hmac" } }

[objects.hmac384]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA384_HMAC"
valueLen = 48

[specs.hmac384]
object = "hmac384"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-hmac384" } }
"#,
    );
    for (spec, token) in [("p256", "tpm"), ("rsa", "tpm-anon"), ("hmac", "tpm"), ("hmac384", "tpm")] {
        assert_eq!(code(&e.km(&["realise", spec, "--token", token, "--update-lock"])), 0, "{spec}");
    }
    assert_eq!(e.locked_id("p256", "rfc7093m4"), IMPORT_P256);
    assert_eq!(e.locked_id("rsa", "rfc7093m4"), IMPORT_RSA2048);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    // An HMAC-SHA384 key is committed with HMAC-SHA384 (the TPM binds the key to its hash).
    let mut mac = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(HMAC384_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA384_HMAC/384");
    assert_eq!(e.locked_id("hmac384", "commitment"), sri(&mac.finalize().into_bytes()));
}

#[test]
fn tpm2_aes_key_is_identified_by_its_kcv() {
    let Some(e) = env("aes") else { return };
    // tpm2-pkcs11 cannot import AES keys, so the oracle here is a consistency check: the same
    // block encrypted through a separate session. The independent AES oracle runs on SoftHSM.
    e.ptool(&["addkey", "--algorithm=aes256", "--key-label=kcv-aes"]);
    e.config(
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.aes]\nobject = \"aes\"\nattributes = { CKA_ENCRYPT = true, CKA_SENSITIVE = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"kcv-aes\" } }\n",
    );
    let r = ["realise", "aes", "--token", "tpm", "--no-update-lock"];
    let first = e.km(&r);
    assert_eq!(code(&first), 10);
    assert_eq!(got_hash(&e.km(&r)), got_hash(&first));
    assert_eq!(code(&e.km(&recording(&r))), 0);
    assert_eq!(code(&e.km(&["check", "aes.id.kcv-ecb"])), 0);

    let s = e.session();
    let h =
        s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Label(b"kcv-aes".to_vec())]).unwrap()[0];
    let block = &<sha2::Sha256 as sha2::Digest>::digest(b"key-management/v1/kcv-ecb/CKK_AES/256")[..16];
    let kcv = s.encrypt(&Mechanism::AesEcb, h, block).unwrap();
    assert_eq!(e.locked_id("aes", "kcv-ecb"), sri(&kcv));
}

/// The `tpm-certify` commitment (§3.7 of docs/DESIGN.md): a native `TPM2_Certify` over the
/// object's Name, host-verified against a provisioned AK, and cross-checked against the
/// material `rfc7093m4` names.
#[test]
fn tpm2_keys_attest_their_tpm_residence() {
    let Some(e) = env("attest") else { return };
    // A generated EC key (9a slot style): attested on the TPM, once the AK is provisioned.
    e.config(
        "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p256]\nobject = \"p256\"\nattributes = { CKA_SIGN = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"attest-p256\" }, autoCreate = true, attestation = true }\n",
    );
    let r = ["realise", "p256", "--token", "tpm", "--no-update-lock"];
    let first = e.km(&r);
    assert_eq!(code(&first), 10, "first use: got the ID, the lock is written by review");
    let got: serde_json::Value = serde_json::from_str(&stdout(&e.km(&["resolve", "p256", "--token", "tpm"]))).unwrap();
    let ids = got["ids"].as_object().unwrap();
    assert_eq!(ids.len(), 1, "only the portable rfc7093m4 is an object ID: {ids:?}");
    assert!(got["attestation"]["id"].as_str().unwrap().starts_with("sha256-"));
    assert_eq!(code(&e.km(&recording(&r))), 0);
    // The lock: the attestation lives on the realisation (per device), the portable ID on the
    // object; the realisation pins the AK beside its attestation ID.
    assert!(e.lock()["objects"]["p256"]["ids"].get("tpm-certify").is_none());
    let real = &e.lock()["realisations"]["p256"]["tpm"];
    assert_eq!(real["schemes"].as_array().unwrap().len(), 1);
    let att = e.locked_attestation("p256", "tpm");
    assert_eq!(att["kind"].as_str(), Some("tpm-certify"));
    assert!(att["root"].as_str().unwrap().starts_with("sha256-"));
    assert_ne!(att["id"].as_str(), Some(e.locked_id("p256", "rfc7093m4").as_str()));
    // Verify is a fresh certify run: a new nonce, the same stable Name.
    assert_eq!(code(&e.km(&["verify", "p256", "--token", "tpm"])), 0);
    assert_eq!(code(&e.km(&["check", "p256.id.tpm-certify", "--token", "tpm"])), 0);
    // The AK is persistent at the default handle: a second run reuses it, so the root is stable.
    let again = e.km(&["resolve", "p256", "--token", "tpm"]);
    let got: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(got["attestation"]["root"].as_str(), att["root"].as_str());

    // Once locked, a run that cannot attest is a scheme downgrade (14) — here no AK at the
    // configured handle. Reads never provision one, so the second verify fails the same way.
    let base = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    let alt = |handle: &str| {
        base.replacen(
            "tokenLabel = \"kmtest\"\n",
            &format!("tokenLabel = \"kmtest\"\noptions = {{ akHandle = \"{handle}\" }}\n"),
            1,
        )
    };
    std::fs::write(e.dir.join("keys.toml"), alt("0x81000017")).unwrap();
    for _ in 0..2 {
        let o = e.km(&["verify", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", String::from_utf8_lossy(&o.stderr));
        assert!(String::from_utf8_lossy(&o.stderr).contains("no Attestation Key at 0x81000017"));
    }
    // A key at the AK handle that is not a restricted signing key is never trusted as the AK:
    // an unrestricted one could sign a forged attestation.
    let ctx = e.dir.join("storage.ctx");
    for args in [
        vec!["tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", ctx.to_str().unwrap()],
        vec!["tpm2_evictcontrol", "-C", "o", "-c", ctx.to_str().unwrap(), "0x81000018"],
    ] {
        let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    std::fs::write(e.dir.join("keys.toml"), alt("0x81000018")).unwrap();
    let o = e.km(&r);
    assert_eq!(code(&o), 13, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not a cakeys Attestation Key"));
    std::fs::write(e.dir.join("keys.toml"), &base).unwrap();

    // HMAC keys attest too (TPM2_Certify covers any loaded object), pairing with `commitment`.
    if cryptoki_hmac_types_fixed(false) {
        let hmac_file = e.dir.join("hmac.bin");
        std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
        e.ptool(&[
            "import",
            "--algorithm=hmac:sha256",
            &format!("--privkey={}", hmac_file.display()),
            "--key-label=attest-hmac",
        ]);
        e.config(
            "[objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
             [specs.hmac]\nobject = \"hmac\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n\
             tokens.tpm = { locator = { CKA_LABEL = \"attest-hmac\" }, attestation = true }\n",
        );
        assert_eq!(code(&e.km(&["realise", "hmac", "--token", "tpm", "--update-lock"])), 0);
        assert!(e.lock()["objects"]["hmac"]["ids"].get("commitment").is_some());
        assert!(e.locked_attestation("hmac", "tpm")["id"].as_str().is_some());
    }
}

/// The same material attested on two TPM tokens (§3.7): each attestation is per device — the
/// imported HMAC's Name differs per import (a fresh seedValue), and the qualified Name per
/// hierarchy — so each realisation pins its own, and the object links them through its one
/// portable `commitment`. Recording them on the object would make the second a mismatch.
#[test]
fn tpm2_each_token_pins_its_own_attestation() {
    let Some(e) = env("attest-two") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
    let ptool = |args: &[&str]| {
        let out = Command::new("tpm2_ptool").args(args).arg(format!("--path={store}")).output().unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    ptool(&["addtoken", "--pid=1", "--label=kmtest2", "--sopin=5678", "--userpin=1234"]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    for label in ["kmtest", "kmtest2"] {
        ptool(&[
            "import",
            "--algorithm=hmac:sha256",
            &format!("--privkey={}", hmac_file.display()),
            "--key-label=two-hmac",
            &format!("--label={label}"),
            "--userpin=1234",
        ]);
    }
    let pin = e.dir.join("pin").display().to_string();
    e.config(&format!(
        "[tokens.tpm2]\nmodule = \"{}\"\ntokenLabel = \"kmtest2\"\npinFile = \"{pin}\"\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"two-hmac\" }}, attestation = true }}\n\
         tokens.tpm2 = {{ locator = {{ CKA_LABEL = \"two-hmac\" }}, attestation = true }}\n",
        e.module
    ));
    assert_eq!(code(&e.km(&["realise", "hmac", "--token", "tpm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["realise", "hmac", "--token", "tpm2", "--update-lock"])), 0);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "{ids:?}");
    let (one, two) = (e.locked_attestation("hmac", "tpm"), e.locked_attestation("hmac", "tpm2"));
    assert_ne!(one["id"].as_str(), two["id"].as_str(), "two imports, two TPM objects, two attestations");
    assert_eq!(one["root"].as_str(), two["root"].as_str(), "one TPM, one AK");
    for t in ["tpm", "tpm2"] {
        assert_eq!(code(&e.km(&["verify", "hmac", "--token", t])), 0);
    }
}

/// The user's portability requirement (§3.7): attestation is provenance for one device. A copy
/// of the same material on a token that attests nothing (here `SoftHSM`) verifies through the
/// portable commitment alone; the TPM realisation's attestation stays on that realisation.
#[test]
fn tpm2_attested_material_travels_to_a_second_hsm() {
    let Some(e) = env("attest-travel") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    let soft = std::env::var("CAKEYS_TEST_MODULE").expect("the SoftHSM module (harness preCheck)");
    let pin = e.dir.join("pin").display().to_string();
    // The same HMAC material on the TPM (imported, attested) and on SoftHSM (planted, not
    // attestable: SoftHSM attests nothing).
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    e.ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=travel-hmac",
    ]);
    e.config(&format!(
        "[tokens.soft]\nmodule = \"{soft}\"\ntokenLabel = \"kmtest\"\npinFile = \"{pin}\"\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac-tpm]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, attestation = true }}\n\n\
         [specs.hmac-soft]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.soft = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }} }}\n\n\
         [specs.hmac-attest-soft]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.soft = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, attestation = true }}\n",
    ));
    let soft_session = open_session(&soft, "kmtest", "1234");
    soft_session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::SHA256_HMAC),
            Attribute::Token(true),
            Attribute::Label(b"travel-hmac".to_vec()),
            Attribute::Value(HMAC_VALUE.to_vec()),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ])
        .unwrap();
    // The portable identity first, from the token without attestation; the TPM realisation
    // then joins the same object through the shared commitment scheme, pinning its attestation.
    assert_eq!(code(&e.km(&["realise", "hmac-soft", "--token", "soft", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["realise", "hmac-tpm", "--token", "tpm", "--update-lock"])), 0);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "the portable ID only: {ids:?}");
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    assert!(e.locked_attestation("hmac-tpm", "tpm")["id"].as_str().unwrap().starts_with("sha256-"));
    // The copy on the second HSM verifies through the commitment; the TPM through both.
    assert_eq!(code(&e.km(&["verify", "hmac-soft", "--token", "soft"])), 0);
    assert_eq!(code(&e.km(&["verify", "hmac-tpm", "--token", "tpm"])), 0);
    // Opting into attestation on a module that attests nothing is refused up front (15).
    let o = e.km(&["realise", "hmac-attest-soft", "--token", "soft", "--no-update-lock"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("attests nothing"), "{}", String::from_utf8_lossy(&o.stderr));
}

/// The committed pair profile tpm2-pkcs11/1.10+swtpm is probe output (docs/PROVIDERS.md
/// phase 3): what this module does on this TPM, measured together. A fresh probe conforms and
/// regenerating it changes no byte.
#[test]
fn the_committed_profile_is_what_the_probe_observes() {
    let Some(e) = env("profile_conformance") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    e.config("");
    let (name, path) = ("tpm2-pkcs11/1.10+swtpm", "modules/tpm2-pkcs11/1.10+swtpm.toml");
    assert_profile_conforms(|args| e.km(args), "tpm", name, path, &e.dir.join("profile.toml"));
}
