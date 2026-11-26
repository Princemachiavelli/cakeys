//! camigrate's liar matrix: the fault table `tests/liars/camigrate.toml`, which cakeys' runner
//! (`crates/cli/tests/common/liars.rs`) runs (docs/archive/REVIEW-2026-11-24/phase2-3-design.md
//! §1). `SoftHSM` runs behind p11-fault as the source of a move (and as the target of an import),
//! and kryoptic is the other side. p11-fault injects one false answer in each cell. There is one
//! test for each class of injected fault, and each test uses its own tokens. Every cell asserts
//! its exit code; the rule and the device bit that its row names (or what its plan names); what
//! it left of the lock, of each token and of the file that it writes; and that the fault was
//! injected. Every run, including the runs without a fault, exits 22 exactly when it changed the
//! lock, and a dry run changes nothing.
//!
//! The tests need what `tests/fault.rs` needs: `P11_FAULT_MODULE` naming `SoftHSM`, and
//! `CAKEYS_KRYOPTIC_MODULE`, which the runner for each test (nix/test-tokens.sh) sets, and
//! `libp11_fault.so` built next to the test binaries.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::liars::{Table, Tool, held, lock_invariant, run_table};
use common::state::{Snapshot, TokenView, snapshot};
use common::xref::Ref;
use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

// There is one test for each class of injected fault, written out by hand, because
// nix/test-count.py does not count a test that a macro generates.

/// Runs the class OK ([`run_table`]): a call that returns `CKR_OK` but does nothing, and a state
/// that no injected fault makes (a profile's unverified row).
#[test]
fn liars_ok() {
    run("OK");
}

/// Runs the class OTHER ([`run_table`]): a call that returns another object than the one that was
/// asked for.
#[test]
fn liars_other() {
    run("OTHER");
}

/// Runs the class FLAG ([`run_table`]): a call that hides what the token reports about itself or
/// about an object.
#[test]
fn liars_flag() {
    run("FLAG");
}

/// Runs the class FORGE ([`run_table`]): an output that the key did not produce.
#[test]
fn liars_forge() {
    run("FORGE");
}

/// Runs the class BLOB ([`run_table`]): a blob that the module returns and accepts back, but that
/// is not the blob that the module produced.
#[test]
fn liars_blob() {
    run("BLOB");
}

/// Runs the class DEV ([`run_table`]): a call that fails with a device error, and the same call
/// refused.
#[test]
fn liars_dev() {
    run("DEV");
}

/// Runs the class LOSS ([`run_table`]): the device disappears from one call of a run onward.
#[test]
fn liars_loss() {
    run("LOSS");
}

fn run(class: &str) {
    let table = Table::camigrate();
    run_table(&table, class, Moves::plant);
}

/// The two tokens of a move, with their objects planted.
struct Moves {
    w: Workdir,
    /// The `SoftHSM` module itself, which runs behind the shim.
    real: String,
    kryoptic: Ref,
    /// The lock after planting. Each cell starts from it.
    planted: Vec<u8>,
}

/// The objects that move from `softhsm` (the other objects are imported into it), with their
/// keys.toml type lines and their spec's attributes. Each spec's locator is its name.
const MOVED: [(&str, &str, &str); 7] = [
    ("ec", EC, "CKA_SIGN = true, CKA_EXTRACTABLE = true"),
    ("rsa-unwrap", RSA, "CKA_UNWRAP = true, CKA_EXTRACTABLE = true"),
    ("aes", AES, "CKA_ENCRYPT = true, CKA_EXTRACTABLE = true"),
    ("hmac", HMAC, "CKA_SIGN = true, CKA_EXTRACTABLE = true"),
    ("aes-u", AES, "CKA_ENCRYPT = true, CKA_EXTRACTABLE = true"),
    ("cert", "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"", ""),
    // The spec declares no CKA_PRIVATE, so the lock records the value that the token reports
    // (false), or records that the token did not report it (flag.hide.CKA_PRIVATE). A declared
    // flag would refuse that second case.
    ("data", "class = \"CKO_DATA\"", ""),
];

/// The objects that are born on kryoptic and imported into `softhsm` from a bundle. Only a private
/// key is imported, because `SoftHSM` unwraps no secret key with its length (its profile's
/// `move.secret-unwrap`), so no bundle carries a secret key to it.
const IMPORTED: [(&str, &str, &str); 1] = [("ec-in", EC, "CKA_SIGN = true, CKA_EXTRACTABLE = true")];

const EC: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
const RSA: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048";
const AES: &str = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
const HMAC: &str = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32";

/// The profile to which `kryoptic-u` is pinned. It is kryoptic's own profile, with its sealed rows
/// (`export.sealed.*`, `unwrap.*`) marked as claimed by the module alone.
const UNVERIFIED: &str = "kryoptic/1.5+unverified";

impl Moves {
    /// Plants `softhsm` behind the shim and kryoptic for the test `name`. It makes the transport
    /// keys, the keys to move on `softhsm` and the keys to import on kryoptic with
    /// `cakeys create`. It puts the certificate and the data object on `softhsm` and records them
    /// with `cakeys lock`, puts a decoy of each object's kind next to it, and exports a bundle of
    /// each imported object. It returns `None` (the test is skipped) when either module is
    /// missing.
    fn plant(name: &str, wrong: &mut Vec<String>) -> Option<Moves> {
        let real = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name)?;
        let kryoptic = suite_var("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE", name)?;
        let w = Workdir::new(name);
        let f = Moves { kryoptic: created_ref("kryoptic", kryoptic), w, real, planted: Vec::new() };
        std::fs::write(f.w.dir.join("so-pin"), "5678\n").unwrap();
        std::fs::write(f.w.dir.join("pass"), "correct horse\n").unwrap();
        f.unverified_profile();
        f.w.write_config(&f.config());
        f.put();
        let made = |verb: &str, spec: &str, token: &str| {
            let (out, problems) = held(&f, &["cakeys", verb, "--spec", spec, "--token", token], &[]);
            assert_eq!(code(&out), 22, "planting {spec}: {}", stderr(&out));
            problems
        };
        wrong.extend(made("create", "tk-softhsm", "softhsm"));
        wrong.extend(made("create", "tk-kryoptic", "kryoptic"));
        wrong.extend(made("lock", "tk-kryoptic", "kryoptic-u"));
        for (o, ..) in MOVED {
            let verb = if matches!(o, "cert" | "data") { "lock" } else { "create" };
            wrong.extend(made(verb, &format!("{o}-src"), "softhsm"));
        }
        for (o, ..) in IMPORTED {
            wrong.extend(made("create", &format!("{o}-src"), "kryoptic"));
            let bundle = f.bundle(o);
            let args = ["export", o, "--from", "kryoptic", "--to", "softhsm", "--out", bundle.to_str().unwrap()];
            let out = f.run(&args, &[]);
            assert_eq!(code(&out), 0, "exporting {o}: {}", stderr(&out));
        }
        Some(Moves { planted: std::fs::read(f.lock()).unwrap(), ..f })
    }

    /// Returns keys.toml: the three tokens, and then each object's two specs, one where the object
    /// is born and one where it lands.
    fn config(&self) -> String {
        let (dir, pin) = (self.w.dir.display(), self.w.dir.join("pin"));
        let mut text = format!("profileDirs = [\"{dir}/profiles\"]\n\n");
        let token = |name: &str, module: &str, extra: &str| {
            format!(
                "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n{extra}\n",
                pin.display()
            )
        };
        text += &token(
            "softhsm",
            &fault_shim(),
            &format!("soCredentialFile = \"{dir}/so-pin\"\nmigrate = {{ transportWith = \"tk-softhsm\" }}\n"),
        );
        text += &token("kryoptic", &self.kryoptic.module, "migrate = { transportWith = \"tk-kryoptic\" }\n");
        text += &token(
            "kryoptic-u",
            &self.kryoptic.module,
            &format!("moduleProfile = \"{UNVERIFIED}\"\nmigrate = {{ transportWith = \"tk-kryoptic\" }}\n"),
        );
        for t in ["softhsm", "kryoptic"] {
            let _ = write!(
                text,
                "[objects.tk-{t}]\n{RSA}\n\n[specs.tk-{t}]\nobject = \"tk-{t}\"\n\
                 attributes = {{ CKA_UNWRAP = true, CKA_EXTRACTABLE = false }}\n\
                 tokens.{t} = {{ locator = {{ CKA_LABEL = \"tk-{t}\" }}, origin = \"create\", binding = \"pop-unwrap\" }}\n"
            );
        }
        // kryoptic-u is the same kryoptic token, so its transport key is the one on kryoptic.
        text += "tokens.kryoptic-u = { locator = { CKA_LABEL = \"tk-kryoptic\" }, origin = \"adopt\", binding = \"pop-unwrap\" }\n\n";
        let spec = |o: &str, ty: &str, attributes: &str, born: &str, lands: &str| {
            let binding = match o {
                "ec" | "ec-in" => ", binding = \"pop-sign\"",
                "rsa-unwrap" => ", binding = \"pop-unwrap\"",
                _ => "",
            };
            let origin = if matches!(o, "cert" | "data") { "adopt" } else { "create" };
            format!(
                "[objects.{o}]\n{ty}\n\n\
                 [specs.{o}-src]\nobject = \"{o}\"\nattributes = {{ {attributes} }}\n\
                 tokens.{born} = {{ locator = {{ CKA_LABEL = \"{o}\" }}, origin = \"{origin}\"{binding} }}\n\n\
                 [specs.{o}-dst]\nobject = \"{o}\"\nattributes = {{ {attributes} }}\n\
                 tokens.{lands} = {{ locator = {{ CKA_LABEL = \"{o}\" }}, origin = \"import\"{binding} }}\n\n"
            )
        };
        for (o, ty, attributes) in MOVED {
            text += &spec(o, ty, attributes, "softhsm", to(o));
        }
        for (o, ty, attributes) in IMPORTED {
            text += &spec(o, ty, attributes, "kryoptic", "softhsm");
        }
        text
    }

    /// Writes kryoptic's committed profile under the name [`UNVERIFIED`], with its sealed rows set
    /// to `by = "unverified"`, in the directory that keys.toml's `profileDirs` names.
    fn unverified_profile(&self) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles/modules/kryoptic/1.5.toml");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let sealed = |l: &str| l.starts_with("\"export.sealed.") || l.starts_with("\"unwrap.");
        let lines: Vec<String> = text
            .lines()
            .map(|l| match l {
                "profile = \"kryoptic/1.5\"" => format!("profile = \"{UNVERIFIED}\""),
                l if sealed(l) => l.replace("by = \"host\"", "by = \"unverified\""),
                l => l.to_owned(),
            })
            .collect();
        assert!(lines.iter().any(|l| sealed(l) && l.contains("unverified")), "{}: no sealed rows", path.display());
        let dir = self.w.dir.join("profiles");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("kryoptic-unverified.toml"), lines.join("\n") + "\n").unwrap();
    }

    /// Puts on `softhsm` the objects that cakeys does not make: the certificate and the data object
    /// under their labels, and an extractable decoy of each object's kind under `<name>-other`, so
    /// that an injected fault can wrap the decoy in the object's place.
    fn put(&self) {
        let s = open_session(&self.real, "kmtest", "1234");
        let label = |n: &str| Attribute::Label(n.as_bytes().to_vec());
        let token = Attribute::Token(true);
        let cert = |name: &str, der: &[u8]| {
            s.create_object(&cert_object(der, name.as_bytes(), None)).unwrap();
        };
        cert("cert", include_bytes!("../../cli/tests/fixtures/adopt-cert.der"));
        cert("cert-other", include_bytes!("../../cli/tests/fixtures/adopt-cert-p384.der"));
        for name in ["data", "data-other"] {
            s.create_object(&[
                Attribute::Class(cryptoki::object::ObjectClass::DATA),
                token.clone(),
                Attribute::Private(false),
                label(name),
                Attribute::Application(b"liars".to_vec()),
                Attribute::Value(format!("{name}: a value of its own").into_bytes()),
            ])
            .unwrap();
        }
        let ec = [token.clone(), label("ec-other"), Attribute::EcParams(P256.to_vec())];
        let private = [token.clone(), label("ec-other"), Attribute::Sign(true), Attribute::Extractable(true)];
        s.generate_key_pair(&Mechanism::EccKeyPairGen, &ec, &private).unwrap();
        let rsa = [token.clone(), label("rsa-unwrap-other"), Attribute::ModulusBits(2048.into())];
        let private = [token.clone(), label("rsa-unwrap-other"), Attribute::Unwrap(true), Attribute::Extractable(true)];
        s.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &rsa, &private).unwrap();
        for (name, kind, m) in [
            ("aes-other", KeyType::AES, Mechanism::AesKeyGen),
            ("aes-u-other", KeyType::AES, Mechanism::AesKeyGen),
            ("hmac-other", KeyType::GENERIC_SECRET, Mechanism::GenericSecretKeyGen),
        ] {
            let t = [
                token.clone(),
                label(name),
                Attribute::KeyType(kind),
                Attribute::ValueLen(32.into()),
                Attribute::Encrypt(kind == KeyType::AES),
                Attribute::Sign(kind != KeyType::AES),
                Attribute::Extractable(true),
            ];
            s.generate_key(&m, &t).unwrap();
        }
    }

    fn lock(&self) -> PathBuf {
        self.w.dir.join("keys.lock")
    }

    /// Returns the path of the bundle of an imported object, which is exported from kryoptic
    /// during planting.
    fn bundle(&self, object: &str) -> PathBuf {
        self.w.dir.join(format!("{object}.bundle.toml"))
    }

    /// Returns the path that `export` writes: a bundle or a key file.
    fn out(&self) -> PathBuf {
        self.w.dir.join("out")
    }

    /// Returns both tokens, compared by their objects. kryoptic is also compared by its objects
    /// and not by its database's bytes, because an object that is made and then removed changes
    /// those bytes (for example, in a move that is refused after the target made the public half).
    fn views(&self) -> [TokenView<'_>; 2] {
        [
            TokenView { name: "softhsm", module: &self.real, label: "kmtest", env: &[], db: vec![] },
            TokenView { db: vec![], ..self.kryoptic.view() },
        ]
    }
}

/// Returns the token to which an object moves.
fn to(object: &str) -> &'static str {
    match object {
        "aes-u" => "kryoptic-u",
        o if o.ends_with("-in") => "softhsm",
        _ => "kryoptic",
    }
}

/// Returns the token on which an object is born.
fn from(object: &str) -> &'static str {
    if object.ends_with("-in") { "kryoptic" } else { "softhsm" }
}

impl Tool for Moves {
    fn dir(&self) -> &Path {
        &self.w.dir
    }

    fn fill(&self, _table: &Table, args: &[String], object: &str) -> Vec<String> {
        let path = |p: PathBuf| p.display().to_string();
        args.iter()
            .map(|a| {
                a.replace("{object}", object)
                    .replace("{spec}", &format!("{object}-src"))
                    .replace("{from}", from(object))
                    .replace("{to}", to(object))
                    .replace("{out}", &path(self.out()))
                    .replace("{pass}", &path(self.w.dir.join("pass")))
                    .replace("{bundle}", &path(self.bundle(object)))
            })
            .collect()
    }

    /// Runs camigrate on the fixture's keys.toml. Arguments that start with `"cakeys"` run cakeys
    /// itself instead (a planting step).
    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let config = self.w.dir.join("keys.toml");
        match args {
            ["cakeys", rest @ ..] => Run::new(sibling("cakeys"), &config).envs(env.iter().copied()).output(rest),
            _ => Run::new(BIN, &config).envs(env.iter().copied()).output(args),
        }
    }

    /// Runs a `before` step, which is a cakeys step (`lock` under the injected fault).
    fn before(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        self.run(&[&["cakeys"], args].concat(), env)
    }

    fn state(&self) -> Snapshot {
        snapshot(&[&self.lock(), &self.out()], &self.views())
    }

    fn kind(&self, what: &str) -> String {
        match what {
            "token softhsm" => "softhsm",
            "token kryoptic" => "kryoptic",
            w if w == self.lock().display().to_string() => "lock",
            _ => "out",
        }
        .to_owned()
    }

    /// Returns the exit code of a run without a fault. A move or an import writes the lock (22),
    /// and an export or a dry run does not (0). The verbs whose names start with "migrate" and do
    /// not end with "--dry-run" are moves.
    fn honest_exit(&self, _table: &Table, verb: &str, _object: &str) -> i32 {
        let moves = verb.starts_with("migrate") && !verb.ends_with("--dry-run");
        if moves || verb == "import" { 22 } else { 0 }
    }

    /// Checks that a run exits 22 exactly when the lock changed, and that a dry run changes
    /// nothing.
    fn invariants(&self, args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
        let mut wrong = lock_invariant(args, exit, changed);
        if args.contains(&"--dry-run") && !changed.is_empty() {
            wrong.push(format!("{args:?}: a dry run changed {changed:?}"));
        }
        wrong
    }

    /// Restores the state after planting: the planted lock, no written file, and no object that a
    /// move or an import made on either token.
    fn restore(&self, _table: &Table) {
        std::fs::write(self.lock(), &self.planted).unwrap();
        let _ = std::fs::remove_file(self.out());
        let landed: Vec<&str> = MOVED.iter().map(|(o, ..)| *o).collect();
        let imported: Vec<&str> = IMPORTED.iter().map(|(o, ..)| *o).collect();
        open_session(&self.kryoptic.module, "kmtest", "1234").clear(&landed);
        open_session(&self.real, "kmtest", "1234").clear(&imported);
    }
}
