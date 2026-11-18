//! The cross-reference harness (`cakeys`' tests/references.rs, `camigrate`'s dry-run tests): every
//! reference token whose suite variables are set, one keys.toml naming them all, and runs of
//! either binary against it.

use super::{BIN, sibling};
use std::fmt::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

/// How a reference gets the material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plant {
    /// `C_CreateObject` through the module.
    Create,
    /// `tpm2_ptool import` (tpm2-pkcs11 creates no keys from values).
    Ptool,
    /// The token of the reference before it, through another configuration.
    Shared,
}

#[derive(Clone)]
pub struct Ref {
    /// The token's name in keys.toml.
    pub name: &'static str,
    pub module: String,
    pub token_label: &'static str,
    /// Environment of every cakeys run against it.
    pub env: &'static [(&'static str, &'static str)],
    pub plant: Plant,
    /// `CKM_EDDSA` is usable: not through p11-kit, whose RPC drops it.
    pub eddsa: bool,
}

pub struct Env {
    pub dir: PathBuf,
    pub refs: Vec<Ref>,
}

fn module(var: &str, require: &str) -> Option<String> {
    let m = std::env::var(var).ok();
    assert!(m.is_some() || std::env::var(require).is_err(), "{var} is required");
    m
}

pub fn env(name: &str) -> Option<Env> {
    let mut refs = Vec::new();
    let r = |name, module, token_label, env, plant, eddsa| Ref { name, module, token_label, env, plant, eddsa };
    if let Some(m) = module("CAKEYS_TEST_MODULE", "CAKEYS_TEST_REQUIRE") {
        refs.push(r("softhsm", m, "kmtest", &[], Plant::Create, true));
    }
    if let Some(m) = module("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE") {
        refs.push(r("kryoptic", m.clone(), "kmtest", &[], Plant::Create, true));
        let der: &[(&str, &str)] = &[("KRYOPTIC_EC_POINT_ENCODING", "DER")];
        refs.push(r("kryoptic-der", m, "kmtest", der, Plant::Shared, true));
    }
    if let Some(m) = module("CAKEYS_P11KIT_CLIENT", "CAKEYS_P11KIT_REQUIRE") {
        refs.push(r("p11kit", m, "kmp11", &[], Plant::Create, false));
    }
    if let Some(m) = module("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE") {
        refs.push(r("tpm2", m, "kmtest", &[], Plant::Ptool, false));
    }
    if refs.len() < 2 {
        eprintln!("skipping {name}: fewer than two reference tokens set");
        return None;
    }
    let dir = super::test_dir(&format!("xref-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, refs })
}

impl Env {
    /// keys.toml: one token per reference, then `body`.
    pub fn config(&self, body: &str) {
        self.config_with(body, &|_| String::new());
    }

    /// [`Self::config`], with `extra` lines in each reference's token table (a table TOML cannot
    /// reopen once written).
    pub fn config_with(&self, body: &str, extra: &dyn Fn(&Ref) -> String) {
        let pin = self.dir.join("pin");
        let mut text = String::new();
        for r in &self.refs {
            let (name, module, label) = (r.name, &r.module, r.token_label);
            writeln!(text, "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"").unwrap();
            writeln!(text, "{}pinFile = \"{}\"\n", extra(r), pin.display()).unwrap();
        }
        std::fs::write(self.dir.join("keys.toml"), text + body).unwrap();
    }

    /// The package's own binary ([`BIN`]) against reference `r`.
    pub fn km(&self, r: &Ref, args: &[&str]) -> Output {
        self.run(std::path::Path::new(BIN), r, args)
    }

    /// [`Self::km`] with `NIX_BUILD_TOP` set, as inside a Nix build sandbox: no dry-run twin,
    /// since the point is what the run itself refuses there. `env` is set on top.
    pub fn km_in_nix_build(&self, r: &Ref, env: &[(&str, &str)], args: &[&str]) -> Output {
        let out = Command::new(BIN)
            .env("NIX_BUILD_TOP", "/build")
            .env_remove("IN_NIX_SHELL")
            .envs(r.env.iter().copied())
            .envs(env.iter().copied())
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ (in a Nix build) {}\n  exit={:?}\n  stderr={}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    /// [`Self::km`] without the dry-run twin, for a run whose input is wrong before any plan
    /// (a missing flag, an empty passphrase file): a plan has nothing to say about those.
    pub fn km_alone(&self, r: &Ref, args: &[&str]) -> Output {
        self.run_once(std::path::Path::new(BIN), r, args)
    }

    /// `cakeys` itself, from a package whose own binary is another (`camigrate`'s tests record
    /// the realisations they plan from with it): [`sibling`].
    pub fn cakeys(&self, r: &Ref, args: &[&str]) -> Output {
        self.run(&sibling("cakeys"), r, args)
    }

    /// Run `bin` against reference `r`. A `camigrate` run that moves something (`export`,
    /// `import`, `migrate` without `--dry-run`) is preceded by its dry-run twin: the same
    /// arguments with `--dry-run`, which must change nothing and whose verdict the real run must
    /// keep ([`Self::dry_run_twin`]).
    fn run(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Output {
        let twin = self.dry_run_twin(bin, r, args);
        let out = self.run_once(bin, r, args);
        if let Some(dry) = twin {
            let real = out.status.code().unwrap();
            // A refusal the dry run saw is the real run's refusal. A dry run that passed promises
            // only what can be known before anything is created: the real run may still meet
            // material that is not the locked one (10) or a blob that does not unwrap (13).
            let kept = if dry == 0 { matches!(real, 0 | 10 | 13) } else { real == dry };
            assert!(kept, "camigrate {}: --dry-run exited {dry}, the run itself {real}", args.join(" "));
        }
        out
    }

    /// The dry-run twin of a `camigrate` run that moves something: its exit code, after
    /// asserting that it left the lock, the output file and every token the run names as they
    /// were. `None` for any other run.
    fn dry_run_twin(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Option<i32> {
        let moves = args.iter().any(|a| matches!(*a, "export" | "import" | "migrate"));
        if bin.file_name().is_none_or(|n| n != "camigrate") || !moves || args.contains(&"--dry-run") {
            return None;
        }
        let value = |flag: &str| args.iter().position(|a| *a == flag).and_then(|i| args.get(i + 1)).copied();
        let lock = value("--lock").map_or_else(|| self.dir.join("keys.lock"), PathBuf::from);
        let files = [Some(lock), value("--out").map(PathBuf::from)];
        let named: Vec<&Ref> =
            self.refs.iter().filter(|t| args.contains(&t.name) && t.plant != Plant::Shared).collect();
        // What must not change, each with its name: the files' bytes and each token's objects.
        let state = || -> Vec<(String, String)> {
            let file = |f: &PathBuf| (f.display().to_string(), format!("{:?}", std::fs::read(f).ok()));
            files
                .iter()
                .flatten()
                .map(file)
                .chain(named.iter().map(|t| (format!("token {}", t.name), objects(t))))
                .collect()
        };
        let before = state();
        let dry = self.run_once(bin, r, &[args, &["--dry-run"]].concat());
        for ((what, was), (_, now)) in before.iter().zip(state()) {
            let changed: Vec<&str> =
                was.lines().filter(|l| !now.contains(l)).chain(now.lines().filter(|l| !was.contains(l))).collect();
            assert!(*was == now, "camigrate {} --dry-run changed {what}:\n{}", args.join(" "), changed.join("\n"));
        }
        dry.status.code()
    }

    fn run_once(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Output {
        let out = Command::new(bin)
            .env_remove("NIX_BUILD_TOP")
            .env_remove("IN_NIX_SHELL")
            .envs(r.env.iter().copied())
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ {} {} ({})\n  exit={:?}\n  stdout={}\n  stderr={}",
            bin.file_name().unwrap().to_string_lossy(),
            args.join(" "),
            r.name,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    pub fn refs(&self, keep: impl Fn(&Ref) -> bool) -> Vec<&Ref> {
        self.refs.iter().filter(|r| keep(r)).collect()
    }

    /// A spec over `object` on `refs`, located by `label`; `extra` is appended to each token entry,
    /// with `origin = "adopt"` unless it names an origin.
    pub fn spec(name: &str, object: &str, attributes: &str, refs: &[&Ref], label: &str, extra: &str) -> String {
        let mut s = format!("[specs.{name}]\nobject = \"{object}\"\n{attributes}");
        let origin = if extra.contains("origin") { "" } else { ", origin = \"adopt\"" };
        for r in refs {
            writeln!(s, "tokens.{} = {{ locator = {{ CKA_LABEL = \"{label}\" }}{extra}{origin} }}", r.name).unwrap();
        }
        s + "\n"
    }
}

/// What a dry run must leave as it was on `r`'s token: every object as `pkcs11-tool` lists it,
/// logged in — a process of its own, so no module is initialized twice in the test's. kryoptic's
/// login alone takes over a second (its PIN's key derivation \[run\]), which made the twin cost
/// ten times the suite: its token is its one database file, compared by content instead.
fn objects(r: &Ref) -> String {
    if r.name.starts_with("kryoptic")
        && let Some(db) = kryoptic_db()
    {
        let bytes = std::fs::read(&db).unwrap_or_default();
        let sum =
            bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3));
        return format!("{}: {} bytes, fnv1a {sum:016x}", db.display(), bytes.len());
    }
    let out = Command::new("pkcs11-tool")
        .envs(r.env.iter().copied())
        .args(["--module", &r.module, "--token-label", r.token_label, "--login", "--pin", "1234", "--list-objects"])
        .output()
        .expect("pkcs11-tool (opensc) lists a reference token's objects for the dry-run twin");
    assert!(out.status.success(), "pkcs11-tool on {}: {}", r.name, String::from_utf8_lossy(&out.stderr));
    // Sorted by line: a module may list its objects in another order each time (kryoptic [run]).
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    lines.join("\n")
}

/// kryoptic's token database: the `dbargs` of `$KRYOPTIC_CONF` (nix/package-common.nix).
fn kryoptic_db() -> Option<PathBuf> {
    let conf = std::fs::read_to_string(std::env::var_os("KRYOPTIC_CONF")?).ok()?;
    let args = conf.lines().find_map(|l| l.trim().strip_prefix("dbargs"))?;
    Some(PathBuf::from(args.trim_start_matches([' ', '=']).trim().trim_matches('"')))
}
