//! The cross-reference harness (used by `cakeys`' tests/references.rs and `camigrate`'s dry-run
//! tests). It collects every reference token whose suite variables are set, writes one keys.toml
//! that names them all, and runs either binary against that keys.toml.

use super::state::{Row, TokenView, assert_unchanged, database, snapshot};
use super::{BIN, REQUIRE_ALL, Run, required_var, sibling, skip};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Output;

/// How a reference gets the material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plant {
    /// `C_CreateObject` through the module.
    Create,
    /// `tpm2_ptool import`, because tpm2-pkcs11 creates no keys from values.
    Ptool,
    /// The token of the reference before this one, used through another configuration.
    Shared,
}

#[derive(Clone)]
pub struct Ref {
    /// The token's name in keys.toml.
    pub name: &'static str,
    pub module: String,
    pub token_label: &'static str,
    /// The environment of every cakeys run against this reference.
    pub env: &'static [(&'static str, &'static str)],
    pub plant: Plant,
    /// Whether `CKM_EDDSA` is usable. It is not usable through p11-kit, whose RPC drops it.
    pub eddsa: bool,
}

impl Ref {
    /// Returns this reference's token, as a snapshot sees it ([`super::state::objects`]).
    pub fn view(&self) -> TokenView<'_> {
        TokenView {
            name: self.name,
            module: &self.module,
            label: self.token_label,
            env: self.env,
            db: database(&self.module, self.env),
        }
    }
}

pub struct Env {
    pub dir: PathBuf,
    pub refs: Vec<Ref>,
}

/// Returns the variable that requires reference `name` ([`required_var`]). When the variable is
/// set, a test that needs the reference fails where it would otherwise skip ([`Env::needs`]).
///
/// # Panics
///
/// Panics for a name that no reference has, because a test that needs it would skip on every run.
pub fn require_var_of(name: &str) -> &'static str {
    match name {
        "softhsm" => "CAKEYS_TEST_REQUIRE",
        "kryoptic" | "kryoptic-der" => "CAKEYS_KRYOPTIC_REQUIRE",
        "p11kit" => "CAKEYS_P11KIT_REQUIRE",
        "tpm2" => "CAKEYS_TPM_REQUIRE",
        other => panic!("no reference is named '{other}'"),
    }
}

pub fn env(name: &str) -> Option<Env> {
    let mut refs = Vec::new();
    let r = |name, module, token_label, env, plant, eddsa| Ref { name, module, token_label, env, plant, eddsa };
    // An unset variable is not reported: a reference that is left out does not count as a skip,
    // unless fewer than two references are left.
    if let Some(m) = required_var("CAKEYS_TEST_MODULE", require_var_of("softhsm")) {
        refs.push(r("softhsm", m, "kmtest", &[], Plant::Create, true));
    }
    if let Some(m) = required_var("CAKEYS_KRYOPTIC_MODULE", require_var_of("kryoptic")) {
        refs.push(r("kryoptic", m.clone(), "kmtest", &[], Plant::Create, true));
        let der: &[(&str, &str)] = &[("KRYOPTIC_EC_POINT_ENCODING", "DER")];
        refs.push(r("kryoptic-der", m, "kmtest", der, Plant::Shared, true));
    }
    if let Some(m) = required_var("CAKEYS_P11KIT_CLIENT", require_var_of("p11kit")) {
        refs.push(r("p11kit", m, "kmp11", &[], Plant::Create, false));
    }
    if let Some(m) = required_var("CAKEYS_TPM_MODULE", require_var_of("tpm2")) {
        refs.push(r("tpm2", m, "kmtest", &[], Plant::Ptool, false));
    }
    if refs.len() < 2 {
        // No variable required the references that are left out, and a run that requires
        // everything has all of them.
        skip(name, REQUIRE_ALL, "fewer than two reference tokens set");
        return None;
    }
    let dir = super::test_dir(&format!("xref-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    std::fs::write(dir.join("keys.lock"), super::EMPTY_LOCK).unwrap();
    Some(Env { dir, refs })
}

impl Env {
    /// Writes keys.toml with one token per reference, followed by `body`.
    pub fn config(&self, body: &str) {
        self.config_with(body, &|_| String::new());
    }

    /// Does what [`Self::config`] does, with `extra` lines in each reference's token table. The
    /// lines must go in here, because TOML cannot reopen a table after it is written.
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

    /// Runs the package's own binary ([`BIN`]) against reference `r`.
    pub fn km(&self, r: &Ref, args: &[&str]) -> Output {
        self.run(std::path::Path::new(BIN), r, args)
    }

    /// Does what [`Self::km`] does, with `NIX_BUILD_TOP` set, as inside a Nix build sandbox. It
    /// runs no dry-run twin, because the test is about what the run itself refuses there. `env`
    /// is set in addition.
    pub fn km_in_nix_build(&self, r: &Ref, env: &[(&str, &str)], args: &[&str]) -> Output {
        self.command(std::path::Path::new(BIN), r)
            .note("in a Nix build")
            .env("NIX_BUILD_TOP", "/build")
            .envs(env.iter().copied())
            .output(args)
    }

    /// Does what [`Self::km`] does, without the dry-run twin, for a run whose input is wrong
    /// before any plan (a missing flag, an empty passphrase file). A plan has nothing to report
    /// about such input.
    pub fn km_alone(&self, r: &Ref, args: &[&str]) -> Output {
        self.run_once(std::path::Path::new(BIN), r, args)
    }

    /// Runs `cakeys` itself ([`sibling`]) from a package whose own binary is another one.
    /// `camigrate`'s tests use it to record the realisations from which they plan.
    pub fn cakeys(&self, r: &Ref, args: &[&str]) -> Output {
        self.run(&sibling("cakeys"), r, args)
    }

    /// Runs `bin` against reference `r`. Before a run that writes (`camigrate`'s `export`,
    /// `import`, `migrate`; `cakeys`' `create`, `delete`, `lock`, `gc`; each without
    /// `--dry-run`), it runs the dry-run twin: the same arguments with `--dry-run`. The twin must
    /// change nothing, and the real run must keep the twin's verdict ([`Self::dry_run_twin`]).
    fn run(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Output {
        let twin = self.dry_run_twin(bin, r, args);
        let out = self.run_once(bin, r, args);
        if let Some(dry) = twin {
            let real = out.status.code().unwrap();
            // Read the rows when the exit codes alone do not show whether the run kept the dry
            // run's result, and also after exit 22, because a pair may have failed after the
            // write. `gc --json` prints names instead of rows, so a parse failure gives no rows.
            let rows = if !stdout_is_rows(&out) {
                vec![]
            } else if !dry.kept_by(real, &[]) {
                super::state::rows(&out)
            } else if real == 22 {
                serde_json::from_slice(&out.stdout).unwrap_or_default()
            } else {
                vec![]
            };
            assert!(
                dry.kept_by(real, &rows),
                "{} {}: --dry-run exited {} (deferring {:?}), the run itself {real}: {rows:?}",
                bin.display(),
                args.join(" "),
                dry.exit,
                dry.deferred
            );
        }
        out
    }

    /// Returns the tokens that a run with `args` reaches, each once. A reference that reads
    /// another reference's token ([`Plant::Shared`], `kryoptic-der`) stands for that token, and
    /// never for no token (review xref.rs F1: a move to `kryoptic-der` compared no token).
    pub fn compared(&self, args: &[&str]) -> Vec<&Ref> {
        let mut named: Vec<&Ref> = Vec::new();
        for t in self.refs.iter().filter(|t| args.contains(&t.name)) {
            let owns = |o: &&Ref| o.plant != Plant::Shared && o.module == t.module && o.token_label == t.token_label;
            let owner = if t.plant == Plant::Shared { self.refs.iter().find(owns) } else { Some(t) };
            let t = owner.unwrap_or_else(|| panic!("{}: shares no reference's token", t.name));
            if !named.iter().any(|n| n.name == t.name) {
                named.push(t);
            }
        }
        named
    }

    /// Runs the dry-run twin of a run that writes, in JSON, and returns its verdict. Before it
    /// returns, it asserts that the twin left the lock, the output file and every token that the
    /// run names (for `cakeys` without `--token`, every token) as they were. It returns `None` for
    /// any other run. Review 2026-11-24 C-4: `cakeys`' dry runs had no twin, and
    /// `create --dry-run` passed where the run refused.
    fn dry_run_twin(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Option<Dry> {
        let verb = |v: &[&str]| args.first().is_some_and(|a| v.contains(a));
        let writes = match bin.file_name().and_then(|n| n.to_str()) {
            Some("camigrate") => verb(&["export", "import", "migrate"]),
            Some("cakeys") => verb(&["create", "delete", "lock", "gc"]),
            _ => false,
        };
        if !writes || args.contains(&"--dry-run") {
            return None;
        }
        let value = |flag: &str| args.iter().position(|a| *a == flag).and_then(|i| args.get(i + 1)).copied();
        let lock = value("--lock").map_or_else(|| self.dir.join("keys.lock"), PathBuf::from);
        let out = value("--out").map(PathBuf::from);
        let files: Vec<&Path> = [Some(&lock), out.as_ref()].into_iter().flatten().map(PathBuf::as_path).collect();
        let mut reached = self.compared(args);
        if reached.is_empty() && !args.contains(&"--token") {
            reached = self.refs.iter().filter(|t| t.plant != Plant::Shared).collect();
        }
        // The run's own reference stands for its token, because the run reaches the token
        // through that reference's module and environment (for example, a fault shim's
        // forwarding).
        let tokens: Vec<TokenView> =
            reached.into_iter().map(|t| if t.name == r.name { r } else { t }).map(Ref::view).collect();
        // Record what must not change, each with its name: the files' bytes and each token's
        // objects.
        let before = snapshot(&files, &tokens);
        let json: &[&str] = if args.contains(&"--json") { &[] } else { &["--json"] };
        // `create --no-update-lock` records nothing, and neither does its dry run, so the flag is
        // dropped from the dry run's arguments.
        let dry_args: Vec<&str> = args.iter().copied().filter(|a| *a != "--no-update-lock").collect();
        let dry = self.run_once(bin, r, &[&dry_args[..], &["--dry-run"], json].concat());
        let what = format!("{} {} --dry-run", bin.display(), args.join(" "));
        assert_unchanged(&before, &snapshot(&files, &tokens), &what);
        let dry = Dry::of(&dry);
        Some(if bin.ends_with("cakeys") && args.first() == Some(&"lock") { dry.comparing() } else { dry })
    }

    fn run_once(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Output {
        self.command(bin, r).output(args)
    }

    /// Returns a run of `bin` on this keys.toml, in reference `r`'s environment.
    fn command(&self, bin: &std::path::Path, r: &Ref) -> Run {
        Run::new(bin, &self.dir.join("keys.toml")).envs(r.env.iter().copied()).note(r.name)
    }

    pub fn refs(&self, keep: impl Fn(&Ref) -> bool) -> Vec<&Ref> {
        self.refs.iter().filter(|r| keep(r)).collect()
    }

    /// Returns a spec over `object` on `refs`, located by `label`. `extra` is appended to each
    /// token entry, together with `origin = "adopt"` unless `extra` names an origin.
    pub fn spec(name: &str, object: &str, attributes: &str, refs: &[&Ref], label: &str, extra: &str) -> String {
        let mut s = format!("[specs.{name}]\nobject = \"{object}\"\n{attributes}");
        let origin = if extra.contains("origin") { "" } else { ", origin = \"adopt\"" };
        for r in refs {
            writeln!(s, "tokens.{} = {{ locator = {{ CKA_LABEL = \"{label}\" }}{extra}{origin} }}", r.name).unwrap();
        }
        s + "\n"
    }
}

/// What a dry run reported (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4): its exit code,
/// and the rules that it named as rules that only the run can decide (each plan's `deferred`, and
/// each row's).
#[derive(Debug)]
pub struct Dry {
    exit: i32,
    deferred: Vec<String>,
    /// Whether this is `cakeys lock --dry-run`, which only compares with the lock. It refuses
    /// what the run records (a first use, 18; a realisation or a change that the lock lacks, 14).
    compares: bool,
}

impl Dry {
    /// A dry run that exited `exit`, deferring `deferred`.
    pub fn new(exit: i32, deferred: Vec<String>) -> Dry {
        Dry { exit, deferred, compares: false }
    }

    /// Returns the same verdict, marked as the comparison of `cakeys lock --dry-run`.
    #[must_use]
    pub fn comparing(self) -> Dry {
        Dry { compares: true, ..self }
    }

    fn of(o: &Output) -> Dry {
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
        let plans = v.get("plans").and_then(serde_json::Value::as_array).cloned();
        let entries = plans.or_else(|| v.as_array().cloned()).unwrap_or_default();
        let deferred = entries
            .iter()
            .flat_map(|e| e.get("deferred").and_then(serde_json::Value::as_array).cloned().unwrap_or_default())
            .filter_map(|d| d.as_str().or_else(|| d.get("rule").and_then(serde_json::Value::as_str)).map(str::to_owned))
            .collect();
        Dry::new(o.status.code().unwrap(), deferred)
    }

    /// Returns whether the real run, which exited `real` with `rows`, is the run that this dry run
    /// promised. The real run must have the same exit code, with three allowances. 0 and 22 count
    /// as the same, because a written lock is not a different outcome. When a comparison refused
    /// something for the lock to record (18 or 14), a real `lock` that writes the lock (22) keeps
    /// the verdict. And a row may end with a failure of the device, which no dry run foresees, or
    /// with a rule that this dry run named as deferred. The decision never depends on the text that
    /// the run prints (review 2026-11-24 L3: a phrase of stderr once allowed a 16 after a dry run
    /// that exited 0). A run that wrote the lock and then failed exits 22, so in that case the exit
    /// code of its failed row is compared instead of 22 (review 2026-11-24 L5).
    pub fn kept_by(&self, real: i32, rows: &[Row]) -> bool {
        let real = match rows.iter().find(|r| r.exit != 0) {
            Some(failed) if real == 22 => i32::from(failed.exit),
            _ => real,
        };
        let succeeded = |c: i32| matches!(c, 0 | 22);
        let admitted = |r: &Row| {
            i32::from(r.exit) == real && (r.device || r.rule.as_ref().is_some_and(|x| self.deferred.contains(x)))
        };
        let recorded = self.compares && matches!(self.exit, 14 | 18) && real == 22;
        real == self.exit || (succeeded(real) && succeeded(self.exit)) || recorded || rows.iter().any(admitted)
    }
}

/// Returns whether `o` printed rows (a JSON array), as `import` and `migrate` do. An export
/// prints a bundle or nothing.
fn stdout_is_rows(o: &Output) -> bool {
    o.stdout.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[')
}
