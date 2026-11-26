//! Checks that nothing changed (review 2026-11-24 C-9: the only such check was private to the
//! dry-run twin). A [`Snapshot`] records the files and the tokens that a run must leave as they
//! were, and [`assert_unchanged`] names what changed. The dry-run twin ([`super::xref`]) takes its
//! snapshots here, and so does the refusal check ([`Workdir::refused`]), which asserts the exit
//! code, the rule that the refused row names, and that the lock and the token are as they were.
//! The refusal check takes only one more argument than an assertion of an exit code and a phrase
//! of stderr, so the strongest assertion is also the easiest one to write.

use super::{Suite, Workdir, code, stderr, stdout};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A row of a per-object verb (`lock`, `create`, `delete`), as the verb prints it.
pub type Row = cakeys_cli_common::Outcome;

/// Returns the rows that a per-object verb printed on stdout (a JSON array), or no rows when it
/// printed nothing.
///
/// # Panics
///
/// Panics when stdout holds something else.
pub fn rows(o: &Output) -> Vec<Row> {
    if o.stdout.trim_ascii().is_empty() {
        return Vec::new();
    }
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("stdout is no rows ({e}): {}", stdout(o)))
}

/// Checks a refusal by `run`, which `what` names. The run must exit `exit`, the row that it
/// refused (the first row that did not pass) must name `rule` and the same exit code, and `files`
/// and `tokens` must be as they were before the run. Returns the rows. [`Workdir::refused`] runs
/// it on the tool, and the harness's own tests give it runs that change what they must not change.
///
/// # Panics
///
/// Panics when any of the three conditions does not hold.
pub fn refusal(
    files: &[&Path],
    tokens: &[TokenView],
    what: &str,
    run: impl FnOnce() -> Output,
    exit: i32,
    rule: &str,
) -> Vec<Row> {
    let before = snapshot(files, tokens);
    let out = run();
    let rows = rows(&out);
    assert_eq!(code(&out), exit, "{what}: {}", stderr(&out));
    let refused = rows.iter().find(|r| r.exit != 0).unwrap_or_else(|| panic!("{what}: no row refused: {rows:?}"));
    let got = (i32::from(refused.exit), refused.rule.as_deref());
    assert_eq!(got, (exit, Some(rule)), "{what}: the refused row: {refused:?}");
    assert_unchanged(&before, &snapshot(files, tokens), what);
    rows
}

impl Workdir {
    /// Runs `args`, with `--json`, as a refusal ([`refusal`]). The run must exit `exit`, the row
    /// that it refused must name `rule`, and the lock (keys.lock, or the file that `--lock` names)
    /// must be as it was. [`Suite::refused`] also checks a token suite's token. Returns the rows.
    pub fn refused(&self, args: &[&str], exit: i32, rule: &str) -> Vec<Row> {
        self.refused_on(&[], args, exit, rule)
    }

    /// Does what [`Self::refused`] does, and also checks that `tokens` are as they were.
    pub fn refused_on(&self, tokens: &[TokenView], args: &[&str], exit: i32, rule: &str) -> Vec<Row> {
        let lock = args.iter().position(|a| *a == "--lock").and_then(|i| args.get(i + 1));
        let lock = lock.map_or_else(|| self.dir.join("keys.lock"), PathBuf::from);
        let args = [&["--json"], args].concat();
        refusal(&[&lock], tokens, &format!("cakeys {}", args.join(" ")), || self.km(&args), exit, rule)
    }
}

impl Suite {
    /// Returns the suite's token `kmtest` (`ref` and `ref-anon` of [`super::reference_tokens`]),
    /// as a snapshot sees it.
    pub fn token_view(&self) -> TokenView<'_> {
        TokenView { name: "kmtest", module: &self.module, label: "kmtest", env: &[], db: database(&self.module, &[]) }
    }

    /// Does what [`Workdir::refused`] does, and also checks that the suite's token
    /// ([`Self::token_view`]) is as it was. It shadows [`Workdir::refused`].
    pub fn refused(&self, args: &[&str], exit: i32, rule: &str) -> Vec<Row> {
        self.refused_on(&[self.token_view()], args, exit, rule)
    }
}

/// What a run must leave as it was, each item with its name: a file's bytes, and a token's objects
/// ([`objects`]).
pub struct Snapshot(Vec<(String, String)>);

/// A token as a [`Snapshot`] sees it ([`objects`]).
pub struct TokenView<'a> {
    /// The name under which a change to the token is reported.
    pub name: &'a str,
    pub module: &'a str,
    pub label: &'a str,
    /// The environment in which the token's module is loaded.
    pub env: &'a [(&'a str, &'a str)],
    /// The files that hold the token, which are compared by content instead of by a list of
    /// objects. Only kryoptic has them ([`database`]).
    pub db: Vec<PathBuf>,
}

/// Records `files` (by bytes; a missing file is `None`) and `tokens` (by their objects), as they
/// are now.
pub fn snapshot(files: &[&Path], tokens: &[TokenView]) -> Snapshot {
    let file = |f: &&Path| (f.display().to_string(), format!("{:?}", std::fs::read(f).ok()));
    let token = |t: &TokenView| (format!("token {}", t.name), objects(t));
    Snapshot(files.iter().map(file).chain(tokens.iter().map(token)).collect())
}

/// Asserts that `after` equals `before`. Otherwise the panic names `context` (the run), what
/// changed, and the lines that differ.
///
/// # Panics
///
/// Panics when a file or a token changed, or when the two snapshots are not of the same things.
pub fn assert_unchanged(before: &Snapshot, after: &Snapshot, context: &str) {
    if let Some((what, lines)) = changes(before, after, context).first() {
        panic!("{context} changed {what}:\n{lines}");
    }
}

/// Returns what changed from `before` to `after` in `context` (the run): each item's name (a
/// file's path, or `token <name>`) and the lines that differ. It is for a caller that judges each
/// item separately, or that names every wrong cell of a table before it fails ([`super::liars`]).
///
/// # Panics
///
/// Panics when the two snapshots are not of the same things.
pub fn changes(before: &Snapshot, after: &Snapshot, context: &str) -> Vec<(String, String)> {
    let names = |s: &Snapshot| s.0.iter().map(|(what, _)| what.clone()).collect::<Vec<_>>();
    assert_eq!(names(before), names(after), "{context}: two snapshots of different things");
    let mut out = Vec::new();
    for ((what, was), (_, now)) in before.0.iter().zip(&after.0) {
        if was != now {
            let changed: Vec<&str> =
                was.lines().filter(|l| !now.contains(l)).chain(now.lines().filter(|l| !was.contains(l))).collect();
            out.push((what.clone(), changed.join("\n")));
        }
    }
    out
}

/// Returns what a run must leave as it was on token `t`: every object as `pkcs11-tool` lists it
/// after a login. `pkcs11-tool` runs in a process of its own, so no module is initialized twice in
/// the test's process. kryoptic's login alone takes over a second (because of its PIN's key
/// derivation \[run\]), which made the dry-run twin cost ten times as much time as the suite. For
/// kryoptic, the token is therefore its one database file ([`TokenView::db`]), which is compared by
/// content instead.
///
/// # Panics
///
/// Panics when `pkcs11-tool` cannot list the token.
pub fn objects(t: &TokenView) -> String {
    if !t.db.is_empty() {
        let hash = |db: &PathBuf| {
            let bytes = std::fs::read(db).unwrap_or_default();
            let sum =
                bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3));
            format!("{}: {} bytes, fnv1a {sum:016x}", db.display(), bytes.len())
        };
        return t.db.iter().map(hash).collect::<Vec<_>>().join("\n");
    }
    let out = Command::new("pkcs11-tool")
        .envs(t.env.iter().copied())
        .args(["--module", t.module, "--token-label", t.label, "--login", "--pin", "1234", "--list-objects"])
        .output()
        .expect("pkcs11-tool (opensc) lists a reference token's objects for a snapshot");
    assert!(out.status.success(), "pkcs11-tool on {}: {}", t.name, String::from_utf8_lossy(&out.stderr));
    // Sort by line, because a module may list its objects in a different order each time
    // (kryoptic [run]). A data object's line holds its handle, which SoftHSM numbers anew in each
    // process (the same objects listed twice came out as "Data object 6" and "Data object 8"
    // [run]), so the handle is left out.
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines: Vec<&str> =
        text.lines().map(|l| if l.starts_with("Data object ") { "Data object" } else { l }).collect();
    lines.sort_unstable();
    lines.join("\n")
}

/// Returns the database files of a token on `module`, when the token is stored in such files. Only
/// the kryoptic reference (`module` is `$CAKEYS_KRYOPTIC_MODULE`) has them: every `dbargs` of its
/// `KRYOPTIC_CONF`, which is the one that `env` sets for its runs, or else the process's
/// (nix/package-common.nix). It returns the files of every slot, because the configuration does not
/// say which slot holds the token's label. Review 2026-11-24 L3: for a reference with a
/// configuration of its own, the process's database was compared instead of its own.
pub fn database(module: &str, env: &[(&str, &str)]) -> Vec<PathBuf> {
    if std::env::var_os("CAKEYS_KRYOPTIC_MODULE").is_none_or(|k| k != module) {
        return vec![];
    }
    let own = env.iter().find(|(k, _)| *k == "KRYOPTIC_CONF").map(|(_, v)| std::ffi::OsString::from(v));
    let Some(conf) = own.or_else(|| std::env::var_os("KRYOPTIC_CONF")).and_then(|c| std::fs::read_to_string(c).ok())
    else {
        return vec![];
    };
    let args = conf.lines().filter_map(|l| l.trim().strip_prefix("dbargs"));
    args.map(|a| PathBuf::from(a.trim_start_matches([' ', '=']).trim().trim_matches('"'))).collect()
}
