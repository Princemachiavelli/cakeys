//! "Nothing changed" (review 2026-11-24 C-9: the one such oracle was private to the dry-run twin):
//! a [`Snapshot`] of the files and the tokens a run must leave as they were, and
//! [`assert_unchanged`], which names what changed. The dry-run twin ([`super::xref`]) takes its
//! snapshots here.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What a run must leave as it was, each with its name: a file's bytes, a token's objects
/// ([`objects`]).
pub struct Snapshot(Vec<(String, String)>);

/// A token as a [`Snapshot`] sees it ([`objects`]).
pub struct TokenView<'a> {
    /// What a change to it is reported as.
    pub name: &'a str,
    pub module: &'a str,
    pub label: &'a str,
    /// The environment its module is loaded in.
    pub env: &'a [(&'a str, &'a str)],
    /// The one file the token is, compared by content instead of listed: kryoptic's
    /// ([`database`]).
    pub db: Option<PathBuf>,
}

/// `files` (by bytes; a missing one is `None`) and `tokens` (by their objects), as they are now.
pub fn snapshot(files: &[&Path], tokens: &[TokenView]) -> Snapshot {
    let file = |f: &&Path| (f.display().to_string(), format!("{:?}", std::fs::read(f).ok()));
    let token = |t: &TokenView| (format!("token {}", t.name), objects(t));
    Snapshot(files.iter().map(file).chain(tokens.iter().map(token)).collect())
}

/// `after` is `before`: else the panic names `context` (the run), what changed and the lines
/// that differ.
///
/// # Panics
///
/// When a file or a token changed, or the two snapshots are not of the same things.
pub fn assert_unchanged(before: &Snapshot, after: &Snapshot, context: &str) {
    let names = |s: &Snapshot| s.0.iter().map(|(what, _)| what.clone()).collect::<Vec<_>>();
    assert_eq!(names(before), names(after), "{context}: two snapshots of different things");
    for ((what, was), (_, now)) in before.0.iter().zip(&after.0) {
        let changed: Vec<&str> =
            was.lines().filter(|l| !now.contains(l)).chain(now.lines().filter(|l| !was.contains(l))).collect();
        assert!(was == now, "{context} changed {what}:\n{}", changed.join("\n"));
    }
}

/// What a run must leave as it was on token `t`: every object as `pkcs11-tool` lists it, logged
/// in — a process of its own, so no module is initialized twice in the test's. kryoptic's login
/// alone takes over a second (its PIN's key derivation \[run\]), which made the dry-run twin cost
/// ten times the suite: its token is its one database file ([`TokenView::db`]), compared by
/// content instead.
///
/// # Panics
///
/// When `pkcs11-tool` cannot list the token.
pub fn objects(t: &TokenView) -> String {
    if let Some(db) = &t.db {
        let bytes = std::fs::read(db).unwrap_or_default();
        let sum =
            bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3));
        return format!("{}: {} bytes, fnv1a {sum:016x}", db.display(), bytes.len());
    }
    let out = Command::new("pkcs11-tool")
        .envs(t.env.iter().copied())
        .args(["--module", t.module, "--token-label", t.label, "--login", "--pin", "1234", "--list-objects"])
        .output()
        .expect("pkcs11-tool (opensc) lists a reference token's objects for a snapshot");
    assert!(out.status.success(), "pkcs11-tool on {}: {}", t.name, String::from_utf8_lossy(&out.stderr));
    // Sorted by line: a module may list its objects in another order each time (kryoptic [run]).
    // A data object's line carries its handle, which SoftHSM numbers afresh in each process (the
    // same objects listed twice came out as "Data object 6" and "Data object 8" [run]): left out.
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines: Vec<&str> =
        text.lines().map(|l| if l.starts_with("Data object ") { "Data object" } else { l }).collect();
    lines.sort_unstable();
    lines.join("\n")
}

/// The database file of a token on `module`, where the token is one: the kryoptic reference's
/// (`module` is `$CAKEYS_KRYOPTIC_MODULE`), the `dbargs` of `$KRYOPTIC_CONF`
/// (nix/package-common.nix).
pub fn database(module: &str) -> Option<PathBuf> {
    if std::env::var_os("CAKEYS_KRYOPTIC_MODULE").is_none_or(|k| k != module) {
        return None;
    }
    let conf = std::fs::read_to_string(std::env::var_os("KRYOPTIC_CONF")?).ok()?;
    let args = conf.lines().find_map(|l| l.trim().strip_prefix("dbargs"))?;
    Some(PathBuf::from(args.trim_start_matches([' ', '=']).trim().trim_matches('"')))
}
