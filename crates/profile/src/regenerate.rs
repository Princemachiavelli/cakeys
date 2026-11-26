//! The writing of a regenerated golden file. A golden file is a file that a build regenerates
//! and compares with the committed copy: a profile, the object matrix's tables, the coverage file
//! or the baseline (docs/DEVELOPMENT.md, "Golden files"). The code under test writes these files,
//! so a regeneration that replaces the committed file would change the expected result together
//! with the code (review 2026-11-24 C-8). Every writer therefore goes through
//! [`write`](fn@write). It writes a file that does not exist yet. It replaces an existing file
//! only when the regeneration is accepted (`caprobe probe --accept`, or [`ACCEPT`] for a
//! `CAKEYS_UPDATE_*` run). Otherwise it writes the text next to the file, as `<file>.new`, so
//! that a person can read the changed rows (`nix/golden-rows.py --stub`) and record them in
//! profiles/LEDGER.toml before accepting the file.

use std::path::{Path, PathBuf};

/// The environment variable that accepts the regeneration of a `CAKEYS_UPDATE_*` run. When it is
/// set, the regeneration replaces the committed file.
pub const ACCEPT: &str = "CAKEYS_ACCEPT";

/// What [`write`](fn@write) did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Written {
    /// The file already held the text: nothing was written.
    Unchanged(PathBuf),
    /// The file did not exist, and it was created.
    Created(PathBuf),
    /// The regeneration was accepted, and the file now holds the text.
    Replaced(PathBuf),
    /// The regeneration was not accepted. The file is unchanged, and the text was written next to
    /// it, at this path.
    Pending(PathBuf),
}

impl Written {
    /// Whether the file now holds the text.
    #[must_use]
    pub fn holds(&self) -> bool {
        !matches!(self, Written::Pending(_))
    }
}

impl std::fmt::Display for Written {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Written::Unchanged(p) => write!(f, "{} is unchanged", p.display()),
            Written::Created(p) => write!(f, "wrote {}", p.display()),
            Written::Replaced(p) => write!(f, "replaced {} (accepted)", p.display()),
            Written::Pending(p) => write!(
                f,
                "wrote {}, beside the file it would replace: review what moved (a golden file's rows \
                 are recorded in profiles/LEDGER.toml: `nix develop -c python3 -I nix/golden-rows.py \
                 --stub`), then regenerate with --accept, or {ACCEPT}=1 for a CAKEYS_UPDATE_* run",
                p.display()
            ),
        }
    }
}

/// Returns whether [`ACCEPT`] is set. For the `CAKEYS_UPDATE_*` runs, this variable does what
/// `--accept` does for caprobe.
#[must_use]
pub fn accepted() -> bool {
    std::env::var_os(ACCEPT).is_some()
}

/// Returns the path at which a regeneration of `path` is kept until it is accepted:
/// `<path>.new`.
#[must_use]
pub fn pending(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    path.with_file_name(name)
}

/// Writes `text` as the regeneration of `path` with [`std::fs::write`]. [`write_with`] describes
/// the rules.
///
/// # Errors
///
/// Returns the IO error from reading `path`, or from writing or removing a file.
pub fn write(path: &Path, text: &str, accept: bool) -> std::io::Result<Written> {
    write_with(path, text, accept, |p, t| std::fs::write(p, t))
}

/// Writes `text` as the regeneration of `path`, through `put`. It writes into `path` when the
/// file does not exist or when `accept` is true. Otherwise, it writes into [`pending`]`(path)`,
/// so it never writes over a file that holds other text unless the regeneration is accepted. A
/// file that already holds `text` is left as it is. Once the file holds the text, a `.new` file
/// that an earlier run left next to it is stale, and this function removes it.
///
/// # Errors
///
/// Returns the error from reading `path` (except when the file does not exist), the error of
/// `put`, or the error from removing the stale `.new` file.
pub fn write_with<E: From<std::io::Error>>(
    path: &Path,
    text: &str,
    accept: bool,
    put: impl FnOnce(&Path, &str) -> Result<(), E>,
) -> Result<Written, E> {
    let now = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let written = match now {
        Some(bytes) if bytes == text.as_bytes() => Written::Unchanged(path.to_owned()),
        Some(_) if !accept => {
            let new = pending(path);
            put(&new, text)?;
            return Ok(Written::Pending(new));
        }
        Some(_) => {
            put(path, text)?;
            Written::Replaced(path.to_owned())
        }
        None => {
            put(path, text)?;
            Written::Created(path.to_owned())
        }
    };
    match std::fs::remove_file(pending(path)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(written),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This tests the rule that every writer of a golden file follows (review 2026-11-24 C-8). A
    /// regeneration replaces the committed file only when it is accepted. Otherwise, it writes
    /// the text next to the file.
    #[test]
    fn regenerate_never_overwrites_without_accept() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("golden.toml");
        let new = dir.path().join("golden.toml.new");
        let read = |p: &Path| std::fs::read_to_string(p).ok();
        // No file exists, so nothing is overwritten, and the file is written.
        assert_eq!(write(&file, "one\n", false).unwrap(), Written::Created(file.clone()));
        assert_eq!(read(&file).as_deref(), Some("one\n"));
        // Different text that is not accepted: the file stays as it was, and the regeneration is
        // written next to it.
        assert_eq!(write(&file, "two\n", false).unwrap(), Written::Pending(new.clone()));
        assert_eq!(read(&file).as_deref(), Some("one\n"));
        assert_eq!(read(&new).as_deref(), Some("two\n"));
        // The same text: nothing is written, and the pending `.new` file is stale, so it is
        // removed.
        assert_eq!(write(&file, "one\n", false).unwrap(), Written::Unchanged(file.clone()));
        assert_eq!(read(&new), None);
        // Accepted: the file is replaced, and no `.new` file remains next to it.
        write(&file, "two\n", false).unwrap();
        assert_eq!(write(&file, "two\n", true).unwrap(), Written::Replaced(file.clone()));
        assert_eq!(read(&file).as_deref(), Some("two\n"));
        assert_eq!(read(&new), None);
        assert!(Written::Pending(new.clone()).to_string().contains("nix/golden-rows.py --stub"));
    }

    /// A file that cannot be read is not treated as an absent file, because an absent file would
    /// be written over.
    #[test]
    fn an_unreadable_file_is_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("golden.toml");
        std::fs::create_dir(&file).unwrap();
        assert!(write(&file, "one\n", false).is_err());
    }

    /// Every test or tool that regenerates a file when a variable is set (`CAKEYS_UPDATE_*`,
    /// `CAKEYS_WRITE_*`) writes through [`write`]. A writer with its own code would again
    /// overwrite the committed file (review 2026-11-24 C-8). Before this rule, each of the four
    /// writers rewrote its file in place.
    #[test]
    fn every_regenerating_writer_goes_through_the_rule() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = vec![crates];
        let (mut readers, mut bypass) = (0, Vec::new());
        while let Some(p) = files.pop() {
            if p.is_dir() {
                files.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
                continue;
            }
            if p.extension().is_none_or(|e| e != "rs") || p.ends_with("profile/src/regenerate.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            let reads =
                ["var_os(\"CAKEYS_UPDATE_", "var_os(\"CAKEYS_WRITE_", "var(\"CAKEYS_UPDATE_", "var(\"CAKEYS_WRITE_"];
            if !reads.iter().any(|r| text.contains(r)) {
                continue;
            }
            readers += 1;
            if !text.contains("regenerate::write") {
                bypass.push(p.display().to_string());
            }
        }
        assert!(readers >= 4, "the regenerating writers were not found: {readers}");
        assert_eq!(bypass, Vec::<String>::new(), "regenerating writers that do not go through regenerate::write");
    }
}
