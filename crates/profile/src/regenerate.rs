//! Writing a regenerated golden file: what a build regenerates and compares with, a profile, the
//! object matrix's tables, the coverage file, the baseline (docs/DEVELOPMENT.md, "Golden
//! files"). The code under test writes them, so a regeneration that replaces the committed file
//! moves the expectation with the code (review 2026-11-24 C-8). Every writer goes through
//! [`write`]: a file that is not there yet is written, but one that is is replaced only when the
//! regeneration is accepted (`caprobe probe --accept`, or [`ACCEPT`] for a `CAKEYS_UPDATE_*`
//! run). Otherwise the text goes beside it, as `<file>.new`, for its moved rows to be read
//! (`nix/golden-rows.py --stub`) and recorded in profiles/LEDGER.toml before it is accepted.

use std::path::{Path, PathBuf};

/// The variable that accepts a `CAKEYS_UPDATE_*` run's regeneration: set, it replaces the file.
pub const ACCEPT: &str = "CAKEYS_ACCEPT";

/// What [`write`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Written {
    /// The file already held the text: nothing was written.
    Unchanged(PathBuf),
    /// The file was not there: it is now.
    Created(PathBuf),
    /// Accepted: the file now holds the text.
    Replaced(PathBuf),
    /// Not accepted: the file is as it was, and the text is beside it, at this path.
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

/// Whether [`ACCEPT`] is set: the `CAKEYS_UPDATE_*` runs' `--accept`.
#[must_use]
pub fn accepted() -> bool {
    std::env::var_os(ACCEPT).is_some()
}

/// Where a regeneration of `path` waits until it is accepted: `<path>.new`.
#[must_use]
pub fn pending(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    path.with_file_name(name)
}

/// Write `text` as the regeneration of `path` with [`std::fs::write`]: see [`write_with`].
///
/// # Errors
///
/// Reading `path`, or writing or removing a file.
pub fn write(path: &Path, text: &str, accept: bool) -> std::io::Result<Written> {
    write_with(path, text, accept, |p, t| std::fs::write(p, t))
}

/// Write `text` as the regeneration of `path`, through `put`: into `path` when it is not there
/// or `accept`, else into [`pending`]`(path)`, never over a file that holds other text unless
/// accepted. A file that already holds `text` is left as it is. Once the file holds the text, a
/// `.new` an earlier run left beside it is stale, and goes.
///
/// # Errors
///
/// Reading `path` (but its absence), `put`'s, or removing the stale `.new`.
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

    /// The rule every writer of a golden file goes through (review 2026-11-24 C-8): a
    /// regeneration replaces the committed file only when accepted, and leaves it beside it
    /// otherwise.
    #[test]
    fn regenerate_never_overwrites_without_accept() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("golden.toml");
        let new = dir.path().join("golden.toml.new");
        let read = |p: &Path| std::fs::read_to_string(p).ok();
        // Nothing there: nothing is overwritten, so it is written.
        assert_eq!(write(&file, "one\n", false).unwrap(), Written::Created(file.clone()));
        assert_eq!(read(&file).as_deref(), Some("one\n"));
        // Other text, not accepted: the file stays, the regeneration waits beside it.
        assert_eq!(write(&file, "two\n", false).unwrap(), Written::Pending(new.clone()));
        assert_eq!(read(&file).as_deref(), Some("one\n"));
        assert_eq!(read(&new).as_deref(), Some("two\n"));
        // The same text: nothing written, and the waiting regeneration is stale.
        assert_eq!(write(&file, "one\n", false).unwrap(), Written::Unchanged(file.clone()));
        assert_eq!(read(&new), None);
        // Accepted: replaced, and nothing left beside it.
        write(&file, "two\n", false).unwrap();
        assert_eq!(write(&file, "two\n", true).unwrap(), Written::Replaced(file.clone()));
        assert_eq!(read(&file).as_deref(), Some("two\n"));
        assert_eq!(read(&new), None);
        assert!(Written::Pending(new.clone()).to_string().contains("nix/golden-rows.py --stub"));
    }

    /// A file that cannot be read is not taken for an absent one, which would be written over.
    #[test]
    fn an_unreadable_file_is_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("golden.toml");
        std::fs::create_dir(&file).unwrap();
        assert!(write(&file, "one\n", false).is_err());
    }

    /// Every test or tool that regenerates under a variable (`CAKEYS_UPDATE_*`,
    /// `CAKEYS_WRITE_*`) writes through [`write`]: a writer of its own would overwrite again
    /// (review 2026-11-24 C-8; the four writers before this rule each rewrote in place).
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
