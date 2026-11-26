//! Reading and writing `keys.lock` on disk: writes of whole files, the advisory lock for updates,
//! and the places where a lock cannot be written (a Nix build, a read-only store).

use super::{LOCK_VERSION, Lock};
use crate::error::{KmError, Result};
use std::path::{Path, PathBuf};

/// # Errors
///
/// Returns `Io` if the file exists but cannot be read, and `Validation` if it is not a valid lock
/// of the current schema. A missing file is an empty lock, not an error.
pub fn load_lock(path: &Path) -> Result<Lock> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_lock(&text, path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Lock { version: LOCK_VERSION, ..Default::default() }),
        Err(e) => Err(KmError::io(format!("reading {}", path.display()))(e)),
    }
}

/// Works as [`load_lock`] on text that was already read. `path` is used only to name the file in
/// messages.
///
/// # Errors
///
/// Returns `Validation` if the text is not a valid lock of the current schema.
pub fn parse_lock(text: &str, path: &Path) -> Result<Lock> {
    let mut lock: Lock =
        toml::from_str(text).map_err(|e| KmError::Validation(format!("{}: {e}", path.display()).into()))?;
    // The recorded types are canonicalized, so that they compare equal to the canonicalized types
    // of keys.toml.
    for t in lock.objects.values_mut().filter_map(|o| o.object_type.as_mut()) {
        t.canonicalize();
    }
    // The recorded locators are canonicalized too, so that a lock written before the locators of
    // keys.toml were converted to lower case still matches.
    for (spec, on) in &mut lock.realisations {
        for (token, r) in on {
            r.locator.canonicalize().map_err(|e| {
                KmError::Validation(format!("{}: realisation '{spec}' on '{token}': {e}", path.display()).into())
            })?;
        }
    }
    lock.check(path)?;
    Ok(lock)
}

/// Writes the lock through a temporary file, which is synced before it is renamed over the old
/// file, and then syncs the directory. So a crash leaves either the old lock or the new lock, and
/// never a truncated lock. A lock that would not load again is refused, and the old file is kept.
///
/// # Errors
///
/// Returns `LockUnwritable` (21) if the lock breaks a load rule (then nothing is written), or if
/// the temporary write, the sync or the rename fails. Returns `Io` if the lock cannot be encoded.
pub fn save_lock(path: &Path, lock: &Lock) -> Result<()> {
    // The lock is checked here also when the save follows a token write. A lock that fails the
    // check is not written, and the error is `LockUnwritable` (21), whichever check refused it,
    // because the token may now hold an object that the lock does not record (review 2026-11-23
    // A-17).
    lock.check(path)
        .map_err(|e| KmError::LockUnwritable(format!("not writing a lock that would not load: {e}").into()))?;
    let text =
        toml::to_string_pretty(lock).map_err(|e| KmError::Io(format!("encoding {}: {e}", path.display()).into()))?;
    // A new lock is created like any new file (0666 under the umask). A lock that exists keeps its
    // mode, and it keeps its owner and group where this user may set them (review 2026-11-23
    // A-4).
    write_file(path, text.as_bytes(), 0o666, true).map_err(|e| match e {
        KmError::Io(m) => KmError::LockUnwritable(m),
        other => other,
    })
}

/// Writes `bytes` to `path` completely or not at all, in the way that [`save_lock`] writes the
/// lock. The function creates a temporary file with a unique name in the same directory, with
/// `mode` under the umask (0600 for a key file). It syncs the file, renames it into place, and
/// syncs the directory. Every tool writes its files with this function.
///
/// # Errors
///
/// Returns `Io` if the temporary write, the sync or the rename fails.
pub fn write_whole(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    write_file(path, bytes, mode, false)
}

/// Works as [`write_whole`]. With `keep`, the new file gets exactly the permission bits of the
/// file that is already at `path` (not under the umask), and also its owner and group as far as
/// this user may set them. So a 0600 lock stays 0600, and a lock that a group shares stays shared
/// with that group.
fn write_file(path: &Path, bytes: &[u8], mode: u32, keep: bool) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    // Follow a symlink to the file that it names. Otherwise, the rename would replace the
    // symlink.
    let path = &resolved(path);
    let dir = lock_dir(path);
    // The temporary file is in the target's directory, so that it is on the same filesystem for
    // the rename. It is removed if this run fails before the rename.
    let mut tmp = tempfile::Builder::new()
        .prefix(".cakeys.")
        .permissions(std::fs::Permissions::from_mode(mode))
        .tempfile_in(dir)
        .map_err(KmError::io(format!("creating a temporary file in {}", dir.display())))?;
    if keep && let Ok(old) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt as _;
        // This is a best effort, and it sets the owner before the mode, because a chown may clear
        // bits that the mode then sets. Only root can give a file to another user, and a user can
        // give a file only to a group that the user is in. An owner or a group that cannot be
        // kept becomes the writer's, as for a new file.
        let file = tmp.as_file();
        if std::os::unix::fs::fchown(file, Some(old.uid()), Some(old.gid())).is_err() {
            let _ = std::os::unix::fs::fchown(file, None, Some(old.gid()));
        }
        file.set_permissions(std::fs::Permissions::from_mode(old.mode() & 0o777))
            .map_err(KmError::io(format!("setting the mode of {}", tmp.path().display())))?;
    }
    tmp.write_all(bytes)
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(KmError::io(format!("writing {}", tmp.path().display())))?;
    tmp.persist(path).map_err(|e| KmError::Io(format!("renaming over {}: {}", path.display(), e.error).into()))?;
    // The rename itself is durable only after the directory is synced.
    std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(KmError::io(format!("syncing {}", dir.display())))
}

/// Returns the directory of a lock file: its parent, or the working directory for a file name
/// without a directory.
pub(super) fn lock_dir(path: &Path) -> &Path {
    path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// Returns the file that `path` names, however it is named (through a symlink or with `..`). A
/// file that does not exist yet is resolved through its directory, and a path that does not
/// resolve is returned as given. Writing, checking and guarding a lock all use this file. So a
/// lock behind a symlink is written through the symlink and never replaced by a copy, and two
/// names for the same lock share one guard (review D2, config.rs F7).
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .or_else(|_| std::fs::canonicalize(lock_dir(path)).map(|d| d.join(path.file_name().unwrap_or_default())))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The advisory lock that is held while a run reads, changes and writes the lock file (finding
/// M3). A run that may update the lock takes it before `load_lock` and releases it after
/// `save_lock`, so two concurrent runs on different tokens cannot lose each other's realisations.
/// Readers never take it, because the rename of the temporary file makes each read a consistent
/// snapshot.
pub struct UpdateGuard(
    #[expect(dead_code, reason = "held, never read: the lock is released when it drops")] std::fs::File,
);

/// Takes the exclusive advisory lock on `<lock>.lck`, and waits for any other run that updates
/// the lock. When another run holds the lock, the function first calls `waiting` with the path of
/// the sidecar file, so that the run can say why it stopped. The sidecar file is created if it
/// does not exist. A leftover sidecar file does no harm, because the lock is advisory and is
/// released when its holder exits. An existing sidecar file is opened read-only, because `flock`
/// needs no write access. So a sidecar file that another user left (0644 under that user's umask)
/// never refuses a run that [`lock_unwritable`] allowed (review 2026-11-23 A-12).
///
/// # Errors
///
/// Returns `Io` if the sidecar file cannot be opened or the advisory lock cannot be taken.
pub fn lock_for_update(lock_path: &Path, waiting: impl FnOnce(&Path)) -> Result<UpdateGuard> {
    // The sidecar file of the resolved lock file, however the run names the lock ([`resolved`]).
    let mut sidecar = resolved(lock_path).into_os_string();
    sidecar.push(".lck");
    let file = match std::fs::File::open(&sidecar) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::File::options().write(true).create(true).truncate(false).open(&sidecar)
        }
        opened => opened,
    }
    .map_err(KmError::io(format!("opening {}", sidecar.to_string_lossy())))?;
    let locking = || KmError::io(format!("locking {}", sidecar.to_string_lossy()));
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            waiting(Path::new(&sidecar));
            file.lock().map_err(locking())?;
        }
        Err(std::fs::TryLockError::Error(e)) => return Err(locking()(e)),
    }
    Ok(UpdateGuard(file))
}

/// Returns why this run cannot write the lock at `lock_path`, or `None` if it can. A run that
/// writes the lock by default (`lock`, `delete`) asks this before it touches a token. So an
/// unwritable lock is refused before the run starts, unless `--no-update-lock` was passed, and a
/// key is never created and then not recorded.
/// - Inside a Nix build sandbox (`NIX_BUILD_TOP` is set and `IN_NIX_SHELL` is not; `nix develop`
///   sets both), a write is lost, because the lock is a read-only store path or a copy that is
///   discarded with the build.
/// - Otherwise, this user must be able to write the lock file, if it exists, and its directory
///   (for the temporary file, the rename and the `.lck` sidecar file). The check uses
///   `access(2)`, so a read-only mount also counts as unwritable.
#[must_use]
pub fn lock_unwritable(lock_path: &Path) -> Option<String> {
    unwritable(lock_path, in_nix_build())
}

/// Returns whether the run is inside a Nix build sandbox: `NIX_BUILD_TOP` is set and
/// `IN_NIX_SHELL` is not (`nix develop` sets both), and [`ALLOW_NIX_STORE_KEYS`] is not set. In a
/// sandbox, a write of the lock is lost, and an admin operation (docs/CAMIGRATE.md D8) is
/// refused.
#[must_use]
pub fn in_nix_build() -> bool {
    std::env::var_os("NIX_BUILD_TOP").is_some()
        && std::env::var_os("IN_NIX_SHELL").is_none()
        && !nix_store_keys_allowed()
}

/// The environment variable `CAKEYS_ALLOW_NIX_STORE_KEYS`. Set it to `1` for disposable keys that
/// a Nix build makes and uses (a test or a VM image), and never for the keys of a deployment. A
/// secret file (`pinFile`, `soCredentialFile`, a secret `migrate.file`, `migrate.passphraseFile`)
/// may then be under `/nix/store`, and no run counts as inside a Nix build sandbox
/// ([`in_nix_build`]). A run then does what a sandboxed run would have refused, and a lock that
/// it writes is lost with the build unless the build keeps it.
pub const ALLOW_NIX_STORE_KEYS: &str = "CAKEYS_ALLOW_NIX_STORE_KEYS";

/// Whether [`ALLOW_NIX_STORE_KEYS`] is set to `1`.
pub(crate) fn nix_store_keys_allowed() -> bool {
    std::env::var_os(ALLOW_NIX_STORE_KEYS).is_some_and(|v| v == "1")
}

/// The Nix store, which anyone on the host can read.
const NIX_STORE: &str = "/nix/store";

/// Returns why `what`, a file that holds a secret, may not be read from `path`, or `None` if it
/// may. The file may not be read when `path` resolves into the Nix store, which everyone can read,
/// and [`ALLOW_NIX_STORE_KEYS`] is not set. Every secret file that keys.toml names gets this
/// check, at load and again when the file is read.
pub(crate) fn secret_in_store(what: &dyn std::fmt::Display, path: &Path) -> Option<String> {
    (!nix_store_keys_allowed() && resolves_under(path, Path::new(NIX_STORE))).then(|| {
        format!(
            "{what} {} is in the Nix store, which anyone on the host can read; keep secret material out of it \
             ({ALLOW_NIX_STORE_KEYS}=1 allows it, for throwaway keys only)",
            path.display()
        )
    })
}

/// Returns whether `path` is `root` or is under it, after both are resolved. The resolution
/// follows symlinks (`./result/k.pem`, `/run/current-system/sw/…`) and applies `..`, and the
/// comparison is component by component, never by a string prefix. For a path that does not
/// exist (yet), the existing part is resolved and the rest is taken as written. A relative path
/// is relative to the working directory, as it would be for a read.
pub(crate) fn resolves_under(path: &Path, root: &Path) -> bool {
    resolve(path).starts_with(resolve(root))
}

/// Returns `path` as an absolute path. Its longest existing prefix is canonicalized, and the
/// remaining components are applied as text (a `..` removes the last component), without access
/// to the filesystem.
fn resolve(path: &Path) -> PathBuf {
    use std::path::Component;
    let path = std::env::current_dir().map_or_else(|_| path.to_owned(), |cwd| cwd.join(path));
    let parts: Vec<Component> = path.components().collect();
    for exists in (0..=parts.len()).rev() {
        let Ok(mut out) = std::fs::canonicalize(parts[..exists].iter().collect::<PathBuf>()) else { continue };
        for part in &parts[exists..] {
            match part {
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(name) => out.push(name),
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        return out;
    }
    path
}

/// Works as [`lock_unwritable`], with the caller saying whether this run is inside a Nix build
/// sandbox.
pub(super) fn unwritable(lock_path: &Path, sandboxed: bool) -> Option<String> {
    let writable = |p: &Path| rustix::fs::access(p, rustix::fs::Access::WRITE_OK).is_ok();
    if sandboxed {
        return Some(format!(
            "this run is inside a Nix build sandbox, where a lock write would be lost ({ALLOW_NIX_STORE_KEYS}=1 runs \
             it as outside, for throwaway keys only)"
        ));
    }
    // The file to which a write would go: a symlink's target, in the target's directory.
    let lock_path = &resolved(lock_path);
    if lock_path.exists() && !writable(lock_path) {
        return Some(format!("{} is not writable", lock_path.display()));
    }
    let dir = lock_dir(lock_path);
    if !writable(dir) {
        return Some(format!("the lock's directory {} is not writable", dir.display()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lock::tests::attestable_lock;
    use crate::config::*;

    /// A lock that cannot be saved is `LockUnwritable` (21), whatever stage of the write failed.
    /// A run that changed the token must report that its record is missing, and must not exit
    /// with 1 like any other I/O error.
    #[test]
    fn a_lock_that_cannot_be_saved_is_its_own_code() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let refused = |path: &Path| {
            let e = save_lock(path, &attestable_lock()).unwrap_err();
            assert_eq!(e.exit_code(), 21, "{e}");
            assert!(e.to_string().contains("lock cannot be written"), "{e}");
        };
        // A parent that is a file is refused for root too, so the test never passes without
        // testing anything (review 2026-11-23 A-16).
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        refused(&file.join("keys.lock"));
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        // A read-only directory, tested only where the permission applies (root can write
        // anyway).
        if std::fs::File::create(ro.join("probe")).is_err() {
            refused(&ro.join("keys.lock"));
        }
    }

    /// A lock behind a symlink (a NixOS layout, with the lock in a checked-out repository) is
    /// written through to its target, and never replaced by a copy that the repository never sees
    /// (config.rs F7).
    #[test]
    fn a_symlinked_lock_is_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let (real, link) = (dir.path().join("repo.lock"), dir.path().join("keys.lock"));
        save_lock(&real, &Lock { version: LOCK_VERSION, ..Default::default() }).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        save_lock(&link, &attestable_lock()).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the link was replaced");
        let text = |p: &Path| std::fs::read_to_string(p).unwrap();
        assert_eq!(text(&real), toml::to_string_pretty(&attestable_lock()).unwrap(), "the target was not written");
        assert_eq!(unwritable(&link, false), None);
    }

    /// A missing lock is an empty lock of the current version. What is saved loads back unchanged,
    /// and no temporary file is left next to it. A file name without a directory is in the
    /// working directory.
    #[test]
    fn a_lock_saves_and_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        let empty = load_lock(&path).unwrap();
        assert_eq!((empty.version, empty.objects.len()), (LOCK_VERSION, 0));
        let mut lock =
            load_lock(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/keys.lock"))).unwrap();
        lock.objects.retain(|name, _| lock.realisations.values().any(|r| r.values().any(|r| r.object == *name)));
        save_lock(&path, &lock).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, toml::to_string_pretty(&load_lock(&path).unwrap()).unwrap());
        assert_eq!(load_lock(&path).unwrap().realisations.len(), lock.realisations.len());
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["keys.lock"]);
        assert_eq!(lock_dir(Path::new("keys.lock")), Path::new("."));
        assert_eq!(lock_dir(&path), dir.path());
    }

    /// A lock that exists keeps exactly its mode across a save, whatever the umask is. A 0600 lock
    /// stays private, and a group's 0660 lock stays shared with the group. A key file never gets
    /// wider permissions from the file that it replaces. A sidecar file that this user cannot
    /// write (another user's, left at 0644) still guards the update, because `flock` needs no
    /// write access (review 2026-11-23 A-4, A-12).
    #[test]
    fn a_saved_lock_keeps_its_mode_and_a_read_only_sidecar_guards() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let set = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        save_lock(&path, &attestable_lock()).unwrap();
        for kept in [0o600, 0o660, 0o640] {
            set(&path, kept);
            save_lock(&path, &attestable_lock()).unwrap();
            assert_eq!(mode(&path), kept, "a save reset the lock's mode");
        }
        let key = dir.path().join("k.pem");
        std::fs::write(&key, "old").unwrap();
        set(&key, 0o644);
        write_whole(&key, b"new", 0o600).unwrap();
        assert_eq!(mode(&key), 0o600, "a key file took the mode of what it replaced");
        let sidecar = dir.path().join("keys.lock.lck");
        std::fs::write(&sidecar, "").unwrap();
        set(&sidecar, 0o444);
        let guard = lock_for_update(&path, |_| unreachable!("nothing else holds it")).unwrap();
        drop(guard);
    }

    /// The reasons why a lock cannot be written: inside a Nix build sandbox, or a lock file or a
    /// directory that this user cannot write. There is no reason when both can be written,
    /// including when the lock does not exist yet.
    #[test]
    fn an_unwritable_lock_says_why() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        // A message names the resolved path (on macOS, /tmp is /private/tmp).
        let real = dir.path().canonicalize().unwrap();
        assert_eq!(unwritable(&path, false), None);
        let sandboxed = unwritable(&path, true).unwrap();
        assert!(sandboxed.contains("inside a Nix build sandbox"), "{sandboxed}");
        std::fs::write(&path, "version = 1\n").unwrap();
        assert_eq!(unwritable(&path, false), None);
        let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        mode(&path, 0o444);
        // access(2) grants every write to root, so the permission cases test nothing when the test
        // runs as root. The test then skips, and a run that requires every test
        // (`CAKEYS_REQUIRE_ALL`) fails instead. Earlier, the test returned here without a message.
        if rustix::fs::access(&path, rustix::fs::Access::WRITE_OK).is_ok() {
            let why = "the permission cases: this user writes a mode-444 file";
            crate::test_skip::skip("an_unwritable_lock_says_why", crate::test_skip::REQUIRE_ALL, why);
            return;
        }
        assert_eq!(unwritable(&path, false), Some(format!("{} is not writable", real.join("keys.lock").display())));
        mode(&path, 0o644);
        mode(dir.path(), 0o555);
        let said = unwritable(&path, false);
        mode(dir.path(), 0o755);
        assert_eq!(said, Some(format!("the lock's directory {} is not writable", real.display())));
        // A lock that does not exist yet, in a directory that cannot be written.
        std::fs::remove_file(&path).unwrap();
        mode(dir.path(), 0o555);
        let said = unwritable(&path, false);
        mode(dir.path(), 0o755);
        assert!(said.is_some_and(|s| s.contains("directory")));
    }

    /// The store guard compares resolved paths component by component. It tells apart a link into
    /// the root, a `..` out of it, and a sibling whose name only starts with the same characters,
    /// whether these paths exist or not.
    #[test]
    fn paths_resolve_before_they_compare() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(dir.path().join("store-not")).unwrap();
        std::os::unix::fs::symlink(&root, dir.path().join("link")).unwrap();
        let under = |p: &str| resolves_under(&dir.path().join(p), &root);
        assert!(under("store/a"));
        assert!(under("link/a/b"), "through a link, to a file that does not exist");
        assert!(under("store-not/../store/a"));
        assert!(!under("store-not/a"), "a string prefix is no parent");
        assert!(!under("store/../a"));
        assert!(!under("link/../a"), "the link's target's parent, not the link's");
        assert!(!under("elsewhere/a"));
    }
}
