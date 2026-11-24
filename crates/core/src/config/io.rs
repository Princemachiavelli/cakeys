//! Reading and writing `keys.lock` on disk: whole-file writes, the update lock, and where a
//! lock cannot be written (a Nix build, a read-only store).

use super::{LOCK_VERSION, Lock};
use crate::error::{KmError, Result};
use std::path::{Path, PathBuf};

/// # Errors
///
/// `Io` if the file exists but cannot be read; `Validation` if it is not a valid lock of the
/// current schema. An absent file is an empty lock, not an error.
pub fn load_lock(path: &Path) -> Result<Lock> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_lock(&text, path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Lock { version: LOCK_VERSION, ..Default::default() }),
        Err(e) => Err(KmError::io(format!("reading {}", path.display()))(e)),
    }
}

/// [`load_lock`] on text already read; `path` only names it in messages.
///
/// # Errors
///
/// `Validation` if it is not a valid lock of the current schema.
pub fn parse_lock(text: &str, path: &Path) -> Result<Lock> {
    let mut lock: Lock =
        toml::from_str(text).map_err(|e| KmError::Validation(format!("{}: {e}", path.display()).into()))?;
    // Recorded types compare equal to canonicalized keys.toml types.
    for t in lock.objects.values_mut().filter_map(|o| o.object_type.as_mut()) {
        t.canonicalize();
    }
    // Recorded locators too: a lock written before keys.toml's were lower-cased still matches.
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

/// Write the lock through a temporary file synced before it is renamed over the old one (and the
/// directory synced after), so a
/// crash leaves the old lock or the new one, never a truncated one. A lock that would not load
/// again is refused, the old one kept.
///
/// # Errors
///
/// `LockUnwritable` (21) if the lock breaks a load rule (nothing is written), or if the temporary
/// write, sync or rename fails; `Io` if the lock cannot be encoded.
pub fn save_lock(path: &Path, lock: &Lock) -> Result<()> {
    // Saved after a token write as any other time: the token may hold what the lock does not
    // record, whichever check stopped the write (review 2026-11-23 A-17).
    lock.check(path)
        .map_err(|e| KmError::LockUnwritable(format!("not writing a lock that would not load: {e}").into()))?;
    let text =
        toml::to_string_pretty(lock).map_err(|e| KmError::Io(format!("encoding {}: {e}", path.display()).into()))?;
    // A new lock is created like any new file (0666 under the umask); one that exists keeps its
    // mode, and its owner and group where this user may set them (review 2026-11-23 A-4).
    write_file(path, text.as_bytes(), 0o666, true).map_err(|e| match e {
        KmError::Io(m) => KmError::LockUnwritable(m),
        other => other,
    })
}

/// Write `bytes` to `path` whole or not at all, as [`save_lock`] writes the lock: a uniquely
/// named temporary file beside it, created with `mode` under the umask (0600 for a key file),
/// synced, renamed into place, and the directory synced. What every tool writes a file with.
///
/// # Errors
///
/// `Io` if the temporary write, sync or rename fails.
pub fn write_whole(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    write_file(path, bytes, mode, false)
}

/// [`write_whole`]; with `keep`, a file already at `path` passes its permission bits to the new
/// one exactly (not under the umask), and its owner and group as far as this user may set them:
/// a 0600 lock stays 0600, and a lock a group shares stays the group's.
fn write_file(path: &Path, bytes: &[u8], mode: u32, keep: bool) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    // Through a symlink to the file it names, which the rename would otherwise replace.
    let path = &resolved(path);
    let dir = lock_dir(path);
    // Beside the target (the same filesystem, for the rename), removed if this run fails before
    // the rename.
    let mut tmp = tempfile::Builder::new()
        .prefix(".cakeys.")
        .permissions(std::fs::Permissions::from_mode(mode))
        .tempfile_in(dir)
        .map_err(KmError::io(format!("creating a temporary file in {}", dir.display())))?;
    if keep && let Ok(old) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt as _;
        // Best effort, owner before mode (a chown may clear bits the mode then sets): only root
        // gives a file another user, and a user gives it only a group it is in. What cannot be
        // kept is the writer's, as for a new file.
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
    // The rename itself is durable once the directory is synced.
    std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(KmError::io(format!("syncing {}", dir.display())))
}

/// The directory a lock file lives in: its parent, or the working directory for a bare name.
pub(super) fn lock_dir(path: &Path) -> &Path {
    path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// The file `path` names, however it is named (a symlink, `..`): a file not yet written resolves
/// through its directory, and one that does not resolve stays as given. Writing, checking and
/// guarding a lock all go to this file, so a symlinked lock is written through, never replaced
/// by a copy, and two names for it share one guard (review D2, config.rs F7).
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .or_else(|_| std::fs::canonicalize(lock_dir(path)).map(|d| d.join(path.file_name().unwrap_or_default())))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The advisory lock held around the lock file's read-modify-write (finding M3). A run that may
/// update the lock takes it before `load_lock` and drops it after `save_lock`, so two concurrent
/// runs on different tokens cannot lose each other's realisations. Readers never take it: the
/// temporary-file rename makes each read a consistent snapshot.
pub struct UpdateGuard(
    #[expect(dead_code, reason = "held, never read: the lock is released when it drops")] std::fs::File,
);

/// Take the exclusive advisory lock on `<lock>.lck`, waiting for any other updater; `waiting` is
/// told the sidecar's path first when another holds it, so a run can say why it stopped. The
/// sidecar file is created if absent; a leftover one is harmless (the lock is advisory and
/// released when its holder exits). One that exists is opened read-only, since `flock` needs no
/// write access: a sidecar another user left (0644 under their umask) never refuses a run that
/// [`lock_unwritable`] let through (review 2026-11-23 A-12).
///
/// # Errors
///
/// `Io` if the sidecar file cannot be opened or the advisory lock cannot be taken.
pub fn lock_for_update(lock_path: &Path, waiting: impl FnOnce(&Path)) -> Result<UpdateGuard> {
    // The lock file's own sidecar, however the run names it ([`resolved`]).
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

/// Why this run cannot write the lock at `lock_path`, if it cannot. A run that writes by default
/// (`lock`, `delete`) asks before it touches a token, so an unwritable lock is a refusal up
/// front — never a key created and then not recorded — unless `--no-update-lock` was passed.
/// - Inside a Nix build sandbox (`NIX_BUILD_TOP` set, `IN_NIX_SHELL` not: `nix develop` sets
///   both) a write is lost: the lock is a read-only store path, or a copy thrown away with the
///   build.
/// - Otherwise the lock file, if present, and its directory (temporary file, rename and the
///   `.lck` sidecar) must be writable by this user (`access(2)`, so a read-only mount counts).
#[must_use]
pub fn lock_unwritable(lock_path: &Path) -> Option<String> {
    unwritable(lock_path, in_nix_build())
}

/// Inside a Nix build sandbox: `NIX_BUILD_TOP` set and `IN_NIX_SHELL` not (`nix develop` sets
/// both), and [`ALLOW_NIX_STORE_KEYS`] not set. Where a lock write is lost, and an admin
/// operation (docs/CAMIGRATE.md D8) refused.
#[must_use]
pub fn in_nix_build() -> bool {
    std::env::var_os("NIX_BUILD_TOP").is_some()
        && std::env::var_os("IN_NIX_SHELL").is_none()
        && !nix_store_keys_allowed()
}

/// `CAKEYS_ALLOW_NIX_STORE_KEYS=1`: for throwaway keys a Nix build makes and uses (a test, a VM
/// image), never a deployment's. A secret file (`pinFile`, `soCredentialFile`, a secret
/// `migrate.file`, `migrate.passphraseFile`) may then be under `/nix/store`, and no run counts as
/// inside a Nix build sandbox ([`in_nix_build`]): what a sandboxed run would have refused, it
/// does, and a lock it writes is lost with the build unless the build keeps it.
pub const ALLOW_NIX_STORE_KEYS: &str = "CAKEYS_ALLOW_NIX_STORE_KEYS";

/// Whether [`ALLOW_NIX_STORE_KEYS`] is set to `1`.
pub(crate) fn nix_store_keys_allowed() -> bool {
    std::env::var_os(ALLOW_NIX_STORE_KEYS).is_some_and(|v| v == "1")
}

/// The Nix store, which anyone on the host can read.
const NIX_STORE: &str = "/nix/store";

/// Why `what`, a file holding a secret, may not be read from `path`: it resolves into the
/// world-readable Nix store, and [`ALLOW_NIX_STORE_KEYS`] is not set. Every secret file keys.toml
/// names is held to it, at load and again when it is read.
pub(crate) fn secret_in_store(what: &dyn std::fmt::Display, path: &Path) -> Option<String> {
    (!nix_store_keys_allowed() && resolves_under(path, Path::new(NIX_STORE))).then(|| {
        format!(
            "{what} {} is in the Nix store, which anyone on the host can read; keep secret material out of it \
             ({ALLOW_NIX_STORE_KEYS}=1 allows it, for throwaway keys only)",
            path.display()
        )
    })
}

/// Whether `path` is `root` or under it once both are resolved: symlinks followed
/// (`./result/k.pem`, `/run/current-system/sw/…`) and `..` taken, component by component, never
/// a string prefix. A path that does not exist (yet) is resolved as far as it does, and the rest
/// taken as written; a relative one is relative to the working directory, as a read would be.
pub(crate) fn resolves_under(path: &Path, root: &Path) -> bool {
    resolve(path).starts_with(resolve(root))
}

/// `path` made absolute with its longest existing prefix canonicalized and the rest applied
/// lexically.
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

/// [`lock_unwritable`], with whether this run is inside a Nix build sandbox given.
pub(super) fn unwritable(lock_path: &Path, sandboxed: bool) -> Option<String> {
    let writable = |p: &Path| rustix::fs::access(p, rustix::fs::Access::WRITE_OK).is_ok();
    if sandboxed {
        return Some(format!(
            "this run is inside a Nix build sandbox, where a lock write would be lost ({ALLOW_NIX_STORE_KEYS}=1 runs \
             it as outside, for throwaway keys only)"
        ));
    }
    // The file a write would go to: a symlink's target, in the target's directory.
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

    /// A lock that cannot be saved is `LockUnwritable` (21), whatever stage of the write failed:
    /// a run that changed the token must say its record is missing, not exit 1 like any I/O.
    #[test]
    fn a_lock_that_cannot_be_saved_is_its_own_code() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let refused = |path: &Path| {
            let e = save_lock(path, &attestable_lock()).unwrap_err();
            assert_eq!(e.exit_code(), 21, "{e}");
            assert!(e.to_string().contains("lock cannot be written"), "{e}");
        };
        // A parent that is a file: refused for root too, so the test never passes untried
        // (review 2026-11-23 A-16).
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        refused(&file.join("keys.lock"));
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        // A read-only directory, where the permission holds (root writes anyway).
        if std::fs::File::create(ro.join("probe")).is_err() {
            refused(&ro.join("keys.lock"));
        }
    }

    /// A symlinked lock (a NixOS layout: the lock in a checked-out repository) is written through
    /// to its target, never replaced by a copy the repository never sees (config.rs F7).
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

    /// A missing lock is an empty one of the current version; what is saved is what loads back,
    /// with no temporary file left beside it; a bare file name lives in the working directory.
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

    /// A lock that exists keeps its mode across a save, exactly and whatever the umask: a 0600
    /// lock stays private, a group's 0660 stays the group's. A key file is never widened by the
    /// file it replaces. A sidecar this user cannot write (another user's, left 0644) still
    /// guards the update: `flock` needs no write access (review 2026-11-23 A-4, A-12).
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

    /// Why a lock cannot be written: inside a Nix build sandbox, a lock file or a directory this
    /// user cannot write; nothing when both can be (a lock not there yet included).
    #[test]
    fn an_unwritable_lock_says_why() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        // What a message names: the path resolved (macOS's /tmp is /private/tmp).
        let real = dir.path().canonicalize().unwrap();
        assert_eq!(unwritable(&path, false), None);
        let sandboxed = unwritable(&path, true).unwrap();
        assert!(sandboxed.contains("inside a Nix build sandbox"), "{sandboxed}");
        std::fs::write(&path, "version = 1\n").unwrap();
        assert_eq!(unwritable(&path, false), None);
        let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        mode(&path, 0o444);
        // access(2) grants root every write: the permission cases mean nothing as root.
        if rustix::fs::access(&path, rustix::fs::Access::WRITE_OK).is_ok() {
            return;
        }
        assert_eq!(unwritable(&path, false), Some(format!("{} is not writable", real.join("keys.lock").display())));
        mode(&path, 0o644);
        mode(dir.path(), 0o555);
        let said = unwritable(&path, false);
        mode(dir.path(), 0o755);
        assert_eq!(said, Some(format!("the lock's directory {} is not writable", real.display())));
        // A lock not there yet in a directory that cannot take it.
        std::fs::remove_file(&path).unwrap();
        mode(dir.path(), 0o555);
        let said = unwritable(&path, false);
        mode(dir.path(), 0o755);
        assert!(said.is_some_and(|s| s.contains("directory")));
    }
}
