//! The loaded PKCS#11 libraries and what `C_GetInfo` reports about each of them (review
//! 2026-11-23 B-5). The process loads one library per module path, and every token of the process
//! shares it.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// An initialized module library. Every `Token` of the module that is open at the same time
/// shares it, and it is finalized when the last of them is dropped, because cryptoki 0.12 never
/// finalizes. Without this, a module library may stay loaded after its last handle is gone
/// (`SoftHSM` does this), and another of its tokens that the process opens later would then fail
/// `C_Initialize` with `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
///
/// After it is finalized, the module stays mapped until the process exits. A module's own threads
/// may still be stopping when `C_Finalize` returns, and unloading the module while they run
/// crashes the process after its work is done (libkmsp11's gRPC threads \[run\] did this in about
/// one run in twenty, with exit code 139 instead of the run's own code). Opening the module again
/// maps the same library and initializes it again.
///
/// The second field is the library's key in [`LIBRARIES`]. The third field holds, for each slot,
/// the user PIN with which a token of this process logged in.
pub(super) struct Library(pub(super) Pkcs11, pub(super) String, pub(super) Logins);

/// For each slot, the user PIN with which a `Token` of this process logged in. When the module
/// answers "already logged in" at open, the configured PIN is checked against this record,
/// because that answer validates no PIN by itself (review 2026-11-23 B-12). The login state
/// belongs to the process (PKCS #11 §5.6), so no other program can have logged in.
pub(super) type Logins = std::sync::Mutex<BTreeMap<u64, Zeroizing<String>>>;

impl Drop for Library {
    /// Finalizes the library while the registry lock is held, and then removes its entry. Until
    /// the entry is removed, a call to [`library()`] for the module on another thread waits
    /// ([`settled`]). Without the wait, that thread could initialize the module again before this
    /// `C_Finalize`, which the module refuses with `CKR_CRYPTOKI_ALREADY_INITIALIZED`, or this
    /// `C_Finalize` could tear down the library that the other thread just initialized
    /// (token/mod.rs F5). No `Library` is dropped while the lock is held (`library` only
    /// upgrades, waits and inserts), so this cannot deadlock.
    fn drop(&mut self) {
        let mut open = LIBRARIES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = self.0.clone().finalize();
        std::mem::forget(self.0.clone());
        if open.get(&self.1).is_some_and(|w| w.strong_count() == 0) {
            open.remove(&self.1);
        }
        FINALIZED.notify_all();
    }
}

/// The registry of initialized libraries. It maps each key to the library that a token holds.
pub(super) type Libraries<T> = BTreeMap<String, std::sync::Weak<T>>;

/// The libraries that this process initialized, by module path. When another open token has
/// already initialized a token's module (for example, the two sides of a move between tokens of
/// one module), the token shares that library instead of initializing it a second time.
pub(super) static LIBRARIES: std::sync::Mutex<Libraries<Library>> = std::sync::Mutex::new(BTreeMap::new());

/// Signalled when a finalized library's entry is removed from [`LIBRARIES`].
pub(super) static FINALIZED: std::sync::Condvar = std::sync::Condvar::new();

/// Returns the library under `key` that a token still holds, or `None` when there is none. When
/// the last holder of the library is finalizing it, the function waits until `finalized` signals
/// the removal of the entry, because the module can be initialized again only after that.
pub(super) fn settled<'a, T>(
    mut open: std::sync::MutexGuard<'a, Libraries<T>>,
    finalized: &std::sync::Condvar,
    key: &str,
) -> (std::sync::MutexGuard<'a, Libraries<T>>, Option<Arc<T>>) {
    loop {
        match open.get(key).map(std::sync::Weak::upgrade) {
            Some(Some(live)) => return (open, Some(live)),
            Some(None) => open = finalized.wait(open).unwrap_or_else(std::sync::PoisonError::into_inner),
            None => return (open, None),
        }
    }
}

/// Returns the initialized library of `module`. That is the library that an open token holds,
/// or otherwise a library that is newly loaded and initialized.
pub(super) fn library(module: &str) -> Result<Arc<Library>> {
    // The key is the file that a path names, as the loader maps it. Two spellings of one module
    // (relative and absolute, or a symlink) are one library, and a second `C_Initialize` on it
    // would be refused. A bare name is left to the loader's own search, and it stays as written.
    let key = module
        .contains('/')
        .then(|| std::fs::canonicalize(module).ok()?.into_os_string().into_string().ok())
        .flatten()
        .unwrap_or_else(|| module.to_owned());
    let open = LIBRARIES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (open, found) = settled(open, &FINALIZED, &key);
    if let Some(library) = found {
        return Ok(library);
    }
    let ctx = Pkcs11::new(module).map_err(ck(&format!("loading {module}")))?;
    // After the load, look the library up again by the file that the loader mapped, so that a
    // bare name and a path to that file are also one library (token/mod.rs F3). When the library
    // is found open, `ctx` is dropped without being initialized, and it releases only its loader
    // reference.
    let key = loaded_path(module).unwrap_or(key);
    let (mut open, found) = settled(open, &FINALIZED, &key);
    if let Some(library) = found {
        return Ok(library);
    }
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map_err(ck("C_Initialize"))?;
    let library = Arc::new(Library(ctx, key.clone(), Logins::default()));
    open.insert(key, Arc::downgrade(&library));
    Ok(library)
}

/// Returns the text of a fixed-width `CK_INFO` or `CK_TOKEN_INFO` field. The function drops the
/// padding (blanks, as the specification says, and NULs, which some modules use), and it turns a
/// run of NULs inside the text into one blank. For example, tpm2-pkcs11 fills the token's model
/// from the TPM's four 4-byte vendor strings, so swtpm reports `SW   TPM` and eight NULs \[run\].
/// This is the only spelling of these fields. The open reads it, the lock records it, and caprobe
/// writes it as a profile's match keys, which resolution compares with what the open read.
#[must_use]
pub fn unpadded(field: &str) -> String {
    field.split('\0').filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ").trim().to_owned()
}

/// Returns what a module reports about itself (`C_GetInfo`), and the file that the loader mapped
/// for `module` with its hash. The lock records this as the module's provenance.
///
/// From this point on, the manufacturer and the description are compared exactly as they are
/// returned here: every provider's `matches` and the profiles' `[match]` compare them exactly
/// (review 2026-11-23 B-26).
pub(super) fn module_info(ctx: &Pkcs11, module: String) -> Result<ModuleInfo> {
    let lib = ctx.get_library_info().map_err(ck("C_GetInfo"))?;
    let path = loaded_path(&module).unwrap_or(module);
    Ok(ModuleInfo {
        hash: std::fs::read(&path).ok().map(|bytes| id::sri(&bytes)),
        path,
        description: unpadded(lib.library_description()),
        manufacturer: unpadded(lib.manufacturer_id()),
        version: lib.library_version().to_string(),
        cryptoki: lib.cryptoki_version().to_string(),
    })
}

/// Returns the file that the dynamic loader mapped for `module`, with symlinks resolved. The lock
/// records this file as provenance, whether `module` is a bare file name (found by the loader's
/// library search), a `/run/current-system` symlink or a store path. The function asks the loader
/// itself (`dladdr` on the module's `C_GetFunctionList`), so the result is the file whose code
/// runs. Returns `None` when the loader cannot tell.
#[expect(unsafe_code, reason = "dlopen(RTLD_NOLOAD)/dlsym/dladdr only look up the loaded module")]
pub(super) fn loaded_path(module: &str) -> Option<String> {
    let name = std::ffi::CString::new(module).ok()?;
    // SAFETY: `name` is a valid NUL-terminated string. With RTLD_NOLOAD, `dlopen` returns the
    // library that `Pkcs11::new` already loaded and adds a reference to it, which is released
    // below. It never loads or initializes anything.
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: `handle` is a live handle, and the symbol name is NUL-terminated. The address is
    // only looked up, and it is never called.
    let symbol = unsafe { libc::dlsym(handle, c"C_GetFunctionList".as_ptr()) };
    // SAFETY: an all-zero `Dl_info` is valid, because all its pointers are null. `dladdr` fills
    // it for `symbol`.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: the same reasons as above apply. `dli_fname` is a NUL-terminated string that the
    // loader owns, and it is copied out before the handle is released. The module also stays
    // loaded through cryptoki's handle.
    let file = (!symbol.is_null() && unsafe { libc::dladdr(symbol, &raw mut info) } != 0 && !info.dli_fname.is_null())
        .then(|| unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned());
    // SAFETY: releases only the reference taken above.
    unsafe { libc::dlclose(handle) };
    std::fs::canonicalize(file?).ok()?.into_os_string().into_string().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed-width fields of `C_GetInfo` and `C_GetTokenInfo` have one normalization, so
    /// that every provider and every match key compares them exactly (review 2026-11-23 B-26).
    #[test]
    fn info_fields_lose_blank_and_nul_padding() {
        assert_eq!(unpadded("Google\0\0\0"), "Google");
        assert_eq!(unpadded("CloudHSM      \0 "), "CloudHSM");
        assert_eq!(unpadded("Yubico (www.yubico.com)"), "Yubico (www.yubico.com)");
        assert_eq!(unpadded("SW   TPM\0\0\0\0\0\0\0\0"), "SW   TPM");
        assert_eq!(unpadded("AMD\0\0\0\0"), "AMD");
        assert_eq!(unpadded("A\0\0B"), "A B");
        assert_eq!(unpadded("2.7\0\0"), "2.7");
    }

    /// A lookup that finds a library whose last holder is finalizing it waits until its entry is
    /// removed (token/mod.rs F5), so the module is initialized again only after that
    /// `C_Finalize`. A library that is still held is shared, and a missing entry returns `None`.
    #[test]
    fn a_library_being_finalized_is_waited_for() {
        let open = Arc::new(std::sync::Mutex::new(Libraries::<u8>::new()));
        let finalized = Arc::new(std::sync::Condvar::new());
        let held = Arc::new(7);
        let dying = Arc::new(8);
        open.lock().unwrap().insert("held".into(), Arc::downgrade(&held));
        open.lock().unwrap().insert("dying".into(), Arc::downgrade(&dying));
        assert_eq!(settled(open.lock().unwrap(), &finalized, "held").1.as_deref(), Some(&7));
        assert!(settled(open.lock().unwrap(), &finalized, "none").1.is_none());
        // The last holder is gone, but its finalize is not done, so the lookup waits for the
        // removal.
        drop(dying);
        let removed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lookup = {
            let (open, finalized, removed) = (Arc::clone(&open), Arc::clone(&finalized), Arc::clone(&removed));
            std::thread::spawn(move || {
                let (_open, found) = settled(open.lock().unwrap(), &finalized, "dying");
                (found.is_none(), removed.load(std::sync::atomic::Ordering::SeqCst))
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        {
            let mut libraries = open.lock().unwrap();
            removed.store(true, std::sync::atomic::Ordering::SeqCst);
            libraries.remove("dying");
            finalized.notify_all();
        }
        assert_eq!(lookup.join().unwrap(), (true, true), "returned before the finalize was done");
    }
}
