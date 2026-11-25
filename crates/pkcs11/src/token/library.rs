//! The loaded PKCS#11 libraries, one per module path and shared by every token of the process,
//! and what `C_GetInfo` says of each (review 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// An initialized module library, shared by every `Token` of the module open at once, and
/// finalized when the last of them is dropped (cryptoki 0.12 never finalizes): a module library
/// may stay loaded after its last handle is gone (`SoftHSM` does), and another of its tokens
/// opened later in the process would then fail `C_Initialize` with
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
///
/// Finalized, the module stays mapped until the process exits: a module's own threads may still
/// be winding down when `C_Finalize` returns, and unloading under them crashes the process after
/// its work is done (libkmsp11's gRPC threads \[run\], about one run in twenty, exit 139 in place of
/// the run's own code). Opening the module again maps the same library and initializes it anew.
///
/// The second field is its key in [`LIBRARIES`]; the third, the user PIN each of its slots was
/// logged in with by a token of this process.
pub(super) struct Library(pub(super) Pkcs11, pub(super) String, pub(super) Logins);

/// By slot, the user PIN a `Token` of this process logged in with: what an "already logged in"
/// answer at open is checked against, since it validates no PIN of its own (review 2026-11-23
/// B-12). Login state is per process (PKCS #11 §5.6), so nothing else can have logged in.
pub(super) type Logins = std::sync::Mutex<BTreeMap<u64, Zeroizing<String>>>;

impl Drop for Library {
    /// Finalized under the registry lock, its entry then removed: until it is, another thread's
    /// [`library()`] for the module waits ([`settled`]) rather than initializing it again before
    /// this `C_Finalize` (refused, `CKR_CRYPTOKI_ALREADY_INITIALIZED`) or having it torn down
    /// by this one (token/mod.rs F5). No `Library` is dropped while the lock is held (`library`
    /// only upgrades, waits and inserts), so this cannot deadlock.
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

/// The registry of initialized libraries: by key, the library a token holds.
pub(super) type Libraries<T> = BTreeMap<String, std::sync::Weak<T>>;

/// The libraries this process initialized, by module path: a token of a module another open
/// token already initialized (the two sides of a move between tokens of one module) shares its
/// library rather than initializing it a second time.
pub(super) static LIBRARIES: std::sync::Mutex<Libraries<Library>> = std::sync::Mutex::new(BTreeMap::new());

/// Signalled when a library's entry leaves [`LIBRARIES`], finalized.
pub(super) static FINALIZED: std::sync::Condvar = std::sync::Condvar::new();

/// The library under `key` that a token still holds; `None` when there is none. One whose last
/// holder is finalizing it is waited for (`finalized` signals its removal): its module can be
/// initialized again only after that.
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

/// The initialized library of `module`: the one an open token holds, else newly loaded and
/// initialized.
pub(super) fn library(module: &str) -> Result<Arc<Library>> {
    // By the file a path names, as the loader maps it: two spellings of one module (relative
    // and absolute, a symlink) are one library, which a second `C_Initialize` would refuse. A
    // bare name is the loader's own search, and stays as written.
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
    // Loaded, by the file the loader mapped: a bare name and a path to that file are one library
    // too (token/mod.rs F3). Found open, `ctx` goes uninitialized: only its loader reference.
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

/// A fixed-width `CK_INFO` field without its padding: blanks by the specification, NULs from
/// some modules.
pub(super) fn unpadded(field: &str) -> String {
    field.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_owned()
}

/// What a module says about itself (`C_GetInfo`), and the file the loader mapped for `module` with
/// its hash: the lock's module provenance.
///
/// The manufacturer and description are compared as they stand from here on: every provider's
/// `matches` and the profiles' `[match]` take them exactly (review 2026-11-23 B-26).
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

/// The file the dynamic loader mapped for `module`, symlinks resolved — what the lock records as
/// provenance, whatever named it: a bare file name (the loader's library search), a
/// `/run/current-system` symlink or a store path. Asked of the loader itself (`dladdr` on the
/// module's `C_GetFunctionList`), so it is the file whose code runs. `None` if it cannot tell.
#[expect(unsafe_code, reason = "dlopen(RTLD_NOLOAD)/dlsym/dladdr only look up the loaded module")]
pub(super) fn loaded_path(module: &str) -> Option<String> {
    let name = std::ffi::CString::new(module).ok()?;
    // SAFETY: a valid NUL-terminated name; RTLD_NOLOAD returns the library `Pkcs11::new` already
    // loaded (adding a reference, released below) and never loads or initializes anything.
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: `handle` is a live handle and the symbol name NUL-terminated; the address is only
    // looked up, never called.
    let symbol = unsafe { libc::dlsym(handle, c"C_GetFunctionList".as_ptr()) };
    // SAFETY: an all-zero `Dl_info` is valid (null pointers); `dladdr` fills it for `symbol`.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `dli_fname` is a NUL-terminated string owned by the loader, copied out
    // before the handle is released (and the module stays loaded through cryptoki's handle).
    let file = (!symbol.is_null() && unsafe { libc::dladdr(symbol, &raw mut info) } != 0 && !info.dli_fname.is_null())
        .then(|| unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned());
    // SAFETY: releases only the reference taken above.
    unsafe { libc::dlclose(handle) };
    std::fs::canonicalize(file?).ok()?.into_os_string().into_string().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One normalisation of `C_GetInfo`'s fixed-width fields, so every provider compares exactly
    /// (review 2026-11-23 B-26).
    #[test]
    fn info_fields_lose_blank_and_nul_padding() {
        assert_eq!(unpadded("Google\0\0\0"), "Google");
        assert_eq!(unpadded("CloudHSM      \0 "), "CloudHSM");
        assert_eq!(unpadded("Yubico (www.yubico.com)"), "Yubico (www.yubico.com)");
    }

    /// A lookup that finds a library whose last holder is finalizing it waits until its entry is
    /// gone (token/mod.rs F5): the module is initialized anew only after that `C_Finalize`. A
    /// library still held is shared; none is none.
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
        // The last holder is gone, its finalize not done: the lookup waits for the removal.
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
