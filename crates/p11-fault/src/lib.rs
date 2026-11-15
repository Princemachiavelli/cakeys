//! p11-fault (`docs/FAULT_SHIM.md`): a PKCS#11 module that loads the real one `P11_FAULT_MODULE`
//! names, forwards every 2.40 function to it, and changes only what the fault plan in
//! `P11_FAULT_PLAN` says; with `P11_FAULT_TRACE`, every call is logged as a JSON line. It is
//! configured from the environment and speaks PKCS#11 names only, so any client can load it:
//! `cakeys`, `pkcs11-tool`, OpenSSL's provider, NSS, p11-kit.
//!
//! A copy of the library named `libp11_fault-<tag>.so` reads `P11_FAULT_MODULE_<TAG>`,
//! `P11_FAULT_PLAN_<TAG>` and `P11_FAULT_TRACE_<TAG>` instead (the tag upper-cased, `-` as `_`),
//! and never the untagged names: one process can then load several shims, each in front of
//! another module, or one shim in front of another, without either reading the other's settings.
#![expect(unsafe_code, reason = "a PKCS#11 module: the C ABI is the whole crate")]

mod forward;
mod hooks;
pub mod names;
pub mod plan;
mod trace;

pub use forward::Fn;

use cryptoki_sys::{CK_FUNCTION_LIST, CK_RV, CKR_ARGUMENTS_BAD, CKR_GENERAL_ERROR, CKR_OK};
use std::cell::Cell;
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};

/// Why the shim cannot run: said once on stderr, and every call then fails with
/// `CKR_GENERAL_ERROR`. A plan with a typo must never become a test of nothing.
#[derive(Debug, Clone)]
pub struct Fatal(String);

impl Fatal {
    fn report(&self) -> CK_RV {
        static SAID: Once = Once::new();
        SAID.call_once(|| eprintln!("p11-fault: {}", self.0));
        CKR_GENERAL_ERROR
    }
}

/// The loaded shim: the real module, its table, the plan, the trace, and the table clients get.
struct Shim {
    /// Never unloaded: `real` points into it for the life of the process.
    _library: libloading::Library,
    pub(crate) real: &'static CK_FUNCTION_LIST,
    pub(crate) plan: plan::Plan,
    trace: Option<trace::Trace>,
    table: CK_FUNCTION_LIST,
}

static SHIM: OnceLock<Result<Shim, Fatal>> = OnceLock::new();

thread_local! {
    /// Set while this thread loads the shim: a call back into it then is a module that leads to
    /// this shim again, which would otherwise wait on its own initialisation for ever.
    static LOADING: Cell<bool> = const { Cell::new(false) };
}

/// The shim, loaded on first use, or why it could not be (every later call fails the same way).
fn shim() -> Result<&'static Shim, Fatal> {
    if LOADING.get() && SHIM.get().is_none() {
        return Err(Fatal(format!("{} leads back to this shim", variable("P11_FAULT_MODULE"))));
    }
    SHIM.get_or_init(|| {
        LOADING.set(true);
        let shim = Shim::load();
        LOADING.set(false);
        shim
    })
    .as_ref()
    .map_err(Fatal::clone)
}

/// This library's own file, as the dynamic loader opened it.
fn own_path() -> Option<PathBuf> {
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    // Not `C_GetFunctionList`: an exported name can resolve to another library's (libp11-kit,
    // loaded by `p11-kit server`, exports one too), and `dladdr` would then name that library.
    // SAFETY: `dladdr` reads the loader's tables for an address inside this library and fills
    // `info`; zeroed memory is a valid `Dl_info` to pass.
    let found = unsafe { libc::dladdr(get_function_list as *const libc::c_void, info.as_mut_ptr()) };
    // SAFETY: on success `dladdr` filled `info`; `dli_fname` is a C string the loader owns for
    // as long as the library stays loaded.
    let name = unsafe {
        let info = info.assume_init();
        if found == 0 || info.dli_fname.is_null() {
            return None;
        }
        CStr::from_ptr(info.dli_fname)
    };
    Some(PathBuf::from(OsStr::from_bytes(name.to_bytes())))
}

/// The tag of a copy of the library, from its file: `TRACE` for `libp11_fault-trace.so`, none
/// for `libp11_fault.so` (or any other name).
fn tag(file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_str()?;
    let tag = stem.strip_prefix("libp11_fault-").filter(|t| !t.is_empty())?;
    Some(tag.to_uppercase().replace('-', "_"))
}

/// This copy's tag ([`tag`]), read once, from the file a symlink that loaded it points to.
fn own_tag() -> Option<&'static str> {
    static TAG: OnceLock<Option<String>> = OnceLock::new();
    TAG.get_or_init(|| {
        let path = own_path()?;
        tag(&path.canonicalize().unwrap_or(path))
    })
    .as_deref()
}

/// `base` for this copy of the library: `base` itself untagged, `base_<TAG>` tagged ([`tag`]).
fn variable(base: &str) -> String {
    match own_tag() {
        Some(tag) => format!("{base}_{tag}"),
        None => base.to_owned(),
    }
}

/// The value of [`variable`]`(base)`, with its name for messages.
fn setting(base: &str) -> (String, Option<OsString>) {
    let name = variable(base);
    let value = std::env::var_os(&name);
    (name, value)
}

impl Shim {
    fn load() -> Result<Shim, Fatal> {
        let (module_var, path) = setting("P11_FAULT_MODULE");
        let path = path.ok_or_else(|| Fatal(format!("{module_var} names no module to forward to")))?;
        let path = Path::new(&path);
        let same = |a: &Path, b: &Path| a.canonicalize().is_ok_and(|a| b.canonicalize().is_ok_and(|b| a == b));
        if own_path().is_some_and(|own| same(path, &own)) {
            return Err(Fatal(format!("{module_var} {} is this shim itself", path.display())));
        }
        let plan = match setting("P11_FAULT_PLAN") {
            (var, Some(p)) => {
                let p = Path::new(&p);
                let text = std::fs::read_to_string(p).map_err(|e| Fatal(format!("{var} {}: {e}", p.display())))?;
                plan::Plan::parse(&text).map_err(|e| Fatal(format!("{var} {}: {e}", p.display())))?
            }
            (_, None) => plan::Plan::default(),
        };
        let (trace_var, trace) = setting("P11_FAULT_TRACE");
        let trace =
            trace.map(|p| trace::Trace::open(&trace_var, Path::new(&p), own_tag().map(str::to_owned))).transpose()?;
        let module = |e: &dyn std::fmt::Display| Fatal(format!("{module_var} {}: {e}", path.display()));
        // SAFETY: loading a PKCS#11 module runs its initialisers, as a client loading it directly
        // would; that is what the client asked for by loading the shim.
        let library = unsafe { libloading::Library::new(path) }.map_err(|e| module(&e))?;
        // SAFETY: `C_GetFunctionList` has this signature in every PKCS#11 module. The table it
        // returns lives in the module, which `_library` keeps loaded for the life of the process.
        let real: &'static CK_FUNCTION_LIST = unsafe {
            let get = library
                .get::<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>(b"C_GetFunctionList\0")
                .map_err(|e| module(&e))?;
            let mut list = std::ptr::null_mut();
            let rv = get(&raw mut list);
            if rv != CKR_OK || list.is_null() {
                return Err(module(&format_args!("C_GetFunctionList returned {rv:#x}")));
            }
            &*list
        };
        let table = forward::table(real);
        Ok(Shim { _library: library, real, plan, trace, table })
    }

    /// One call of `function`: counted, answered by the plan or forwarded by `forward` (which
    /// calls the real module and says which rule, if any, changed what it answered), and traced
    /// with what `observe` reads from its arguments once it has returned.
    fn call(
        &self,
        function: Fn,
        forward: impl FnOnce(&plan::Call) -> Result<(CK_RV, Option<usize>), Fatal>,
        observe: impl FnOnce(&mut trace::Detail),
    ) -> Result<CK_RV, Fatal> {
        let call = self.plan.count(function);
        let (rv, rule) = if let Some((rv, rule)) = self.plan.before(&call) {
            (rv, Some(rule))
        } else {
            let (real, fired) = forward(&call)?;
            self.plan.after(&call).map_or((real, fired), |(rv, rule)| (rv, Some(rule)))
        };
        if let Some(trace) = &self.trace {
            let mut detail = trace::Detail::default();
            observe(&mut detail);
            trace.line(&call, rv, rule, &detail);
        }
        Ok(rv)
    }
}

/// Every entry point: a panic never crosses the C boundary, and a shim that cannot load says
/// why once.
fn guard(f: impl FnOnce() -> Result<CK_RV, Fatal>) -> CK_RV {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(rv)) => rv,
        Ok(Err(fatal)) => fatal.report(),
        Err(_) => CKR_GENERAL_ERROR,
    }
}

/// The module's entry point: the shim's own table, whose functions forward to the real module.
///
/// # Safety
///
/// `out` is null or points to writable memory for one pointer, as PKCS#11 requires of callers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(out: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    // SAFETY: the caller's pointer, under the same contract.
    unsafe { get_function_list(out) }
}

/// [`C_GetFunctionList`] under a name this library does not export, so that the shim's own table
/// and [`own_path`] refer to this library's entry point and never to another library's of the
/// same exported name.
///
/// # Safety
///
/// As [`C_GetFunctionList`].
pub(crate) unsafe extern "C" fn get_function_list(out: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    guard(|| {
        if out.is_null() {
            return Ok(CKR_ARGUMENTS_BAD);
        }
        let shim = shim()?;
        // SAFETY: `out` is not null, and the caller gave writable memory for one pointer. The
        // table is in a static: it outlives every caller.
        unsafe { *out = (&raw const shim.table).cast_mut() };
        Ok(CKR_OK)
    })
}

#[cfg(test)]
mod tests {
    use super::tag;
    use std::path::Path;

    #[test]
    fn a_copy_is_tagged_by_its_file_name() {
        assert_eq!(tag(Path::new("/nix/store/x/lib/libp11_fault.so")), None);
        assert_eq!(tag(Path::new("/tmp/t/libp11_fault-trace.so")).as_deref(), Some("TRACE"));
        assert_eq!(tag(Path::new("libp11_fault-p11-kit.so")).as_deref(), Some("P11_KIT"));
        assert_eq!(tag(Path::new("libp11_fault-.so")), None);
        assert_eq!(tag(Path::new("libsofthsm2.so")), None);
    }
}
