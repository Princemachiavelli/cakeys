//! p11-fault (`docs/FAULT_SHIM.md`): a PKCS#11 module that loads the real one `P11_FAULT_MODULE`
//! names, forwards every 2.40 function to it, and changes only what the fault plan in
//! `P11_FAULT_PLAN` says; with `P11_FAULT_TRACE`, every call is logged as a JSON line. It is
//! configured from the environment and speaks PKCS#11 names only, so any client can load it:
//! `cakeys`, `pkcs11-tool`, OpenSSL's provider, NSS, p11-kit.
#![expect(unsafe_code, reason = "a PKCS#11 module: the C ABI is the whole crate")]

mod forward;
mod hooks;
pub mod names;
pub mod plan;
mod trace;

pub use forward::Fn;

use cryptoki_sys::{CK_FUNCTION_LIST, CK_RV, CKR_ARGUMENTS_BAD, CKR_GENERAL_ERROR, CKR_OK};
use std::path::Path;
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

/// The shim, loaded on first use, or why it could not be (every later call fails the same way).
fn shim() -> Result<&'static Shim, Fatal> {
    SHIM.get_or_init(Shim::load).as_ref().map_err(Fatal::clone)
}

impl Shim {
    fn load() -> Result<Shim, Fatal> {
        let path = std::env::var_os("P11_FAULT_MODULE")
            .ok_or_else(|| Fatal("P11_FAULT_MODULE names no module to forward to".into()))?;
        let path = Path::new(&path);
        let plan = match std::env::var_os("P11_FAULT_PLAN") {
            Some(p) => {
                let p = Path::new(&p);
                let text =
                    std::fs::read_to_string(p).map_err(|e| Fatal(format!("P11_FAULT_PLAN {}: {e}", p.display())))?;
                plan::Plan::parse(&text).map_err(|e| Fatal(format!("P11_FAULT_PLAN {}: {e}", p.display())))?
            }
            None => plan::Plan::default(),
        };
        let trace = std::env::var_os("P11_FAULT_TRACE").map(|p| trace::Trace::open(Path::new(&p))).transpose()?;
        let module = |e: &dyn std::fmt::Display| Fatal(format!("P11_FAULT_MODULE {}: {e}", path.display()));
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
    /// calls the real module and says which rule, if any, changed what it answered), and traced.
    fn call(
        &self,
        function: Fn,
        forward: impl FnOnce(&plan::Call) -> Result<(CK_RV, Option<usize>), Fatal>,
    ) -> Result<CK_RV, Fatal> {
        let call = self.plan.count(function);
        let (rv, rule) = if let Some((rv, rule)) = self.plan.before(&call) {
            (rv, Some(rule))
        } else {
            let (real, fired) = forward(&call)?;
            self.plan.after(&call).map_or((real, fired), |(rv, rule)| (rv, Some(rule)))
        };
        if let Some(trace) = &self.trace {
            trace.line(&call, rv, rule);
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
