//! p11-fault (`docs/FAULT_SHIM.md`) is a PKCS#11 module that loads the real module that
//! `P11_FAULT_MODULE` names, forwards every 2.40 function to it, and changes only what the fault
//! plan in `P11_FAULT_PLAN` says. With `P11_FAULT_TRACE`, it logs every call as a JSON line. It
//! is configured from the environment and uses only PKCS#11 names, so any client can load it:
//! `cakeys`, `pkcs11-tool`, OpenSSL's provider, NSS, and p11-kit.
//!
//! A copy of the library named `libp11_fault-<tag>.so` reads `P11_FAULT_MODULE_<TAG>`,
//! `P11_FAULT_PLAN_<TAG>` and `P11_FAULT_TRACE_<TAG>` instead (the tag in upper case, with `-`
//! replaced by `_`), and never the untagged names. One process can then load several shims, each
//! in front of a different module, or one shim in front of another, and no shim reads the
//! settings of another.
#![expect(unsafe_code, reason = "a PKCS#11 module: the C ABI is the whole crate")]

mod forward;
mod hooks;
pub use p11_names as names;
pub mod plan;
mod record;
mod trace;

pub use forward::Fn;

use cryptoki_sys::{CK_FUNCTION_LIST, CK_RV, CKR_ARGUMENTS_BAD, CKR_GENERAL_ERROR, CKR_OK};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The reason why the shim cannot run, or cannot answer one call. The shim prints it on stderr,
/// and the call fails with `CKR_GENERAL_ERROR` (every call fails, when the shim could not load).
/// A plan with a typo must never turn into a test that tests nothing.
#[derive(Debug, Clone)]
pub struct Fatal(String);

impl Fatal {
    fn report(&self) -> CK_RV {
        if first_time(&self.0) {
            eprintln!("p11-fault: {}", self.0);
        }
        CKR_GENERAL_ERROR
    }
}

/// Returns whether `message` is printed for the first time in this process. Each fatal error is
/// printed once. A load failure, which every later call repeats, is printed once, and a later,
/// different error (such as a label that resolves to nothing) is still printed when it occurs.
fn first_time(message: &str) -> bool {
    static SAID: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    SAID.lock().map_or(true, |mut said| said.insert(message.to_owned()))
}

/// The loaded shim: the real module, its table, the plan, the trace, and the table that clients
/// get.
struct Shim {
    /// The real module's library, which is never unloaded, because `real` points into it for the
    /// life of the process.
    _library: libloading::Library,
    pub(crate) real: &'static CK_FUNCTION_LIST,
    pub(crate) plan: plan::Plan,
    trace: Option<trace::Trace>,
    table: CK_FUNCTION_LIST,
    /// What the open search of each caller session has returned so far (for `add_label` and
    /// `replace_label`).
    pub(crate) searches: hooks::Searches,
    /// What the functions that a `replay_output` rule names have returned so far.
    pub(crate) outputs: hooks::Outputs,
    /// The recorder that `P11_FAULT_RECORD_VALUES=public` turns on, which decides the public
    /// values that a trace line records.
    recorder: Option<record::Recorder>,
}

static SHIM: OnceLock<Result<Shim, Fatal>> = OnceLock::new();

thread_local! {
    /// Set while this thread loads the shim. A call back into the shim during the load means
    /// that the module leads to this shim again, and such a call would otherwise wait for its
    /// own initialization forever.
    static LOADING: Cell<bool> = const { Cell::new(false) };
}

/// Returns the shim, which is loaded on first use, or the reason why it could not be loaded
/// (every later call then fails in the same way).
fn shim() -> Result<&'static Shim, Fatal> {
    if LOADING.get() && SHIM.get().is_none() {
        return Err(Fatal(format!("{} leads back to this shim", variable("P11_FAULT_MODULE"))));
    }
    SHIM.get_or_init(|| while_loading(Shim::load)).as_ref().map_err(Fatal::clone)
}

/// Runs `load` with [`LOADING`] set on this thread, and clears the flag however `load` ends.
/// Before, a panic left the flag set, and the thread's next call reported a recursion that never
/// happened.
fn while_loading<T>(load: impl FnOnce() -> T) -> T {
    struct Loading;
    impl Drop for Loading {
        fn drop(&mut self) {
            LOADING.set(false);
        }
    }
    LOADING.set(true);
    let _loading = Loading;
    load()
}

/// Returns this library's own file, as the dynamic loader opened it.
fn own_path() -> Option<PathBuf> {
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    // The code passes the address of `get_function_list`, not of `C_GetFunctionList`, because an
    // exported name can resolve to another library's symbol (libp11-kit, which `p11-kit server`
    // loads, also exports one), and `dladdr` would then name that library.
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

/// Returns the tag of a copy of the library, from its file name: `TRACE` for
/// `libp11_fault-trace.so`, and no tag for `libp11_fault.so` (or for any other name).
fn tag(file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_str()?;
    let tag = stem.strip_prefix("libp11_fault-").filter(|t| !t.is_empty())?;
    Some(tag.to_uppercase().replace('-', "_"))
}

/// Returns this copy's tag ([`tag`]). The tag is read once, from the file that the loaded path
/// points to after any symlinks are resolved.
fn own_tag() -> Option<&'static str> {
    static TAG: OnceLock<Option<String>> = OnceLock::new();
    TAG.get_or_init(|| {
        let path = own_path()?;
        tag(&path.canonicalize().unwrap_or(path))
    })
    .as_deref()
}

/// Returns the name of the variable `base` for this copy of the library: `base` itself for an
/// untagged copy, and `base_<TAG>` for a tagged copy ([`tag`]).
fn variable(base: &str) -> String {
    match own_tag() {
        Some(tag) => format!("{base}_{tag}"),
        None => base.to_owned(),
    }
}

/// Returns the value of [`variable`]`(base)`, with the variable's name for messages.
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
        let (record_var, record) = setting("P11_FAULT_RECORD_VALUES");
        let recorder = record::Recorder::new(&record_var, record, trace.is_some())?;
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
        let (searches, outputs) = (hooks::Searches::default(), hooks::Outputs::default());
        Ok(Shim { _library: library, real, plan, trace, table, searches, outputs, recorder })
    }

    /// Handles one call of `function`. The call is counted, and its rules are chosen by what
    /// `observe` reads from its arguments before the call. The plan answers the call, or
    /// `forward` forwards it (`forward` calls the real module and returns which rule, if any,
    /// changed the answer). The call is then traced with what `observe` reads after it has
    /// returned. A `Fatal` from the choice of rules (a label that cannot be resolved) or from
    /// `forward` (a hook that cannot do what its rule says) is also traced, as the
    /// `CKR_GENERAL_ERROR` that the caller sees, with its message.
    fn call(
        &self,
        function: Fn,
        forward: impl FnOnce(&plan::Call) -> Result<(CK_RV, Option<usize>), Fatal>,
        observe: impl std::ops::Fn(&mut trace::Detail),
    ) -> Result<CK_RV, Fatal> {
        let mut about = trace::Detail::default();
        if !self.plan.rules().is_empty() || self.recorder.is_some() {
            observe(&mut about);
        }
        let (call, chosen) = self.select(function, &about);
        if self.plan.aborts(&call).is_some() {
            std::process::abort();
        }
        // `filled` is true when the real call ran and succeeded, so its outputs hold what the
        // module wrote. A rule that answered before the real call left the outputs as the caller
        // passed them.
        let (rv, rule, filled, fatal) = if let Err(fatal) = chosen {
            (CKR_GENERAL_ERROR, None, false, Some(fatal))
        } else if let Some((rv, rule)) = self.plan.before(&call) {
            (rv, Some(rule), false, None)
        } else {
            match forward(&call) {
                Ok((real, fired)) => {
                    let (rv, rule) = self.plan.after(&call).map_or((real, fired), |(rv, rule)| (rv, Some(rule)));
                    (rv, rule, real == CKR_OK, None)
                }
                Err(fatal) => (CKR_GENERAL_ERROR, None, false, Some(fatal)),
            }
        };
        if let Some(trace) = &self.trace {
            let mut detail = trace::Detail::default();
            detail.ok = filled;
            detail.fatal = fatal.as_ref().map(|f| f.0.clone());
            if let Some(recorder) = &self.recorder {
                detail.record = recorder.recording(self, function, &about, filled);
            }
            observe(&mut detail);
            trace.line(&call, rv, rule, &detail);
        }
        fatal.map_or(Ok(rv), Err)
    }

    /// Counts a call of `function` and chooses its rules by what was read from its arguments
    /// (`about`), resolving `of_label` on the caller's token. Also returns an error when a label
    /// could not be resolved.
    fn select(&self, function: Fn, about: &trace::Detail) -> (plan::Call, Result<(), Fatal>) {
        let mut call = self.plan.counted(function);
        let session = about.session;
        // SAFETY: real-module calls on the caller's session and handles, in its call.
        let is_of = |label: &[u8], objects: &[_]| unsafe { hooks::is_of(self, session, objects, label) };
        let chosen = self.plan.select(&mut call, about, is_of);
        (call, chosen)
    }
}

/// Wraps every entry point, so that a panic never crosses the C boundary and a shim that cannot
/// load prints the reason once.
fn guard(f: impl FnOnce() -> Result<CK_RV, Fatal>) -> CK_RV {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(rv)) => rv,
        Ok(Err(fatal)) => fatal.report(),
        Err(_) => CKR_GENERAL_ERROR,
    }
}

/// The module's entry point, which returns the shim's own table, whose functions forward to the
/// real module.
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

/// Returns a shim in front of the module whose table is `real`, under `plan`, tracing to
/// `trace`. The unit tests use it with a table of their own functions.
#[cfg(test)]
pub(crate) fn fake(real: &CK_FUNCTION_LIST, plan: &str, trace: Option<&Path>) -> Shim {
    let real: &'static CK_FUNCTION_LIST = Box::leak(Box::new(*real));
    Shim {
        // Any library works here, because the fake module is the test binary's own code.
        _library: libloading::os::unix::Library::this().into(),
        real,
        plan: plan::Plan::parse(plan).unwrap(),
        trace: trace.map(|p| trace::Trace::open("P11_FAULT_TRACE", p, None).unwrap()),
        table: forward::table(real),
        searches: hooks::Searches::default(),
        outputs: hooks::Outputs::default(),
        recorder: None,
    }
}

/// A table with no function in it, for [`fake`].
#[cfg(test)]
pub(crate) fn empty_table() -> CK_FUNCTION_LIST {
    // SAFETY: every field is a version of two bytes or an `Option` of a function pointer, for
    // which zero is `None`.
    unsafe { std::mem::zeroed() }
}

#[cfg(test)]
mod tests {
    use super::{Fatal, Fn, LOADING, empty_table, fake, first_time, tag, while_loading};
    use cryptoki_sys::{CK_TOKEN_INFO, CKR_DEVICE_ERROR, CKR_OK};
    use std::path::{Path, PathBuf};

    /// Returns the path of a new, empty trace file for the test `name`.
    fn trace_file(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("p11-fault-{}-{name}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// Each fatal error is printed once, and a second, different error is printed too. Before,
    /// the first error suppressed every later one.
    #[test]
    fn each_fatal_is_said_once() {
        assert!(first_time("test: one fatal"));
        assert!(!first_time("test: one fatal"));
        assert!(first_time("test: another fatal"));
    }

    /// A hook that cannot do what its rule says fails the call, and the trace records the call
    /// with the value that the caller saw and the reason.
    #[test]
    fn a_fatal_call_is_traced() {
        let path = trace_file("fatal");
        let shim = fake(&empty_table(), "", Some(&path));
        let out = shim.call(Fn::C_SignInit, |_| Err(Fatal("use_label: nothing".into())), |_| {});
        assert!(out.is_err());
        let [line] = &lines(&path)[..] else { panic!("one line, not {:?}", lines(&path)) };
        assert_eq!(
            (&line["fn"], &line["rv"], &line["rule"], &line["fatal"]),
            (&"C_SignInit".into(), &"CKR_GENERAL_ERROR".into(), &serde_json::Value::Null, &"use_label: nothing".into())
        );
    }

    /// An output is read only where the real call filled it. It is not read under a rule that
    /// answered `CKR_OK` in place of the real call, nor after a real failure that an `after`
    /// rule turned into `CKR_OK`.
    #[test]
    fn outputs_are_read_only_where_the_module_filled_them() {
        let path = trace_file("outputs");
        let plan = "[[rule]]\nfn = \"C_GetTokenInfo\"\ncall = 1\nrv = \"CKR_OK\"\n\n\
                    [[rule]]\nfn = \"C_GetTokenInfo\"\ncall = 2\nrv = \"CKR_OK\"\nwhen = \"after\"\n";
        let shim = fake(&empty_table(), plan, Some(&path));
        // SAFETY: zero is a valid `CK_TOKEN_INFO`.
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        info.flags = 0xdead;
        let info = &raw const info;
        let observe = |d: &mut crate::trace::Detail| unsafe { d.token_info(info) };
        for real in [CKR_OK, CKR_DEVICE_ERROR, CKR_OK] {
            assert_eq!(shim.call(Fn::C_GetTokenInfo, |_| Ok((real, None)), observe).ok(), Some(CKR_OK));
        }
        let flags: Vec<_> = lines(&path).iter().map(|l| l["token_flags"].clone()).collect();
        assert_eq!(flags, [serde_json::Value::Null, serde_json::Value::Null, 0xdead.into()]);
    }

    /// A panic while loading leaves the thread able to load again, and no recursion is
    /// reported.
    #[test]
    fn a_panic_while_loading_clears_the_mark() {
        let panicked = std::panic::catch_unwind(|| while_loading(|| panic!("a module that panics")));
        assert!(panicked.is_err());
        assert!(!LOADING.get());
    }

    #[test]
    fn a_copy_is_tagged_by_its_file_name() {
        assert_eq!(tag(Path::new("/nix/store/x/lib/libp11_fault.so")), None);
        assert_eq!(tag(Path::new("/tmp/t/libp11_fault-trace.so")).as_deref(), Some("TRACE"));
        assert_eq!(tag(Path::new("libp11_fault-p11-kit.so")).as_deref(), Some("P11_KIT"));
        assert_eq!(tag(Path::new("libp11_fault-.so")), None);
        assert_eq!(tag(Path::new("libsofthsm2.so")), None);
    }
}
