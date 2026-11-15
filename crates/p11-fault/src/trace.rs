//! The call log (`P11_FAULT_TRACE`): one JSON line per call, appended, so the processes of a
//! test run (each loads the shim afresh) interleave whole lines in one file.

use crate::Fatal;
use crate::plan::Call;
use cryptoki_sys::CK_RV;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Trace {
    file: Mutex<std::fs::File>,
    seq: AtomicU64,
}

impl Trace {
    /// Open `path`, which the variable `var` named, for appending.
    pub(crate) fn open(var: &str, path: &Path) -> Result<Trace, Fatal> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Fatal(format!("{var} {}: {e}", path.display())))?;
        Ok(Trace { file: Mutex::new(file), seq: AtomicU64::new(0) })
    }

    /// Log `call`, the value its caller saw, and the plan's rule (from 1) that decided it, if any.
    /// A write that fails is dropped: the trace never changes what the caller sees.
    pub(crate) fn line(&self, call: &Call, rv: CK_RV, rule: Option<usize>) {
        let line = serde_json::json!({
            "pid": std::process::id(),
            "seq": self.seq.fetch_add(1, Ordering::Relaxed),
            "fn": call.function.name(),
            "n": call.n,
            "rv": crate::names::rv_name(rv).map_or_else(|| format!("{rv:#x}"), str::to_owned),
            "rule": rule,
        });
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
        }
    }
}
