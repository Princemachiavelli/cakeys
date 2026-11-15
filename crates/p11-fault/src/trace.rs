//! The call log (`P11_FAULT_TRACE`): one JSON line per call, appended, so the processes of a
//! test run (each loads the shim afresh) interleave whole lines in one file.
//!
//! Beside the function and what it returned, a line says what the call was about ([`Detail`]):
//! the mechanism, the user type, the session flags, the attribute types of a template and the
//! object classes, key types and certificate types it named. They are numbers: the reader maps
//! them to names (the coverage file of docs/PLAN.md A1 uses the spec baseline). `exe` names the
//! program that made the call, so a test harness's own calls can be told from the tool's.

use crate::Fatal;
use crate::plan::Call;
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_FLAGS, CK_MECHANISM, CK_MECHANISM_TYPE, CK_RV, CK_ULONG, CK_USER_TYPE,
    CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_KEY_TYPE,
};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Trace {
    file: Mutex<std::fs::File>,
    seq: AtomicU64,
    /// The calling program's file name.
    exe: Option<String>,
    /// This copy's tag (`libp11_fault-<tag>.so`), if any.
    shim: Option<String>,
}

/// What one call was about, read from its arguments once it has returned (an input template is
/// unchanged then, and an output one filled in).
#[derive(Debug, Default)]
pub(crate) struct Detail {
    mechanism: Option<CK_MECHANISM_TYPE>,
    user: Option<CK_USER_TYPE>,
    flags: Option<CK_FLAGS>,
    attributes: Vec<CK_ATTRIBUTE_TYPE>,
    classes: Vec<CK_ULONG>,
    key_types: Vec<CK_ULONG>,
    certificate_types: Vec<CK_ULONG>,
}

impl Detail {
    /// The mechanism of a `CK_MECHANISM` argument.
    ///
    /// # Safety
    ///
    /// `mechanism` is null or points to a `CK_MECHANISM`, as the call's contract requires.
    pub(crate) unsafe fn mechanism(&mut self, mechanism: *const CK_MECHANISM) {
        if !mechanism.is_null() {
            // SAFETY: not null, and the caller's contract makes it a readable `CK_MECHANISM`.
            self.mechanism = Some(unsafe { (*mechanism).mechanism });
        }
    }

    /// A `CK_MECHANISM_TYPE` argument.
    pub(crate) fn mechanism_type(&mut self, mechanism: CK_MECHANISM_TYPE) {
        self.mechanism = Some(mechanism);
    }

    /// A `CK_USER_TYPE` argument.
    pub(crate) fn user(&mut self, user: CK_USER_TYPE) {
        self.user = Some(user);
    }

    /// A `CK_FLAGS` argument.
    pub(crate) fn flags(&mut self, flags: CK_FLAGS) {
        self.flags = Some(flags);
    }

    /// A template of `count` entries: every attribute type, and the values of the class, key
    /// type and certificate type entries that carry one.
    ///
    /// # Safety
    ///
    /// `template` is null or points to `count` readable `CK_ATTRIBUTE`s, each `pValue` null or
    /// pointing to `ulValueLen` readable bytes, as the call's contract requires.
    pub(crate) unsafe fn template(&mut self, template: *const CK_ATTRIBUTE, count: CK_ULONG) {
        let Ok(count) = usize::try_from(count) else { return };
        if template.is_null() || count == 0 {
            return;
        }
        // SAFETY: not null, and the caller's contract makes it `count` readable entries.
        let entries = unsafe { std::slice::from_raw_parts(template, count) };
        for e in entries {
            self.attributes.push(e.type_);
            let list = match e.type_ {
                CKA_CLASS => &mut self.classes,
                CKA_KEY_TYPE => &mut self.key_types,
                CKA_CERTIFICATE_TYPE => &mut self.certificate_types,
                _ => continue,
            };
            if !e.pValue.is_null() && usize::try_from(e.ulValueLen) == Ok(size_of::<CK_ULONG>()) {
                // SAFETY: `pValue` holds `ulValueLen` readable bytes, one `CK_ULONG`, perhaps
                // unaligned.
                list.push(unsafe { e.pValue.cast::<CK_ULONG>().read_unaligned() });
            }
        }
    }
}

impl Trace {
    /// Open `path`, which the variable `var` named, for appending; `shim` is this copy's tag.
    pub(crate) fn open(var: &str, path: &Path, shim: Option<String>) -> Result<Trace, Fatal> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Fatal(format!("{var} {}: {e}", path.display())))?;
        let exe = std::env::current_exe().ok().and_then(|p| Some(p.file_name()?.to_string_lossy().into_owned()));
        Ok(Trace { file: Mutex::new(file), seq: AtomicU64::new(0), exe, shim })
    }

    /// Log `call`, the value its caller saw, the plan's rule (from 1) that decided it, if any,
    /// and what it was about. A write that fails is dropped: the trace never changes what the
    /// caller sees.
    pub(crate) fn line(&self, call: &Call, rv: CK_RV, rule: Option<usize>, detail: &Detail) {
        let mut line = serde_json::json!({
            "pid": std::process::id(),
            "seq": self.seq.fetch_add(1, Ordering::Relaxed),
            "exe": self.exe,
            "fn": call.function.name(),
            "n": call.n,
            "rv": crate::names::rv_name(rv).map_or_else(|| format!("{rv:#x}"), str::to_owned),
            "rule": rule,
        });
        let fields = line.as_object_mut().expect("a JSON object");
        if let Some(shim) = &self.shim {
            fields.insert("shim".into(), shim.as_str().into());
        }
        let numbers = [("mechanism", detail.mechanism), ("user", detail.user), ("flags", detail.flags)];
        for (name, value) in numbers {
            if let Some(value) = value {
                fields.insert(name.into(), value.into());
            }
        }
        let lists = [
            ("attributes", &detail.attributes),
            ("class", &detail.classes),
            ("key_type", &detail.key_types),
            ("certificate_type", &detail.certificate_types),
        ];
        for (name, values) in lists {
            if !values.is_empty() {
                fields.insert(name.into(), values.as_slice().into());
            }
        }
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Detail;
    use cryptoki_sys::{CK_ATTRIBUTE, CK_ULONG, CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKK_EC, CKO_PRIVATE_KEY};

    #[test]
    fn a_template_gives_its_types_and_the_classes_and_key_types_it_names() {
        let (mut class, mut key_type) = (CKO_PRIVATE_KEY, CKK_EC);
        let mut label = *b"k";
        let entry = |type_, p: *mut u8, len: usize| CK_ATTRIBUTE {
            type_,
            pValue: p.cast(),
            ulValueLen: CK_ULONG::try_from(len).unwrap(),
        };
        let template = [
            entry(CKA_CLASS, (&raw mut class).cast(), size_of::<CK_ULONG>()),
            entry(CKA_KEY_TYPE, (&raw mut key_type).cast(), size_of::<CK_ULONG>()),
            entry(CKA_LABEL, label.as_mut_ptr(), 1),
            // A length query: the type, no value.
            entry(CKA_KEY_TYPE, std::ptr::null_mut(), 0),
        ];
        let mut d = Detail::default();
        // SAFETY: four entries, each value null or as long as it says.
        unsafe { d.template(template.as_ptr(), 4) };
        assert_eq!(d.attributes, [CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_KEY_TYPE]);
        assert_eq!((&d.classes[..], &d.key_types[..]), (&[CKO_PRIVATE_KEY][..], &[CKK_EC][..]));
        // SAFETY: a null template is no template.
        unsafe { d.template(std::ptr::null(), 3) };
    }
}
