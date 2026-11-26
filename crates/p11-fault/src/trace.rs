//! The call log (`P11_FAULT_TRACE`) has one JSON line for each call, appended to the file, so
//! that the processes of a test run (each of which loads the shim again) interleave whole lines
//! in one file.
//!
//! Besides the function and what it returned, a line says what the call was about ([`Detail`]):
//! the mechanism, the user type, the session flags, the attribute types of a template, and the
//! object classes, key types and certificate types that the template named. These values are
//! numbers, and the reader maps them to names (the coverage file of docs/PLAN.md A1 uses the spec
//! baseline). `exe` names the program that made the call, so that a test harness's own calls can
//! be told apart from the tool's calls.

use crate::Fatal;
use crate::plan::Call;
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_BYTE, CK_C_INITIALIZE_ARGS, CK_ECDH1_DERIVE_PARAMS, CK_FLAGS, CK_MECHANISM,
    CK_MECHANISM_INFO, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RSA_AES_KEY_WRAP_PARAMS, CK_RSA_PKCS_OAEP_PARAMS,
    CK_RSA_PKCS_PSS_PARAMS, CK_RV, CK_SESSION_HANDLE, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_USER_TYPE,
    CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_KEY_TYPE, CKM_ECDH1_COFACTOR_DERIVE, CKM_ECDH1_DERIVE, CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS,
};
use std::fmt::Write as _;
use std::io::Write;
use std::os::raw::c_void;
use std::path::Path;
use std::sync::Mutex;

pub(crate) struct Trace {
    file: Mutex<std::fs::File>,
    /// The calling program's file name.
    exe: Option<String>,
    /// This copy's tag (`libp11_fault-<tag>.so`), if any.
    shim: Option<String>,
}

/// What one call was about, read from its arguments. The arguments are read before the call for
/// the plan's matchers (the outputs are not filled yet, so they are not read), and after the call
/// has returned for the trace (an input template is unchanged then, and an output template is
/// filled in).
#[derive(Debug, Default)]
pub(crate) struct Detail {
    /// True when the real call ran and returned `CKR_OK`. Only then are its outputs read. A rule
    /// that answered in place of the real call, or a failure that an `after` rule hid, filled
    /// nothing.
    pub(crate) ok: bool,
    /// The reason why the shim failed the call itself (`Fatal`), if it did.
    pub(crate) fatal: Option<String>,
    pub(crate) mechanism: Option<CK_MECHANISM_TYPE>,
    /// The OAEP or PSS hash from the mechanism's parameters. The next three fields hold the MGF,
    /// the OAEP source and the ECDH KDF from the same parameters.
    hash: Option<CK_MECHANISM_TYPE>,
    mgf: Option<CK_ULONG>,
    source: Option<CK_ULONG>,
    kdf: Option<CK_ULONG>,
    user: Option<CK_USER_TYPE>,
    flags: Option<CK_FLAGS>,
    /// The flags of `C_Initialize`. The next three fields hold the flags of the slot, token or
    /// mechanism information that a call returned.
    init_flags: Option<CK_FLAGS>,
    slot_flags: Option<CK_FLAGS>,
    token_flags: Option<CK_FLAGS>,
    mechanism_flags: Option<CK_FLAGS>,
    pub(crate) attributes: Vec<CK_ATTRIBUTE_TYPE>,
    pub(crate) classes: Vec<CK_ULONG>,
    pub(crate) key_types: Vec<CK_ULONG>,
    certificate_types: Vec<CK_ULONG>,
    /// The session that the call names, and in the next field the objects that it names.
    /// `of_label` looks at them, and they are not traced.
    pub(crate) session: Option<CK_SESSION_HANDLE>,
    pub(crate) objects: Vec<CK_OBJECT_HANDLE>,
    /// What may be recorded of the values that the call returned (`P11_FAULT_RECORD_VALUES`).
    /// The next two fields hold what was recorded: the attribute values, and the data and the
    /// signature of `C_Sign`.
    pub(crate) record: crate::record::Recording,
    values: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>,
    signed: Option<(Vec<u8>, Vec<u8>)>,
}

impl Detail {
    /// Reads the mechanism of a `CK_MECHANISM` argument, and the enumerated choices in the
    /// parameters of the mechanisms that cakeys uses with parameters: an OAEP or PSS hash and
    /// MGF, an OAEP source, and an ECDH KDF. Each choice is read only when the parameter is as
    /// long as its structure.
    ///
    /// # Safety
    ///
    /// `mechanism` is null or points to a `CK_MECHANISM` whose `pParameter` is null or points to
    /// `ulParameterLen` readable bytes, as the call's contract requires.
    pub(crate) unsafe fn mechanism(&mut self, mechanism: *const CK_MECHANISM) {
        if mechanism.is_null() {
            return;
        }
        // SAFETY: not null, and the caller's contract makes it a readable `CK_MECHANISM`.
        let m = unsafe { &*mechanism };
        self.mechanism = Some(m.mechanism);
        let p = m.pParameter.cast_const();
        let fits = |size: usize| !p.is_null() && usize::try_from(m.ulParameterLen) == Ok(size);
        match m.mechanism {
            CKM_RSA_PKCS_OAEP if fits(size_of::<CK_RSA_PKCS_OAEP_PARAMS>()) => {
                // SAFETY: the parameter holds a whole `CK_RSA_PKCS_OAEP_PARAMS`.
                unsafe { self.oaep(p.cast()) };
            }
            CKM_RSA_AES_KEY_WRAP if fits(size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>()) => {
                // SAFETY: the parameter holds a whole `CK_RSA_AES_KEY_WRAP_PARAMS`, whose OAEP
                // parameters are null or a `CK_RSA_PKCS_OAEP_PARAMS` by the same contract.
                unsafe { self.oaep(p.cast::<CK_RSA_AES_KEY_WRAP_PARAMS>().read_unaligned().pOAEPParams) };
            }
            CKM_RSA_PKCS_PSS
            | CKM_SHA1_RSA_PKCS_PSS
            | CKM_SHA224_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
                if fits(size_of::<CK_RSA_PKCS_PSS_PARAMS>()) =>
            {
                // SAFETY: the parameter holds a whole `CK_RSA_PKCS_PSS_PARAMS`.
                let pss = unsafe { p.cast::<CK_RSA_PKCS_PSS_PARAMS>().read_unaligned() };
                (self.hash, self.mgf) = (Some(pss.hashAlg), Some(pss.mgf));
            }
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE if fits(size_of::<CK_ECDH1_DERIVE_PARAMS>()) => {
                // SAFETY: the parameter holds a whole `CK_ECDH1_DERIVE_PARAMS`.
                self.kdf = Some(unsafe { p.cast::<CK_ECDH1_DERIVE_PARAMS>().read_unaligned() }.kdf);
            }
            _ => {}
        }
    }

    /// Reads the hash, the MGF and the source of OAEP parameters.
    ///
    /// # Safety
    ///
    /// `params` is null or points to a `CK_RSA_PKCS_OAEP_PARAMS`.
    unsafe fn oaep(&mut self, params: *const CK_RSA_PKCS_OAEP_PARAMS) {
        if !params.is_null() {
            // SAFETY: not null, and the contract makes it a `CK_RSA_PKCS_OAEP_PARAMS`.
            let oaep = unsafe { params.read_unaligned() };
            (self.hash, self.mgf, self.source) = (Some(oaep.hashAlg), Some(oaep.mgf), Some(oaep.source));
        }
    }

    /// A `CK_MECHANISM_TYPE` argument.
    pub(crate) fn mechanism_type(&mut self, mechanism: CK_MECHANISM_TYPE) {
        self.mechanism = Some(mechanism);
    }

    /// A `CK_SESSION_HANDLE` argument.
    pub(crate) fn session(&mut self, session: CK_SESSION_HANDLE) {
        self.session = Some(session);
    }

    /// Records a `CK_OBJECT_HANDLE` argument, after the handles that came before it.
    pub(crate) fn object(&mut self, object: CK_OBJECT_HANDLE) {
        self.objects.push(object);
    }

    /// A `CK_USER_TYPE` argument.
    pub(crate) fn user(&mut self, user: CK_USER_TYPE) {
        self.user = Some(user);
    }

    /// A `CK_FLAGS` argument.
    pub(crate) fn flags(&mut self, flags: CK_FLAGS) {
        self.flags = Some(flags);
    }

    /// Reads the argument of `C_Initialize`: the flags of its `CK_C_INITIALIZE_ARGS`, if there
    /// are any.
    ///
    /// # Safety
    ///
    /// `args` is null or points to a `CK_C_INITIALIZE_ARGS`, as `C_Initialize` requires.
    pub(crate) unsafe fn initialize(&mut self, args: *const c_void) {
        if !args.is_null() {
            // SAFETY: not null, and `C_Initialize`'s contract makes it a `CK_C_INITIALIZE_ARGS`.
            self.init_flags = Some(unsafe { (*args.cast::<CK_C_INITIALIZE_ARGS>()).flags });
        }
    }

    /// Reads the flags of the `CK_SLOT_INFO` that a successful `C_GetSlotInfo` filled.
    ///
    /// # Safety
    ///
    /// `info` is null or points to a `CK_SLOT_INFO`.
    pub(crate) unsafe fn slot_info(&mut self, info: *const CK_SLOT_INFO) {
        if self.ok && !info.is_null() {
            // SAFETY: not null, and the call filled it.
            self.slot_flags = Some(unsafe { (*info).flags });
        }
    }

    /// Reads the flags of the `CK_TOKEN_INFO` that a successful `C_GetTokenInfo` filled.
    ///
    /// # Safety
    ///
    /// `info` is null or points to a `CK_TOKEN_INFO`.
    pub(crate) unsafe fn token_info(&mut self, info: *const CK_TOKEN_INFO) {
        if self.ok && !info.is_null() {
            // SAFETY: not null, and the call filled it.
            self.token_flags = Some(unsafe { (*info).flags });
        }
    }

    /// Reads the flags of the `CK_MECHANISM_INFO` that a successful `C_GetMechanismInfo`
    /// filled.
    ///
    /// # Safety
    ///
    /// `info` is null or points to a `CK_MECHANISM_INFO`.
    pub(crate) unsafe fn mechanism_info(&mut self, info: *const CK_MECHANISM_INFO) {
        if self.ok && !info.is_null() {
            // SAFETY: not null, and the call filled it.
            self.mechanism_flags = Some(unsafe { (*info).flags });
        }
    }

    /// Reads a template of `count` entries: every attribute type, and the values of the class,
    /// key type and certificate type entries that carry a value.
    ///
    /// # Safety
    ///
    /// `template` is null or points to `count` readable `CK_ATTRIBUTE`s, each `pValue` null or
    /// pointing to `ulValueLen` readable bytes, as the call's contract requires.
    pub(crate) unsafe fn template(&mut self, template: *const CK_ATTRIBUTE, count: CK_ULONG) {
        // SAFETY: the caller's contract, passed on.
        unsafe { self.read_template(template, count, true) };
    }

    /// Reads a template that the call fills (`C_GetAttributeValue`): every attribute type, and
    /// the values that [`Detail::template`] reads only when the call filled them
    /// ([`Detail::ok`]). Otherwise, the buffers hold whatever the caller left there.
    ///
    /// # Safety
    ///
    /// As [`Detail::template`].
    pub(crate) unsafe fn filled_template(&mut self, template: *const CK_ATTRIBUTE, count: CK_ULONG) {
        // SAFETY: the caller's contract, passed on.
        unsafe { self.read_template(template, count, self.ok) };
        let Ok(count) = usize::try_from(count) else { return };
        if !self.ok || template.is_null() || count == 0 || self.record.attributes.is_empty() {
            return;
        }
        // SAFETY: not null, and the caller's contract makes it `count` readable entries, each
        // value filled to its length by the call.
        for e in unsafe { std::slice::from_raw_parts(template, count) } {
            let Ok(len) = usize::try_from(e.ulValueLen) else { continue };
            if self.record.attributes.contains(&e.type_) && !e.pValue.is_null() && e.ulValueLen != CK_ULONG::MAX {
                // SAFETY: the call filled `ulValueLen` bytes there.
                let value = unsafe { std::slice::from_raw_parts(e.pValue.cast::<u8>(), len) };
                self.values.push((e.type_, value.to_vec()));
            }
        }
    }

    /// Returns the attribute values that were recorded.
    #[cfg(test)]
    pub(crate) fn values(&self) -> &[(CK_ATTRIBUTE_TYPE, Vec<u8>)] {
        &self.values
    }

    /// Returns the data and the signature of `C_Sign` that were recorded.
    #[cfg(test)]
    pub(crate) fn recorded_signature(&self) -> Option<&(Vec<u8>, Vec<u8>)> {
        self.signed.as_ref()
    }

    /// Records the data of `C_Sign` and the signature that it returned, when they may be
    /// recorded ([`Detail::record`]) and the call filled the signature.
    ///
    /// # Safety
    ///
    /// `data` is null or `data_len` readable bytes; `signature_len` null or readable, and
    /// `signature` null or that many readable bytes once the call has filled them.
    pub(crate) unsafe fn signed(
        &mut self,
        data: *const CK_BYTE,
        data_len: CK_ULONG,
        signature: *const CK_BYTE,
        signature_len: *const CK_ULONG,
    ) {
        if !self.ok || !self.record.signed || data.is_null() || signature.is_null() || signature_len.is_null() {
            return;
        }
        // SAFETY: as the contract says; the call wrote the signature's length and bytes.
        unsafe {
            let (Ok(n), Ok(m)) = (usize::try_from(data_len), usize::try_from(*signature_len)) else { return };
            let read = |p: *const CK_BYTE, n: usize| std::slice::from_raw_parts(p, n).to_vec();
            self.signed = Some((read(data, n), read(signature, m)));
        }
    }

    /// Does what [`Detail::template`] does, but reads the values only when `values` is true.
    ///
    /// # Safety
    ///
    /// As [`Detail::template`].
    unsafe fn read_template(&mut self, template: *const CK_ATTRIBUTE, count: CK_ULONG, values: bool) {
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
            if values && !e.pValue.is_null() && usize::try_from(e.ulValueLen) == Ok(size_of::<CK_ULONG>()) {
                // SAFETY: `pValue` holds `ulValueLen` readable bytes, one `CK_ULONG`, perhaps
                // unaligned.
                list.push(unsafe { e.pValue.cast::<CK_ULONG>().read_unaligned() });
            }
        }
    }
}

/// Returns `bytes` in lower-case hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl Trace {
    /// Opens `path`, which the variable `var` named, for appending. `shim` is this copy's tag.
    pub(crate) fn open(var: &str, path: &Path, shim: Option<String>) -> Result<Trace, Fatal> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Fatal(format!("{var} {}: {e}", path.display())))?;
        let exe = std::env::current_exe().ok().and_then(|p| Some(p.file_name()?.to_string_lossy().into_owned()));
        Ok(Trace { file: Mutex::new(file), exe, shim })
    }

    /// Logs `call`, the value that its caller saw, the plan's rule (counted from 1) that decided
    /// it, if any, and what the call was about. A write that fails is dropped, because the trace
    /// must never change what the caller sees.
    pub(crate) fn line(&self, call: &Call, rv: CK_RV, rule: Option<usize>, detail: &Detail) {
        let mut line = serde_json::json!({
            "pid": std::process::id(),
            "seq": call.seq,
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
        if let Some(fatal) = &detail.fatal {
            fields.insert("fatal".into(), fatal.as_str().into());
        }
        let numbers = [
            ("mechanism", detail.mechanism),
            ("hash", detail.hash),
            ("mgf", detail.mgf),
            ("source", detail.source),
            ("kdf", detail.kdf),
            ("user", detail.user),
            ("flags", detail.flags),
            ("init_flags", detail.init_flags),
            ("slot_flags", detail.slot_flags),
            ("token_flags", detail.token_flags),
            ("mechanism_flags", detail.mechanism_flags),
        ];
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
        if !detail.values.is_empty() {
            let values: Vec<_> = detail.values.iter().map(|(t, v)| serde_json::json!([t, hex(v)])).collect();
            fields.insert("values".into(), values.into());
        }
        if let Some((data, signature)) = &detail.signed {
            fields.insert("signed".into(), serde_json::json!({"data": hex(data), "signature": hex(signature)}));
        }
        // The line is written with one write, so the processes that share the file (O_APPEND)
        // interleave whole lines. `writeln!` makes one write for each formatted piece, and with
        // it the processes interleaved parts of lines.
        let mut text = line.to_string();
        text.push('\n');
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(text.as_bytes());
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
            // A length query has the type and no value.
            entry(CKA_KEY_TYPE, std::ptr::null_mut(), 0),
        ];
        let mut d = Detail::default();
        // SAFETY: four entries, each value null or as long as it says.
        unsafe { d.template(template.as_ptr(), 4) };
        assert_eq!(d.attributes, [CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_KEY_TYPE]);
        assert_eq!((&d.classes[..], &d.key_types[..]), (&[CKO_PRIVATE_KEY][..], &[CKK_EC][..]));
        // SAFETY: a null template is read as no template.
        unsafe { d.template(std::ptr::null(), 3) };
    }

    /// A template that the call fills gives its values only when the call filled it. A failed
    /// `C_GetAttributeValue` leaves the caller's buffers as they were, and their contents are
    /// meaningless to a reader.
    #[test]
    fn a_filled_template_gives_values_only_when_filled() {
        let mut class = CKO_PRIVATE_KEY;
        let template = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: (&raw mut class).cast(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>()).unwrap(),
        }];
        for ok in [false, true] {
            let mut d = Detail { ok, ..Detail::default() };
            // SAFETY: one entry, its value as long as it says.
            unsafe { d.filled_template(template.as_ptr(), 1) };
            assert_eq!(d.attributes, [CKA_CLASS]);
            assert_eq!(d.classes, if ok { vec![CKO_PRIVATE_KEY] } else { vec![] }, "ok = {ok}");
        }
    }
}
