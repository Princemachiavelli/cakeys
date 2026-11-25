//! `P11_FAULT_RECORD_VALUES=public`: the trace records the values a test compares with what the
//! token holds, and only those that are public: a public key's point, modulus, exponent and
//! parameters, a key's `CKA_PUBLIC_KEY_INFO` and TPM2 public blob, a certificate's value, and
//! the nonce and signature of a TPM2 certification. Never a secret's: no `CKA_VALUE` but a
//! certificate's, no template a caller sends (it may carry key material), no signature but a
//! certification's. The trace file is no place for secrets, and a test run's traces are kept.

use crate::forward::Fn;
use crate::trace::Detail;
use crate::{Fatal, Shim, hooks};
use cryptoki_sys::{
    CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE, CK_SESSION_HANDLE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS,
    CKA_PUBLIC_EXPONENT, CKA_PUBLIC_KEY_INFO, CKA_VALUE, CKO_CERTIFICATE,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::{Mutex, PoisonError};

/// tpm2-pkcs11's `CKA_TPM2_PUB_BLOB`: the key's `TPM2B_PUBLIC` (its vendor.rs).
const CKA_TPM2_PUB_BLOB: CK_ATTRIBUTE_TYPE = 0x8F00_0002;
/// tpm2-pkcs11's `CKM_TPM2_CERTIFY` and `CKM_TPM2_CERTIFY_OBJECT`: `C_Sign` certifies a key, its
/// data the nonce (qualifying data), its signature the attestation's.
const CKM_TPM2_CERTIFY: CK_MECHANISM_TYPE = 0x8F00_0001;
const CKM_TPM2_CERTIFY_OBJECT: CK_MECHANISM_TYPE = 0x8F00_0003;

/// The attributes `C_GetAttributeValue` may record the value of, on any object.
pub(crate) const PUBLIC: [CK_ATTRIBUTE_TYPE; 6] =
    [CKA_EC_POINT, CKA_EC_PARAMS, CKA_PUBLIC_KEY_INFO, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_TPM2_PUB_BLOB];

/// What one call's trace line may record the values of: nothing, by default.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Recording {
    /// The attribute types whose values a `C_GetAttributeValue` returned are recorded.
    pub(crate) attributes: Vec<CK_ATTRIBUTE_TYPE>,
    /// `C_Sign`'s data and signature are recorded.
    pub(crate) signed: bool,
}

/// What `function` may record: `certificate`, the object `C_GetAttributeValue` reads is a
/// certificate; `certify`, the operation `C_Sign` ends is a TPM2 certification.
#[must_use]
pub(crate) fn allowed(function: Fn, certificate: bool, certify: bool) -> Recording {
    match function {
        Fn::C_GetAttributeValue => {
            let mut attributes = PUBLIC.to_vec();
            if certificate {
                attributes.push(CKA_VALUE);
            }
            Recording { attributes, signed: false }
        }
        Fn::C_Sign if certify => Recording { attributes: Vec::new(), signed: true },
        _ => Recording::default(),
    }
}

/// The recorder `P11_FAULT_RECORD_VALUES=public` turns on: the mechanism of each session's
/// latest `C_SignInit`, to tell a certification's `C_Sign` from another.
#[derive(Default)]
pub(crate) struct Recorder(Mutex<BTreeMap<CK_SESSION_HANDLE, CK_MECHANISM_TYPE>>);

impl Recorder {
    /// The recorder the variable `var` asks for with `value`; `traced`, a trace is written.
    ///
    /// # Errors
    ///
    /// Any value but `public`, or `public` with no trace to record into: refused, never ignored,
    /// so that a test that asks for values never reads a trace without them.
    pub(crate) fn new(var: &str, value: Option<OsString>, traced: bool) -> Result<Option<Recorder>, Fatal> {
        match value {
            None => Ok(None),
            Some(v) if v != "public" => {
                Err(Fatal(format!("{var} = {}: only \"public\" (no secret is ever recorded)", v.to_string_lossy())))
            }
            Some(_) if !traced => Err(Fatal(format!("{var} = public: no P11_FAULT_TRACE to record into"))),
            Some(_) => Ok(Some(Recorder::default())),
        }
    }

    /// What the call of `function` that `about` describes (read before it) may record, once it
    /// has returned (`ok`: with `CKR_OK`). The object's class is read from the real module when
    /// the template asks for `CKA_VALUE`.
    pub(crate) fn recording(&self, shim: &Shim, function: Fn, about: &Detail, ok: bool) -> Recording {
        let Some(session) = about.session else { return Recording::default() };
        let mut signing = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if function == Fn::C_SignInit
            && ok
            && let Some(mechanism) = about.mechanism
        {
            signing.insert(session, mechanism);
        }
        let certify = matches!(signing.get(&session), Some(&(CKM_TPM2_CERTIFY | CKM_TPM2_CERTIFY_OBJECT)));
        drop(signing);
        let certificate = function == Fn::C_GetAttributeValue
            && about.attributes.contains(&CKA_VALUE)
            && about.objects.first().is_some_and(|&object| {
                // SAFETY: a real-module call on the caller's session and handle, in its call.
                (unsafe { hooks::class_of(shim, session, object) }) == Some(CKO_CERTIFICATE)
            });
        allowed(function, certificate, certify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::{CK_ATTRIBUTE, CK_ULONG};

    /// No secret is ever recorded: of every function, only `C_GetAttributeValue` records
    /// attribute values, and those only of the public attributes (a certificate's value
    /// besides); only a certification's `C_Sign` records its data and signature. Through the
    /// trace's own reader, every attribute p11-names knows, on an object of every class, comes
    /// out only where it is public. A value but `public`, or no trace, is refused.
    #[test]
    fn record_values_refuses_secrets() {
        for &function in Fn::ALL {
            for (certificate, certify) in [(false, false), (false, true), (true, false), (true, true)] {
                let r = allowed(function, certificate, certify);
                let getter = function == Fn::C_GetAttributeValue;
                assert!(
                    r.attributes.iter().all(|a| getter && (PUBLIC.contains(a) || (certificate && *a == CKA_VALUE)))
                );
                assert_eq!(r.signed, function == Fn::C_Sign && certify, "{}", function.name());
            }
        }
        for &(class_name, class) in crate::names::CLASS {
            let mut values: Vec<[u8; 4]> = crate::names::ATTRIBUTE.iter().map(|_| [1, 2, 3, 4]).collect();
            let template: Vec<CK_ATTRIBUTE> = crate::names::ATTRIBUTE
                .iter()
                .zip(&mut values)
                .map(|(&(_, type_), v)| CK_ATTRIBUTE { type_, pValue: v.as_mut_ptr().cast(), ulValueLen: 4 })
                .collect();
            let mut detail = Detail::default();
            detail.ok = true;
            detail.record = allowed(Fn::C_GetAttributeValue, class == CKO_CERTIFICATE, false);
            // SAFETY: a template of ours, each value four bytes.
            unsafe { detail.filled_template(template.as_ptr(), template.len() as CK_ULONG) };
            for (type_, _) in detail.values() {
                let name = crate::names::ATTRIBUTE.iter().find(|(_, t)| t == type_).map_or("?", |(n, _)| n);
                let public = PUBLIC.contains(type_) || (class == CKO_CERTIFICATE && *type_ == CKA_VALUE);
                assert!(public, "{name} of a {class_name} recorded");
            }
            let public = |t: &CK_ATTRIBUTE_TYPE| PUBLIC.contains(t) || (class == CKO_CERTIFICATE && *t == CKA_VALUE);
            let want = crate::names::ATTRIBUTE.iter().filter(|(_, t)| public(t)).count();
            assert_eq!(detail.values().len(), want, "{class_name}: each public attribute p11-names knows");
        }
        // A certification's nonce and signature, and no other signing's.
        for (certify, want) in [(true, Some((vec![1, 2], vec![3, 4, 5]))), (false, None)] {
            let (data, signature, n) = ([1u8, 2], [3u8, 4, 5], 3 as CK_ULONG);
            let mut detail = Detail::default();
            detail.ok = true;
            detail.record = allowed(Fn::C_Sign, false, certify);
            // SAFETY: buffers of ours, as long as they say.
            unsafe { detail.signed(data.as_ptr(), 2, signature.as_ptr(), &raw const n) };
            assert_eq!(detail.recorded_signature(), want.as_ref(), "certify {certify}");
        }
        let refused = |value: Option<&str>, traced| {
            Recorder::new("P11_FAULT_RECORD_VALUES", value.map(OsString::from), traced).err().map(|f| f.0)
        };
        assert!(refused(Some("all"), true).is_some_and(|f| f.contains("only \"public\"")));
        assert!(refused(Some("secret"), true).is_some_and(|f| f.contains("only \"public\"")));
        assert!(refused(Some("public"), false).is_some_and(|f| f.contains("no P11_FAULT_TRACE")));
        assert_eq!((refused(None, false), refused(Some("public"), true)), (None, None));
    }
}
