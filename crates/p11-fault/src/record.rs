//! With `P11_FAULT_RECORD_VALUES=public`, the trace records the values that a test compares with
//! what the token holds, and only the values that are public: a public key's point, modulus,
//! exponent and parameters, a key's `CKA_PUBLIC_KEY_INFO` and TPM2 public blob, a certificate's
//! value, and the nonce and signature of a TPM2 certification. It never records a secret value:
//! no `CKA_VALUE` except a certificate's, no template that a caller sends (because a template may
//! carry key material), and no signature except a certification's. The trace file must not
//! hold secrets, because the traces of a test run are kept.

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

/// The `CKA_TPM2_PUB_BLOB` attribute of tpm2-pkcs11, which holds the key's `TPM2B_PUBLIC` (see
/// the crate's vendor.rs).
const CKA_TPM2_PUB_BLOB: CK_ATTRIBUTE_TYPE = 0x8F00_0002;
/// The `CKM_TPM2_CERTIFY` and `CKM_TPM2_CERTIFY_OBJECT` mechanisms of tpm2-pkcs11. With them,
/// `C_Sign` certifies a key: its data is the nonce (the qualifying data), and its signature is
/// the attestation's signature.
const CKM_TPM2_CERTIFY: CK_MECHANISM_TYPE = 0x8F00_0001;
const CKM_TPM2_CERTIFY_OBJECT: CK_MECHANISM_TYPE = 0x8F00_0003;

/// The attributes whose values `C_GetAttributeValue` may record, on any object.
pub(crate) const PUBLIC: [CK_ATTRIBUTE_TYPE; 6] =
    [CKA_EC_POINT, CKA_EC_PARAMS, CKA_PUBLIC_KEY_INFO, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_TPM2_PUB_BLOB];

/// The values that one call's trace line may record. By default, it records none.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Recording {
    /// The attribute types whose values, as `C_GetAttributeValue` returned them, are recorded.
    pub(crate) attributes: Vec<CK_ATTRIBUTE_TYPE>,
    /// Whether the data and the signature of `C_Sign` are recorded.
    pub(crate) signed: bool,
}

/// Returns what `function` may record. `certificate` is true when the object that
/// `C_GetAttributeValue` reads is a certificate, and `certify` is true when the operation that
/// `C_Sign` ends is a TPM2 certification.
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

/// The recorder that `P11_FAULT_RECORD_VALUES=public` turns on. It holds the mechanism of each
/// session's latest `C_SignInit`, so that it can tell a certification's `C_Sign` from any other
/// `C_Sign`.
#[derive(Default)]
pub(crate) struct Recorder(Mutex<BTreeMap<CK_SESSION_HANDLE, CK_MECHANISM_TYPE>>);

impl Recorder {
    /// Returns the recorder that the variable `var` asks for with `value`. `traced` is true when
    /// a trace is written.
    ///
    /// # Errors
    ///
    /// Refuses any value other than `public`, and `public` when there is no trace to record
    /// into. The value is refused and never ignored, so that a test that asks for values never
    /// reads a trace without them.
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

    /// Returns what the call of `function` may record after it has returned. `about` describes
    /// the call, as it was read before the call, and `ok` is true when the call returned
    /// `CKR_OK`. The object's class is read from the real module when the template asks for
    /// `CKA_VALUE`.
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

    /// No secret is ever recorded. Of all functions, only `C_GetAttributeValue` records
    /// attribute values, and only the values of the public attributes (and a certificate's
    /// value). Only a certification's `C_Sign` records its data and signature. When the trace's
    /// own reader reads every attribute that p11-names knows, on an object of every class, a
    /// value appears only where it is public. A value other than `public`, or no trace, is
    /// refused.
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
        // A certification's nonce and signature are recorded, and no other signing's.
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
