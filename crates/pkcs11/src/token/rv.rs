//! `CK_RV`: its names, its values, and the errors into which a failed call is turned (review
//! 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// Returns the `CKR_*` name of a module's failure, or `CKR 0x…` for a value that has no
/// constant. cryptoki's `Display` prints the specification's prose, which changes with the
/// binding, so a message (and a profile row's evidence) names the return value by its constant.
#[must_use]
pub fn rv_name(e: &CkError) -> String {
    match e {
        CkError::Pkcs11(rv, _) => rv_error_name(*rv),
        other => other.to_string(),
    }
}

/// Returns the name of the `CKR_*` constant that an `RvError` stands for. For a variant, the
/// name is derived from the variant (`GeneralError` -> `CKR_GENERAL_ERROR`). For a value for
/// which cryptoki has no variant (for example, a 3.2 code that an unpatched binding lacks), the
/// name comes from the table of `p11-names`, or is `CKR 0x…` when the table has no name.
pub(super) fn rv_error_name(rv: RvError) -> String {
    match rv {
        RvError::VendorDefined(v) | RvError::UnknownErrorCode(v) => rv_value_name(v),
        rv => derived_name(rv),
    }
}

/// Returns the return value behind cryptoki's `RvError`. The value of the constant comes from
/// the table of `p11-names`, which `cryptoki-sys` defines, so every build has it, whether or not
/// the binding is patched (review 2026-11-23 B-6). The test `every_variant_has_its_value` checks
/// that the table is complete.
#[must_use]
pub fn rv_value(rv: RvError) -> Option<cryptoki_sys::CK_RV> {
    match rv {
        RvError::VendorDefined(v) | RvError::UnknownErrorCode(v) => Some(v),
        rv => p11_names::rv(&derived_name(rv)),
    }
}

/// Derives a name from the variant of `RvError` (`GeneralError` -> `CKR_GENERAL_ERROR`). This
/// works because every variant is named after its constant.
pub(super) fn derived_name(rv: RvError) -> String {
    let mut out = String::from("CKR");
    for c in format!("{rv:?}").chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// Returns the return value of a failed module call, for [`KmError::with_rv`]. Code matches on
/// this value (ISSUES.md Q3), and the message names it for people.
#[must_use]
pub fn rv_of(e: &CkError) -> Option<u64> {
    match e {
        CkError::Pkcs11(rv, _) => rv_value(*rv),
        _ => None,
    }
}

/// Returns the result of one attribute read. It returns the attribute, or `None` when the module
/// has no value to show (the attribute is absent or sensitive, and cryptoki leaves it out of the
/// result). Any failure is `Unavailable`, with the module's return value. A failed read is never
/// treated as "none", because a missing `CKA_LABEL` would skip ykcs11's attestation certificate,
/// or widen the store row search of tpm2-pkcs11.
///
/// # Errors
///
/// `Unavailable` when `C_GetAttributeValue` fails.
pub fn read_attribute(what: &str, read: std::result::Result<Vec<Attribute>, CkError>) -> Result<Option<Attribute>> {
    match read {
        Ok(v) => Ok(v.into_iter().next()),
        Err(e) => Err(KmError::Unavailable(Msg::from(format!("C_GetAttributeValue ({what}): {e}")).with_rv(rv_of(&e)))),
    }
}

/// Returns whether the return value that an error carries (`KmError::rv`, `Msg::rv`) is `want`.
#[must_use]
pub fn rv_is(rv: Option<u64>, want: RvError) -> bool {
    rv.is_some_and(|v| Rv::from(v) == Rv::Error(want))
}

/// Returns the `CKR_*` name of a return value that an error carries, or `CKR 0x…` for a value
/// that has no name.
#[must_use]
pub fn rv_value_name(v: u64) -> String {
    p11_names::rv_name(v).map_or_else(|| format!("CKR {v:#x}"), str::to_owned)
}

/// The start of the message of a failed SO login. When this login fails, a module step that
/// needs the Security Officer cannot run, and the probe stops there instead of recording a
/// row.
pub const SO_LOGIN: &str = "C_Login (SO)";

pub(super) fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}").into()).with_rv(rv_of(&e))
}

/// Returns whether `e` says that the device, the token or the session failed, as opposed to a
/// problem with the requested object or attribute. The function matches on cryptoki's error
/// variant.
#[must_use]
pub fn device_failed(e: &CkError) -> bool {
    matches!(e, CkError::Pkcs11(rv, _) if device_error(*rv))
}

/// Returns whether the return value `rv`, as an error carries it ([`KmError::rv`]), is one of
/// the values that [`device_failed`] matches. This is what a row's `device` field means (review
/// 2026-11-24 C-1): a failure that no dry run can predict.
#[must_use]
pub fn device_failed_rv(rv: u64) -> bool {
    matches!(Rv::from(rv), Rv::Error(e) if device_error(e))
}

/// Returns the error for a module's refusal of a request. `msg` carries the failed call's return
/// value ([`rv_of`]). The result is the verdict of `refused` (unsupported, exit 15), unless the
/// return value says that the device, the token or the session failed ([`device_failed_rv`]).
/// Such a failure gives no answer to the request, so the result is then unavailable (exit 16),
/// as the row's `device` field says. Every refusal that is made from a module's error goes
/// through this one mapping (review 2026-11-24 L4a-1: a commitment's device failure was reported
/// as unsupported).
pub fn refused_unless_device(msg: Msg, refused: impl FnOnce(Msg) -> KmError) -> KmError {
    if msg.rv().is_some_and(device_failed_rv) { KmError::Unavailable(msg) } else { refused(msg) }
}

/// Returns whether `rv` is one of the return values that [`device_failed`] matches. These are
/// the values that the names table lists (`cakeys_names::DEVICE_FAILED_RV`), so that a profile
/// row that cites one of them and the token's own error agree (phase1-design §2.5). This crate
/// reads cryptoki's error only to get its name.
fn device_error(rv: RvError) -> bool {
    cakeys_names::is_device_failure(&rv_error_name(rv))
}

/// Reads an optional attribute. Returns `None` when the object lacks the attribute or when the
/// module refuses to read it (ykcs11 refuses `CKA_PUBLIC_KEY_INFO` with `CKR_ARGUMENTS_BAD`, and
/// a build may be unable to name a mechanism). A failure of the device, the token or the session
/// ([`device_failed`]) is still unavailable (exit 16), and it is never treated as the absence of
/// the attribute (review D7). Otherwise, a policy flag that was left out would be reported as a
/// changed key (exit 14), and a missing point of a public key object would be reported as
/// another key (exit 13).
pub(super) fn if_readable<T>(read: std::result::Result<Option<T>, CkError>) -> Result<Option<T>> {
    match read {
        Ok(v) => Ok(v),
        Err(e) if device_failed(&e) => Err(ck("C_GetAttributeValue")(e)),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    /// A failed attribute read is unavailable (exit 16) with the module's return value, and it is
    /// never "none". An attribute for which the module has no value is `None` (the providers'
    /// attestation lookups depend on this).
    #[test]
    fn a_failed_attribute_read_is_unavailable() {
        let failed = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::GetAttributeValue);
        let e = read_attribute("CKA_LABEL", Err(failed)).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("CKA_LABEL")), "{e}");
        assert_eq!(e.rv(), Some(0x8000_0001));
        assert_eq!(read_attribute("CKA_LABEL", Ok(vec![])).unwrap(), None);
        let label = Attribute::Label(b"k".to_vec());
        assert_eq!(read_attribute("CKA_LABEL", Ok(vec![label.clone()])).unwrap(), Some(label));
    }

    /// Every return value for which cryptoki has a variant converts back to itself through the
    /// name derived from the variant, and that name is its name. This shows that the table of
    /// `p11-names` covers every variant in every build (review 2026-11-23 B-6).
    #[test]
    fn every_variant_has_its_value() {
        for v in 1..0x1000 {
            let Rv::Error(rv) = Rv::from(v) else { continue };
            if matches!(rv, RvError::UnknownErrorCode(_)) {
                continue;
            }
            assert_eq!(rv_value(rv), Some(v), "{rv:?} ({v:#x})");
            assert_eq!(rv_value_name(v), derived_name(rv), "{v:#x}");
        }
    }

    /// Each device-failure name that the profile loader reads (`DEVICE_FAILED_RV`) is a real
    /// `CKR_*` constant for which this build has a variant. Together they are exactly what
    /// [`device_failed`] matches: the eleven values that the token crate listed by variant before
    /// (phase1-design §2.5).
    #[test]
    fn the_device_failures_are_one_list() {
        let pinned = [
            RvError::DeviceError,
            RvError::DeviceMemory,
            RvError::DeviceRemoved,
            RvError::HostMemory,
            RvError::GeneralError,
            RvError::TokenNotPresent,
            RvError::TokenNotRecognized,
            RvError::SessionClosed,
            RvError::SessionHandleInvalid,
            RvError::CryptokiNotInitialized,
            RvError::FunctionCanceled,
        ];
        for name in cakeys_names::DEVICE_FAILED_RV {
            let v = p11_names::rv(name).unwrap_or_else(|| panic!("{name} is no CKR_*"));
            let Rv::Error(rv) = Rv::from(v) else { panic!("{name}") };
            assert!(pinned.contains(&rv), "{name}");
            assert!(device_failed(&CkError::Pkcs11(rv, Function::Initialize)), "{name}");
            assert!(device_failed_rv(v), "{name}");
        }
        assert_eq!(pinned.len(), cakeys_names::DEVICE_FAILED_RV.len());
        let refused = CkError::Pkcs11(RvError::MechanismInvalid, Function::GenerateKey);
        assert!(!device_failed(&refused));
    }

    /// A refusal made from a module's error gets the requested verdict only when the module
    /// answered. Every return value of a failed device, token or session is unavailable (exit
    /// 16), whatever the caller would say. Every other return value gets the caller's verdict. The
    /// return value is kept in both cases (review 2026-11-24 L4a-1: a commitment's device failure
    /// was reported as unsupported).
    #[test]
    fn a_device_failure_is_never_a_refusal() {
        let unsupported =
            |v: u64| refused_unless_device(Msg::from("asked".to_owned()).with_rv(Some(v)), KmError::Unsupported);
        for v in 1..0x1000 {
            let e = unsupported(v);
            assert_eq!(e.rv(), Some(v), "{v:#x}");
            assert_eq!(matches!(e, KmError::Unavailable(_)), device_failed_rv(v), "{}: {e:?}", rv_value_name(v));
            assert_eq!(matches!(e, KmError::Unsupported(_)), !device_failed_rv(v), "{}: {e:?}", rv_value_name(v));
        }
        for name in cakeys_names::DEVICE_FAILED_RV {
            assert!(matches!(unsupported(p11_names::rv(name).unwrap()), KmError::Unavailable(_)), "{name}");
        }
        let none = refused_unless_device(Msg::from("no call".to_owned()), KmError::Unsupported);
        assert!(matches!(none, KmError::Unsupported(_)), "{none:?}");
    }

    #[test]
    fn values_without_a_variant_go_by_their_value() {
        let vendor = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::Initialize);
        assert_eq!(rv_name(&vendor), "CKR 0x80000001");
        // A value that no constant has.
        assert_eq!(rv_value_name(0x20f), "CKR 0x20f");
        // `CKR_TOKEN_NOT_INITIALIZED` (PKCS#11 3.2) is a variant that only the patch adds, and
        // `p11-names` names it in both cases.
        assert_eq!(rv_value_name(0x208), "CKR_TOKEN_NOT_INITIALIZED");
        assert_eq!(rv_value_name(0x30), "CKR_DEVICE_ERROR");
        assert_eq!(rv_value_name(0), "CKR_OK");
    }
}
