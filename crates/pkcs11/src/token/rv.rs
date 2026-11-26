//! `CK_RV`: its names, its values, and the errors a failed call becomes (review 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// The `CKR_*` name of a module's failure: cryptoki's `Display` is the spec's prose, which
/// changes with the binding, so a message (and a profile row's evidence) names the return value
/// by its constant; `CKR 0x…` for a value no constant has.
#[must_use]
pub fn rv_name(e: &CkError) -> String {
    match e {
        CkError::Pkcs11(rv, _) => rv_error_name(*rv),
        other => other.to_string(),
    }
}

/// The `CKR_*` constant an `RvError` stands for: the name derived from its variant
/// (`GeneralError` -> `CKR_GENERAL_ERROR`); a value cryptoki has no variant for by `p11-names`'
/// table (a 3.2 code an unpatched binding lacks), else `CKR 0x…`.
pub(super) fn rv_error_name(rv: RvError) -> String {
    match rv {
        RvError::VendorDefined(v) | RvError::UnknownErrorCode(v) => rv_value_name(v),
        rv => derived_name(rv),
    }
}

/// The return value behind cryptoki's `RvError`: its constant's value in `p11-names`' table,
/// which `cryptoki-sys` defines, so every build carries it, patched binding or not (review
/// 2026-11-23 B-6); `every_variant_has_its_value` holds the table complete.
#[must_use]
pub fn rv_value(rv: RvError) -> Option<cryptoki_sys::CK_RV> {
    match rv {
        RvError::VendorDefined(v) | RvError::UnknownErrorCode(v) => Some(v),
        rv => p11_names::rv(&derived_name(rv)),
    }
}

/// A name from `RvError`'s variant (`GeneralError` -> `CKR_GENERAL_ERROR`): every variant is
/// named after its constant.
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

/// The return value of a failed module call, for [`KmError::with_rv`]: what code matches on
/// (ISSUES.md Q3), where the message names it for people.
#[must_use]
pub fn rv_of(e: &CkError) -> Option<u64> {
    match e {
        CkError::Pkcs11(rv, _) => rv_value(*rv),
        _ => None,
    }
}

/// One attribute read: the attribute, `None` when the module has none to show (absent or
/// sensitive, which cryptoki leaves out of the result), and any other failure `Unavailable` with
/// the module's return value. A failed read is never taken for "none": a missing `CKA_LABEL`
/// would pass over ykcs11's attestation certificate, or widen tpm2-pkcs11's store row search.
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

/// Whether the return value an error carries (`KmError::rv`, `Msg::rv`) is `want`.
#[must_use]
pub fn rv_is(rv: Option<u64>, want: RvError) -> bool {
    rv.is_some_and(|v| Rv::from(v) == Rv::Error(want))
}

/// The `CKR_*` name of a return value an error carries; `CKR 0x…` for one with no name.
#[must_use]
pub fn rv_value_name(v: u64) -> String {
    p11_names::rv_name(v).map_or_else(|| format!("CKR {v:#x}"), str::to_owned)
}

/// What an SO login that fails says first: a module step that needs the Security Officer
/// cannot run, and the probe stops there instead of recording a row.
pub const SO_LOGIN: &str = "C_Login (SO)";

pub(super) fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}").into()).with_rv(rv_of(&e))
}

/// Whether `e` says the device, the token or the session failed, rather than anything of the
/// object or attribute asked for. Matched on cryptoki's error, the variant it has.
#[must_use]
pub fn device_failed(e: &CkError) -> bool {
    matches!(e, CkError::Pkcs11(rv, _) if device_error(*rv))
}

/// Whether the return value `rv`, as an error carries it ([`KmError::rv`]), is one of
/// [`device_failed`]'s: what a row's `device` says (review 2026-11-24 C-1), a failure no dry
/// run can foresee.
#[must_use]
pub fn device_failed_rv(rv: u64) -> bool {
    matches!(Rv::from(rv), Rv::Error(e) if device_error(e))
}

/// A module's refusal of what was asked, `msg` carrying the failed call's return value
/// ([`rv_of`]): `refused`'s verdict on it (unsupported, 15), unless the return value says the
/// device, the token or the session failed ([`device_failed_rv`]), which answers nothing of what
/// was asked: then unavailable (16), as the row's `device` says. The one mapping every refusal
/// made from a module's error goes through (review 2026-11-24 L4a-1: a commitment's device
/// failure was said unsupported).
pub fn refused_unless_device(msg: Msg, refused: impl FnOnce(Msg) -> KmError) -> KmError {
    if msg.rv().is_some_and(device_failed_rv) { KmError::Unavailable(msg) } else { refused(msg) }
}

/// [`device_failed`]'s return values: those `cakeys_profile::DEVICE_FAILED_RV` names, so a
/// profile row citing one and the token's own error agree (phase1-design §2.5).
fn device_error(rv: RvError) -> bool {
    cakeys_profile::DEVICE_FAILED_RV.contains(&rv_error_name(rv).as_str())
}

/// An optional attribute read: `None` where the object lacks the attribute or the module
/// refuses to read it (ykcs11 refuses `CKA_PUBLIC_KEY_INFO` with `CKR_ARGUMENTS_BAD`, a build
/// may not name a mechanism). A failure of the device, token or session ([`device_failed`]) is
/// still unavailable (16), never read as the attribute's absence: a policy flag left out read
/// as a changed key (14), a public key object's point as another key (13) (review D7).
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

    /// A failed attribute read is unavailable (16) with the module's return value, never "none";
    /// an attribute the module has none of is `None` (the providers' attestation lookups).
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

    /// Every return value cryptoki has a variant for converts back to itself through the name
    /// derived from the variant, and is named by it: `p11-names`' table covers every variant, in
    /// every build (review 2026-11-23 B-6).
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

    /// The device-failure names the profile loader reads (`DEVICE_FAILED_RV`) are each a real
    /// `CKR_*` this build has a variant for, and are exactly what [`device_failed`] matches: the
    /// eleven the token crate listed by variant before (phase1-design §2.5).
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
        for name in cakeys_profile::DEVICE_FAILED_RV {
            let v = p11_names::rv(name).unwrap_or_else(|| panic!("{name} is no CKR_*"));
            let Rv::Error(rv) = Rv::from(v) else { panic!("{name}") };
            assert!(pinned.contains(&rv), "{name}");
            assert!(device_failed(&CkError::Pkcs11(rv, Function::Initialize)), "{name}");
            assert!(device_failed_rv(v), "{name}");
        }
        assert_eq!(pinned.len(), cakeys_profile::DEVICE_FAILED_RV.len());
        let refused = CkError::Pkcs11(RvError::MechanismInvalid, Function::GenerateKey);
        assert!(!device_failed(&refused));
    }

    /// A refusal made from a module's error is the verdict asked for only when the module
    /// answered: every return value of a failed device, token or session is unavailable (16),
    /// whatever the caller would say, and every other is the caller's, its return value kept
    /// either way (review 2026-11-24 L4a-1: a commitment's device failure was unsupported).
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
        for name in cakeys_profile::DEVICE_FAILED_RV {
            assert!(matches!(unsupported(p11_names::rv(name).unwrap()), KmError::Unavailable(_)), "{name}");
        }
        let none = refused_unless_device(Msg::from("no call".to_owned()), KmError::Unsupported);
        assert!(matches!(none, KmError::Unsupported(_)), "{none:?}");
    }

    #[test]
    fn values_without_a_variant_go_by_their_value() {
        let vendor = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::Initialize);
        assert_eq!(rv_name(&vendor), "CKR 0x80000001");
        // A value no constant has.
        assert_eq!(rv_value_name(0x20f), "CKR 0x20f");
        // CKR_TOKEN_NOT_INITIALIZED (PKCS#11 3.2): a variant only the patch adds, named by
        // `p11-names` either way.
        assert_eq!(rv_value_name(0x208), "CKR_TOKEN_NOT_INITIALIZED");
        assert_eq!(rv_value_name(0x30), "CKR_DEVICE_ERROR");
        assert_eq!(rv_value_name(0), "CKR_OK");
    }
}
