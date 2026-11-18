//! tpm2-pkcs11's P-521 `CKA_EC_POINT` fix-up on any bytes: what it repairs is DER of the same
//! point, what it leaves alone is the input, and a repaired value is left alone. Never a panic.
#![no_main]

use cakeys_tpm2_pkcs11::fix_ec_point;
use libfuzzer_sys::fuzz_target;
use std::borrow::Cow;

fuzz_target!(|raw: &[u8]| {
    match fix_ec_point(raw) {
        Cow::Borrowed(same) => assert_eq!(same, raw),
        Cow::Owned(fixed) => {
            // `04 81 <len> <len bytes>`: the long form of the length the input wrote short.
            assert_eq!(&fixed[..2], &[0x04, 0x81]);
            assert_eq!(usize::from(fixed[2]), fixed.len() - 3);
            assert_eq!(&fixed[3..], &raw[2..]);
            assert!(matches!(fix_ec_point(&fixed), Cow::Borrowed(_)), "a repaired point is repaired again");
        }
    }
});
