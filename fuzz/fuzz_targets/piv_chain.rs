//! A YubiKey PIV attestation chain, as `check` verifies it: a slot certificate and the device
//! certificate that signed it, to Yubico's pinned roots and the test fixture's, dates included.
//! Read or refused with an error, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = cakeys_ykcs11::fuzzing::piv_attestation(bytes);
});
