//! tpm2-pkcs11's P-521 `CKA_EC_POINT` fix-up on any bytes: what it repairs is DER of the same
//! point, what it leaves alone is the input, and a repaired value is left alone. Never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|raw: &[u8]| cakeys_tpm2_pkcs11::fuzzing::ec_point_fix(raw));
