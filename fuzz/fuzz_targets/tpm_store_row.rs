//! A tpm2-pkcs11 store row (`tobjects.attrs`, `pobjects.config`), as the tpm-certify attestation
//! reads it: parsed or refused with an error, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = cakeys_tpm2_pkcs11::attest::fuzzing::store_row(text);
});
