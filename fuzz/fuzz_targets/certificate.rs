//! Token bytes as an X.509 certificate: its subject key, never a panic.
#![no_main]

use cakeys_core::id;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(spki) = id::cert_spki(data) {
        assert_eq!(id::spki_canonical(&spki).unwrap(), spki);
    }
});
