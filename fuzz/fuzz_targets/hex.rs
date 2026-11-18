//! Hex on any bytes: they round-trip through `encode` and `decode` in either case, and read as
//! text (when UTF-8), `decode` takes them exactly when they are hex of whole bytes.
#![no_main]

use cakeys_core::fuzzing::{hex_round_trips, only_hex_decodes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hex_round_trips(data);
    if let Ok(text) = std::str::from_utf8(data) {
        only_hex_decodes(text);
    }
});
