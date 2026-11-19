//! A capability profile through caprobe's emitter: every row key in the text is the key its
//! capability writes back, and what the parser reads emits a text that reads back as the same
//! profile and emits to the same text.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(text) = std::str::from_utf8(bytes) {
        caprobe::fuzzing::profile_round_trip(text);
    }
});
