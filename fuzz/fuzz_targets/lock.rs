//! keys.lock text: it loads or is refused as invalid (17), never a panic, and a lock that loads
//! is written back as it reads (`cakeys_core::fuzzing::lock_round_trips`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| cakeys_core::fuzzing::lock_round_trips(text));
