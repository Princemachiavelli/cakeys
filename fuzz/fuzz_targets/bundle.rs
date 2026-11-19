//! An export bundle's text (docs/CAMIGRATE.md D5): it is read or refused as invalid (17), never a
//! panic, and one that reads is read back from its writing as it was
//! (`camigrate::fuzzing::bundle_round_trips`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| camigrate::fuzzing::bundle_round_trips(text));
