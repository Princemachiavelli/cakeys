//! keys.lock text: it loads or is refused as invalid (17), never a panic.
#![no_main]

use cakeys_core::config::parse_lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Err(e) = parse_lock(text, std::path::Path::new("keys.lock")) {
        assert_eq!(e.exit_code(), 17, "{e}");
    }
});
