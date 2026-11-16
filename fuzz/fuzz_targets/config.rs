//! keys.toml text: it loads, or is refused as invalid (17) or as naming an object type cakeys
//! does not manage (15), never a panic.
#![no_main]

use cakeys_core::config::parse_config_with;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Err(e) = parse_config_with(text, std::path::Path::new("keys.toml"), &|_| Some("/x".into())) {
        assert!(matches!(e.exit_code(), 15 | 17), "{e}");
    }
});
