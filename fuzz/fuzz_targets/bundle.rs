//! An export bundle's text (docs/CAMIGRATE.md D5): it is read or refused as invalid (17), never a panic.
#![no_main]

use camigrate::bundle::Bundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Err(e) = Bundle::parse(text, std::path::Path::new("bundle.toml")) {
        assert_eq!(e.exit_code(), 17, "{e}");
    }
});
