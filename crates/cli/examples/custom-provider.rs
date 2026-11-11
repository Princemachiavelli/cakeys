//! A downstream `key-mgmnt` with an extra provider for an in-house PKCS#11 module.
//! `cargo run --example custom-provider -- --config keys.toml caps --token acme`

use key_mgmnt_pkcs11::provider::Provider;
use key_mgmnt_pkcs11::token::ModuleInfo;
use std::process::ExitCode;

struct Acme;

impl Provider for Acme {
    fn name(&self) -> &'static str {
        "acme"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "Acme Corp"
    }
}

fn main() -> ExitCode {
    key_mgmnt::main(key_mgmnt::default_registry().with(Acme))
}
