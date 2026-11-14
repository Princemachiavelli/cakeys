//! A downstream `cakeys` with an extra provider for an in-house PKCS#11 module.
//! `cargo run --example custom-provider -- --config keys.toml verify <spec> --token acme`

use cakeys_pkcs11::provider::Provider;
use cakeys_pkcs11::token::ModuleInfo;
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
    cakeys::main(&cakeys::default_registry().with(Acme))
}
