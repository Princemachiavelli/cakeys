//! A downstream `cakeys` with an extra provider for an in-house PKCS#11 module.
//! `cargo run --example custom-provider -- --config keys.toml check <object> --token acme`

use cakeys_core::Result;
use cakeys_pkcs11::Token;
use cakeys_pkcs11::provider::{Checked, Create, Provider};
use cakeys_pkcs11::token::{CreateNote, ModuleInfo};
use std::process::ExitCode;

struct Acme;

impl Provider for Acme {
    fn name(&self) -> &'static str {
        "acme"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "Acme Corp"
    }

    /// An override of an operation receives a request the token has checked: where the key may
    /// go (`placement`) was asked, and the session the module writes in (`manages_as_so`)
    /// entered, before it is called. It wraps the default here.
    fn create(&self, tok: &Token, req: &Checked<Create<'_>>) -> Result<Option<CreateNote>> {
        tok.create_declared(req)
    }
}

fn main() -> ExitCode {
    cakeys::main(&cakeys::default_registry().with(Acme))
}
