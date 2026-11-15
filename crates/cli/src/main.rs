//! `cakeys`: pins PKCS#11 objects to content-addressed IDs and verifies them (docs/CAKEYS.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    cakeys::main(&cakeys::default_registry())
}
