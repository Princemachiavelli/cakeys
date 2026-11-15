//! `camigrate`: moves keys between tokens (docs/CAMIGRATE.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    camigrate::main(&camigrate::default_registry())
}
