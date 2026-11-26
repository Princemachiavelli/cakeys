//! `camigrate`: moves keys between tokens (docs/CAMIGRATE.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    // `COMPLETE=<shell> camigrate` prints the completion script for that shell. The script then
    // runs this program again each time the user presses Tab.
    clap_complete::CompleteEnv::with_factory(camigrate::command).complete();
    camigrate::main(&camigrate::default_registry())
}
