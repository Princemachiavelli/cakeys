//! `camigrate`: moves keys between tokens (docs/CAMIGRATE.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    // `COMPLETE=<shell> camigrate` prints the shell's completion script; the script calls back here per tab.
    clap_complete::CompleteEnv::with_factory(camigrate::command).complete();
    camigrate::main(&camigrate::default_registry())
}
