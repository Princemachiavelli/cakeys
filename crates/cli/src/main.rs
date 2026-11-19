//! `cakeys`: pins PKCS#11 objects to content-addressed IDs and verifies them (docs/CAKEYS.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    // `COMPLETE=<shell> cakeys` prints the shell's completion script; the script calls back here per tab.
    clap_complete::CompleteEnv::with_factory(cakeys::command).complete();
    cakeys::main(&cakeys::default_registry())
}
