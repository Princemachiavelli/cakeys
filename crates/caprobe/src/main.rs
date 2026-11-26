//! `caprobe`: measures PKCS#11 modules into capability profiles (docs/CAPROBE.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    // `COMPLETE=<shell> caprobe` prints the completion script for the shell, and the script calls
    // this binary again for each completion request.
    clap_complete::CompleteEnv::with_factory(caprobe::command).complete();
    caprobe::main(&caprobe::default_registry())
}
