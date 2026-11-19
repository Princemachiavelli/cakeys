//! `caprobe`: measures PKCS#11 modules into capability profiles (docs/CAPROBE.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    // `COMPLETE=<shell> caprobe` prints the shell's completion script; the script calls back here per tab.
    clap_complete::CompleteEnv::with_factory(caprobe::command).complete();
    caprobe::main(&caprobe::default_registry())
}
