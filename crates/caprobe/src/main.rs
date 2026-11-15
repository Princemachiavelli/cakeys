//! `caprobe`: measures PKCS#11 modules into capability profiles (docs/CAPROBE.md).

use std::process::ExitCode;

fn main() -> ExitCode {
    caprobe::main(&caprobe::default_registry())
}
