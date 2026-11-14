use std::process::ExitCode;

fn main() -> ExitCode {
    caprobe::main(&caprobe::default_registry())
}
