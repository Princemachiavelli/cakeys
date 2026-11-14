use std::process::ExitCode;

fn main() -> ExitCode {
    camigrate::main(&camigrate::default_registry())
}
