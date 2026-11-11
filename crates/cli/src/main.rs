use std::process::ExitCode;

fn main() -> ExitCode {
    key_mgmnt::main(key_mgmnt::default_registry())
}
