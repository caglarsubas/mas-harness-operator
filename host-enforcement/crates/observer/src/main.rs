//! HE-001 scaffold: no module logic yet. It parses only its own argv, opens no file and exits.
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next()) {
        (None, None) => ExitCode::SUCCESS,
        _ => ExitCode::from(2),
    }
}
