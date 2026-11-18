use std::process::ExitCode;

fn main() -> ExitCode {
    println!("sovereigngate v{}", sovereigngate::ENGINE_VERSION);
    ExitCode::SUCCESS
}