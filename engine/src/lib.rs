pub mod cli;
pub mod report;
pub mod rules;
pub mod scanner;

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
