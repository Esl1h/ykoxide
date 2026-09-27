#![forbid(unsafe_code)]

mod cli;

use anyhow::bail;
use clap::Parser;

use cli::{AgeCommand, Cli, Command, HmacCommand};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let name = match cli.command {
        Command::Info => "info",
        Command::Age(AgeCommand::Setup) => "age setup",
        Command::Age(AgeCommand::Encrypt { .. }) => "age encrypt",
        Command::Age(AgeCommand::Decrypt { .. }) => "age decrypt",
        Command::Hmac(HmacCommand::Encrypt { .. }) => "hmac encrypt",
        Command::Hmac(HmacCommand::Decrypt { .. }) => "hmac decrypt",
        Command::Verify { .. } => "verify",
        Command::Backup { .. } => "backup",
    };
    bail!("`{name}` is not implemented yet")
}
