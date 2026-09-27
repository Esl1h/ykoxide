#![forbid(unsafe_code)]

mod cli;
mod commands;
mod device;
mod ui;

use std::process::ExitCode;

use anyhow::bail;
use clap::Parser;

use cli::{AgeCommand, Cli, Command, HmacCommand};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            ui::fail(format!("{err:#}"));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Info => commands::info::run(cli.serial),
        Command::Age(AgeCommand::Setup) => bail!("`age setup` is not implemented yet"),
        Command::Age(AgeCommand::Encrypt { .. }) => bail!("`age encrypt` is not implemented yet"),
        Command::Age(AgeCommand::Decrypt { .. }) => bail!("`age decrypt` is not implemented yet"),
        Command::Hmac(HmacCommand::Encrypt { .. }) => {
            bail!("`hmac encrypt` is not implemented yet")
        }
        Command::Hmac(HmacCommand::Decrypt { .. }) => {
            bail!("`hmac decrypt` is not implemented yet")
        }
        Command::Verify { .. } => bail!("`verify` is not implemented yet"),
        Command::Backup { .. } => bail!("`backup` is not implemented yet"),
    }
}
