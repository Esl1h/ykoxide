#![forbid(unsafe_code)]

mod cli;
mod commands;
mod config;
mod device;
mod io;
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
        Command::Age(AgeCommand::Encrypt {
            file,
            recipient,
            out,
        }) => commands::age::encrypt(&file, recipient, &out),
        Command::Age(AgeCommand::Decrypt {
            file,
            identity,
            out,
        }) => commands::age::decrypt(&file, identity, &out),
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
