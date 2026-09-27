#![forbid(unsafe_code)]

mod cli;
mod commands;
mod config;
mod device;
mod format;
mod io;
mod ui;

use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::Parser;

use cli::{AgeCommand, Cli, Command, HmacCommand};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            ui::fail(format!("{err:#}"));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Info => commands::info::run(cli.serial)?,
        Command::Age(AgeCommand::Setup) => bail!("`age setup` is not implemented yet"),
        Command::Age(AgeCommand::Encrypt {
            file,
            recipient,
            out,
        }) => commands::age::encrypt(&file, recipient, &out)?,
        Command::Age(AgeCommand::Decrypt {
            file,
            identity,
            out,
        }) => commands::age::decrypt(&file, identity, &out)?,
        Command::Hmac(HmacCommand::Encrypt { file, slot, out }) => {
            commands::hmac::encrypt(&file, slot.slot, &out, cli.serial.map(|s| s.0))?
        }
        Command::Hmac(HmacCommand::Decrypt { file, slot, out }) => {
            commands::hmac::decrypt(&file, slot.slot, &out, cli.serial.map(|s| s.0))?
        }
        Command::Verify {
            file,
            identity,
            slot,
        } => {
            if !commands::verify::run(&file, identity, slot.slot, cli.serial.map(|s| s.0))? {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Backup { .. } => bail!("`backup` is not implemented yet"),
    }
    Ok(ExitCode::SUCCESS)
}
