#![forbid(unsafe_code)]

mod age_yubikey;
mod cli;
mod commands;
mod config;
mod device;
mod format;
mod io;
mod rfc3339;
mod ui;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use cli::{AgeCommand, Cli, Command, HmacCommand, Output};

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
        Command::Age(AgeCommand::Setup {
            generate,
            slot,
            touch_policy,
            pin_policy,
            force,
        }) => commands::age::setup(&commands::age::SetupOpts {
            generate,
            slot,
            touch_policy: touch_policy.as_str(),
            pin_policy: pin_policy.as_str(),
            force,
        })?,
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
        Command::Backup { output, force } => {
            commands::backup::run(cli.serial, &Output { output, force })?
        }
        Command::Sign {
            file,
            key,
            piv_slot,
            out,
        } => commands::sign::sign(&file, key, piv_slot, &out, cli.serial)?,
        Command::VerifySig {
            file,
            signature,
            allowed_signers,
            pubkey,
            identity,
        } => {
            if !commands::sign::verify_sig(&file, signature, allowed_signers, pubkey, identity)? {
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
