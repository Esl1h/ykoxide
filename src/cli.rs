use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ykox", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show a report of the connected YubiKey(s)
    Info,
    /// age encryption backed by a YubiKey PIV slot
    #[command(subcommand)]
    Age(AgeCommand),
    /// File encryption using the OTP HMAC-SHA1 challenge-response slot
    #[command(subcommand)]
    Hmac(HmacCommand),
    /// Check that an encrypted file can be decrypted, without writing plaintext
    Verify {
        file: PathBuf,
        /// age identity file (repeatable); defaults to the one from `age setup`
        #[arg(short, long)]
        identity: Vec<PathBuf>,
    },
    /// Export the YubiKey configuration state as JSON
    Backup {
        /// Output file; defaults to stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum AgeCommand {
    /// Generate an age identity on the YubiKey PIV applet
    Setup,
    /// Encrypt a file to one or more recipients
    Encrypt {
        file: PathBuf,
        /// age recipient or recipients file (repeatable); defaults to the one from `age setup`
        #[arg(short, long)]
        recipient: Vec<String>,
        #[command(flatten)]
        out: Output,
    },
    /// Decrypt a file with one or more identities
    Decrypt {
        file: PathBuf,
        /// age identity file (repeatable); defaults to the one from `age setup`
        #[arg(short, long)]
        identity: Vec<PathBuf>,
        #[command(flatten)]
        out: Output,
    },
}

#[derive(Subcommand)]
pub enum HmacCommand {
    /// Encrypt a file with a key derived from the YubiKey HMAC response
    Encrypt {
        file: PathBuf,
        #[command(flatten)]
        slot: Slot,
    },
    /// Decrypt a file produced by `hmac encrypt` or by yk-encrypt-file.sh
    Decrypt {
        file: PathBuf,
        #[command(flatten)]
        slot: Slot,
    },
}

#[derive(Args)]
pub struct Output {
    /// Output file
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct Slot {
    /// OTP slot configured for HMAC-SHA1 challenge-response
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=2))]
    pub slot: u8,
}
