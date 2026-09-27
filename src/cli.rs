use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use yubikey::Serial;

#[derive(Parser)]
#[command(name = "ykox", version, about)]
pub struct Cli {
    /// Use only the YubiKey with this serial number
    #[arg(long, global = true)]
    pub serial: Option<Serial>,

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
        #[command(flatten)]
        slot: Slot,
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
    Setup {
        /// Generate a new identity, overwriting the target slot
        #[arg(long)]
        generate: bool,
        /// Retired PIV slot (1 to 20) where the identity lives
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=20))]
        slot: u8,
        /// Touch policy for the generated key
        #[arg(long, value_enum, default_value_t = PolicyArg::Cached)]
        touch_policy: PolicyArg,
        /// PIN policy for the generated key
        #[arg(long, value_enum, default_value_t = PolicyArg::Once)]
        pin_policy: PolicyArg,
        /// Overwrite existing configuration files
        #[arg(long)]
        force: bool,
    },
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

/// Policies shared by touch and PIN (the plugin accepts the same words).
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PolicyArg {
    Always,
    Cached,
    Once,
    Never,
}

impl PolicyArg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Cached => "cached",
            Self::Once => "once",
            Self::Never => "never",
        }
    }
}

#[derive(Subcommand)]
pub enum HmacCommand {
    /// Encrypt a file with a key derived from the YubiKey HMAC response
    Encrypt {
        file: PathBuf,
        #[command(flatten)]
        slot: Slot,
        #[command(flatten)]
        out: Output,
    },
    /// Decrypt a file produced by `hmac encrypt` or by yk-encrypt-file.sh
    Decrypt {
        file: PathBuf,
        #[command(flatten)]
        slot: Slot,
        #[command(flatten)]
        out: Output,
    },
}

#[derive(Args)]
pub struct Output {
    /// Output file
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Overwrite the output file if it exists
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct Slot {
    /// OTP slot configured for HMAC-SHA1 challenge-response
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=2))]
    pub slot: u8,
}
