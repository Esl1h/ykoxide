use std::io::sink;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::commands::{age, hmac};
use crate::format::{self, legacy};
use crate::ui;

/// Checks whether the file decrypts; never writes plaintext.
/// Returns `false` when decryption fails (exit code 1).
pub fn run(file: &Path, identities: Vec<PathBuf>, slot: u8, serial: Option<u32>) -> Result<bool> {
    let format = format::detect(file);
    let label = match format {
        format::Format::Legacy => "legacy openssl",
        format::Format::AgeScrypt => "age scrypt",
        format::Format::AgeRecipients => "age recipients",
        format::Format::AgeArmored => "age armored",
        format::Format::Unknown => {
            bail!("unknown file format: {}", file.display());
        }
    };

    let result = match format {
        format::Format::AgeRecipients | format::Format::AgeArmored => verify_age(file, &identities),
        format::Format::AgeScrypt | format::Format::Legacy => {
            verify_with_yubikey(file, slot, format, serial)
        }
        format::Format::Unknown => unreachable!(),
    };

    match result {
        Ok(()) => {
            ui::success(format!("OK: {} decrypts ({label})", file.display()));
            if format == format::Format::Legacy {
                ui::warn(
                    "legacy format has no authentication; a wrong key passes about 1 time in 256",
                );
            }
            Ok(true)
        }
        Err(err) => {
            ui::fail(format!(
                "{} does not decrypt ({label}): {err:#}",
                file.display()
            ));
            Ok(false)
        }
    }
}

fn verify_age(file: &Path, identity_args: &[PathBuf]) -> Result<()> {
    let identities = age::load_identities(identity_args)?;
    let mut plaintext =
        age::decryptor_for(file)?.decrypt(identities.iter().map(|i| i.as_ref() as &_))?;
    std::io::copy(&mut plaintext, &mut sink()).context("failed to read the decrypted stream")?;
    Ok(())
}

fn verify_with_yubikey(
    file: &Path,
    slot: u8,
    format: format::Format,
    serial: Option<u32>,
) -> Result<()> {
    let (challenge_hex, response_hex) = hmac::load_challenge_response(file, slot, serial)?;
    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    match format {
        format::Format::Legacy => {
            let passphrase = legacy::derive_passphrase(&challenge_hex, &response_hex);
            legacy::decrypt(input, passphrase.as_bytes(), &mut sink())
        }
        format::Format::AgeScrypt => {
            let identity = hmac::scrypt_identity(&response_hex);
            let mut plaintext =
                age::decryptor_for(file)?.decrypt(std::iter::once(&identity as &_))?;
            std::io::copy(&mut plaintext, &mut sink())
                .context("failed to read the decrypted stream")?;
            Ok(())
        }
        _ => unreachable!(),
    }
}
