use std::io::sink;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::commands::{age, fido2, hmac};
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
        format::Format::AgeRecipients | format::Format::AgeArmored => {
            verify_age(file, &identities)?;
            Ok("age recipients/armored")
        }
        format::Format::AgeScrypt => {
            // A scrypt file can come from `hmac encrypt` (challenge sidecar)
            // or from `fido2 encrypt` (JSON sidecar); go by whichever exists.
            if fido2_sidecar_path(file).is_file() {
                fido2::verify(file, serial.map(yubikey::Serial::from))?;
                Ok("age scrypt (fido2)")
            } else {
                verify_hmac_scrypt(file, slot, serial)?;
                Ok("age scrypt")
            }
        }
        format::Format::Legacy => verify_legacy(file, slot, serial).map(|_| "legacy openssl"),
        format::Format::Unknown => unreachable!(),
    };

    match result {
        Ok(label) => {
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

/// `FILE.yk.age` becomes `FILE.yk.fido2`, mirroring the sidecar rule of
/// `fido2 encrypt`.
fn fido2_sidecar_path(file: &Path) -> PathBuf {
    match file.extension() {
        Some(ext) if ext == "age" => file.with_extension("fido2"),
        _ => {
            let stem = file
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            file.with_file_name(format!("{stem}.fido2"))
        }
    }
}

fn verify_hmac_scrypt(file: &Path, slot: u8, serial: Option<u32>) -> Result<()> {
    let (_, response_hex) = hmac::load_challenge_response(file, slot, serial)?;
    let identity = hmac::scrypt_identity(&response_hex);
    let mut plaintext = age::decryptor_for(file)?.decrypt(std::iter::once(&identity as &_))?;
    std::io::copy(&mut plaintext, &mut sink()).context("failed to read the decrypted stream")?;
    Ok(())
}

fn verify_legacy(file: &Path, slot: u8, serial: Option<u32>) -> Result<()> {
    let (challenge_hex, response_hex) = hmac::load_challenge_response(file, slot, serial)?;
    let passphrase = legacy::derive_passphrase(&challenge_hex, &response_hex);
    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    legacy::decrypt(input, passphrase.as_bytes(), &mut sink())
}
