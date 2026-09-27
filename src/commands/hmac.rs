use std::io::{BufReader, Cursor, Read, copy};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor, scrypt};
use anyhow::{Context as _, Result, bail};

use crate::cli::Output;
use crate::device::otp;
use crate::format::legacy;
use crate::io::{self, OutputRule};
use crate::ui;

pub fn encrypt(file: &Path, slot: u8, out: &Output, serial: Option<u32>) -> Result<()> {
    let main_path = io::destination(out.output.as_deref(), file, &OutputRule::Append("yk.age"))
        .context("hmac encrypt requires a file output, not stdout")?;
    let challenge_path = challenge_path_for(&main_path);

    if main_path.exists() && !out.force {
        bail!(
            "output already exists: {} (use --force)",
            main_path.display()
        );
    }
    if challenge_path.exists() && !out.force {
        bail!(
            "output already exists: {} (use --force)",
            challenge_path.display()
        );
    }

    let raw_challenge = random_challenge()?;
    let challenge_hex = hex::encode(&raw_challenge);

    let response = otp::challenge_response(slot, &raw_challenge, serial)?;
    let passphrase = SecretString::from(hex::encode(*response));

    let mut output = io::Output::create(Some(main_path.clone()), out.force)?;
    let encryptor = Encryptor::with_user_passphrase(passphrase);
    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let mut writer = encryptor.wrap_output(output.writer())?;
    copy(&mut BufReader::new(input), &mut writer)
        .with_context(|| format!("failed to read {}", file.display()))?;
    writer
        .finish()
        .context("failed to write the encrypted output")?;
    output.finish()?;

    write_challenge_file(&challenge_path, &challenge_hex, out.force)?;
    ui::success(format!("Encrypted file: {}", main_path.display()));
    ui::success(format!("Challenge saved: {}", challenge_path.display()));
    Ok(())
}

pub fn decrypt(file: &Path, slot: u8, out: &Output, serial: Option<u32>) -> Result<()> {
    let default_output = output_base(file);
    let (challenge_hex, response_hex) = load_challenge_response(file, slot, serial)?;

    let mut input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    // Read a small prefix to detect the format, then keep streaming the rest.
    let mut prefix = Vec::new();
    Read::by_ref(&mut input)
        .take(24)
        .read_to_end(&mut prefix)
        .context("failed to read the file header")?;
    let mut reader = Cursor::new(prefix.clone()).chain(input);

    let dest = if prefix.starts_with(legacy::MAGIC) {
        let passphrase = legacy::derive_passphrase(&challenge_hex, &response_hex);
        let mut output = io::Output::create(Some(default_output.clone()), out.force)?;
        legacy::decrypt(&mut reader, passphrase.as_bytes(), output.writer())?;
        output.finish()?;
        default_output
    } else if prefix.starts_with(b"age-encryption.org/v1") {
        let identity = scrypt_identity(&response_hex);
        let decryptor = Decryptor::new(&mut reader)
            .with_context(|| format!("{} is not a valid age file", file.display()))?;
        let mut plaintext = decryptor.decrypt(std::iter::once(&identity as &_))?;
        let mut output = io::Output::create(Some(default_output.clone()), out.force)?;
        copy(&mut plaintext, output.writer())?;
        output.finish()?;
        default_output
    } else {
        bail!("unrecognized file format: expected a legacy (Salted__) or age file");
    };

    ui::success(format!("Decrypted: {}", dest.display()));
    Ok(())
}

/// Reads the challenge next to `file` and asks the YubiKey for the HMAC
/// response; returns (challenge hex, response hex).
pub(crate) fn load_challenge_response(
    file: &Path,
    slot: u8,
    serial: Option<u32>,
) -> Result<(String, String)> {
    // The challenge sits next to the input with only the last extension
    // swapped: FILE.yk.enc becomes FILE.yk.challenge.
    let challenge_path = match file.extension() {
        Some(ext) if ext == "enc" || ext == "age" => file.with_extension("challenge"),
        _ => bail!(
            "cannot determine the challenge file for {} (expected .enc or .age)",
            file.display()
        ),
    };
    if !challenge_path.is_file() {
        bail!("challenge file not found: {}", challenge_path.display());
    }

    let challenge_raw = std::fs::read_to_string(&challenge_path)
        .with_context(|| format!("failed to read {}", challenge_path.display()))?;
    // Legacy challenges were written with echo, so trim spaces and the newline.
    let challenge_hex = challenge_raw.trim().to_owned();
    let raw_challenge = hex::decode(&challenge_hex)
        .with_context(|| format!("challenge in {} is not valid hex", challenge_path.display()))?;
    if raw_challenge.len() != 32 {
        bail!(
            "challenge in {} has {} bytes, expected 32",
            challenge_path.display(),
            raw_challenge.len()
        );
    }

    let response = otp::challenge_response(slot, &raw_challenge, serial)?;
    let response_hex = hex::encode(*response);
    Ok((challenge_hex, response_hex))
}

pub(crate) fn scrypt_identity(response_hex: &str) -> scrypt::Identity {
    scrypt::Identity::new(SecretString::from(response_hex.to_owned()))
}

/// `FILE.yk.age` becomes `FILE.yk.challenge`; the challenge always sits next
/// to the encrypted file, keeping the name and swapping the extension.
fn challenge_path_for(main_path: &Path) -> PathBuf {
    let stem = main_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    main_path.with_file_name(format!("{stem}.challenge"))
}

/// `FILE.yk.enc` and `FILE.enc` become `FILE`; anything else gets `.decrypted`.
fn output_base(file: &Path) -> PathBuf {
    let name = file.to_string_lossy();
    for suffix in [".yk.enc", ".yk.age", ".enc", ".age"] {
        if let Some(base) = name.strip_suffix(suffix) {
            return PathBuf::from(base);
        }
    }
    PathBuf::from(format!("{name}.decrypted"))
}

fn random_challenge() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("failed to read random bytes from /dev/urandom")?;
    Ok(buf)
}

fn write_challenge_file(path: &Path, challenge_hex: &str, force: bool) -> Result<()> {
    let mut temp = io::Output::create(Some(path.to_path_buf()), force)?;
    temp.writer()
        .write_all(format!("{challenge_hex}\n").as_bytes())?;
    temp.finish()
}
