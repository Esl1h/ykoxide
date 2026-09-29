//! `fido2` commands: file encryption keyed by a FIDO2 hmac-secret credential.
//!
//! Own format (phase 6, path 2): the ciphertext is an age scrypt file whose
//! passphrase is the hex of the hmac-secret output, and a JSON sidecar
//! (`FILE.yk.fido2`) carries the credential reference and the per-file salt.

use std::io::{BufReader, copy};
use std::path::{Path, PathBuf};

use std::io::Read as _;

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor, scrypt};
use anyhow::{Context as _, Result, bail};
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli::Output;
use crate::config;
use crate::device::fido2::{self, Credential};
use crate::io::{self, OutputRule};
use crate::ui;

const FORMAT_VERSION: u32 = 1;

/// Configuration written by `fido2 enroll`: the default credential for
/// `fido2 encrypt`.
#[derive(Serialize, Deserialize)]
struct CredentialFile {
    version: u32,
    rp_id: String,
    /// base64 (standard, no padding).
    credential_id: String,
    require_pin: bool,
}

/// Per-file sidecar with the salt used for the derivation.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct SidecarFile {
    version: u32,
    rp_id: String,
    /// base64 (standard, no padding).
    credential_id: String,
    /// base64 (standard, no padding).
    salt: String,
    require_pin: bool,
}

pub fn enroll(rp_id: &str, require_pin: bool, force: bool) -> Result<()> {
    let pin = if require_pin {
        Some(ui::prompt_secret("FIDO2 PIN (echo disabled): ")?)
    } else {
        None
    };
    let credential = fido2::enroll(rp_id, pin.as_deref().map(|p| p.as_str()))?;

    let dir = config::fido2_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let path = dir.join("credential.json");
    if path.exists() && !force {
        bail!(
            "credential configuration already exists: {} (use --force)",
            path.display()
        );
    }
    let file = CredentialFile {
        version: FORMAT_VERSION,
        rp_id: credential.rp_id.clone(),
        credential_id: BASE64_STANDARD_NO_PAD.encode(&credential.credential_id),
        require_pin,
    };
    let json = serde_json::to_string_pretty(&file).context("failed to serialize the credential")?;
    std::fs::write(&path, format!("{json}\n"))
        .with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    ui::success(format!(
        "Credential created; configuration saved: {}",
        path.display()
    ));
    Ok(())
}

pub fn encrypt(file: &Path, out: &Output, serial: Option<yubikey::Serial>) -> Result<()> {
    warn_serial(serial);
    let main_path = io::destination(out.output.as_deref(), file, &OutputRule::Append("yk.age"))
        .context("fido2 encrypt requires a file output, not stdout")?;
    let sidecar_path = sidecar_path_for(&main_path);

    for path in [&main_path, &sidecar_path] {
        if path.exists() && !out.force {
            bail!("output already exists: {} (use --force)", path.display());
        }
    }

    let stored = read_credential_file()?;
    let credential = Credential {
        rp_id: stored.rp_id.clone(),
        credential_id: BASE64_STANDARD_NO_PAD
            .decode(&stored.credential_id)
            .context("invalid credential id in the fido2 configuration")?,
    };

    let salt: [u8; 32] = random_salt()?;
    let secret = derive_secret(&credential, &salt, stored.require_pin)?;
    let passphrase = SecretString::from(hex::encode(*secret));

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

    let sidecar = SidecarFile {
        version: FORMAT_VERSION,
        rp_id: stored.rp_id,
        credential_id: stored.credential_id,
        salt: BASE64_STANDARD_NO_PAD.encode(salt),
        require_pin: stored.require_pin,
    };
    let json = serde_json::to_string_pretty(&sidecar).context("failed to serialize the sidecar")?;
    std::fs::write(&sidecar_path, format!("{json}\n"))
        .with_context(|| format!("failed to write {}", sidecar_path.display()))?;

    ui::success(format!("Encrypted file: {}", main_path.display()));
    ui::success(format!("Sidecar saved: {}", sidecar_path.display()));
    Ok(())
}

pub fn decrypt(file: &Path, out: &Output, serial: Option<yubikey::Serial>) -> Result<()> {
    warn_serial(serial);
    let dest = match out.output.as_deref() {
        Some(p) if p == Path::new("-") => None,
        Some(p) => Some(p.to_path_buf()),
        None => Some(crate::commands::hmac::output_base(file)),
    };
    // Fail on an existing output before asking the YubiKey for a touch.
    let mut output = io::Output::create(dest.clone(), out.force)?;

    let sidecar_path = sidecar_path_for(file);
    let sidecar_raw = std::fs::read_to_string(&sidecar_path)
        .with_context(|| format!("failed to read {}", sidecar_path.display()))?;
    let sidecar: SidecarFile = serde_json::from_str(&sidecar_raw)
        .with_context(|| format!("{} is not a valid fido2 sidecar", sidecar_path.display()))?;
    if sidecar.version != FORMAT_VERSION {
        bail!(
            "unsupported fido2 sidecar version {} in {}",
            sidecar.version,
            sidecar_path.display()
        );
    }
    let credential = Credential {
        rp_id: sidecar.rp_id.clone(),
        credential_id: BASE64_STANDARD_NO_PAD
            .decode(&sidecar.credential_id)
            .context("invalid credential id in the fido2 sidecar")?,
    };
    let salt_raw = BASE64_STANDARD_NO_PAD
        .decode(&sidecar.salt)
        .context("invalid salt in the fido2 sidecar")?;
    if salt_raw.len() != 32 {
        bail!(
            "salt in {} has {} bytes, expected 32",
            sidecar_path.display(),
            salt_raw.len()
        );
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_raw);

    let secret = derive_secret(&credential, &salt, sidecar.require_pin)?;
    let passphrase = SecretString::from(hex::encode(*secret));

    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let identity = scrypt::Identity::new(passphrase);
    let decryptor = Decryptor::new(BufReader::new(input))
        .with_context(|| format!("{} is not a valid age file", file.display()))?;
    let mut plaintext = decryptor.decrypt(std::iter::once(&identity as &_))?;
    copy(&mut plaintext, output.writer())?;
    output.finish()?;

    if let Some(dest) = dest {
        ui::success(format!("Decrypted: {}", dest.display()));
    }
    Ok(())
}

/// Verifies that `file` decrypts with the sidecar's credential; used by
/// `ykox verify` for age scrypt files that have a `.fido2` sidecar.
pub fn verify(file: &Path, serial: Option<yubikey::Serial>) -> Result<()> {
    use std::io::sink;

    warn_serial(serial);
    let sidecar_path = sidecar_path_for(file);
    let sidecar_raw = std::fs::read_to_string(&sidecar_path)
        .with_context(|| format!("failed to read {}", sidecar_path.display()))?;
    let sidecar: SidecarFile = serde_json::from_str(&sidecar_raw)
        .with_context(|| format!("{} is not a valid fido2 sidecar", sidecar_path.display()))?;
    let credential = Credential {
        rp_id: sidecar.rp_id,
        credential_id: BASE64_STANDARD_NO_PAD
            .decode(&sidecar.credential_id)
            .context("invalid credential id in the fido2 sidecar")?,
    };
    let salt_raw = BASE64_STANDARD_NO_PAD
        .decode(&sidecar.salt)
        .context("invalid salt in the fido2 sidecar")?;
    let mut salt = [0u8; 32];
    if salt_raw.len() != 32 {
        bail!("salt in {} does not have 32 bytes", sidecar_path.display());
    }
    salt.copy_from_slice(&salt_raw);

    let secret = derive_secret(&credential, &salt, sidecar.require_pin)?;
    let passphrase = SecretString::from(hex::encode(*secret));
    let identity = scrypt::Identity::new(passphrase);
    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let decryptor = Decryptor::new(BufReader::new(input))
        .with_context(|| format!("{} is not a valid age file", file.display()))?;
    let mut plaintext = decryptor.decrypt(std::iter::once(&identity as &_))?;
    std::io::copy(&mut plaintext, &mut sink()).context("failed to read the decrypted stream")?;
    Ok(())
}

fn derive_secret(
    credential: &Credential,
    salt: &[u8; 32],
    require_pin: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    let pin = if require_pin {
        Some(ui::prompt_secret("FIDO2 PIN (echo disabled): ")?)
    } else {
        None
    };
    fido2::derive(credential, salt, pin.as_deref().map(|p| p.as_str()))
}

fn read_credential_file() -> Result<CredentialFile> {
    let path = config::fido2_dir()?.join("credential.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let file: CredentialFile = serde_json::from_str(&raw).with_context(|| {
        format!(
            "{} is not a valid fido2 credential configuration",
            path.display()
        )
    })?;
    if file.version != FORMAT_VERSION {
        bail!(
            "unsupported fido2 credential version {} in {}",
            file.version,
            path.display()
        );
    }
    Ok(file)
}

/// `FILE.yk.age` becomes `FILE.yk.fido2`: the sidecar always sits next to
/// the encrypted file, keeping the name and swapping the extension.
fn sidecar_path_for(main_path: &Path) -> PathBuf {
    match main_path.extension() {
        Some(ext) if ext == "age" => main_path.with_extension("fido2"),
        _ => {
            let stem = main_path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            main_path.with_file_name(format!("{stem}.fido2"))
        }
    }
}

fn random_salt() -> Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .context("failed to read random bytes from /dev/urandom")?;
    Ok(salt)
}

fn warn_serial(serial: Option<yubikey::Serial>) {
    if serial.is_some() {
        ui::warn("--serial does not apply to FIDO2 keys; using the connected FIDO2 device");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_json_round_trip() {
        let sidecar = SidecarFile {
            version: FORMAT_VERSION,
            rp_id: "age-encryption.org".to_owned(),
            credential_id: BASE64_STANDARD_NO_PAD.encode([1u8; 16]),
            salt: BASE64_STANDARD_NO_PAD.encode([2u8; 32]),
            require_pin: true,
        };
        let json = serde_json::to_string_pretty(&sidecar).unwrap();
        let parsed: SidecarFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sidecar);
    }

    #[test]
    fn sidecar_path_swaps_the_last_extension() {
        assert_eq!(
            sidecar_path_for(Path::new("dir/secret.yk.age")),
            PathBuf::from("dir/secret.yk.fido2")
        );
        assert_eq!(
            sidecar_path_for(Path::new("dir/secret.age")),
            PathBuf::from("dir/secret.fido2")
        );
        assert_eq!(
            sidecar_path_for(Path::new("plain")),
            PathBuf::from("plain.fido2")
        );
    }

    /// The passphrase wiring (hex of the derived secret into a scrypt
    /// recipient) must round trip without hardware: the same hex through
    /// `scrypt::Identity` decrypts what the encryptor wrote.
    #[test]
    fn scrypt_round_trip_with_derived_passphrase() {
        use std::io::{Read as _, Write as _};

        let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
        let passphrase = age::secrecy::SecretString::from(hex::encode(secret));

        let plaintext = b"fido2 round trip\n";
        let encryptor = Encryptor::with_user_passphrase(passphrase.clone());
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();

        let identity = scrypt::Identity::new(passphrase);
        let decryptor = Decryptor::new(&ciphertext[..]).unwrap();
        let mut reader = decryptor.decrypt(std::iter::once(&identity as &_)).unwrap();
        let mut decrypted = Vec::new();
        reader.read_to_end(&mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
