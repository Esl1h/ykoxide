use std::io::{BufReader, copy};
use std::path::{Path, PathBuf};

use age::cli_common::StdinGuard;
use age::secrecy::SecretString;
use age::{
    Callbacks, Decryptor, Encryptor, Identity, IdentityFile, Recipient, armor::ArmoredReader,
};
use anyhow::{Context as _, Error, Result, bail};
use yubikey::piv::SlotId;
use yubikey::{PinPolicy, TouchPolicy};

use crate::age_yubikey;
use crate::cli::Output;
use crate::config;
use crate::device;
use crate::io::{self, OutputRule};
use crate::ui;

/// age plugin UI: messages on stderr, secrets via a no-echo prompt.
#[derive(Clone, Copy)]
pub(crate) struct PluginCallbacks;

impl Callbacks for PluginCallbacks {
    fn display_message(&self, message: &str) {
        ui::info(message);
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        ui::info(description);
        ui::prompt_secret("PIN: ")
            .ok()
            .map(|pin| SecretString::from(pin.as_str()))
    }
}

pub fn encrypt(file: &Path, recipients: Vec<String>, out: &Output) -> Result<()> {
    let dir = config::config_dir()?;
    let strings = config::resolve_recipients(&dir, &recipients)?;

    // YubiKey recipients go through the native piv-p256 stanza; the rest
    // (X25519, other plugins) through the age parser.
    let mut all: Vec<Box<dyn Recipient + Send>> = Vec::new();
    let mut others = Vec::new();
    for r in strings {
        if r.starts_with(age_yubikey::RECIPIENT_STRING_PREFIX) {
            let recipient: age_yubikey::Recipient = r.parse()?;
            all.push(Box::new(recipient));
        } else {
            others.push(r);
        }
    }
    if !others.is_empty() {
        let mut stdin_guard = StdinGuard::new(false);
        let parsed =
            age::cli_common::read_recipients(others, vec![], vec![], None, &mut stdin_guard)
                .map_err(|e| Error::new(e).context("failed to parse recipients"))?;
        all.extend(parsed);
    }

    let encryptor = Encryptor::with_recipients(all.iter().map(|r| r.as_ref() as &dyn Recipient))
        .map_err(Error::new)
        .context("failed to create the encryptor")?;

    let dest = io::destination(out.output.as_deref(), file, &OutputRule::Append("age"));
    let mut output = io::Output::create(dest, out.force)?;

    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let mut writer = encryptor.wrap_output(output.writer())?;
    copy(&mut BufReader::new(input), &mut writer)
        .with_context(|| format!("failed to read {}", file.display()))?;
    writer
        .finish()
        .context("failed to write the encrypted output")?;
    output.finish()?;
    Ok(())
}

pub fn decrypt(file: &Path, identities: Vec<PathBuf>, out: &Output) -> Result<()> {
    let ids = load_identities(&identities)?;

    let mut reader =
        decryptor_for(file)?.decrypt(ids.iter().map(|i| i.as_ref() as &dyn Identity))?;

    let dest = io::destination(
        out.output.as_deref(),
        file,
        &OutputRule::StripOrAppend {
            ext: "age",
            fallback: "decrypted",
        },
    );
    let mut output = io::Output::create(dest, out.force)?;
    copy(&mut reader, output.writer())?;
    output.finish()?;
    Ok(())
}

/// Resolves identities from arguments and configuration files, warning about
/// touch when a plugin identity is present. YubiKey identities are native.
pub(crate) fn load_identities(
    identity_args: &[PathBuf],
) -> Result<Vec<Box<dyn Identity + Send + Sync>>> {
    let dir = config::config_dir()?;
    let entries = config::resolve_identities(&dir, identity_args)?;

    let mut ids: Vec<Box<dyn Identity + Send + Sync>> = Vec::new();
    let mut has_plugin = false;
    for entry in &entries {
        has_plugin |= entry.contains("AGE-PLUGIN-");
        let content = io::identity_content(entry)?;

        // Split the identity lines: YubiKey identities are handled natively;
        // the rest go through the age identity file parser.
        let mut yubikey_lines = Vec::new();
        let mut other_lines = Vec::new();
        for line in content.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with(age_yubikey::IDENTITY_STRING_PREFIX) {
                yubikey_lines.push(line.to_owned());
            } else {
                other_lines.push(line.to_owned());
            }
        }
        for line in yubikey_lines {
            let identity: age_yubikey::Identity = line.parse()?;
            ids.push(Box::new(identity));
        }
        if !other_lines.is_empty() {
            let identity_file =
                IdentityFile::from_buffer(BufReader::new(other_lines.join("\n").as_bytes()))
                    .with_context(|| format!("failed to parse identity {entry}"))?;
            ids.extend(
                identity_file
                    .with_callbacks(PluginCallbacks)
                    .into_identities()?,
            );
        }
    }
    if ids.is_empty() {
        anyhow::bail!("no identities found; run 'ykox age setup', or pass -i");
    }
    if has_plugin {
        ui::info("Touch your YubiKey if it blinks");
    }
    Ok(ids)
}

/// A decryptor over the whole file, binary or armored.
pub(crate) type AgeDecryptor = Decryptor<ArmoredReader<BufReader<std::fs::File>>>;

pub(crate) fn decryptor_for(file: &Path) -> Result<AgeDecryptor> {
    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    Decryptor::new(ArmoredReader::new(input))
        .with_context(|| format!("{} is not a valid age file", file.display()))
}

/// Options for `age setup`.
pub struct SetupOpts {
    pub generate: bool,
    pub slot: u8,
    pub touch_policy: crate::cli::PolicyArg,
    pub pin_policy: crate::cli::PolicyArg,
    pub force: bool,
}

pub fn setup(opts: &SetupOpts, serial: Option<yubikey::Serial>) -> Result<()> {
    let dir = config::config_dir()?;
    let (identity, recipient) = match opts.generate {
        false => reuse(opts, serial)?,
        true => generate(opts, serial)?,
    };

    write_config(&dir, &identity, &recipient, opts.force)?;
    ui::success("Identity saved.");
    // The recipient is data; it goes to stdout.
    println!("{recipient}");
    ui::info("The private key lives inside the YubiKey; it was never on disk.");
    Ok(())
}

fn retired_slot(slot: u8) -> Result<yubikey::piv::RetiredSlotId> {
    yubikey::piv::RetiredSlotId::try_from(0x81 + slot)
        .with_context(|| format!("invalid retired slot {slot}"))
}

/// Reuses an existing age identity found on the target slot.
fn reuse(opts: &SetupOpts, serial: Option<yubikey::Serial>) -> Result<(String, String)> {
    let mut yk = device::open(serial)?;
    let piv_slot = retired_slot(opts.slot)?;
    let cert = yubikey::certificate::Certificate::read(&mut yk, SlotId::Retired(piv_slot))
        .with_context(|| {
            format!(
                "no age identity found on retired slot {}; pass --generate to create one",
                opts.slot
            )
        })?;
    let identity = age_yubikey::Identity::from_certificate(&cert, yk.serial(), piv_slot)?;
    let recipient = age_yubikey::Recipient::from_certificate(&cert)
        .context("the slot key is not an age P-256 identity")?;
    Ok((identity.to_string(), recipient.to_string()))
}

/// Generates a new identity in the target slot (destructive; asks for YES).
fn generate(opts: &SetupOpts, serial: Option<yubikey::Serial>) -> Result<(String, String)> {
    let piv_slot = 0x81u8 + opts.slot;
    ui::warn(format!(
        "This will OVERWRITE the existing key in PIV retired slot {} ({piv_slot:02x}).",
        opts.slot
    ));
    ui::warn("Any data encrypted to the current key will be UNRECOVERABLE.");
    let answer = ui::prompt_public("[?] Type 'YES' to confirm: ")?;
    if answer != "YES" {
        ui::info("Aborted.");
        anyhow::bail!("generation aborted");
    }

    let pin_policy = match opts.pin_policy {
        crate::cli::PolicyArg::Always => PinPolicy::Always,
        crate::cli::PolicyArg::Once => PinPolicy::Once,
        crate::cli::PolicyArg::Never => PinPolicy::Never,
        crate::cli::PolicyArg::Cached => bail!("cached is not a valid PIN policy"),
    };
    let touch_policy = match opts.touch_policy {
        crate::cli::PolicyArg::Always => TouchPolicy::Always,
        crate::cli::PolicyArg::Cached => TouchPolicy::Cached,
        crate::cli::PolicyArg::Never => TouchPolicy::Never,
        crate::cli::PolicyArg::Once => bail!("once is not a valid touch policy"),
    };

    let mut yk = device::open(serial)?;
    let (identity, recipient) = age_yubikey::generate_identity(
        &mut yk,
        retired_slot(opts.slot)?,
        "yk-toolkit",
        pin_policy,
        touch_policy,
    )?;
    Ok((identity.to_string(), recipient.to_string()))
}

/// Writes the two configuration files with the script's permissions:
/// directory 0700, identity 0600, recipient 0644.
pub(crate) fn write_config(dir: &Path, identity: &str, recipient: &str, force: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let identity_path = dir.join(config::YUBIKEY_IDENTITY_FILE);
    let recipient_path = dir.join(config::YUBIKEY_RECIPIENT_FILE);
    for path in [&identity_path, &recipient_path] {
        if path.exists() && !force {
            bail!(
                "configuration file already exists: {} (use --force)",
                path.display()
            );
        }
    }

    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", dir.display()))?;

    std::fs::write(&identity_path, format!("{identity}\n"))
        .with_context(|| format!("failed to write {}", identity_path.display()))?;
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))?;

    std::fs::write(&recipient_path, format!("{recipient}\n"))
        .with_context(|| format!("failed to write {}", recipient_path.display()))?;
    std::fs::set_permissions(&recipient_path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_config_sets_script_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "AGE-PLUGIN-YUBIKEY-1", "age1yubikey1", false).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.path()), 0o700);
        assert_eq!(mode(&dir.path().join(config::YUBIKEY_IDENTITY_FILE)), 0o600);
        assert_eq!(
            mode(&dir.path().join(config::YUBIKEY_RECIPIENT_FILE)),
            0o644
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join(config::YUBIKEY_IDENTITY_FILE)).unwrap(),
            "AGE-PLUGIN-YUBIKEY-1\n"
        );
    }

    #[test]
    fn write_config_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "AGE-PLUGIN-YUBIKEY-1", "age1yubikey1", false).unwrap();
        let err =
            write_config(dir.path(), "AGE-PLUGIN-YUBIKEY-2", "age1yubikey2", false).unwrap_err();
        assert!(err.to_string().contains("use --force"));

        write_config(dir.path(), "AGE-PLUGIN-YUBIKEY-2", "age1yubikey2", true).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(config::YUBIKEY_IDENTITY_FILE)).unwrap(),
            "AGE-PLUGIN-YUBIKEY-2\n"
        );
    }
}
