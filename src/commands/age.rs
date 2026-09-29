use std::io::{BufReader, copy};
use std::path::{Path, PathBuf};

use age::cli_common::StdinGuard;
use age::secrecy::SecretString;
use age::{
    Callbacks, Decryptor, Encryptor, Identity, IdentityFile, Recipient, armor::ArmoredReader,
};
use anyhow::{Context as _, Error, Result, bail};

use crate::age_yubikey;
use crate::cli::Output;
use crate::config;
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

/// Options for `age setup`, mirroring the plugin's CLI.
pub struct SetupOpts {
    pub generate: bool,
    pub slot: u8,
    pub touch_policy: &'static str,
    pub pin_policy: &'static str,
    pub force: bool,
}

pub fn setup(opts: &SetupOpts) -> Result<()> {
    let dir = config::config_dir()?;
    let (identity, recipient) = match opts.generate {
        false => reuse(opts)?,
        true => generate(opts)?,
    };

    write_config(&dir, &identity, &recipient, opts.force)?;
    ui::success("Identity saved.");
    // The recipient is data; it goes to stdout.
    println!("{recipient}");
    ui::info("The private key lives inside the YubiKey; it was never on disk.");
    Ok(())
}

fn reuse(opts: &SetupOpts) -> Result<(String, String)> {
    let list = run_plugin(&["--list"])?;
    let recipient = first_line_starting(&list, "age1").with_context(|| {
        format!("no age identity found on the YubiKey; pass --generate to create one on retired slot {}", opts.slot)
    })?;
    extract_identity(opts, recipient)
}

fn extract_identity(opts: &SetupOpts, recipient: &str) -> Result<(String, String)> {
    let out = run_plugin(&["--identity", "--slot", &opts.slot.to_string()])?;
    let identity = first_line_starting(&out, "AGE-PLUGIN-YUBIKEY-").with_context(|| {
        format!(
            "failed to extract the identity from slot {}; check that the slot holds a key",
            opts.slot
        )
    })?;
    Ok((identity.to_owned(), recipient.to_owned()))
}

fn generate(opts: &SetupOpts) -> Result<(String, String)> {
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

    ui::info("Touch YubiKey if it blinks. PIN may be required.");
    run_plugin(&[
        "--generate",
        "--slot",
        &opts.slot.to_string(),
        "--name",
        "yk-toolkit",
        "--touch-policy",
        opts.touch_policy,
        "--pin-policy",
        opts.pin_policy,
    ])?;

    ui::info("Extracting new identity from YubiKey...");
    let list = run_plugin(&["--list"])?;
    let recipient = first_line_starting(&list, "age1")
        .context("generation finished but no recipient found in the list")?;
    extract_identity(opts, recipient)
}

fn run_plugin(args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("age-plugin-yubikey")
        .args(args)
        .output()
        .with_context(|| {
            "age-plugin-yubikey not found in PATH; install it with 'cargo install age-plugin-yubikey --locked'"
        })?;
    if !output.status.success() {
        bail!(
            "age-plugin-yubikey {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn first_line_starting<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines().map(str::trim).find(|l| l.starts_with(prefix))
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

    #[test]
    fn first_line_starting_skips_comments_and_blanks() {
        let text = "# comment\n\n  AGE-PLUGIN-YUBIKEY-1\nother";
        assert_eq!(
            first_line_starting(text, "AGE-PLUGIN-"),
            Some("AGE-PLUGIN-YUBIKEY-1")
        );
        assert_eq!(first_line_starting(text, "age1"), None);
    }
}
