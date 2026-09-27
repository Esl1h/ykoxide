use std::io::{BufReader, copy};
use std::path::{Path, PathBuf};

use age::cli_common::StdinGuard;
use age::secrecy::SecretString;
use age::{
    Callbacks, Decryptor, Encryptor, Identity, IdentityFile, Recipient, armor::ArmoredReader,
};
use anyhow::{Context as _, Error, Result};

use crate::cli::Output;
use crate::config;
use crate::io::{self, OutputRule};
use crate::ui;

/// age plugin UI: messages on stderr, secrets via a no-echo prompt.
#[derive(Clone, Copy)]
struct PluginCallbacks;

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
        ui::prompt_secret("PIN: ").ok().map(SecretString::from)
    }
}

pub fn encrypt(file: &Path, recipients: Vec<String>, out: &Output) -> Result<()> {
    let dir = config::config_dir()?;
    let resolved = config::resolve_recipients(&dir, &recipients)?;

    let mut stdin_guard = StdinGuard::new(false);
    let recipients = age::cli_common::read_recipients(
        resolved.recipients,
        resolved.files,
        vec![],
        None,
        &mut stdin_guard,
    )
    .map_err(|e| Error::new(e).context("failed to parse recipients"))?;

    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn Recipient))
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
    let dir = config::config_dir()?;
    let entries = config::resolve_identities(&dir, &identities)?;

    let mut ids: Vec<Box<dyn Identity + Send + Sync>> = Vec::new();
    let mut has_plugin = false;
    for entry in &entries {
        has_plugin |= entry.contains("AGE-PLUGIN-");
        let content = io::identity_content(entry)?;
        let identity_file = IdentityFile::from_buffer(BufReader::new(content.as_bytes()))
            .with_context(|| format!("failed to parse identity {entry}"))?;
        ids.extend(
            identity_file
                .with_callbacks(PluginCallbacks)
                .into_identities()?,
        );
    }
    if ids.is_empty() {
        anyhow::bail!("no identities found; run 'ykox age setup', or pass -i");
    }
    if has_plugin {
        ui::info("Touch your YubiKey if it blinks");
    }

    let input =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let decryptor = Decryptor::new(ArmoredReader::new(BufReader::new(input)))
        .with_context(|| format!("{} is not an age file", file.display()))?;

    let mut reader = decryptor.decrypt(ids.iter().map(|i| i.as_ref() as &dyn Identity))?;

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
