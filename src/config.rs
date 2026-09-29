//! Configuration directory and resolution of recipients and identities,
//! following the yk-toolkit shell script conventions.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const RECIPIENTS_FILE: &str = "recipients.txt";
pub const IDENTITIES_FILE: &str = "identities.txt";
pub const YUBIKEY_IDENTITY_FILE: &str = "yubikey-identity.txt";
pub const YUBIKEY_RECIPIENT_FILE: &str = "yubikey-recipient.txt";

/// `~/.config/yk-toolkit/age/`, the directory used by the shell scripts.
pub fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("yk-toolkit").join("age"))
        .context("could not determine the user configuration directory")
}

/// `~/.config/yk-toolkit/fido2/`, next to the age directory and not inside it.
pub fn fido2_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("yk-toolkit").join("fido2"))
        .context("could not determine the user configuration directory")
}

fn valid_lines(path: &Path) -> Result<Vec<String>> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

pub fn resolve_recipients(dir: &Path, args: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();

    let sources: Vec<String> = if !args.is_empty() {
        args.to_vec()
    } else {
        let recipients_file = dir.join(RECIPIENTS_FILE);
        let from_file = recipients_file.is_file() && {
            let lines = valid_lines(&recipients_file)?;
            !lines.is_empty()
        };
        let yubikey_file = dir.join(YUBIKEY_RECIPIENT_FILE);
        if from_file {
            vec![recipients_file.display().to_string()]
        } else if yubikey_file.is_file() {
            vec![yubikey_file.display().to_string()]
        } else {
            anyhow::bail!(
                "no recipients found; run 'ykox age setup', create {}, or pass -r",
                recipients_file.display()
            )
        }
    };

    for source in &sources {
        let path = Path::new(source);
        if path.is_file() {
            out.extend(valid_lines(path)?);
        } else if source.starts_with("age1") {
            out.push(source.clone());
        } else {
            anyhow::bail!("invalid recipient: {source} is neither a recipient nor an existing file")
        }
    }
    Ok(out)
}

/// Identity entries resolved from CLI arguments and configuration files.
///
/// Each entry is either a path to an identity file or, for the
/// `yubikey-identity.txt` fallback, the identity string itself.
pub fn resolve_identities(dir: &Path, args: &[PathBuf]) -> Result<Vec<String>> {
    if !args.is_empty() {
        return Ok(args.iter().map(|p| p.display().to_string()).collect());
    }

    let identities_file = dir.join(IDENTITIES_FILE);
    if identities_file.is_file() {
        let lines = valid_lines(&identities_file)?;
        if !lines.is_empty() {
            return Ok(lines);
        }
    }

    let yubikey_file = dir.join(YUBIKEY_IDENTITY_FILE);
    if yubikey_file.is_file() {
        let lines = valid_lines(&yubikey_file)?;
        if !lines.is_empty() {
            return Ok(lines);
        }
    }

    anyhow::bail!(
        "no identities found; run 'ykox age setup', create {}, or pass -i",
        identities_file.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn args_take_precedence() {
        let dir = tempdir().unwrap();
        write(&dir.path().join(RECIPIENTS_FILE), "age1fromconfig\n");
        let resolved = resolve_recipients(dir.path(), &["age1fromarg".into()]).unwrap();
        assert_eq!(resolved, vec!["age1fromarg"]);
    }

    #[test]
    fn arg_may_be_a_recipients_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("extra.txt");
        write(&file, "age1a\n# comment\n\nage1b\n");
        let resolved = resolve_recipients(dir.path(), &[file.display().to_string()]).unwrap();
        assert_eq!(resolved, vec!["age1a", "age1b"]);
    }

    #[test]
    fn arg_that_is_neither_fails() {
        let dir = tempdir().unwrap();
        assert!(resolve_recipients(dir.path(), &["nope".into()]).is_err());
    }

    #[test]
    fn recipients_file_wins_over_yubikey() {
        let dir = tempdir().unwrap();
        write(&dir.path().join(RECIPIENTS_FILE), "age1multi\n");
        write(&dir.path().join(YUBIKEY_RECIPIENT_FILE), "age1yubikey\n");
        let resolved = resolve_recipients(dir.path(), &[]).unwrap();
        assert_eq!(resolved, vec!["age1multi"]);
    }

    #[test]
    fn yubikey_recipient_is_fallback() {
        let dir = tempdir().unwrap();
        write(&dir.path().join(YUBIKEY_RECIPIENT_FILE), "age1yubikey\n");
        let resolved = resolve_recipients(dir.path(), &[]).unwrap();
        assert_eq!(resolved, vec!["age1yubikey"]);
    }

    #[test]
    fn no_recipients_is_an_error() {
        let dir = tempdir().unwrap();
        let err = resolve_recipients(dir.path(), &[]).unwrap_err();
        assert!(err.to_string().contains("no recipients found"));
    }

    #[test]
    fn empty_recipients_file_falls_through() {
        let dir = tempdir().unwrap();
        write(&dir.path().join(RECIPIENTS_FILE), "# only comments\n");
        write(&dir.path().join(YUBIKEY_RECIPIENT_FILE), "age1yubikey\n");
        let resolved = resolve_recipients(dir.path(), &[]).unwrap();
        assert_eq!(resolved, vec!["age1yubikey"]);
    }

    #[test]
    fn identities_from_args() {
        let dir = tempdir().unwrap();
        let args = vec![PathBuf::from("/tmp/id1.txt")];
        let resolved = resolve_identities(dir.path(), &args).unwrap();
        assert_eq!(resolved, vec!["/tmp/id1.txt".to_string()]);
    }

    #[test]
    fn identities_file_lists_paths() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join(IDENTITIES_FILE),
            "/tmp/id1.txt\n/tmp/id2.txt\n",
        );
        let resolved = resolve_identities(dir.path(), &[]).unwrap();
        assert_eq!(
            resolved,
            vec!["/tmp/id1.txt".to_string(), "/tmp/id2.txt".to_string()]
        );
    }

    #[test]
    fn yubikey_identity_is_fallback() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join(YUBIKEY_IDENTITY_FILE),
            "AGE-PLUGIN-YUBIKEY-1\n",
        );
        let resolved = resolve_identities(dir.path(), &[]).unwrap();
        assert_eq!(resolved, vec!["AGE-PLUGIN-YUBIKEY-1".to_string()]);
    }

    #[test]
    fn no_identities_is_an_error() {
        let dir = tempdir().unwrap();
        let err = resolve_identities(dir.path(), &[]).unwrap_err();
        assert!(err.to_string().contains("no identities found"));
    }
}
