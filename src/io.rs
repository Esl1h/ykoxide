//! Output path resolution and atomic file writing.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tempfile::NamedTempFile;

/// Rule to derive the default output path from the input path.
pub enum OutputRule {
    /// `FILE` becomes `FILE.<ext>`, e.g. `FILE.age`.
    Append(&'static str),
    /// `FILE.<ext>` becomes `FILE`; anything else becomes `FILE.<fallback>`.
    StripOrAppend {
        ext: &'static str,
        fallback: &'static str,
    },
}

pub fn default_output(input: &Path, rule: &OutputRule) -> PathBuf {
    let mut name = input
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    match rule {
        OutputRule::Append(ext) => {
            name.push(format!(".{ext}"));
        }
        OutputRule::StripOrAppend { ext, fallback } => {
            let stripped = input
                .to_string_lossy()
                .strip_suffix(&format!(".{ext}"))
                .map(|s| s.to_owned());
            match stripped {
                Some(s) => name = s.into(),
                None => name.push(format!(".{fallback}")),
            }
        }
    }
    input.with_file_name(name)
}

/// Destination chosen from `-o`: `-` means stdout, absence means the default.
pub fn destination(explicit: Option<&Path>, input: &Path, rule: &OutputRule) -> Option<PathBuf> {
    match explicit {
        Some(p) if p == Path::new("-") => None,
        Some(p) => Some(p.to_path_buf()),
        None => Some(default_output(input, rule)),
    }
}

/// An output that either streams to stdout or writes atomically to a file:
/// the data lands in a temporary file next to the destination and is moved
/// into place only after the write succeeds.
pub enum Output {
    Stdout(io::Stdout),
    File(NamedTempFile, PathBuf),
}

impl Output {
    pub fn create(dest: Option<PathBuf>, force: bool) -> Result<Self> {
        match dest {
            None => Ok(Self::Stdout(io::stdout())),
            Some(path) => {
                if path.exists() && !force {
                    bail!("output already exists: {} (use --force)", path.display());
                }
                let dir = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let temp = NamedTempFile::new_in(dir)
                    .with_context(|| format!("failed to create a temporary file in {dir:?}"))?;
                Ok(Self::File(temp, path))
            }
        }
    }

    pub fn writer(&mut self) -> &mut dyn io::Write {
        match self {
            Self::Stdout(w) => w,
            Self::File(t, _) => t,
        }
    }

    pub fn finish(self) -> Result<()> {
        match self {
            Self::Stdout(_) => Ok(()),
            Self::File(mut temp, dest) => {
                temp.flush()?;
                if dest.exists() {
                    // Only reachable with --force.
                    temp.persist(&dest)
                        .map_err(|e| anyhow::Error::new(e.error))
                        .with_context(|| format!("failed to overwrite {}", dest.display()))?;
                } else {
                    temp.persist_noclobber(&dest)
                        .map_err(|e| anyhow::Error::new(e.error))
                        .with_context(|| format!("failed to create {}", dest.display()))?;
                }
                Ok(())
            }
        }
    }
}

/// Whether an identity entry names an existing file; otherwise it is the
/// identity content itself (the `yubikey-identity.txt` fallback).
pub fn identity_content(entry: &str) -> Result<String> {
    let path = Path::new(entry);
    if path.is_file() {
        fs::read_to_string(path).with_context(|| format!("failed to read {entry}"))
    } else {
        Ok(entry.to_owned())
    }
}
