//! Human-facing output: everything goes to stderr, data goes to stdout.

use anyhow::{Context as _, Result};

pub fn info(msg: impl AsRef<str>) {
    eprintln!("[*] {}", msg.as_ref());
}

pub fn success(msg: impl AsRef<str>) {
    eprintln!("[+] {}", msg.as_ref());
}

pub fn fail(msg: impl AsRef<str>) {
    eprintln!("[✗] {}", msg.as_ref());
}

/// Read a secret (PIN, passphrase) without echo.
pub fn prompt_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("failed to read the secret")
}
