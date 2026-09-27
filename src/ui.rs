//! Human-facing output: everything goes to stderr, data goes to stdout.

use std::io::Write as _;

use anyhow::{Context as _, Result};

pub fn info(msg: impl AsRef<str>) {
    eprintln!("[*] {}", msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    eprintln!("[!] {}", msg.as_ref());
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

/// Read a non-secret answer from stdin (echo on).
pub fn prompt_public(prompt: &str) -> Result<String> {
    use std::io::BufRead;
    print!("{prompt}");
    std::io::stdout()
        .flush()
        .context("failed to write the prompt")?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read the answer")?;
    Ok(line.trim().to_owned())
}
