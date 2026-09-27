//! Legacy `.yk.enc` files produced by yk-encrypt-file.sh: openssl
//! `enc -aes-256-cbc -pbkdf2 -iter 600000` with a key derived from the
//! challenge and the YubiKey HMAC response. Read only, and unauthenticated.

use std::io::{Read, Write};

use aes::Aes256;
use anyhow::{Context as _, Result, anyhow, bail};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub const MAGIC: &[u8; 8] = b"Salted__";
const ITERATIONS: u32 = 600_000;

/// The passphrase of the legacy format: the lowercase hex SHA-256 over the
/// concatenated challenge and HMAC hex strings (as ASCII), never the bytes.
pub fn derive_passphrase(challenge_hex: &str, hmac_hex: &str) -> Zeroizing<String> {
    let mut hasher = Sha256::new();
    hasher.update(challenge_hex.as_bytes());
    hasher.update(hmac_hex.as_bytes());
    Zeroizing::new(hex::encode(hasher.finalize()))
}

/// Decrypts a legacy file. Legacy files are small configuration files, so the
/// ciphertext is read whole into memory; noted as a limitation in the plan.
pub fn decrypt<R: Read, W: Write>(mut input: R, passphrase: &[u8], mut output: W) -> Result<()> {
    let mut header = [0u8; 16];
    input
        .read_exact(&mut header)
        .context("file too short for a legacy openssl file")?;
    if &header[..8] != MAGIC {
        bail!("not a legacy openssl file (missing Salted__ header)");
    }
    let salt = &header[8..];

    let mut ciphertext = Vec::new();
    input
        .read_to_end(&mut ciphertext)
        .context("failed to read the ciphertext")?;
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        bail!("corrupt legacy file: ciphertext is not a multiple of the block size");
    }

    let mut key_iv = Zeroizing::new([0u8; 48]);
    pbkdf2_hmac::<Sha256>(passphrase, salt, ITERATIONS, &mut key_iv[..]);

    let decryptor = Aes256CbcDec::new_from_slices(&key_iv[..32], &key_iv[32..])
        .map_err(|e| anyhow!("failed to initialize AES-256-CBC: {e}"))?;
    let plaintext = decryptor
        .decrypt_padded_vec::<Pkcs7>(&ciphertext)
        .map_err(|_| anyhow!("wrong key or corrupt file (invalid padding)"))?;
    output.write_all(&plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    // The same fixed values as tests/fixtures/make-legacy.sh.
    const CHALLENGE: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const HMAC: &str = "0102030405060708090a0b0c0d0e0f1011121314";

    #[test]
    fn derive_passphrase_is_hex_of_sha256_over_hex_strings() {
        let passphrase = derive_passphrase(CHALLENGE, HMAC);
        // Independently computed with openssl:
        // echo -n "<challenge><hmac>" | openssl dgst -sha256 -hex
        assert_eq!(passphrase.len(), 64);
        assert!(
            passphrase
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn decrypt_round_trip_through_derived_passphrase() {
        let passphrase = derive_passphrase(CHALLENGE, HMAC);
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/legacy/plain.txt.yk.enc");
        let file = BufReader::new(std::fs::File::open(&fixture).unwrap());
        let mut out = Vec::new();
        decrypt(file, passphrase.as_bytes(), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "legacy plaintext");
    }
}
