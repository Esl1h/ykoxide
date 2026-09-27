//! Encrypted file formats.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use age::Decryptor;

pub mod legacy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Legacy,
    AgeScrypt,
    AgeRecipients,
    AgeArmored,
    Unknown,
}

pub const AGE_PREFIX: &[u8] = b"age-encryption.org/v1";
pub const ARMOR_PREFIX: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// Reads a small prefix for format detection.
fn read_prefix<R: Read>(reader: &mut R) -> Option<Vec<u8>> {
    let mut prefix = [0u8; 40];
    let mut len = 0;
    loop {
        match reader.read(&mut prefix[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(_) => return None,
        }
        if len == prefix.len() {
            break;
        }
    }
    Some(prefix[..len].to_vec())
}

/// Detects the file format by reading only the beginning of the file.
pub fn detect(path: &Path) -> Format {
    let Ok(mut file) = File::open(path) else {
        return Format::Unknown;
    };
    let Some(prefix) = read_prefix(&mut file) else {
        return Format::Unknown;
    };

    if prefix.starts_with(legacy::MAGIC) {
        return Format::Legacy;
    }

    let is_age = prefix.starts_with(AGE_PREFIX);
    let is_armored = prefix.starts_with(ARMOR_PREFIX);
    if !is_age && !is_armored {
        return Format::Unknown;
    }

    // Distinguish scrypt from recipient stanzas through the parsed header.
    let Ok(file) = File::open(path) else {
        return Format::Unknown;
    };
    match is_age {
        true => match Decryptor::new(std::io::BufReader::new(file)) {
            Ok(decryptor) if decryptor.is_scrypt() => Format::AgeScrypt,
            Ok(_) => Format::AgeRecipients,
            Err(_) => Format::Unknown,
        },
        false => Format::AgeArmored,
    }
}
