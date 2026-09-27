//! Device discovery and session handling over PC/SC.

use anyhow::{Context, Result, anyhow, bail};
use yubikey::reader::Context as ReaderContext;
use yubikey::{Serial, Version, YubiKey};

/// A YubiKey found behind a PC/SC reader.
#[derive(Debug)]
pub struct DeviceSummary {
    pub reader: String,
    pub name: String,
    pub serial: Serial,
    pub version: Version,
}

pub fn list() -> Result<Vec<DeviceSummary>> {
    let mut ctx = ReaderContext::open().map_err(|err| {
        // When pcscd is not running, pcsc surfaces "The Smart card resource
        // manager is not running" in the error chain; make that actionable.
        if format!("{err:#}").contains("resource manager") {
            anyhow!("failed to open the PC/SC context: is the pcscd service running?")
        } else {
            anyhow::Error::new(err).context("failed to open the PC/SC context")
        }
    })?;

    let mut devices = Vec::new();
    for reader in ctx.iter()? {
        // Readers may hold smart cards that are not YubiKeys; skip those.
        let Ok(yk) = reader.open() else {
            continue;
        };
        devices.push(DeviceSummary {
            reader: reader.name().into_owned(),
            name: yk.name().to_owned(),
            serial: yk.serial(),
            version: yk.version(),
        });
    }
    Ok(devices)
}

pub fn open(serial: Option<Serial>) -> Result<YubiKey> {
    let Some(serial) = serial else {
        let devices = list()?;
        return match devices.as_slice() {
            [] => bail!("no YubiKey connected"),
            [only] => open(Some(only.serial)),
            many => {
                let serials = many
                    .iter()
                    .map(|d| d.serial.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("multiple YubiKeys connected ({serials}); pass --serial <N> to choose one")
            }
        };
    };

    YubiKey::open_by_serial(serial).with_context(|| format!("failed to open YubiKey {serial}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only hardware test: run with `YKOX_TEST_HW=1 cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn list_finds_connected_key() {
        if std::env::var("YKOX_TEST_HW").is_err() {
            return;
        }
        let devices = list().unwrap();
        assert!(!devices.is_empty());
        if let Ok(serial) = std::env::var("YKOX_TEST_SERIAL") {
            assert!(
                devices.iter().any(|d| d.serial.to_string() == serial),
                "no device with serial {serial}, found: {}",
                devices
                    .iter()
                    .map(|d| d.serial.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}
