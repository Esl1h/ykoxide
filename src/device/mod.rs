//! Device discovery and session handling over PC/SC.

pub mod fido2;
pub mod mgmt;
pub mod openpgp;
pub mod otp;
pub mod piv;

use anyhow::{Context, Result, anyhow, bail};
use pcsc::{Protocols, Scope, ShareMode};
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

/// Opens a raw PC/SC card to the reader holding the YubiKey with `serial`
/// (or the only one connected). The caller MUST disconnect with
/// `Disposition::LeaveCard`: the default drop resets the card.
pub(crate) fn connect_card(serial: Option<Serial>) -> Result<(pcsc::Card, String)> {
    let devices = list()?;
    let target = match serial {
        Some(serial) => devices
            .iter()
            .find(|d| d.serial == serial)
            .map(|d| d.reader.clone())
            .with_context(|| format!("no YubiKey with serial {serial} connected"))?,
        None => match devices.as_slice() {
            [] => bail!("no YubiKey connected"),
            [one] => one.reader.clone(),
            _ => bail!("multiple YubiKeys connected; pass --serial <N> to choose one"),
        },
    };

    let ctx = pcsc::Context::establish(Scope::System)
        .map_err(|e| anyhow!("failed to open the PC/SC context: {e}"))?;
    let reader_cstr = std::ffi::CString::new(target.clone())?;
    let card = ctx
        .connect(&reader_cstr, ShareMode::Shared, Protocols::T1)
        .with_context(|| format!("failed to connect to reader {target}"))?;
    Ok((card, target))
}

/// Sends an APDU and collects the response, following SW 0x61 chaining.
pub(crate) fn send_apdu(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut buf = [0u8; pcsc::MAX_BUFFER_SIZE];
    let mut data: Vec<u8> = card
        .transmit(apdu, &mut buf)
        .with_context(|| format!("APDU {:02x} {:02x} failed", apdu[1], apdu[2]))?
        .to_vec();

    loop {
        if data.len() < 2 {
            bail!("short APDU response");
        }
        let sw = data[data.len() - 2..].to_vec();
        match sw.as_slice() {
            [0x90, 0x00] => return Ok(data[..data.len() - 2].to_vec()),
            [0x61, more] => {
                let get_response = [0x00, 0xC0, 0x00, 0x00, *more];
                let chunk = card
                    .transmit(&get_response, &mut buf)
                    .context("GET RESPONSE failed")?;
                data.truncate(data.len() - 2);
                data.extend_from_slice(chunk);
            }
            _ => bail!("APDU failed with status {:02x}{:02x}", sw[0], sw[1]),
        }
    }
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
