use anyhow::{Context as _, Result};
use yubikey::certificate::Certificate;
use yubikey::piv::{SlotId, metadata};
use yubikey::{Serial, YubiKey};

use crate::device::{self, piv};
use crate::ui;

pub fn run(serial: Option<Serial>) -> Result<()> {
    // List before opening: dropping a PC/SC connection resets the card and
    // would invalidate a session that is already open.
    let devices = device::list()?;
    let target = match serial {
        Some(serial) => devices
            .iter()
            .find(|d| d.serial == serial)
            .map(|d| d.serial)
            .with_context(|| format!("no YubiKey with serial {serial} connected"))?,
        None => match devices.as_slice() {
            [] => anyhow::bail!("no YubiKey connected"),
            [one] => one.serial,
            _ => anyhow::bail!(
                "multiple YubiKeys connected; pass --serial <N> to choose one (serials: {})",
                devices
                    .iter()
                    .map(|d| d.serial.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        },
    };
    let summary = devices
        .iter()
        .find(|d| d.serial == target)
        .expect("serial came from this list");

    let mut yk = device::open(Some(target))?;
    ui::info(format!(
        "{} (serial {}, firmware {}, reader {})",
        summary.name, summary.serial, summary.version, summary.reader,
    ));

    let supports_metadata = piv::metadata_supported(summary.version);
    for (slot, label) in slots() {
        print_slot(&mut yk, slot, &label, supports_metadata);
    }
    Ok(())
}

fn slots() -> Vec<(SlotId, String)> {
    piv::all_piv_slots()
        .into_iter()
        .map(|(slot, hex)| match hex.as_str() {
            "9a" => (slot, "9a authentication".to_string()),
            "9c" => (slot, "9c signature".to_string()),
            "9d" => (slot, "9d key management".to_string()),
            "9e" => (slot, "9e card authentication".to_string()),
            raw => {
                let index = u8::from_str_radix(raw, 16).unwrap_or(0) - 0x82 + 1;
                (slot, format!("{raw} retired {index}"))
            }
        })
        .collect()
}

fn print_slot(yk: &mut YubiKey, slot: SlotId, label: &str, supports_metadata: bool) {
    let mut line = format!("slot {label}: ");
    match Certificate::read(yk, slot) {
        Ok(cert) => {
            let subject = cert.cert.tbs_certificate.subject.to_string();
            if subject.is_empty() {
                line.push_str("certificate present");
            } else {
                line.push_str(&format!("certificate: {subject}"));
            }
        }
        // The crate signals an absent certificate as an empty or missing
        // object, not as a distinct "empty slot" state.
        Err(yubikey::Error::NotFound | yubikey::Error::InvalidObject) => line.push_str("empty"),
        Err(err) => line.push_str(&format!("certificate unavailable: {err}")),
    }

    if supports_metadata && let Ok(meta) = metadata(yk, slot) {
        line.push_str(&format!("; key {:?}", meta.algorithm));
        if let Some((pin, touch)) = meta.policy {
            line.push_str(&format!(", pin policy {pin:?}, touch policy {touch:?}"));
        }
    }
    ui::info(line);
}
