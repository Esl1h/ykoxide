use anyhow::{Context as _, Result};
use yubikey::certificate::Certificate;
use yubikey::piv::{RetiredSlotId, SlotId, metadata};
use yubikey::{Serial, Version, YubiKey};

use crate::device::piv;
use crate::ui;

pub fn run(serial: Option<Serial>) -> Result<()> {
    // List before opening: dropping a PC/SC connection resets the card and
    // would invalidate a session that is already open.
    let devices = piv::list()?;
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

    let mut yk = piv::open(Some(target))?;
    ui::info(format!(
        "{} (serial {}, firmware {}, reader {})",
        summary.name, summary.serial, summary.version, summary.reader,
    ));

    let supports_metadata = metadata_supported(summary.version);
    for (slot, label) in slots() {
        print_slot(&mut yk, slot, &label, supports_metadata);
    }
    Ok(())
}

fn metadata_supported(version: Version) -> bool {
    // Slot metadata arrived with firmware 5.2.3; only report it from 5.3 on.
    (version.major, version.minor) >= (5, 3)
}

fn slots() -> Vec<(SlotId, String)> {
    let mut slots = vec![
        (SlotId::Authentication, "9a authentication".to_string()),
        (SlotId::Signature, "9c signature".to_string()),
        (SlotId::KeyManagement, "9d key management".to_string()),
        (
            SlotId::CardAuthentication,
            "9e card authentication".to_string(),
        ),
    ];
    for raw in 0x82..=0x95u8 {
        let Ok(retired) = RetiredSlotId::try_from(raw) else {
            continue;
        };
        let index = raw - 0x82 + 1;
        slots.push((
            SlotId::Retired(retired),
            format!("{raw:02x} retired {index}"),
        ));
    }
    slots
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
