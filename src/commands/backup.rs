use anyhow::{Context as _, Result};
use serde::Serialize;
use yubikey::certificate::Certificate;
use yubikey::piv::metadata;

use crate::cli::Output;
use crate::device::{self, mgmt, openpgp, piv};
use crate::io::{self};
use crate::rfc3339;
use crate::ui;

#[derive(Serialize)]
pub struct Backup {
    pub generated_at: String,
    pub ykoxide_version: &'static str,
    pub device: DeviceSection,
    pub piv: std::collections::BTreeMap<String, PivSlot>,
    pub otp: OtpSection,
    pub fido2: Fido2Section,
    pub openpgp: OpenPgpSection,
}

#[derive(Serialize)]
pub struct DeviceSection {
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub form_factor: Option<String>,
    pub usb_enabled: Option<Vec<String>>,
    pub nfc_enabled: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct PivSlot {
    pub algorithm: Option<String>,
    pub pin_policy: Option<String>,
    pub touch_policy: Option<String>,
    pub certificate_subject: Option<String>,
    pub certificate_not_after: Option<String>,
}

#[derive(Serialize)]
pub struct OtpSection {
    pub slot1_configured: Option<bool>,
    pub slot2_configured: Option<bool>,
}

#[derive(Serialize)]
pub struct Fido2Section {
    pub versions: Option<Vec<String>>,
    pub extensions: Option<Vec<String>>,
    pub options: Option<Vec<(String, bool)>>,
    pub resident_credentials_count: Option<u64>,
}

#[derive(Serialize)]
pub struct OpenPgpSection {
    pub fingerprints: Option<Fingerprints>,
    pub cardholder_name: Option<String>,
    pub url: Option<String>,
}

#[derive(Serialize)]
pub struct Fingerprints {
    pub sig: Option<String>,
    pub dec: Option<String>,
    pub aut: Option<String>,
}

pub fn run(serial: Option<yubikey::Serial>, out: &Output) -> Result<()> {
    let devices = device::list()?;
    let summary = match serial {
        Some(serial) => devices
            .iter()
            .find(|d| d.serial == serial)
            .with_context(|| format!("no YubiKey with serial {serial} connected"))?,
        None => match devices.as_slice() {
            [] => anyhow::bail!("no YubiKey connected"),
            [one] => one,
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
    let serial = Some(summary.serial);

    let mut yk = device::open(serial)?;

    // PIV slots (the session closes before raw PC/SC access below: dropped
    // PC/SC connections reset the card).
    let mut piv_slots = std::collections::BTreeMap::new();
    let supports_metadata = piv::metadata_supported(summary.version);
    for (slot, key) in piv::all_piv_slots() {
        let mut entry = PivSlot {
            algorithm: None,
            pin_policy: None,
            touch_policy: None,
            certificate_subject: None,
            certificate_not_after: None,
        };
        if let Ok(cert) = Certificate::read(&mut yk, slot) {
            let subject = cert.cert.tbs_certificate.subject.to_string();
            if !subject.is_empty() {
                entry.certificate_subject = Some(subject);
            }
            let not_after = cert.cert.tbs_certificate.validity.not_after;
            entry.certificate_not_after = Some(rfc3339::rfc3339_from_unix(
                not_after.to_unix_duration().as_secs(),
            ));
        }
        if supports_metadata && let Ok(meta) = metadata(&mut yk, slot) {
            entry.algorithm = Some(format!("{:?}", meta.algorithm));
            if let Some((pin, touch)) = meta.policy {
                entry.pin_policy = Some(format!("{pin:?}"));
                entry.touch_policy = Some(format!("{touch:?}"));
            }
        }
        piv_slots.insert(key, entry);
    }
    drop(yk);

    // Management applet over a raw PC/SC connection.
    let (card, _reader) = device::connect_card(serial)?;
    let device_info = match mgmt::read_device_info(&card) {
        Ok(info) => Some(info),
        Err(err) => {
            ui::warn(format!("failed to read the device info: {err:#}"));
            None
        }
    };
    let openpgp_status = match openpgp::read_card_status(&card) {
        Ok(status) => Some(status),
        Err(err) => {
            ui::warn(format!("failed to read the OpenPGP status: {err:#}"));
            None
        }
    };
    let _ = card.disconnect(pcsc::Disposition::LeaveCard);
    // FIDO2 via HID.
    let fido2 = read_fido2_info();

    let backup = Backup {
        generated_at: rfc3339::now(),
        ykoxide_version: env!("CARGO_PKG_VERSION"),
        device: DeviceSection {
            serial: Some(summary.serial.to_string()),
            firmware: Some(summary.version.to_string()),
            form_factor: device_info.as_ref().map(|d| d.form_factor.clone()),
            usb_enabled: device_info.as_ref().map(|d| d.usb_enabled.clone()),
            nfc_enabled: device_info.as_ref().map(|d| d.nfc_enabled.clone()),
        },
        piv: piv_slots,
        // The OTP slot state lives behind the OTP HID feature report
        // protocol, which is not implemented; ykman reads it over HID too.
        otp: OtpSection {
            slot1_configured: None,
            slot2_configured: None,
        },
        fido2,
        openpgp: OpenPgpSection {
            fingerprints: openpgp_status.as_ref().map(|s| Fingerprints {
                sig: s.fingerprints_sig.clone(),
                dec: s.fingerprints_dec.clone(),
                aut: s.fingerprints_aut.clone(),
            }),
            cardholder_name: openpgp_status
                .as_ref()
                .and_then(|s| s.cardholder_name.clone()),
            url: openpgp_status.as_ref().and_then(|s| s.url.clone()),
        },
    };

    let json = serde_json::to_string_pretty(&backup).context("failed to serialize the backup")?;
    // Default output is stdout; `-` also means stdout.
    let dest = match out.output.as_deref() {
        Some(p) if p == std::path::Path::new("-") => None,
        Some(p) => Some(p.to_path_buf()),
        None => None,
    };
    let mut output = io::Output::create(dest, out.force)?;
    writeln!(output.writer(), "{json}")?;
    output.finish()?;
    Ok(())
}

fn read_fido2_info() -> Fido2Section {
    use ctap_hid_fido2::{FidoKeyHidFactory, LibCfg};

    let mut cfg = LibCfg::init();
    cfg.enable_log = false;
    // The YubiKey FIDO HID interface reports an empty serial number, so the
    // device cannot be matched to --serial; take the only one connected.
    let open = FidoKeyHidFactory::create(&cfg);

    match open.and_then(|device| device.get_info()) {
        Ok(info) => Fido2Section {
            versions: Some(info.versions),
            extensions: Some(info.extensions),
            options: Some(info.options),
            resident_credentials_count: None,
        },
        Err(err) => {
            ui::warn(format!("failed to read the FIDO2 info: {err:#}"));
            empty_fido2()
        }
    }
}

fn empty_fido2() -> Fido2Section {
    Fido2Section {
        versions: None,
        extensions: None,
        options: None,
        resident_credentials_count: None,
    }
}
