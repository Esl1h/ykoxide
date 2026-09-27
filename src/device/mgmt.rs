//! Management applet (APDUs via PC/SC): device info TLVs.
//!
//! APDU sequence and TLV tags follow Yubico's yubikit/management.py
//! (github.com/Yubico/yubikey-manager, `read_device_info`, tags 0x01-0x19).

use anyhow::{Context as _, Result, anyhow};

use super::send_apdu;

const AID_MANAGEMENT: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
const INS_READ_CONFIG: u8 = 0x1D;

/// TLV tags from yubikit/management.py.
const TAG_SERIAL: u16 = 0x02;
const TAG_USB_ENABLED: u16 = 0x03;
const TAG_FORM_FACTOR: u16 = 0x04;
const TAG_VERSION: u16 = 0x05;
const TAG_NFC_ENABLED: u16 = 0x0E;
const TAG_MORE_DATA: u16 = 0x10;

/// YubiKey application bitmask, yubikit/management.py `CAPABILITY`.
pub(crate) const CAPABILITIES: &[(u32, &str)] = &[
    (0x01, "OTP"),
    (0x02, "U2F"),
    (0x08, "OPENPGP"),
    (0x10, "PIV"),
    (0x20, "OATH"),
    (0x100, "HSMAUTH"),
    (0x200, "FIDO2"),
];

pub(crate) fn decode_capabilities(mask: u32) -> Vec<String> {
    CAPABILITIES
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

/// YubiKey form factors, yubikit/management.py `FORM_FACTOR`.
pub(crate) fn decode_form_factor(code: u32) -> String {
    match code {
        0x00 => "unknown",
        0x01 => "keychain (USB-A)",
        0x02 => "nano (USB-A)",
        0x03 => "keychain (USB-C)",
        0x04 => "nano (USB-C)",
        0x05 => "keychain (USB-C, Lightning)",
        0x06 => "bio (USB-A)",
        0x07 => "bio (USB-C)",
        _ => "unknown",
    }
    .to_string()
}

#[derive(Debug, Default)]
pub struct DeviceInfo {
    pub serial: Option<u32>,
    pub version: Option<String>,
    pub form_factor: String,
    pub usb_enabled: Vec<String>,
    pub nfc_enabled: Vec<String>,
}

/// Parses a TLV list: 1 or 2 byte tags (5Fxx/7Fxx), 1 byte length with
/// 0x81/0x82 long form.
pub(crate) fn parse_tlvs(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut tlvs = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let first = data[i];
        let (tag, tag_len) = match first {
            0x5F | 0x7F if i + 1 < data.len() => (u16::from_be_bytes([first, data[i + 1]]), 2),
            t => (t as u16, 1),
        };
        i += tag_len;
        if i >= data.len() {
            return Err(anyhow!("truncated TLV (no length byte for tag {tag:02x})"));
        }
        let len = match data[i] {
            0x81 if i + 1 < data.len() => {
                i += 1;
                data[i] as usize
            }
            0x82 if i + 2 < data.len() => {
                i += 2;
                u16::from_be_bytes([data[i - 1], data[i]]) as usize
            }
            n => n as usize,
        };
        i += 1;
        if i + len > data.len() {
            return Err(anyhow!("truncated TLV (value of tag {tag:02x})"));
        }
        tlvs.push((tag, data[i..i + len].to_vec()));
        i += len;
    }
    Ok(tlvs)
}

/// Selects the Management applet and reads the device info TLV pages.
pub fn read_device_info(card: &pcsc::Card) -> Result<DeviceInfo> {
    let select = [
        &[0x00, 0xA4, 0x04, 0x00, AID_MANAGEMENT.len() as u8][..],
        AID_MANAGEMENT,
    ]
    .concat();
    let applet_version = send_apdu(card, &select)?;
    // The select response is the applet version as ASCII text.
    let default_version = String::from_utf8_lossy(&applet_version).trim().to_owned();

    let mut info = DeviceInfo {
        serial: None,
        version: Some(default_version),
        form_factor: decode_form_factor(0),
        usb_enabled: Vec::new(),
        nfc_enabled: Vec::new(),
    };

    let mut page = 0u8;
    let mut more = true;
    while more {
        more = false;
        let apdu = [0x00, INS_READ_CONFIG, page, 0x00, 0x00];
        let encoded = send_apdu(card, &apdu)
            .with_context(|| format!("failed to read device info page {page}"))?;
        page += 1;
        if encoded.is_empty() {
            break;
        }
        // Response is a length byte followed by that many bytes of TLVs.
        let len = encoded[0] as usize;
        if len != encoded.len() - 1 {
            return Err(anyhow!("invalid device info length on page {}", page - 1));
        }
        for (tag, value) in parse_tlvs(&encoded[1..])? {
            match tag {
                TAG_MORE_DATA => more = !value.iter().all(|b| *b == 0),
                TAG_SERIAL => {
                    info.serial = Some(value.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32))
                }
                TAG_VERSION => {
                    if value.len() >= 3 {
                        info.version = Some(format!("{}.{}.{}", value[0], value[1], value[2]));
                    }
                }
                TAG_FORM_FACTOR => {
                    let code = value.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32);
                    info.form_factor = decode_form_factor(code);
                }
                TAG_USB_ENABLED => {
                    info.usb_enabled = decode_capabilities(mask_from(&value));
                }
                TAG_NFC_ENABLED => {
                    info.nfc_enabled = decode_capabilities(mask_from(&value));
                }
                _ => {}
            }
        }
    }
    Ok(info)
}

fn mask_from(value: &[u8]) -> u32 {
    value.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_tlvs() {
        let data = [0x02, 0x02, 0x01, 0x02, 0x05, 0x03, 0x05, 0x04, 0x03];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs[0], (0x02, vec![0x01, 0x02]));
        assert_eq!(tlvs[1], (0x05, vec![0x05, 0x04, 0x03]));
    }

    #[test]
    fn parses_long_form_tlvs() {
        let data = [0x09, 0x81, 0x02, 0xAA, 0xBB];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs[0], (0x09, vec![0xAA, 0xBB]));
    }

    #[test]
    fn parses_real_device_info_page() {
        // Real reading from a YubiKey 5 NFC (firmware 5.2.6), captured with
        // YKOX_DEBUG_APDU during development; the leading 0x2e is the length.
        let page = hex::decode(
            "2e0102023f0302023f020400cc2f6f04010105030502060602000007010f0801000d02023f0e02023f0a01000f0100",
        )
        .unwrap();
        let tlvs = parse_tlvs(&page[1..]).unwrap();
        let get = |tag: u16| tlvs.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.clone());
        assert_eq!(get(TAG_SERIAL).unwrap(), vec![0x00, 0xcc, 0x2f, 0x6f]);
        assert_eq!(get(TAG_VERSION).unwrap(), vec![0x05, 0x02, 0x06]);
        assert_eq!(get(TAG_FORM_FACTOR).unwrap(), vec![0x01]);
        assert_eq!(get(TAG_USB_ENABLED).unwrap(), vec![0x02, 0x3f]);
        assert_eq!(get(TAG_NFC_ENABLED).unwrap(), vec![0x02, 0x3f]);
        assert_eq!(mask_from(&get(TAG_SERIAL).unwrap()), 13_381_487);
        assert_eq!(
            decode_capabilities(mask_from(&get(TAG_USB_ENABLED).unwrap())),
            vec!["OTP", "U2F", "OPENPGP", "PIV", "OATH", "FIDO2"]
        );
    }

    #[test]
    fn parses_two_byte_tags() {
        // 5F 52 is the historical bytes tag inside the OpenPGP app data.
        let data = [0x5F, 0x52, 0x03, 0x00, 0x31, 0xF5, 0x4F, 0x00];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs[0], (0x5F52, vec![0x00, 0x31, 0xF5]));
        assert_eq!(tlvs[1], (0x4F, vec![]));
    }

    #[test]
    fn rejects_truncated_tlv() {
        assert!(parse_tlvs(&[0x02, 0x04, 0x01]).is_err());
    }

    #[test]
    fn decodes_capability_mask() {
        assert_eq!(
            decode_capabilities(0x01 | 0x08 | 0x200),
            vec!["OTP", "OPENPGP", "FIDO2"]
        );
        assert!(decode_capabilities(0).is_empty());
    }

    #[test]
    fn decodes_form_factor() {
        assert_eq!(decode_form_factor(0x04), "nano (USB-C)");
        assert_eq!(decode_form_factor(0x99), "unknown");
    }

    #[test]
    fn rfc3339_formats_utc() {
        // 2026-09-27T00:00:00Z
        assert_eq!(
            crate::rfc3339::rfc3339_from_unix(1_790_467_200),
            "2026-09-27T00:00:00Z"
        );
        // Epoch.
        assert_eq!(crate::rfc3339::rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
    }
}
