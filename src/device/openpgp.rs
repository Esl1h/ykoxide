//! OpenPGP applet (APDUs via PC/SC): card status for the backup.
//!
//! DO numbers and parsing follow Yubico's yubikit/openpgp.py
//! (github.com/Yubico/yubikey-manager): APPLICATION_RELATED_DATA 0x6E,
//! discretionary data 0x73, fingerprints 0xC5, cardholder name 0x5B,
//! URL 0x5F50, GET DATA ins 0xCA.

use anyhow::{Context as _, Result};

use super::send_apdu;

const AID_OPENPGP: &[u8] = &[0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
const INS_GET_DATA: u8 = 0xCA;

#[derive(Debug, Default)]
pub struct CardStatus {
    pub fingerprints_sig: Option<String>,
    pub fingerprints_dec: Option<String>,
    pub fingerprints_aut: Option<String>,
    pub cardholder_name: Option<String>,
    pub url: Option<String>,
}

/// Selects the OpenPGP applet and reads the status data objects.
pub fn read_card_status(card: &pcsc::Card) -> Result<CardStatus> {
    let select = [
        &[0x00, 0xA4, 0x04, 0x00, AID_OPENPGP.len() as u8][..],
        AID_OPENPGP,
    ]
    .concat();
    send_apdu(card, &select).context("failed to select the OpenPGP applet")?;

    let mut status = CardStatus::default();

    // Application related data: 4F (AID), 5F52 (historical), 73 (discretionary).
    let app_data = get_data(card, 0x00, 0x6E)?;
    if let Some(fp) = find_nested(&app_data, &[0x6E], 0x73).and_then(|d| find_tlv(&d, 0xC5)) {
        let fmt = |raw: Option<&[u8]>| -> Option<String> {
            let raw = raw?;
            if raw.len() != 20 || raw.iter().all(|b| *b == 0) {
                None
            } else {
                Some(raw.iter().map(|b| format!("{b:02X}")).collect())
            }
        };
        status.fingerprints_sig = fmt(fp.get(..20));
        status.fingerprints_dec = fmt(fp.get(20..40));
        status.fingerprints_aut = fmt(fp.get(40..60));
    }

    // Cardholder related data: 5B (name).
    let holder_data = get_data(card, 0x00, 0x65)?;
    if let Some(name) = find_nested(&holder_data, &[0x65], 0x5B) {
        status.cardholder_name = Some(String::from_utf8_lossy(&name).trim().to_owned());
    }

    // URL is a top level DO with a two byte tag.
    let url = get_data(card, 0x5F, 0x50)?;
    if !url.is_empty() {
        status.url = Some(String::from_utf8_lossy(&url).trim().to_owned());
    }

    Ok(status)
}

fn get_data(card: &pcsc::Card, p1: u8, p2: u8) -> Result<Vec<u8>> {
    send_apdu(card, &[0x00, INS_GET_DATA, p1, p2, 0x00])
        .with_context(|| format!("GET DATA {p1:02x}{p2:02x} failed"))
}

/// Walks a chain of nesting TLVs and finds `tag` in the innermost level.
fn find_nested(data: &[u8], nest: &[u16], tag: u16) -> Option<Vec<u8>> {
    let mut current = data.to_vec();
    for container in nest {
        current = find_tlv(&current, *container)?;
    }
    find_tlv(&current, tag)
}

fn find_tlv(data: &[u8], tag: u16) -> Option<Vec<u8>> {
    let tlvs = super::mgmt::parse_tlvs(data).ok()?;
    tlvs.into_iter().find(|(t, _)| *t == tag).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_application_related_data() {
        // Real GET DATA 00 CA 00 6E response from a YubiKey 5 with an OpenPGP
        // key, captured during development.
        let data = hex::decode(concat!(
            "6e8201374f10d27600012401030400061338148700005f520800730000e00590007f740381012073820110c00a7d000bfe080000f",
            "f0000c106011000001100c206011000001100c306011000001100da06010800001100c407ff7f7f7f030303c550b2a75fd1edd7c8",
            "48aadd73b196dfc57df89fa884d9687614ea63a90bfb633f5a9cff1a789198aba14cb9ff81cdec943494a4fffe6fb7c2cb60d99df",
            "a0000000000000000000000000000000000000000c650000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd106",
            "62c05ff662c05ff687e986e00000000de0801020202030281027f660802020bfe02020bfed6020020d7020020d8020020d9020020",
        ))
        .unwrap();
        let fp = find_nested(&data, &[0x6E], 0x73)
            .and_then(|d| find_tlv(&d, 0xC5))
            .expect("fingerprints not found");
        assert_eq!(fp.len(), 80);
        assert_eq!(
            fp[..20]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
            "B2A75FD1EDD7C848AADD73B196DFC57DF89FA884"
        );
    }

    #[test]
    fn parses_cardholder_name() {
        // Real GET DATA 00 CA 00 65 response (name = "Silva<<Esli").
        let data = hex::decode("65165b0b53696c76613c3c45736c695f2d02656e5f350131").unwrap();
        let name = find_nested(&data, &[0x65], 0x5B).unwrap();
        assert_eq!(String::from_utf8_lossy(&name), "Silva<<Esli");
    }
}
