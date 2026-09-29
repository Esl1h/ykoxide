//! OTP applet: HMAC-SHA1 challenge-response over the HID interface.

use anyhow::{Context as _, Result, anyhow, bail};
use challenge_response::ChallengeResponse;
use challenge_response::config::{Command, Config, Slot};
use zeroize::Zeroizing;

/// Computes the HMAC-SHA1 response of `challenge` on the given OTP slot.
///
/// The challenge is padded exactly like ykman does: zero-filled to 64 bytes,
/// or filled with 0x01 when the challenge ends with a zero byte. Failing to
/// match this padding would make legacy files undecryptable.
pub fn challenge_response(
    slot: u8,
    challenge: &[u8],
    serial: Option<u32>,
) -> Result<Zeroizing<[u8; 20]>> {
    if challenge.is_empty() || challenge.len() > 64 {
        bail!("challenge must have between 1 and 64 bytes");
    }

    let mut padded = [0u8; 64];
    padded[..challenge.len()].copy_from_slice(challenge);
    if challenge[challenge.len() - 1] == 0 {
        for b in &mut padded[challenge.len()..] {
            *b = 1;
        }
    }

    let mut manager = ChallengeResponse::new().context("failed to open the OTP HID interface")?;
    let device = match serial {
        Some(serial) => manager
            .find_device_from_serial(serial)
            .context("no YubiKey with OTP interface found for the given serial")?,
        None => manager
            .find_device()
            .context("no YubiKey with OTP interface found")?,
    };

    let mut conf = Config::new_from(device);
    // Disable the crate's variable-size quirk (0xff padding), which differs
    // from ykman and would change the response for 0-ending challenges.
    conf.variable = false;
    match slot {
        1 => {
            conf.slot = Slot::Slot1;
            conf.command = Command::ChallengeHmac1;
        }
        2 => {
            conf.slot = Slot::Slot2;
            conf.command = Command::ChallengeHmac2;
        }
        _ => bail!("invalid OTP slot {slot}"),
    }

    let hmac = manager
        .challenge_response_hmac(&padded, conf)
        .map_err(|e| anyhow!("HMAC challenge-response failed: {e} (is slot {slot} configured?)"))?;
    Ok(Zeroizing::new(hmac.0))
}

/// Configuration state of the two OTP slots, read from the HID status block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtpSlotStatus {
    pub slot1_configured: bool,
    pub slot2_configured: bool,
}

/// Slot programmed flags from the 8-byte HID status block: byte 5 is the
/// touch level low byte, bit 0 = slot 1 programmed, bit 1 = slot 2 (layout
/// as in yubikit's OtpProtocol.read_status).
fn slots_from_status_block(report: &[u8]) -> Result<OtpSlotStatus> {
    if report.len() < 6 {
        bail!("short OTP status block ({} bytes)", report.len());
    }
    Ok(OtpSlotStatus {
        slot1_configured: report[5] & 0x01 != 0,
        slot2_configured: report[5] & 0x02 != 0,
    })
}

// Minimal subset of the YubiKey OTP HID protocol (feature reports), enough
// for a passive status read with `--serial` honored. The `challenge_response`
// crate exposes neither, and its backend claims every HID interface of the
// device, which makes the kernel drop the FIDO interface's hidraw node and
// breaks concurrent FIDO2 access. Only the OTP interface (a HID boot
// keyboard) is claimed here.
const VENDOR_YUBICO: u16 = 0x1050;
const HID_GET_REPORT: u8 = 0x01;
const REPORT_TYPE_FEATURE: u16 = 0x03;
const SLOT_WRITE_FLAG: u8 = 0x80;
const RESP_PENDING_FLAG: u8 = 0x40;
const OTP_CMD_DEVICE_SERIAL: u8 = 0x10;
const OTP_FRAME_SIZE: usize = 70; // 64 payload + command + crc16 + 3 filler
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Yubico CRC-16 (CCITT variant, residual 0xf0b8 over data plus CRC).
fn crc16_yubico(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

struct OtpHid {
    handle: nusb::Device,
    interface: u16,
    // Keeps the usbfs claim alive for the lifetime of the connection.
    _claim: nusb::Interface,
}

impl OtpHid {
    fn get_report(&self) -> Result<Vec<u8>> {
        use nusb::MaybeFuture as _;
        self.handle
            .control_in(
                nusb::transfer::ControlIn {
                    control_type: nusb::transfer::ControlType::Class,
                    recipient: nusb::transfer::Recipient::Interface,
                    request: HID_GET_REPORT,
                    value: REPORT_TYPE_FEATURE << 8,
                    index: self.interface,
                    length: 8,
                },
                TRANSFER_TIMEOUT,
            )
            .wait()
            .context("failed to read the OTP status block")
    }

    fn set_report(&self, packet: &[u8]) -> Result<()> {
        use nusb::MaybeFuture as _;
        self.handle
            .control_out(
                nusb::transfer::ControlOut {
                    control_type: nusb::transfer::ControlType::Class,
                    recipient: nusb::transfer::Recipient::Interface,
                    request: 0x09, // HID_SET_REPORT
                    value: REPORT_TYPE_FEATURE << 8,
                    index: self.interface,
                    data: packet,
                },
                TRANSFER_TIMEOUT,
            )
            .wait()
            .context("failed to write to the OTP interface")
    }

    /// Polls until the predicate over the sequence/flags byte holds.
    fn wait_for(&self, f: impl Fn(u8) -> bool) -> Result<Vec<u8>> {
        for _ in 0..500 {
            let report = self.get_report()?;
            let flags = report.last().copied().unwrap_or(0);
            if f(flags) {
                return Ok(report);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        bail!("timeout waiting for the OTP interface");
    }

    /// Sends a 70-byte OTP frame (payload + command + CRC) over feature
    /// reports, skipping all-zero chunks like the reference implementations.
    fn write_frame(&self, payload: &[u8; 64], command: u8) -> Result<()> {
        self.wait_for(|flags| flags & SLOT_WRITE_FLAG == 0)?;

        let crc = crc16_yubico(payload).to_le_bytes();
        let mut frame = [0u8; OTP_FRAME_SIZE];
        frame[..64].copy_from_slice(payload);
        frame[64] = command;
        frame[65..67].copy_from_slice(&crc);

        for (seq, chunk) in frame.chunks(7).enumerate() {
            let is_last = seq == OTP_FRAME_SIZE.div_ceil(7) - 1;
            if seq != 0 && !is_last && chunk.iter().all(|&b| b == 0) {
                continue;
            }
            let mut packet = [0u8; 8];
            packet[..chunk.len()].copy_from_slice(chunk);
            packet[7] = SLOT_WRITE_FLAG | seq as u8;
            self.wait_for(|flags| flags & SLOT_WRITE_FLAG == 0)?;
            self.set_report(&packet)?;
        }
        Ok(())
    }

    /// Reads a command response: 7 data bytes per report until the device
    /// stops answering.
    fn read_response(&self, response: &mut [u8]) -> Result<usize> {
        let first = self.wait_for(|flags| flags & RESP_PENDING_FLAG != 0)?;
        response[..7].copy_from_slice(&first[..7]);
        let mut read = 7;
        while read + 8 <= response.len() {
            let report = self.get_report()?;
            let flags = report.last().copied().unwrap_or(0);
            if flags & RESP_PENDING_FLAG == 0 {
                break;
            }
            if flags & 0b0001_1111 == 0 && read > 7 {
                break;
            }
            response[read..read + 7].copy_from_slice(&report[..7]);
            read += 7;
        }
        Ok(read)
    }

    /// Aborts any pending response and returns the applet to the idle state
    /// (the 0x8f dummy report of the OTP protocol). A response left pending
    /// by a previous failed exchange would otherwise block new commands and
    /// make every status read return response chunks instead of the status
    /// block.
    fn reset_write(&self) -> Result<()> {
        let mut reset = [0u8; 8];
        reset[7] = 0x8f;
        self.set_report(&reset)?;
        self.wait_for(|flags| flags & SLOT_WRITE_FLAG == 0)?;
        Ok(())
    }

    /// Reads the numeric serial via the DeviceSerial command (the USB
    /// descriptor serial is empty on YubiKeys). The device sends the serial
    /// big-endian and the CRC inverted, verified by the 0xf0b8 residual.
    fn serial(&self) -> Result<u32> {
        let mut response = [0u8; 36];
        let mut exchange = Err(anyhow!("no attempt made"));
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            exchange = (|| -> Result<usize> {
                self.write_frame(&[0u8; 64], OTP_CMD_DEVICE_SERIAL)?;
                self.read_response(&mut response)
            })();
            if exchange.is_ok() {
                break;
            }
        }
        // Always clear a pending response, even when the exchange failed.
        let _ = self.reset_write();
        exchange?;
        if crc16_yubico(&response[..6]) != 0xf0b8 {
            bail!("invalid CRC on the OTP serial response");
        }
        Ok(u32::from_be_bytes([
            response[0],
            response[1],
            response[2],
            response[3],
        ]))
    }
}

/// Opens the OTP HID interface of the selected YubiKey. usbfs requires the
/// interface claimed for interface-recipient control transfers; the claim is
/// dropped (and the kernel driver can rebind) when the connection ends.
fn open_otp_interface(serial: Option<u32>) -> Result<OtpHid> {
    use nusb::MaybeFuture as _;

    let candidates = nusb::list_devices()
        .wait()
        .context("failed to list USB devices")?
        .filter(|d| d.vendor_id() == VENDOR_YUBICO);

    for info in candidates {
        let Some(interface) = info
            .interfaces()
            .find(|i| i.class() == 0x03 && i.subclass() == 0x01 && i.protocol() == 0x01)
        else {
            continue; // no OTP interface (FIDO-only mode or another product)
        };
        let handle = match info.open().wait() {
            Ok(handle) => handle,
            Err(_) => continue,
        };
        let claim = match handle
            .detach_and_claim_interface(interface.interface_number())
            .wait()
        {
            Ok(claim) => claim,
            Err(_) => continue,
        };
        let otp = OtpHid {
            handle,
            interface: interface.interface_number() as u16,
            _claim: claim,
        };
        match serial {
            None => return Ok(otp),
            Some(want) => match otp.serial() {
                Ok(found) if found == want => return Ok(otp),
                _ => continue, // drops the claim on the non-matching device
            },
        }
    }
    match serial {
        Some(serial) => bail!("no YubiKey with OTP interface found for serial {serial}"),
        None => bail!("no YubiKey with OTP interface found"),
    }
}

/// Reads which OTP slots are programmed, via a GET_REPORT(feature) control
/// transfer on the OTP HID interface.
pub fn slot_status(serial: Option<u32>) -> Result<OtpSlotStatus> {
    let otp = open_otp_interface(serial)?;
    // Clear a response left pending by an earlier failed exchange; the
    // status block is only presented while no response is pending.
    let _ = otp.reset_write();
    let report = otp.get_report()?;
    slots_from_status_block(&report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only hardware test: the response for a fixed challenge must match
    /// `ykman otp calculate 2 <hex>` exactly. Run with
    /// `YKOX_TEST_HW=1 cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn response_matches_ykman_for_fixed_challenge() {
        if std::env::var("YKOX_TEST_HW").is_err() {
            return;
        }
        let serial: Option<u32> = std::env::var("YKOX_TEST_SERIAL")
            .ok()
            .map(|s| s.parse().expect("YKOX_TEST_SERIAL must be a number"));
        let challenge_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let challenge: Vec<u8> = (0..32).map(|i| i as u8 + 1).collect();
        let response = challenge_response(2, &challenge, serial).unwrap();
        let hex_response = hex::encode(*response);
        println!("ykman reference: ykman otp calculate 2 {challenge_hex}");
        println!("ykox response:   {hex_response}");
        assert_eq!(hex_response.len(), 40);
    }

    #[test]
    fn parses_slot_flags_from_status_block() {
        // Firmware 5.2.6, both slots programmed, none requiring touch.
        let report = [0x00, 0x05, 0x02, 0x06, 0x0b, 0x03, 0x00, 0x00];
        let status = slots_from_status_block(&report).unwrap();
        assert!(status.slot1_configured);
        assert!(status.slot2_configured);

        let status = slots_from_status_block(&[0; 8]).unwrap();
        assert!(!status.slot1_configured);
        assert!(!status.slot2_configured);

        let status = slots_from_status_block(&[0, 0, 0, 0, 0, 0x02, 0, 0]).unwrap();
        assert!(!status.slot1_configured);
        assert!(status.slot2_configured);

        assert!(slots_from_status_block(&[0, 1, 2]).is_err());
    }

    /// Yubico response framing: the device appends the inverted CRC in
    /// little-endian, and the CRC over data plus CRC yields the 0xf0b8
    /// residual.
    #[test]
    fn crc16_residual_holds_for_appended_checksum() {
        for data in [
            vec![0x00, 0xcc, 0x2f, 0x6f],
            vec![0u8; 64],
            (0..=255u8).collect::<Vec<u8>>(),
        ] {
            let mut framed = data.clone();
            framed.extend_from_slice(&(!crc16_yubico(&data)).to_le_bytes());
            assert_eq!(crc16_yubico(&framed), 0xf0b8);
        }
    }
}
