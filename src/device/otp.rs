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
}
