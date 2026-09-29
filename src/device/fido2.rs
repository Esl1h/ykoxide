//! FIDO2 hmac-secret derivation over the CTAP2 HID interface.
//!
//! Path 2 of the phase 6 design (own format): a non-resident credential is
//! created once with `enroll`, and every file carries its own 32-byte salt;
//! the hmac-secret output is the passphrase of an age scrypt recipient, like
//! the OTP HMAC flow of `hmac encrypt`.

use crate::ui;
use std::io::Read as _;

use anyhow::{Context as _, Result};
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as AssertionExtension;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as MakeExtension;
use zeroize::Zeroizing;

/// A non-resident credential reference: the token stores the private key and
/// the files store this descriptor.
#[derive(Clone, Debug)]
pub struct Credential {
    pub rp_id: String,
    pub credential_id: Vec<u8>,
}

fn open_device() -> Result<ctap_hid_fido2::FidoKeyHid> {
    let mut cfg = ctap_hid_fido2::LibCfg::init();
    cfg.enable_log = false;
    // The FIDO HID interface reports an empty serial number, so the device
    // cannot be matched to --serial; take the only one connected.
    FidoKeyHidFactory::create(&cfg).context("failed to open the FIDO2 device")
}

/// Creates a non-resident credential with the hmac-secret extension. The
/// token asks for a touch; with a PIN, it also verifies the PIN.
pub fn enroll(rp_id: &str, pin: Option<&str>) -> Result<Credential> {
    let device = open_device()?;

    let mut challenge = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut challenge))
        .context("failed to read random bytes from /dev/urandom")?;

    ui::info("Touch your YubiKey if it blinks");
    let attestation = device
        .make_credential_with_extensions(
            rp_id,
            &challenge,
            pin,
            Some(&vec![MakeExtension::HmacSecret(Some(true))]),
        )
        .context("FIDO2 credential creation failed")?;
    Ok(Credential {
        rp_id: rp_id.to_owned(),
        credential_id: attestation.credential_descriptor.id,
    })
}

/// Derives the 32-byte hmac-secret output for `salt`. The token asks for a
/// touch; with a PIN, it also verifies the PIN.
pub fn derive(
    credential: &Credential,
    salt: &[u8; 32],
    pin: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>> {
    let device = open_device()?;
    // The challenge only feeds the discarded assertion signature; the
    // derivation depends on the salt carried by the extension.
    let challenge = [0u8; 32];

    ui::info("Touch your YubiKey if it blinks");
    let assertion = device
        .get_assertion_with_extensions(
            &credential.rp_id,
            &challenge,
            std::slice::from_ref(&credential.credential_id),
            pin,
            Some(&vec![AssertionExtension::HmacSecret(Some(*salt))]),
        )
        .context("FIDO2 assertion failed")?;

    let secret = assertion
        .extensions
        .iter()
        .find_map(|ext| match ext {
            AssertionExtension::HmacSecret(output) => *output,
            _ => None,
        })
        .context("the token did not answer with an hmac-secret output")?;
    Ok(Zeroizing::new(secret))
}
