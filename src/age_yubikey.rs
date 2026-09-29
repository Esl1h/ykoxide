//! Native implementation of the `piv-p256` age stanza, the format used by
//! age-plugin-yubikey 0.5. Format reference: the plugin's src/format.rs and
//! src/p256.rs (github.com/str4d/age-plugin-yubikey).
//!
//! The recipient is a bech32 string with HRP `age1yubikey1` over the
//! compressed SEC-1 encoding of the slot's P-256 public key. The identity is
//! a bech32 string with HRP `AGE-PLUGIN-YUBIKEY-` over 9 bytes: serial (LE),
//! retired slot id, and the 4-byte key tag (SHA-256 of the compressed key).

use std::collections::HashSet;
use std::fmt;
use std::io::Read as _;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza};
use age_core::primitives::{aead_decrypt, aead_encrypt};
use anyhow::{Context as _, anyhow};
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine};
use bech32::{FromBase32, ToBase32, Variant};
use der::oid::AssociatedOid;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use sha2::{Digest, Sha256};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::AsExtension;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use yubikey::certificate::Certificate;
use yubikey::piv::{self, AlgorithmId, RetiredSlotId, SlotId};
use yubikey::{MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};

use crate::ui;

const STANZA_TAG: &str = "piv-p256";
const STANZA_KEY_LABEL: &[u8] = b"piv-p256";
const TAG_BYTES: usize = 4;
const EPK_BYTES: usize = 33;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;
const FILE_KEY_BYTES: usize = 16;

/// bech32 HRPs (the separator `1` is added by the encoding).
const RECIPIENT_HRP: &str = "age1yubikey";
const IDENTITY_HRP: &str = "age-plugin-yubikey-";
/// String prefixes of the full encoded strings, for dispatch.
pub const RECIPIENT_STRING_PREFIX: &str = "age1yubikey1";
pub const IDENTITY_STRING_PREFIX: &str = "AGE-PLUGIN-YUBIKEY-";

const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_OID: &str = "1.2.840.10045.3.1.7";

/// HKDF-SHA256 (RFC 5869), matching the plugin's hkdf usage: extract with the
/// salt over the shared secret, expand with the stanza label.
fn hkdf(salt: &[u8], info: &[u8], ikm: &[u8]) -> [u8; 32] {
    // HMAC-SHA256 accepts keys of any length, so new_from_slice cannot fail.
    let mut prk_mac =
        Hmac::<Sha256>::new_from_slice(salt).expect("HMAC-SHA256 accepts any key length");
    prk_mac.update(ikm);
    let prk: [u8; 32] = prk_mac.finalize().into_bytes().into();

    // First block only: L = 32 < HashLen * 255.
    let mut okm_mac =
        Hmac::<Sha256>::new_from_slice(&prk).expect("HMAC-SHA256 accepts any key length");
    okm_mac.update(info);
    okm_mac.update(&[1]);
    okm_mac.finalize().into_bytes().into()
}

fn random_scalar() -> anyhow::Result<p256::SecretKey> {
    loop {
        let mut bytes = [0u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        if let Ok(sk) = p256::SecretKey::from_slice(&bytes) {
            return Ok(sk);
        }
    }
}

fn random_bytes<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The `age1yubikey1...` recipient: a P-256 public key, compressed.
#[derive(Clone, Debug)]
pub struct Recipient {
    public: PublicKey,
}

impl Recipient {
    /// Extracts the P-256 public key from the slot's certificate (which
    /// stores it uncompressed).
    pub fn from_certificate(cert: &Certificate) -> Option<Self> {
        let spki = cert.subject_pki();
        if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY_OID {
            return None;
        }
        let curve: der::asn1::ObjectIdentifier =
            spki.algorithm.parameters.as_ref()?.decode_as().ok()?;
        if curve.to_string() != P256_OID {
            return None;
        }
        Some(Self {
            public: PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes()).ok()?,
        })
    }

    fn compressed(&self) -> EncodedPoint {
        self.public.to_encoded_point(true)
    }

    fn tag(&self) -> [u8; TAG_BYTES] {
        let digest = Sha256::digest(self.compressed().as_bytes());
        (&digest[..TAG_BYTES])
            .try_into()
            .expect("length is correct")
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            &bech32::encode(
                RECIPIENT_HRP,
                self.compressed().as_bytes().to_base32(),
                Variant::Bech32,
            )
            .expect("HRP is valid"),
        )
    }
}

impl FromStr for Recipient {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        if !s.starts_with(RECIPIENT_STRING_PREFIX) {
            anyhow::bail!("not a yubikey recipient");
        }
        let (hrp, data, _) =
            bech32::decode(s).map_err(|e| anyhow::anyhow!("invalid yubikey recipient: {e}"))?;
        // bech32 normalizes the HRP to lowercase on decode.
        if !hrp.eq_ignore_ascii_case(RECIPIENT_HRP) {
            anyhow::bail!("not a yubikey recipient");
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|e| anyhow::anyhow!("invalid yubikey recipient: {e}"))?;
        let point_bytes: [u8; EPK_BYTES] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid yubikey recipient length"))?;
        let point =
            EncodedPoint::from_bytes(point_bytes).map_err(|_| anyhow::anyhow!("invalid point"))?;
        let public = PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("invalid point"))?;
        Ok(Self { public })
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        // The ephemeral scalar comes from the OS CSPRNG via /dev/urandom.
        let esk = random_scalar().map_err(|e| EncryptError::Io(std::io::Error::other(e)))?;
        let epk = esk.public_key().to_encoded_point(true);

        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            esk.to_nonzero_scalar(),
            self.public.as_affine(),
        );
        let mut salt = Vec::with_capacity(EPK_BYTES * 2);
        salt.extend_from_slice(epk.as_bytes());
        salt.extend_from_slice(self.compressed().as_bytes());
        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared.raw_secret_bytes());

        let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());
        let stanza = Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(self.tag()),
                BASE64_STANDARD_NO_PAD.encode(epk.as_bytes()),
            ],
            body: encrypted_file_key,
        };
        Ok((vec![stanza], HashSet::new()))
    }
}

/// The `AGE-PLUGIN-YUBIKEY-...` identity: a reference to a key on a YubiKey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub serial: Serial,
    pub slot: RetiredSlotId,
    pub tag: [u8; TAG_BYTES],
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        f.write_str(
            &bech32::encode(IDENTITY_HRP, bytes.to_base32(), Variant::Bech32)
                .expect("HRP is valid")
                .to_uppercase(),
        )
    }
}

impl FromStr for Identity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        if !s.starts_with(IDENTITY_STRING_PREFIX) {
            anyhow::bail!("not a yubikey identity");
        }
        let (hrp, data, _) =
            bech32::decode(s).map_err(|e| anyhow::anyhow!("invalid yubikey identity: {e}"))?;
        // bech32 normalizes the HRP to lowercase on decode.
        if !hrp.eq_ignore_ascii_case(IDENTITY_HRP) {
            anyhow::bail!("not a yubikey identity");
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|e| anyhow::anyhow!("invalid yubikey identity: {e}"))?;
        if bytes.len() < 9 {
            anyhow::bail!("invalid yubikey identity length");
        }
        let serial = Serial(u32::from_le_bytes(bytes[..4].try_into().unwrap()));
        let slot = RetiredSlotId::try_from(bytes[4])
            .map_err(|_| anyhow::anyhow!("invalid yubikey identity slot"))?;
        Ok(Self {
            serial,
            slot,
            tag: bytes[5..9].try_into().unwrap(),
        })
    }
}

struct RecipientLine {
    tag: [u8; TAG_BYTES],
    /// Compressed SEC-1 ephemeral point.
    epk: EncodedPoint,
    encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientLine {
    /// Returns `None` if the stanza is not a `piv-p256` stanza.
    fn from_stanza(s: &Stanza) -> Option<Self> {
        if s.tag != STANZA_TAG || s.args.len() != 2 {
            return None;
        }
        let tag: [u8; TAG_BYTES] = BASE64_STANDARD_NO_PAD
            .decode(&s.args[0])
            .ok()?
            .try_into()
            .ok()?;
        let epk: [u8; EPK_BYTES] = BASE64_STANDARD_NO_PAD
            .decode(&s.args[1])
            .ok()?
            .try_into()
            .ok()?;
        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = s.body.clone().try_into().ok()?;
        Some(Self {
            tag,
            epk: EncodedPoint::from_bytes(epk).ok()?,
            encrypted_file_key,
        })
    }
}

impl age::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        let line = RecipientLine::from_stanza(stanza)?;
        if line.tag != self.tag {
            return None;
        }
        Some(self.unwrap_line(&line))
    }
}

impl Identity {
    /// Builds the identity for the key certified by `cert` in the given slot.
    pub fn from_certificate(
        cert: &Certificate,
        serial: Serial,
        slot: RetiredSlotId,
    ) -> anyhow::Result<Self> {
        let recipient = Recipient::from_certificate(cert)
            .ok_or_else(|| anyhow::anyhow!("slot holds no age-compatible P-256 key"))?;
        Ok(Self {
            serial,
            slot,
            tag: recipient.tag(),
        })
    }

    fn unwrap_line(&self, line: &RecipientLine) -> Result<FileKey, DecryptError> {
        let mut yk =
            YubiKey::open_by_serial(self.serial).map_err(|_| DecryptError::KeyDecryptionFailed)?;

        let cert = Certificate::read(&mut yk, SlotId::Retired(self.slot))
            .map_err(|_| DecryptError::KeyDecryptionFailed)?;
        let recipient =
            Recipient::from_certificate(&cert).ok_or(DecryptError::KeyDecryptionFailed)?;

        let (pin_policy, touch_policy) = slot_policies(&mut yk, &cert, self.slot)
            .map_err(|_| DecryptError::KeyDecryptionFailed)?;
        if touch_policy != TouchPolicy::Never {
            ui::info("Touch your YubiKey if it blinks");
        }
        if pin_policy == PinPolicy::Always
            || (pin_policy == PinPolicy::Once && yk.verify_pin(&[]).is_err())
        {
            let pin = ui::prompt_secret(&format!(
                "Enter the PIN for YubiKey {} (echo disabled): ",
                self.serial
            ))
            .map_err(|_| DecryptError::KeyDecryptionFailed)?;
            yk.verify_pin(pin.as_bytes())
                .map_err(|_| DecryptError::KeyDecryptionFailed)?;
        }

        // The YubiKey scalar multiplication takes the uncompressed point.
        let uncompressed = p256::PublicKey::from_encoded_point(&line.epk)
            .into_option()
            .ok_or(DecryptError::KeyDecryptionFailed)?
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let shared = piv::decrypt_data(
            &mut yk,
            &uncompressed,
            AlgorithmId::EccP256,
            SlotId::Retired(self.slot),
        )
        .map_err(|_| DecryptError::KeyDecryptionFailed)?;

        let mut salt = Vec::with_capacity(EPK_BYTES * 2);
        salt.extend_from_slice(line.epk.as_bytes());
        salt.extend_from_slice(recipient.compressed().as_bytes());
        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, &shared);

        let plaintext = aead_decrypt(&enc_key, FILE_KEY_BYTES, &line.encrypted_file_key)
            .map_err(|_| DecryptError::DecryptionFailed)?;
        let bytes: [u8; FILE_KEY_BYTES] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| DecryptError::DecryptionFailed)?;
        Ok(FileKey::new(Box::new(bytes)))
    }
}

/// Slot policies from the firmware metadata (5.3+) or the certificate
/// extension the plugin writes (older firmware).
fn slot_policies(
    yk: &mut YubiKey,
    cert: &Certificate,
    slot: RetiredSlotId,
) -> anyhow::Result<(PinPolicy, TouchPolicy)> {
    if let Ok(meta) = piv::metadata(yk, SlotId::Retired(slot))
        && let Some((pin, touch)) = meta.policy
    {
        return Ok((pin, touch));
    }
    cert_policy(cert)
}

pub(crate) fn cert_policy(cert: &Certificate) -> anyhow::Result<(PinPolicy, TouchPolicy)> {
    let extensions = cert
        .cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("certificate has no policy extension"))?;
    const POLICY_OID_STR: &str = "1.3.6.1.4.1.41482.3.8";
    let policy_oid = der::asn1::ObjectIdentifier::new(POLICY_OID_STR)
        .map_err(|_| anyhow::anyhow!("invalid policy OID"))?;
    let ext = extensions
        .iter()
        .find(|e| e.extn_id == policy_oid)
        .ok_or_else(|| anyhow::anyhow!("certificate has no policy extension"))?;
    if ext.extn_value.as_bytes().len() != 2 {
        anyhow::bail!("invalid policy extension");
    }
    let pin = PinPolicy::try_from(ext.extn_value.as_bytes()[0])
        .map_err(|_| anyhow::anyhow!("invalid pin policy in certificate"))?;
    let touch = TouchPolicy::try_from(ext.extn_value.as_bytes()[1])
        .map_err(|_| anyhow::anyhow!("invalid touch policy in certificate"))?;
    Ok((pin, touch))
}

/// The Yubico PIV slot policy extension (1.3.6.1.4.1.41482.3.8): two raw
/// bytes, the PIN policy then the touch policy. Firmware before 5.3 has no
/// slot metadata, so the plugin stores the policies here and reads them back
/// from the certificate.
#[derive(Clone, Copy, Debug)]
struct PolicyExtension {
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
}

impl AssociatedOid for PolicyExtension {
    const OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");
}

impl der::Encode for PolicyExtension {
    fn encoded_len(&self) -> der::Result<der::Length> {
        der::asn1::OctetString::new([self.pin_policy.into(), self.touch_policy.into()])?
            .encoded_len()
    }

    fn encode(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        der::asn1::OctetString::new([self.pin_policy.into(), self.touch_policy.into()])?
            .encode(writer)
    }
}

impl AsExtension for PolicyExtension {
    fn critical(&self, _subject: &Name, _extensions: &[x509_cert::ext::Extension]) -> bool {
        false
    }

    fn to_extension(
        &self,
        _subject: &Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> der::Result<x509_cert::ext::Extension> {
        Ok(x509_cert::ext::Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: false,
            extn_value: der::asn1::OctetString::new([
                self.pin_policy.into(),
                self.touch_policy.into(),
            ])?,
        })
    }
}

/// Subject RDNs in the DER order the plugin writes them: O, OU, CN, all as
/// UTF8String.
fn subject_rdns(name: &str) -> anyhow::Result<Name> {
    subject_rdns_for("age-plugin-yubikey", env!("CARGO_PKG_VERSION"), name)
}

fn subject_rdns_for(o: &str, ou: &str, cn: &str) -> anyhow::Result<Name> {
    let rdn = |oid: &str, value: &str| -> anyhow::Result<RelativeDistinguishedName> {
        let atv = AttributeTypeAndValue {
            oid: der::asn1::ObjectIdentifier::new(oid)?,
            value: der::asn1::Any::new(der::Tag::Utf8String, value.as_bytes().to_vec())?,
        };
        let mut set = der::asn1::SetOfVec::new();
        set.insert(atv)?;
        Ok(RelativeDistinguishedName(set))
    };
    Ok(RdnSequence(vec![
        rdn("2.5.4.10", o)?,
        rdn("2.5.4.11", ou)?,
        rdn("2.5.4.3", cn)?,
    ]))
}

/// Generates a new P-256 age identity in a retired slot, mirroring the
/// age-plugin-yubikey 0.5.1 generate flow (its src/builder.rs and src/key.rs):
/// PIN verification, management key authentication with migration to a
/// PIN-protected key, ECC P-256 key generation, and a self-signed
/// certificate carrying the policy extension.
pub fn generate_identity(
    yk: &mut YubiKey,
    slot: RetiredSlotId,
    name: &str,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> anyhow::Result<(Identity, Recipient)> {
    // Management operations require the PIN, and the protected management
    // key is wrapped with it, so the PIN comes first.
    let pin = ui::prompt_secret(&format!(
        "Enter the PIN for YubiKey {} (echo disabled): ",
        yk.serial()
    ))?;
    yk.verify_pin(pin.as_bytes())
        .map_err(|e| anyhow!("wrong PIN: {e}"))?;

    match MgmKey::get_protected(yk) {
        Ok(mgm) => yk
            .authenticate(mgm)
            .map_err(|e| anyhow!("management key authentication failed: {e}"))?,
        Err(_) => {
            // Fall back to the default management key and migrate, exactly
            // like the plugin does on first generation.
            yk.authenticate(MgmKey::default()).map_err(|e| {
                anyhow!("could not authenticate with the protected or default management key: {e}")
            })?;
            let mgm = MgmKey::generate();
            mgm.set_protected(yk)
                .context("failed to migrate to a PIN-protected management key")?;
            ui::info("Migrated the management key to a PIN-protected one.");
        }
    }

    if touch_policy != TouchPolicy::Never {
        ui::info("Touch your YubiKey if it blinks");
    }
    let spki = piv::generate(
        yk,
        SlotId::Retired(slot),
        AlgorithmId::EccP256,
        pin_policy,
        touch_policy,
    )
    .context("PIV key generation failed")?;

    // The certificate signature is an operation of the fresh key: it may
    // ask for the PIN again (policy Always) or a touch.
    if pin_policy == PinPolicy::Always {
        let pin = ui::prompt_secret("Enter the PIN again (echo disabled): ")?;
        yk.verify_pin(pin.as_bytes()).context("wrong PIN")?;
    }
    if touch_policy != TouchPolicy::Never {
        ui::info("Touch your YubiKey if it blinks");
    }

    let serial_number =
        SerialNumber::new(&random_bytes::<20>()?).context("invalid certificate serial")?;
    let validity = Validity {
        not_before: x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_system_time(std::time::SystemTime::now())
                .context("invalid notBefore time")?,
        ),
        not_after: x509_cert::time::Time::INFINITY,
    };
    let policy = PolicyExtension {
        pin_policy,
        touch_policy,
    };
    let cert = Certificate::generate_self_signed::<_, p256::NistP256>(
        yk,
        SlotId::Retired(slot),
        serial_number,
        validity,
        subject_rdns(name)?,
        spki,
        |builder| {
            builder.add_extension(&policy).map_err(|e| match e {
                x509_cert::builder::Error::Asn1(err) => err,
                other => {
                    let _ = other;
                    der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
                }
            })
        },
    )
    .context("failed to create and store the self-signed certificate")?;

    let identity = Identity::from_certificate(&cert, yk.serial(), slot)?;
    let recipient =
        Recipient::from_certificate(&cert).context("the generated key is not a P-256 key")?;
    Ok((identity, recipient))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::Recipient as _;

    const RFC5869_IKM: &[u8] = &[0x0b; 22];
    const RFC5869_SALT: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    const RFC5869_INFO: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

    #[test]
    fn hkdf_matches_rfc5869_vector() {
        // Test Case 1 from RFC 5869.
        let okm = hkdf(RFC5869_SALT, RFC5869_INFO, RFC5869_IKM);
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn recipient_round_trip() {
        let sk = p256::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let recipient = Recipient {
            public: sk.public_key(),
        };
        let s = recipient.to_string();
        assert!(s.starts_with(RECIPIENT_STRING_PREFIX));
        let parsed = Recipient::from_str(&s).unwrap();
        assert_eq!(
            parsed.compressed().as_bytes(),
            recipient.compressed().as_bytes()
        );
        assert!(Recipient::from_str("age1qqqq").is_err());
    }

    #[test]
    fn identity_round_trip() {
        let identity = Identity {
            serial: Serial(13381487),
            slot: RetiredSlotId::R1,
            tag: [0xde, 0xad, 0xbe, 0xef],
        };
        let s = identity.to_string();
        assert!(s.starts_with(IDENTITY_STRING_PREFIX));
        assert_eq!(Identity::from_str(&s).unwrap(), identity);
        assert!(Identity::from_str("AGE-PLUGIN-YUBIKEY-1QQQQQ").is_err());
    }

    /// The subject must be DER-identical to the one the plugin writes
    /// (O, OU, CN as UTF8String, in this order). Reference: the certificate
    /// on YubiKey 13381487 slot 82, written by age-plugin-yubikey 0.5.0.
    #[test]
    fn subject_der_matches_the_plugin_certificate() {
        use der::Encode as _;
        let subject = subject_rdns_for("age-plugin-yubikey", "0.5.0", "yk-toolkit").unwrap();
        let expected = concat!(
            "3042311b3019060355040a0c126167652d706c7567696e2d797562696b6579",
            "310e300c060355040b0c05302e352e303113301106035504030c0a796b2d746f6f6c6b6974"
        );
        assert_eq!(hex::encode(subject.to_der().unwrap()), expected);
    }

    /// The policy extension must carry the same OID and 2-byte value the
    /// plugin writes (pin policy, then touch policy).
    #[test]
    fn policy_extension_matches_the_plugin_encoding() {
        let ext = PolicyExtension {
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Cached,
        }
        .to_extension(&RdnSequence(vec![]), &[])
        .unwrap();
        assert_eq!(ext.extn_id.to_string(), "1.3.6.1.4.1.41482.3.8");
        assert!(!ext.critical);
        assert_eq!(hex::encode(ext.extn_value.as_bytes()), "0203");
    }

    #[test]
    fn stanza_round_trip_without_hardware() {
        // Wrap to a test key and verify the stanza shape; the unwrap side
        // needs the YubiKey and is covered by hardware tests.
        let sk = p256::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let recipient = Recipient {
            public: sk.public_key(),
        };
        let file_key = FileKey::new(Box::new([42u8; FILE_KEY_BYTES]));
        let (stanzas, labels) = recipient.wrap_file_key(&file_key).unwrap();
        assert!(labels.is_empty());
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, STANZA_TAG);
        assert_eq!(stanzas[0].args.len(), 2);
        assert_eq!(stanzas[0].body.len(), ENCRYPTED_FILE_KEY_BYTES);

        let line = RecipientLine::from_stanza(&stanzas[0]).unwrap();
        assert_eq!(line.tag, recipient.tag());

        // A different stanza tag does not match.
        let other = Stanza {
            tag: "x25519".to_owned(),
            args: stanzas[0].args.clone(),
            body: stanzas[0].body.clone(),
        };
        assert!(RecipientLine::from_stanza(&other).is_none());
    }

    /// Read-only hardware test: the native recipient and identity encodings
    /// must match the official plugin's strings byte for byte. Run with
    /// `YKOX_TEST_HW=1 cargo test -- --ignored` (needs age-plugin-yubikey
    /// in PATH).
    #[test]
    #[ignore]
    fn format_matches_age_plugin_yubikey_binary() {
        use std::process::Command;

        if std::env::var("YKOX_TEST_HW").is_err() {
            return;
        }
        let Ok(list) = Command::new("age-plugin-yubikey").arg("--list").output() else {
            eprintln!("age-plugin-yubikey not in PATH; skipping");
            return;
        };
        let list = String::from_utf8_lossy(&list.stdout);
        let recipient_str = list
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(RECIPIENT_STRING_PREFIX))
            .expect("no recipient in --list output");

        // The native encoding must reproduce the plugin's recipient exactly.
        let recipient = Recipient::from_str(recipient_str).unwrap();
        assert_eq!(recipient.to_string(), recipient_str);

        let identity_out = Command::new("age-plugin-yubikey")
            .args(["--identity", "--slot", "1"])
            .output()
            .unwrap();
        let identity_out = String::from_utf8_lossy(&identity_out.stdout);
        let identity_str = identity_out
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(IDENTITY_STRING_PREFIX))
            .expect("no identity in --identity output");

        // Same for the identity, and the tag must match the recipient's.
        let identity = Identity::from_str(identity_str).unwrap();
        assert_eq!(identity.to_string(), identity_str);
        assert_eq!(identity.tag, recipient.tag());

        if let Ok(serial) = std::env::var("YKOX_TEST_SERIAL") {
            assert_eq!(identity.serial.to_string(), serial);
        }
    }
}
