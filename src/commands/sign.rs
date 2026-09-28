use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use ssh_key::public::{EcdsaPublicKey, KeyData, SkEd25519};
use ssh_key::{
    Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey, Signature, SshSig,
    private::KeypairData,
};
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{PinPolicy, TouchPolicy};
use zeroize::Zeroizing;

use crate::cli::Output;
use crate::device;
use crate::io::{self, OutputRule};
use crate::ui;

const NAMESPACE: &str = "file";
const SIGNATURE_SUFFIX: &str = "sig";

pub fn sign(
    file: &Path,
    key: Option<PathBuf>,
    piv_slot: Option<String>,
    out: &Output,
    serial: Option<yubikey::Serial>,
) -> Result<()> {
    let sig = match piv_slot {
        Some(slot) => sign_piv(file, &slot, serial)?,
        None => {
            let key_path = key.unwrap_or_else(default_ssh_key);
            sign_ssh(file, &key_path, serial)?
        }
    };

    let dest = io::destination(
        out.output.as_deref(),
        file,
        &OutputRule::Append(SIGNATURE_SUFFIX),
    );
    let mut output = io::Output::create(dest, out.force)?;
    // The PEM already ends with a newline.
    write!(output.writer(), "{sig}")?;
    output.finish()?;
    Ok(())
}

fn default_ssh_key() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".ssh/id_ed25519_sk")
}

fn sign_ssh(file: &Path, key_path: &Path, serial: Option<yubikey::Serial>) -> Result<String> {
    let contents =
        std::fs::read(file).with_context(|| format!("failed to read {}", file.display()))?;
    let key_str = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let mut private = PrivateKey::from_openssh(&key_str)
        .with_context(|| format!("failed to parse {}", key_path.display()))?;
    if private.is_encrypted() {
        let passphrase = Zeroizing::new(ui::prompt_secret(&format!(
            "Passphrase for {}: ",
            key_path.display()
        ))?);
        private = private
            .decrypt(passphrase.as_bytes())
            .map_err(|_| anyhow!("wrong passphrase for {}", key_path.display()))?;
    }

    match private.key_data() {
        KeypairData::SkEd25519(sk) => return sign_sk(file, sk, serial),
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => {}
        // Software RSA signing goes through the rsa crate, which leaks key
        // bits through timing (Marvin attack, RUSTSEC-2023-0071, no fix).
        _ => bail!(
            "unsupported key type {}: use an ed25519, ecdsa or ed25519-sk key",
            private.algorithm()
        ),
    }
    private
        .sign(NAMESPACE, HashAlg::Sha512, &contents)
        .map(|sig| sig.to_pem(LineEnding::default()))
        .map(|s| s.map_err(|e| anyhow!("failed to armor the signature: {e}")))
        .map_err(|e| anyhow!("failed to sign: {e}"))?
}

/// Signs with the FIDO2 hardware behind an `ed25519-sk` key: the SSHSIG
/// signed data goes to the token as the client data (hashed by the CTAP
/// layer), exactly as OpenSSH does in sk-usbhid.c.
fn sign_sk(
    file: &Path,
    sk: &ssh_key::private::SkEd25519,
    _serial: Option<yubikey::Serial>,
) -> Result<String> {
    use ctap_hid_fido2::LibCfg;
    use ctap_hid_fido2::fidokey::FidoKeyHid;

    let contents =
        std::fs::read(file).with_context(|| format!("failed to read {}", file.display()))?;
    let signed_data = SshSig::signed_data(NAMESPACE, HashAlg::Sha512, &contents)
        .map_err(|e| anyhow!("failed to assemble the signed data: {e}"))?;

    let mut cfg = LibCfg::init();
    cfg.enable_log = false;
    let device = FidoKeyHid::new(&[], &cfg).context("no FIDO2 device found")?;
    ui::info("Touch your YubiKey if it blinks");
    let assertion = device
        .get_assertion(
            sk.public().application(),
            &signed_data,
            &[sk.key_handle().to_vec()],
            None,
        )
        .or_else(|err| {
            ui::warn(format!(
                "assertion without PIN failed ({err}); retrying with PIN"
            ));
            let pin = ui::prompt_secret("FIDO2 PIN: ")?;
            device.get_assertion(
                sk.public().application(),
                &signed_data,
                &[sk.key_handle().to_vec()],
                Some(&pin),
            )
        })
        .context("FIDO2 assertion failed")?;

    // The signature covers authData || clientDataHash, with authData =
    // rpIdHash(32) || flags(1) || counter(4); the SSH sk format carries only
    // the raw signature, flags and counter.
    if assertion.signature.len() != 64 {
        bail!("unexpected ed25519 assertion signature length");
    }
    let mut sig_blob = assertion.signature;
    sig_blob.push(assertion.flags.as_u8());
    sig_blob.extend_from_slice(&assertion.sign_count.to_be_bytes());

    let public = KeyData::SkEd25519(SkEd25519::new(
        *sk.public().public_key(),
        sk.public().application(),
    ));
    let signature = Signature::new(Algorithm::SkEd25519, sig_blob)
        .map_err(|e| anyhow!("failed to encode the signature: {e}"))?;
    let ssh_sig = SshSig::new(public, NAMESPACE, HashAlg::Sha512, signature)
        .map_err(|e| anyhow!("failed to assemble the SSHSIG: {e}"))?;
    ssh_sig
        .to_pem(LineEnding::default())
        .map_err(|e| anyhow!("failed to armor the signature: {e}"))
}

fn sign_piv(file: &Path, slot_str: &str, serial: Option<yubikey::Serial>) -> Result<String> {
    let contents =
        std::fs::read(file).with_context(|| format!("failed to read {}", file.display()))?;
    let slot = parse_piv_slot(slot_str)?;

    let mut yk = device::open(serial)?;
    let cert = yubikey::certificate::Certificate::read(&mut yk, slot).with_context(|| {
        format!("slot {slot_str} has no certificate to derive the public key from")
    })?;
    let (pin_policy, touch_policy) = piv_policies(&mut yk, &cert, slot);
    if touch_policy != TouchPolicy::Never {
        ui::info("Touch your YubiKey if it blinks");
    }
    if pin_policy == PinPolicy::Always
        || (pin_policy == PinPolicy::Once && yk.verify_pin(&[]).is_err())
    {
        let pin = ui::prompt_secret("Enter the PIN (echo disabled): ")?;
        yk.verify_pin(pin.as_bytes()).context("wrong PIN")?;
    }

    let signed_data = SshSig::signed_data(NAMESPACE, HashAlg::Sha512, &contents)
        .map_err(|e| anyhow!("failed to assemble the signed data: {e}"))?;
    // PIV ECDSA signs the provided digest; SSH ecdsa-sha2-nistp256 hashes
    // SHA-256.
    let digest = {
        use sha2::Digest;
        sha2::Sha256::digest(&signed_data)
    };
    let der_sig = piv::sign_data(&mut yk, &digest, AlgorithmId::EccP256, slot)
        .context("PIV signature failed")?;
    let (r, s) = der_ecdsa_sig(&der_sig)?;
    let sig_data = [ssh_mpint(&r), ssh_mpint(&s)].concat();
    let signature = Signature::new(
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        sig_data,
    )
    .map_err(|e| anyhow!("failed to encode the signature: {e}"))?;

    // The slot certificate carries the public key in uncompressed SEC-1.
    let ec_point = cert.subject_pki().subject_public_key.raw_bytes().to_vec();
    let public =
        KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&ec_point).map_err(|e| anyhow!("{e}"))?);
    let ssh_sig = SshSig::new(public, NAMESPACE, HashAlg::Sha512, signature)
        .map_err(|e| anyhow!("failed to assemble the SSHSIG: {e}"))?;
    ssh_sig
        .to_pem(LineEnding::default())
        .map_err(|e| anyhow!("failed to armor the signature: {e}"))
}

fn piv_policies(
    yk: &mut yubikey::YubiKey,
    cert: &yubikey::certificate::Certificate,
    slot: SlotId,
) -> (PinPolicy, TouchPolicy) {
    if let Ok(meta) = piv::metadata(yk, slot)
        && let Some((pin, touch)) = meta.policy
    {
        return (pin, touch);
    }
    crate::age_yubikey::cert_policy(cert).unwrap_or((PinPolicy::Once, TouchPolicy::Never))
}

pub fn verify_sig(
    file: &Path,
    signature: Option<PathBuf>,
    allowed_signers: Option<PathBuf>,
    pubkey: Option<PathBuf>,
    principal: Option<String>,
) -> Result<bool> {
    let sig_path = signature.unwrap_or_else(|| {
        let mut name = file
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".{SIGNATURE_SUFFIX}"));
        file.with_file_name(name)
    });
    let sig_str = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("failed to read {}", sig_path.display()))?;
    let sig = SshSig::from_pem(sig_str)
        .with_context(|| format!("{} is not an SSHSIG signature", sig_path.display()))?;
    let contents =
        std::fs::read(file).with_context(|| format!("failed to read {}", file.display()))?;

    let result: Result<(), anyhow::Error> = if let Some(allowed) = allowed_signers {
        let principal =
            principal.context("--identity <principal> is required with --allowed-signers")?;
        verify_allowed_signers(&allowed, &principal, file, &contents, &sig)
    } else if let Some(pub_path) = pubkey {
        let key = read_public_key(&pub_path)?;
        key.verify(NAMESPACE, &contents, &sig)
            .map_err(|e| anyhow!("{e}"))
    } else {
        bail!("pass --allowed-signers <file> or --pubkey <key>");
    };

    match result {
        Ok(()) => {
            ui::success(format!(
                "Good \"{}\" signature for {} with {} key from {}",
                NAMESPACE,
                sig.namespace(),
                sig.algorithm(),
                sig_path.display(),
            ));
            Ok(true)
        }
        Err(err) => {
            ui::fail(format!("bad signature: {err}"));
            Ok(false)
        }
    }
}

fn read_public_key(path: &Path) -> Result<PublicKey> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    content
        .trim()
        .lines()
        .next()
        .context("empty public key file")?
        .parse::<PublicKey>()
        .with_context(|| format!("failed to parse {}", path.display()))
}

fn verify_allowed_signers(
    allowed: &Path,
    principal: &str,
    _file: &Path,
    contents: &[u8],
    sig: &SshSig,
) -> Result<()> {
    let content = std::fs::read_to_string(allowed)
        .with_context(|| format!("failed to read {}", allowed.display()))?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(principals) = fields.next() else {
            continue;
        };
        let Some(_key_type) = fields.next() else {
            continue;
        };
        let Some(key_blob) = fields.next() else {
            continue;
        };
        if !principals.split(',').any(|p| p == principal) {
            continue;
        }
        let Ok(key) = format!("{_key_type} {key_blob}").parse::<PublicKey>() else {
            continue;
        };
        // The signature must carry the same public key as the allowed entry.
        if key.key_data() != sig.public_key() {
            continue;
        }
        if key.verify(NAMESPACE, contents, sig).is_ok() {
            return Ok(());
        }
    }
    bail!("no allowed signer matched principal {principal} for this signature")
}

fn parse_piv_slot(s: &str) -> Result<SlotId> {
    let raw = u8::from_str_radix(s, 16).with_context(|| format!("invalid PIV slot {s:?}"))?;
    Ok(match raw {
        0x9a => SlotId::Authentication,
        0x9c => SlotId::Signature,
        0x9d => SlotId::KeyManagement,
        0x9e => SlotId::CardAuthentication,
        r @ 0x82..=0x95 => SlotId::Retired(
            RetiredSlotId::try_from(r).map_err(|_| anyhow!("invalid PIV slot {s:?}"))?,
        ),
        _ => bail!("invalid PIV slot {s:?}"),
    })
}

use yubikey::piv::RetiredSlotId;

/// Splits a DER ECDSA-SigValue into (r, s) big-endian integers.
fn der_ecdsa_sig(der_sig: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // SEQUENCE { INTEGER r, INTEGER s }
    if der_sig.len() < 8 || der_sig[0] != 0x30 {
        bail!("invalid DER ECDSA signature");
    }
    let mut i = 2;
    if der_sig[1] & 0x80 != 0 {
        i += (der_sig[1] & 0x7f) as usize;
    }
    if der_sig.get(i) != Some(&0x02) || i + 1 >= der_sig.len() {
        bail!("invalid DER ECDSA signature");
    }
    let rlen = der_sig[i + 1] as usize;
    let r = der_sig
        .get(i + 2..i + 2 + rlen)
        .context("truncated DER signature")?
        .to_vec();
    let j = i + 2 + rlen;
    if der_sig.get(j) != Some(&0x02) || j + 1 >= der_sig.len() {
        bail!("invalid DER ECDSA signature");
    }
    let slen = der_sig[j + 1] as usize;
    let s = der_sig
        .get(j + 2..j + 2 + slen)
        .context("truncated DER signature")?
        .to_vec();
    Ok((r, s))
}

/// SSH mpint: big-endian two's complement, minimal, sign bit padded.
fn ssh_mpint(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let mut out = bytes[start..].to_vec();
    if out[0] & 0x80 != 0 {
        out.insert(0, 0);
    }
    let len = (out.len() as u32).to_be_bytes();
    len.iter().chain(out.iter()).copied().collect()
}
