# ykoxide

[![CI](https://github.com/Esl1h/ykoxide/actions/workflows/ci.yml/badge.svg)](https://github.com/Esl1h/ykoxide/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Esl1h/ykoxide)](https://github.com/Esl1h/ykoxide/releases/latest)
[![crates.io](https://img.shields.io/crates/v/ykoxide)](https://crates.io/crates/ykoxide)
[![MSRV](https://img.shields.io/crates/msrv/ykoxide)](Cargo.toml)
[![License: MIT](https://img.shields.io/github/license/Esl1h/ykoxide)](LICENSE)

YubiKey toolkit in Rust, shipped as a single binary (`ykox`) with no runtime dependency on `ykman`, `age` or `openssl`:

- age encryption on a PIV slot, interoperable with `age-plugin-yubikey`
- file encryption with the OTP HMAC-SHA1 challenge-response slot
- FIDO2 `hmac-secret` file encryption (experimental)
- SSHSIG file signing and verification, with FIDO2 (`sk`) keys or a PIV slot
- device report and configuration backup as JSON

Rust rewrite of [yubikey-shell-toolkit](https://github.com/Esl1h/yubikey-shell-toolkit); it reads the files and configuration that toolkit created.

## Contents

- [Install](#install)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Status and compatibility](#status-and-compatibility)
- [Security](#security)
- [Configuration files](#configuration-files)
- [Contributing](#contributing)
- [License and credits](#license-and-credits)

## Install

### Prebuilt binaries

Linux x86_64 and aarch64 tarballs are attached to every [release](https://github.com/Esl1h/ykoxide/releases). Each release lists SHA256SUMS, and releases from 0.1.1 on also carry a build provenance attestation.

```sh
VERSION=0.1.1
TARGET=x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu
gh release download "v$VERSION" --repo Esl1h/ykoxide \
  --pattern "ykoxide-$VERSION-$TARGET.tar.gz" --pattern SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "ykoxide-$VERSION-$TARGET.tar.gz" --repo Esl1h/ykoxide
tar xzf "ykoxide-$VERSION-$TARGET.tar.gz"
install -m 0755 "ykoxide-$VERSION-$TARGET/ykox" ~/.local/bin/ykox
```

### From crates.io

```sh
cargo install ykoxide --locked   # builds from source, needs the build dependencies below
cargo binstall ykoxide           # downloads the release binary instead
```

### From source

```sh
git clone https://github.com/Esl1h/ykoxide
cd ykoxide
cargo build --release
./target/release/ykox --help
```

Rust 1.89 or newer (install it with [rustup](https://rustup.rs)).

## Requirements

- **Build:** the PC/SC and udev development headers. Fedora: `sudo dnf install pcsc-lite-devel systemd-devel`. Debian and Ubuntu: `sudo apt install libpcsclite-dev libudev-dev pkg-config`.
- **Run:** the PC/SC daemon installed and running (`sudo systemctl enable --now pcscd.socket`), plus the `libpcsclite` and `libudev` shared libraries. On Arch, install `pcsclite` and `ccid`: `sudo pacman -S pcsclite ccid`. On Fedora, `pcsc-lite` and `pcsc-lite-ccid`. `info`, `age` and the PIV signing mode go through PC/SC, and `backup` needs it too for the PIV and OpenPGP parts; `fido2`, `hmac` and `sign` with an `sk` key use the key over USB.
- **USB access:** FIDO2 and OTP talk to the key over HID/USB. On Fedora and Arch that worked without extra setup. If those commands fail with a permission error on your system, install the udev rules for security keys shipped by your distribution (for example `libu2f-udev` on Debian and Ubuntu) and re-plug the key.
- **Touch:** OTP, FIDO2 and SSH `sk` operations wait for a touch. The key blinks while it waits.

## Quick start

```sh
ykox info                        # is the key detected?
ykox age setup                   # extract (or generate) the age identity on the key
ykox age encrypt secret.txt      # secret.txt.age
ykox age decrypt secret.txt.age
ykox sign report.pdf             # report.pdf.sig, verifiable with ssh-keygen -Y verify
```

## Commands

Every device-touching command accepts a global `--serial <N>` to pick the YubiKey when more than one is connected. It does not apply to FIDO2, whose HID interface reports no serial.

### info

```sh
ykox info
```

Shows model, serial, firmware and, for each PIV slot (9a, 9c, 9d, 9e and the retired 82 to 95), the certificate subject and the key metadata (firmware 5.3+).

### age

age encryption backed by the YubiKey PIV applet, compatible with the files created by the shell scripts and by `age-plugin-yubikey`.

```sh
ykox age setup                 # extract or generate the age identity on the key
ykox age encrypt -r age1yubikey1... secret.txt
ykox age encrypt secret.txt    # recipients from the configuration files
ykox age decrypt secret.txt.age
```

Recipients and identities resolve in this order: `-r`/`-i` arguments, then `~/.config/yk-toolkit/age/recipients.txt` (or `identities.txt`), then the `yubikey-recipient.txt`/`yubikey-identity.txt` written by `age setup`. `-o -` writes to stdout; an existing output needs `--force`.

The `age1yubikey1...` recipient and identity paths, including `age setup --generate`, are native: the `age-plugin-yubikey` binary is not needed.

### hmac

File encryption with the OTP applet's HMAC-SHA1 challenge-response slot (slot 2 by default, `--slot 1|2`). Reads and writes both formats:

```sh
ykox hmac encrypt secret.txt        # secret.txt.yk.age + secret.txt.yk.challenge
ykox hmac decrypt secret.txt.yk.age
ykox hmac decrypt secret.txt.yk.enc # legacy files from yk-encrypt-file.sh
```

The legacy `.yk.enc` format is unauthenticated: a wrong key passes about 1 time in 256.

### fido2

Experimental. File encryption with a FIDO2 `hmac-secret` credential, meant for keys without PIV or OTP such as the Security Key line (not yet tested on one). See [Status and compatibility](#status-and-compatibility).

```sh
ykox fido2 enroll                     # create the credential (one time, adds it to the token)
ykox fido2 enroll --require-pin       # ... asking the FIDO2 PIN on every derivation
ykox fido2 encrypt secret.txt         # secret.txt.yk.age + secret.txt.yk.fido2
ykox fido2 decrypt secret.txt.yk.age
```

`enroll` stores the credential reference in `~/.config/yk-toolkit/fido2/credential.json` (0600); each encrypted file carries a JSON sidecar (`.yk.fido2`) with the credential id and its own 32-byte salt, so files never share a derived key. Creating the credential asks for the FIDO2 PIN once when the token has one. After that the token asks for a touch on every operation; with `--require-pin` it also asks for the PIN on every derivation. Losing the sidecar file means losing the salt, and with it the file contents.

### verify

Checks that an encrypted file still decrypts, without writing plaintext:

```sh
ykox verify secret.txt.age
```

Exit code 0 when the file decrypts, 1 when it does not.

### sign / verify-sig

Detached file signatures in the SSHSIG format (verifiable with `ssh-keygen -Y verify`), namespace `file`, SHA-512:

```sh
ykox sign report.pdf                        # default key: ~/.ssh/id_ed25519_sk
ykox sign report.pdf --piv-slot 9c          # PIV ECDSA P-256 slot instead
ykox verify-sig report.pdf --pubkey signer.pub
ykox verify-sig report.pdf --allowed-signers signers.txt --identity me@example.com
```

`--key` takes an ed25519, ecdsa or ed25519-sk key; RSA keys are refused. `sign` needs a touch (and the FIDO2 PIN when the key requires one). `verify-sig` exits 0 for a good signature and 1 for a bad one.

### backup

```sh
ykox backup -o yubikey.json
```

Dumps the device state (serial, firmware, form factor, enabled applets over USB/NFC, PIV slots, OTP slot state, FIDO2 capabilities including AAGUID and PIN retries, OpenPGP fingerprints) as JSON. Never includes secrets.

## Status and compatibility

ykoxide is pre-1.0. The command line and the newer file formats may still change; release notes call out breaking changes.

- **Tested systems:** Fedora 44 and Omarchy 4.0.3 (Arch-based), both x86_64. Other distributions and CPU architectures are untested.
- **Tested keys:** a YubiKey 5 NFC (USB-A, firmware 5.2.6) and a YubiKey 5C (USB-C, firmware 5.4.3). Other models are untested.
- **YubiKey 5 NFC:** on both systems, `info`, `backup`, age encrypt and decrypt with the PIV slot 82 identity, HMAC on OTP slot 2 and SSHSIG with an `sk` key. The FIDO2 round trip was run on Omarchy.
- **YubiKey 5C:** on both systems, `info`, `backup` and the FIDO2 round trip; SSHSIG with an `sk` key on Omarchy. Its OTP slot 2 is not configured and it holds no age identity, so HMAC and age were not run on it.
- **Checked against the reference tools (YubiKey 5 NFC, Fedora):** age files interoperate with `age-plugin-yubikey` in both directions; the HMAC response matches `ykman otp calculate`; legacy `.yk.enc` files from the shell toolkit decrypt; SSHSIG signatures verify with `ssh-keygen -Y verify`; the device fields of `backup` match `ykman`.
- **Not exercised on hardware:** generating a new PIV key with `age setup --generate`; only extracting an existing identity was.
- **aarch64:** release binaries are built and tested in CI on a native ARM runner, but have not been run against a key.
- **FIDO2 is experimental:** enroll, encrypt, `verify` and decrypt work end to end on both keys, from version 0.1.2 on (earlier releases cannot enroll on these tokens). It has not been tried on a Security Key or on a token with built-in user verification such as a fingerprint reader. The file format is specific to `ykox` and is not interoperable with `age-plugin-fido2-hmac`; it may change before 1.0.

## Security

- PINs and passphrases are read without echo and zeroized after use. `backup` never includes secrets.
- `sign` refuses RSA keys. `cargo audit` ignores `RUSTSEC-2023-0071` (`rsa`, pulled in by the `yubikey` crate) on purpose: `ykox` performs no RSA operation, so the vulnerable path is unreachable (see `.cargo/audit.toml`).
- The legacy `.yk.enc` format has no authentication (see [hmac](#hmac)). Prefer the `.yk.age` formats.
- `ykox` protects the key material, not the plaintext: it does not defend against malware on the host that reads decrypted files.
- CI runs `cargo audit` and `cargo deny`, and CodeQL scans the repository. Release tags are GPG-signed, and release tarballs come with SHA256SUMS and, from 0.1.1, a build provenance attestation.

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public issue for it.

## Configuration files

`~/.config/yk-toolkit/age/`:

- `recipients.txt`: one recipient per line; empty lines and `#` comments ignored.
- `identities.txt`: one identity FILE PATH per line; empty lines and `#` ignored.
- `yubikey-identity.txt` / `yubikey-recipient.txt`: written by `age setup` (0600/0644).

`~/.config/yk-toolkit/fido2/credential.json`: written by `fido2 enroll` (0600), the default credential for `fido2 encrypt`.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License and credits

[MIT](LICENSE).

ykoxide builds on the work of these projects: the [`age`](https://github.com/str4d/rage) crate, [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) (the piv-p256 format it interoperates with), the [`yubikey`](https://github.com/iqlusioninc/yubikey.rs) crate for PIV, [`ctap-hid-fido2`](https://github.com/gebogebogebo/ctap-hid-fido2) for FIDO2, [`ssh-key`](https://github.com/RustCrypto/SSH) for SSHSIG and [`nusb`](https://github.com/kevinmehall/nusb) for USB access.
