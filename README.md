# ykoxide

YubiKey toolkit in Rust: age encryption on a PIV slot, HMAC challenge-response file encryption, SSHSIG file signing, device info and config backup, shipped as a single binary (`ykox`) with no runtime dependency on `ykman`, `age` or `openssl`.

Rust rewrite of [yubikey-shell-toolkit](https://github.com/Esl1h/yubikey-shell-toolkit).

## Build

Requires the Rust toolchain (via rustup) and the PC/SC development headers.

```sh
sudo dnf install rustup pcsc-lite-devel   # Fedora
rustup-init -y
cargo build --release
./target/release/ykox --help
```

`pcscd` must be running to talk to the YubiKey. The FIDO2 and OTP HID operations need `libudev` (installed with `systemd-devel` on Fedora).

## Commands

Every device-touching command accepts a global `--serial <N>` to pick the YubiKey when more than one is connected.

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

File encryption with a FIDO2 `hmac-secret` credential, for keys without PIV or OTP (works on the Security Key line):

```sh
ykox fido2 enroll                     # create the credential (one time, adds it to the token)
ykox fido2 enroll --require-pin       # ... asking the FIDO2 PIN on every derivation
ykox fido2 encrypt secret.txt         # secret.txt.yk.age + secret.txt.yk.fido2
ykox fido2 decrypt secret.txt.yk.age
```

`enroll` stores the credential reference in `~/.config/yk-toolkit/fido2/credential.json` (0600); each encrypted file carries a JSON sidecar (`.yk.fido2`) with the credential id and its own 32-byte salt, so files never share a derived key. The token asks for a touch on every operation; with `--require-pin` it also asks for the FIDO2 PIN. Losing the sidecar file means losing the salt, and with it the file contents.

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

## Configuration files

`~/.config/yk-toolkit/age/`:

- `recipients.txt`: one recipient per line; empty lines and `#` comments ignored.
- `identities.txt`: one identity FILE PATH per line; empty lines and `#` ignored.
- `yubikey-identity.txt` / `yubikey-recipient.txt`: written by `age setup` (0600/0644).

`~/.config/yk-toolkit/fido2/credential.json`: written by `fido2 enroll` (0600), the default credential for `fido2 encrypt`.

## License

MIT
