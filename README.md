# ykoxide

YubiKey toolkit in Rust: age encryption on a PIV slot, HMAC challenge-response file encryption, device info and config backup, shipped as a single binary (`ykox`) with no runtime dependency on `ykman`, `age` or `openssl`.

Rust rewrite of [yubikey-shell-toolkit](https://github.com/Esl1h/yubikey-shell-toolkit). Work in progress: every subcommand is a stub for now.

## Build

Requires the Rust toolchain (via rustup) and the PC/SC development headers.

```sh
sudo dnf install rustup pcsc-lite-devel   # Fedora
rustup-init -y
cargo build --release
./target/release/ykox --help
```

`pcscd` must be running to talk to the YubiKey.

## Usage

```sh
ykox info
ykox age setup
ykox age encrypt -r age1yubikey1... secret.txt
ykox age decrypt secret.txt.age
ykox hmac encrypt secret.txt
ykox hmac decrypt secret.txt.yk.enc
ykox verify secret.txt.age
ykox backup -o yubikey.json
```

## License

MIT
