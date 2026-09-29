# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); until 1.0 the command line and the newer file formats may change.

## [Unreleased]

## [0.1.1] - 2026-09-29

No changes to the `ykox` binary itself: this release is about packaging, documentation and supply chain.

### Added

- crates.io `keywords` and `categories`, and `cargo binstall` metadata pointing at the release tarballs.
- README with install paths, requirements, a quick start, a status section and a security section.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates and a pull request template.
- Dependabot updates for cargo and GitHub Actions, and CodeQL scanning.
- A weekly scheduled run of `cargo audit` and `cargo deny`, and a CI job that builds with the minimum supported Rust version.
- Build provenance attestations for the release tarballs (verify with `gh attestation verify`) and generated release notes.

### Changed

- The workflows use the Node 24 releases of `actions/checkout`, `actions/upload-artifact`, `actions/download-artifact` and `softprops/action-gh-release`.
- The x86_64 release build runs on `ubuntu-24.04` instead of `ubuntu-latest`, so the minimum glibc of the binary does not rise when `ubuntu-latest` moves to Ubuntu 26.

## [0.1.0] - 2026-09-29

First release: Linux x86_64 and aarch64 binaries with SHA256SUMS.

### Added

- `info`: model, serial, firmware and PIV slot report.
- `age setup`, `age encrypt` and `age decrypt` on a PIV slot with a native piv-p256 implementation, interoperable in both directions with `age-plugin-yubikey`. `age setup` extracts an existing identity or generates one on the key.
- `hmac encrypt` and `hmac decrypt` with the OTP HMAC-SHA1 challenge-response slot, plus read support for the legacy `.yk.enc` files of the shell toolkit.
- `fido2 enroll`, `fido2 encrypt` and `fido2 decrypt` with a FIDO2 `hmac-secret` credential (experimental).
- `verify`: check that an encrypted file decrypts, without writing plaintext.
- `sign` and `verify-sig`: SSHSIG signatures with ed25519, ecdsa or ed25519-sk keys (passphrase-protected keys supported) or a PIV slot. RSA keys are refused.
- `backup`: device state as JSON, including AAGUID, FIDO2 PIN retries and OTP slot state.

[Unreleased]: https://github.com/Esl1h/ykoxide/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Esl1h/ykoxide/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Esl1h/ykoxide/releases/tag/v0.1.0
