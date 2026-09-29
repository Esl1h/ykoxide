# Security policy

## Supported versions

Only the latest release receives security fixes. ykoxide is pre-1.0, so a fix ships as a new patch or minor release.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: <https://github.com/Esl1h/ykoxide/security/advisories/new>

Include the affected version (`ykox --version`), the command involved and the steps to reproduce. Do not include real PINs, keys, passphrases or private files; a redacted example is enough.

This is a one-person project, so responses are best effort. The aim is to acknowledge a report within a week, agree on a fix and a disclosure date with you, and credit you in the release notes if you want to be named.

## Scope

In scope:

- Flaws in how `ykox` handles PINs, passphrases, keys or plaintext (leaks, missing zeroization, unsafe file permissions).
- Flaws in the file formats it writes, or in signature and decryption checks that accept data they should reject.
- Problems in the release pipeline that could let a tampered binary pass the published checksums or attestation.

Out of scope:

- Vulnerabilities in a dependency: report them upstream. Advisories that reach `ykox` are tracked with `cargo audit` and `cargo deny` in CI; the one that is ignored on purpose (`RUSTSEC-2023-0071`) is explained in `.cargo/audit.toml`.
- Physical attacks on the YubiKey itself, and malware on the host that reads plaintext after decryption.
- The lack of authentication in the legacy `.yk.enc` format, which is documented in the README and kept only for reading old files.
