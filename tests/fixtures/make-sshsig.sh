#!/usr/bin/env bash
# Regenerates the SSHSIG fixtures in tests/fixtures/sshsig/ with a plain
# ed25519 key created here, signing a small known plaintext with
# ssh-keygen -Y sign (namespace "file", SHA-512).
set -euo pipefail

FIXTURES="$(cd "$(dirname "$0")/sshsig" && pwd)"

printf 'file to sign\n' > "$FIXTURES/plain.txt"

rm -rf "$FIXTURES/ssh"
mkdir -p "$FIXTURES/ssh"
KEY="$FIXTURES/ssh/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -C ykoxide-fixtures -f "$KEY"

printf 'ykoxide-fixtures %s\n' "$(cat "$KEY.pub")" > "$FIXTURES/allowed_signers"

ssh-keygen -Y sign -f "$KEY" -n file "$FIXTURES/plain.txt"

echo "[+] Fixtures written to $FIXTURES"
