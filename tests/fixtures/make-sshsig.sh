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
# The comment marks the key as test-only wherever it shows up, since the
# private key is committed on purpose.
ssh-keygen -q -t ed25519 -N '' \
  -C 'ykoxide-fixtures: throwaway test-only key, public on purpose, never trust or reuse' \
  -f "$KEY"
cp "$KEY.pub" "$FIXTURES/pubkey.txt"

printf 'ykoxide-fixtures %s\n' "$(cat "$KEY.pub")" > "$FIXTURES/allowed_signers"

# ssh-keygen -Y sign prompts before overwriting an existing signature.
rm -f "$FIXTURES/plain.txt.sig"
ssh-keygen -Y sign -f "$KEY" -n file "$FIXTURES/plain.txt"

echo "[+] Fixtures written to $FIXTURES"
