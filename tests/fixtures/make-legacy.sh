#!/usr/bin/env bash
# Regenerates the legacy fixtures in tests/fixtures/legacy/ the same way
# yk-encrypt-file.sh does, with a fixed challenge and a fixed HMAC response
# (as if ykman otp calculate had returned it for that challenge).
#
# The expected values are mirrored in src/format/legacy.rs tests.
set -euo pipefail

FIXTURES="$(cd "$(dirname "$0")/legacy" && pwd)"

CHALLENGE="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
HMAC="0102030405060708090a0b0c0d0e0f1011121314"
PLAINTEXT="legacy plaintext"

printf '%s' "$PLAINTEXT" > "$FIXTURES/plain.txt"

KEY=$(printf '%s' "${CHALLENGE}${HMAC}" | openssl dgst -sha256 -binary | xxd -p -c 256)

openssl enc -aes-256-cbc -pbkdf2 -iter 600000 \
    -k "$KEY" \
    -in "$FIXTURES/plain.txt" \
    -out "$FIXTURES/plain.txt.yk.enc"

printf '%s\n' "$CHALLENGE" > "$FIXTURES/plain.txt.yk.challenge"

echo "[+] Fixtures written to $FIXTURES"
