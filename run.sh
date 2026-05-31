#!/usr/bin/env bash
# SecureChat direct launcher (no Tor).
# For Tor mode, use: bash run_tor.sh
set -euo pipefail
cd "$(dirname "$0")"

if ! python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" 2>/dev/null; then
    echo "[*] Installing dependency: cryptography"
    pip install cryptography --break-system-packages 2>/dev/null \
        || pip install cryptography
fi

exec python3 -m securechat "$@"
