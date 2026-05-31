#!/usr/bin/env bash
# =============================================================================
#  SecureChat over Tor — run_tor.sh
#  Entry point for BOTH the host and the guest.
#  No IP addresses ever leave either machine.
# =============================================================================
set -euo pipefail

# Always run from the directory this script lives in
cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# Colours — use printf so they work on every POSIX shell / terminal
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
MAG='\033[0;35m'
DIM='\033[2m'
RST='\033[0m'

p() { printf "%b\n" "$@"; }   # portable coloured print

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
check_python() {
    if ! command -v python3 &>/dev/null; then
        p "${RED}[!] python3 not found. Install Python 3.8+${RST}"
        exit 1
    fi
    if ! python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" 2>/dev/null; then
        p "${YEL}[*] Installing Python dependency: cryptography${RST}"
        pip install cryptography --break-system-packages 2>/dev/null \
            || pip install cryptography
    fi
}

check_tor() {
    if ! command -v tor &>/dev/null; then
        p "${YEL}[!] Tor not found — installing...${RST}"
        sudo apt-get update -qq && sudo apt-get install -y tor
    fi
    if ! systemctl is-active --quiet tor 2>/dev/null; then
        p "${YEL}[!] Starting Tor service...${RST}"
        sudo systemctl start tor
        sleep 4
    fi
    if systemctl is-active --quiet tor 2>/dev/null; then
        p "${GRN}[+] Tor is running${RST}"
    else
        p "${RED}[!] Tor failed to start. Try: sudo systemctl start tor${RST}"
        exit 1
    fi
}

check_torsocks() {
    if ! command -v torsocks &>/dev/null; then
        p "${YEL}[!] torsocks not found — installing...${RST}"
        sudo apt-get install -y torsocks
    fi
    p "${GRN}[+] torsocks ready${RST}"
}

# ---------------------------------------------------------------------------
# Read / create Tor hidden service for SecureChat
# ---------------------------------------------------------------------------
setup_hidden_service() {
    local torrc=/etc/tor/torrc
    local hs_dir=/var/lib/tor/securechat

    # Create directory with correct ownership
    if [ ! -d "$hs_dir" ]; then
        sudo mkdir -p "$hs_dir"
        sudo chown debian-tor:debian-tor "$hs_dir" 2>/dev/null \
            || sudo chown tor:tor "$hs_dir" 2>/dev/null || true
        sudo chmod 700 "$hs_dir"
    fi

    # Append hidden-service config to torrc if not already present
    if ! grep -q "HiddenServiceDir $hs_dir" "$torrc" 2>/dev/null; then
        p "${YEL}[!] Adding SecureChat hidden service to torrc...${RST}"
        printf "\n# SecureChat hidden service\nHiddenServiceDir %s\nHiddenServicePort 57311 127.0.0.1:57311\n" \
            "$hs_dir" | sudo tee -a "$torrc" >/dev/null
        sudo systemctl restart tor
        p "${YEL}[*] Waiting for Tor to generate onion keys (up to 30 s)...${RST}"
        local waited=0
        while [ ! -f "$hs_dir/hostname" ] && [ "$waited" -lt 30 ]; do
            sleep 2; waited=$((waited+2))
            printf "."
        done
        printf "\n"
    fi

    if [ ! -f "$hs_dir/hostname" ]; then
        p "${RED}[!] Onion address not generated yet. Wait a moment and retry.${RST}"
        exit 1
    fi

    ONION=$(sudo cat "$hs_dir/hostname" | tr -d '[:space:]')
    export ONION
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
show_banner() {
    clear
    printf "%b\n" "${GRN}"
    printf "%s\n" "  ============================================================"
    printf "%s\n" "       SECURECHAT  --  Tor Hidden Service Mode"
    printf "%s\n" "       AES-256-GCM  |  One-time code  |  Zero logs"
    printf "%s\n" "  ============================================================"
    printf "%b\n" "${RST}"
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
show_menu() {
    printf "\n"
    printf "%b\n" "${CYN}  Select an option:${RST}"
    printf "\n"
    printf "%b\n" "    ${GRN}[1]${RST}  Host a session   (start listener, get onion address)"
    printf "%b\n" "    ${GRN}[2]${RST}  Join a session   (enter onion address + code)"
    printf "%b\n" "    ${GRN}[3]${RST}  Exit"
    printf "\n"
}

# ---------------------------------------------------------------------------
# HOST MODE
# Binds locally — Tor routes inbound hidden-service traffic to port 57311.
# No torsocks needed here; only the guest uses torsocks.
# ---------------------------------------------------------------------------
host_mode() {
    clear
    p "${GRN}  === HOST MODE ===${RST}"
    printf "\n"

    setup_hidden_service

    # Derive session code by running a tiny Python snippet
    SESSION_CODE=$(python3 -c "
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath('.')))
sys.path.insert(0, '.')
from securechat.crypto import generate_session_code
print(generate_session_code())
")

    printf "\n"
    p "${GRN}  Your Tor hidden service is ready.${RST}"
    p "${GRN}  Send BOTH items below to the person you want to chat with:${RST}"
    printf "\n"
    printf "%b\n" "${YEL}  +----------------------------------------------------------+"
    printf "%b\n" "  |                                                          |"
    printf   "  |   Onion address :  ${CYN}%-38s${YEL}|  \n"  "${ONION}"
    printf   "  |   Session code  :  ${CYN}%-38s${YEL}|  \n"  "${SESSION_CODE}"
    printf "%b\n" "  |                                                          |"
    printf "%b\n" "  +----------------------------------------------------------+${RST}"
    printf "\n"
    p "${DIM}  Share via phone call, Signal, or any out-of-band channel.${RST}"
    p "${DIM}  Do NOT share over an unencrypted channel.${RST}"
    printf "\n"
    p "${YEL}  Waiting for guest to connect... (15-minute timeout)${RST}"
    p "${DIM}  Press Ctrl+C to cancel.${RST}"
    printf "\n"

    # Export so securechat.py's run_host() knows we are in tor mode
    export SECURECHAT_TOR_MODE=1
    export SECURECHAT_SESSION_CODE="$SESSION_CODE"

    # Run securechat host — plain python3, NO torsocks
    python3 -m securechat host --port 57311
}

# ---------------------------------------------------------------------------
# GUEST / CONNECT MODE
# Uses torsocks to route the TCP connection through Tor to the .onion address.
# ---------------------------------------------------------------------------
connect_mode() {
    clear
    p "${GRN}  === CONNECT MODE ===${RST}"
    printf "\n"
    p "  Enter the details shared by the host:"
    printf "\n"

    printf "  Onion address  (xxxx...xxxx.onion) : "
    read -r GUEST_ONION
    GUEST_ONION=$(printf "%s" "$GUEST_ONION" | tr -d '[:space:]')

    if [[ ! "$GUEST_ONION" =~ \.onion$ ]]; then
        p "${RED}[!] That doesn't look like a valid .onion address.${RST}"
        sleep 2
        return
    fi

    printf "  Session code   (XXXX-XXXX-XXXX)    : "
    read -r GUEST_CODE
    GUEST_CODE=$(printf "%s" "$GUEST_CODE" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')

    if [ -z "$GUEST_CODE" ]; then
        p "${RED}[!] No session code entered.${RST}"
        sleep 2
        return
    fi

    printf "\n"
    p "${YEL}  Routing through Tor to ${GUEST_ONION}...${RST}"
    p "${DIM}  Tor circuits may take 15-30 seconds to build. Please wait.${RST}"
    printf "\n"

    # Pre-fill host address so securechat.py's run_connect() skips the prompt
    export SECURECHAT_PEER_HOST="$GUEST_ONION"
    export SECURECHAT_PEER_CODE="$GUEST_CODE"

    # torsocks intercepts all TCP calls and tunnels them through Tor
    torsocks python3 -m securechat connect --port 57311
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    show_banner
    check_python
    check_tor
    check_torsocks

    while true; do
        show_menu
        printf "  Choice [1/2/3]: "
        read -r choice
        case "$choice" in
            1) host_mode    ;;
            2) connect_mode ;;
            3)
                clear
                p "${GRN}  SecureChat closed. No logs. No history. No trace.${RST}"
                exit 0
                ;;
            *) p "${RED}  Invalid choice — enter 1, 2, or 3.${RST}" ;;
        esac
    done
}

main
