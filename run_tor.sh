#!/usr/bin/env bash
# =============================================================================
#  SecureChat over Tor — run_tor.sh
#  Host fetches their own onion address manually, pastes it in, gets a code.
#  Guest enters onion address + code to connect.
#  No IP addresses ever leave either machine.
# =============================================================================

cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

p() { printf "%b\n" "$@"; }

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
        pip install cryptography --break-system-packages 2>/dev/null || pip install cryptography
    fi
}

check_tor() {
    if ! command -v tor &>/dev/null; then
        p "${YEL}[!] Tor not found — installing...${RST}"
        sudo apt-get update -qq && sudo apt-get install -y tor
    fi
    if systemctl is-active --quiet tor@default 2>/dev/null; then
        p "${GRN}[+] Tor is running (tor@default)${RST}"
    elif systemctl is-active --quiet tor 2>/dev/null; then
        p "${GRN}[+] Tor is running${RST}"
    else
        p "${YEL}[!] Starting Tor...${RST}"
        sudo systemctl start tor@default 2>/dev/null || sudo systemctl start tor
        sleep 4
        p "${GRN}[+] Tor started${RST}"
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
    printf "%b\n" "    ${GRN}[1]${RST}  Host a session"
    printf "%b\n" "    ${GRN}[2]${RST}  Join a session"
    printf "%b\n" "    ${GRN}[3]${RST}  Show my onion address"
    printf "%b\n" "    ${GRN}[4]${RST}  Exit"
    printf "\n"
}

# ---------------------------------------------------------------------------
# Show the onion address — host runs this first in a separate terminal
# or uses option 3 before starting host mode
# ---------------------------------------------------------------------------
show_onion_address() {
    clear
    p "${CYN}  === YOUR ONION ADDRESS ===${RST}"
    printf "\n"

    # Try the two possible hostname locations
    local hostname_file=""
    if [ -f "/var/lib/tor/securechat/hostname" ]; then
        hostname_file="/var/lib/tor/securechat/hostname"
    elif [ -f "/var/lib/tor/hidden_service/hostname" ]; then
        hostname_file="/var/lib/tor/hidden_service/hostname"
    fi

    if [ -n "$hostname_file" ]; then
        local onion
        onion=$(sudo cat "$hostname_file" | tr -d '[:space:]')
        printf "\n"
        printf "%b\n" "${YEL}  +----------------------------------------------------------+"
        printf "%b\n" "  |                                                          |"
        printf          "  |   ${CYN}%-58s${YEL}|  \n"  "$onion"
        printf "%b\n" "  |                                                          |"
        printf "%b\n" "  +----------------------------------------------------------+${RST}"
        printf "\n"
        p "${DIM}  Copy the address above. You will paste it when you start host mode.${RST}"
    else
        printf "\n"
        p "${RED}  [!] No onion address found yet.${RST}"
        p "${YEL}  Run these commands to set up your hidden service first:${RST}"
        printf "\n"
        printf "%b\n" "${DIM}  ── Setup commands ────────────────────────────────────────"
        printf "%b\n" ""
        printf "%b\n" "  1. Add hidden service to Tor config:"
        printf "%b\n" "${CYN}     sudo bash -c 'printf \"\\n# SecureChat\\nHiddenServiceDir /var/lib/tor/securechat\\nHiddenServicePort 57311 127.0.0.1:57311\\n\" >> /etc/tor/instances/default/torrc'${RST}"
        printf "%b\n" ""
        printf "%b\n" "     (If that path does not exist, use /etc/tor/torrc instead)"
        printf "%b\n" ""
        printf "%b\n" "  2. Create the directory:"
        printf "%b\n" "${CYN}     sudo mkdir -p /var/lib/tor/securechat${RST}"
        printf "%b\n" "${CYN}     sudo chown debian-tor:debian-tor /var/lib/tor/securechat${RST}"
        printf "%b\n" "${CYN}     sudo chmod 700 /var/lib/tor/securechat${RST}"
        printf "%b\n" ""
        printf "%b\n" "  3. Restart Tor:"
        printf "%b\n" "${CYN}     sudo systemctl restart tor@default${RST}"
        printf "%b\n" ""
        printf "%b\n" "  4. Wait ~15 seconds, then read your onion address:"
        printf "%b\n" "${CYN}     sudo cat /var/lib/tor/securechat/hostname${RST}"
        printf "%b\n" ""
        printf "%b\n" "  ──────────────────────────────────────────────────────────${RST}"
        printf "\n"
        p "${DIM}  Once you have the address, come back and choose option 1 to host.${RST}"
    fi

    printf "\n"
    printf "  Press Enter to return to menu..."
    read -r _
}

# ---------------------------------------------------------------------------
# HOST MODE
# User pastes their onion address, gets a session code, shares both out-of-band
# ---------------------------------------------------------------------------
host_mode() {
    clear
    p "${GRN}  === HOST MODE ===${RST}"
    printf "\n"
    p "${DIM}  You need your onion address before continuing.${RST}"
    p "${DIM}  If you don't have it yet, press Ctrl+C, choose option 3 first.${RST}"
    printf "\n"

    # Prompt host to paste their onion address
    printf "  Paste your onion address (.onion) : "
    read -r HOST_ONION
    HOST_ONION=$(printf "%s" "$HOST_ONION" | tr -d '[:space:]')

    if [[ ! "$HOST_ONION" =~ \.onion$ ]]; then
        p "${RED}[!] That doesn't look like a valid .onion address.${RST}"
        sleep 2
        return
    fi

    # Generate session code
    p "${DIM}[*] Generating session code...${RST}"
    local SESSION_CODE
    SESSION_CODE=$(python3 -c "
import sys, os
sys.path.insert(0, '.')
from securechat.crypto import generate_session_code
print(generate_session_code())
")

    if [ -z "$SESSION_CODE" ]; then
        p "${RED}[!] Failed to generate session code.${RST}"
        p "${RED}    Make sure securechat/crypto.py exists in this directory.${RST}"
        sleep 3
        return
    fi

    # Display what to share with the guest
    printf "\n"
    p "${GRN}  Send BOTH of these to your guest via phone/Signal/any out-of-band channel:${RST}"
    printf "\n"
    printf "%b\n" "${YEL}  +----------------------------------------------------------+"
    printf "%b\n" "  |                                                          |"
    printf          "  |   Onion address :  ${CYN}%-38s${YEL}|  \n"  "$HOST_ONION"
    printf          "  |   Session code  :  ${CYN}%-38s${YEL}|  \n"  "$SESSION_CODE"
    printf "%b\n" "  |                                                          |"
    printf "%b\n" "  +----------------------------------------------------------+${RST}"
    printf "\n"
    p "${RED}  Do NOT send these over unencrypted channels.${RST}"
    printf "\n"
    p "${YEL}  Waiting for guest to connect... (Ctrl+C to cancel)${RST}"
    printf "\n"

    export SECURECHAT_TOR_MODE=1
    export SECURECHAT_SESSION_CODE="$SESSION_CODE"
    export ONION="$HOST_ONION"

    python3 -m securechat host --port 57311
}

# ---------------------------------------------------------------------------
# GUEST / CONNECT MODE
# ---------------------------------------------------------------------------
connect_mode() {
    clear
    p "${GRN}  === CONNECT MODE ===${RST}"
    printf "\n"
    p "  Enter the details sent to you by the host:"
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
    p "${YEL}  Connecting to ${GUEST_ONION} via Tor...${RST}"
    p "${DIM}  Circuit build may take 15-30 seconds. Please wait.${RST}"
    printf "\n"

    export SECURECHAT_PEER_HOST="$GUEST_ONION"
    export SECURECHAT_PEER_CODE="$GUEST_CODE"

    torsocks python3 -m securechat connect --port 57311
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    show_banner
    sudo -v
    check_python
    check_tor
    check_torsocks

    while true; do
        show_menu
        printf "  Choice [1/2/3/4]: "
        read -r choice
        case "$choice" in
            1) host_mode         ;;
            2) connect_mode      ;;
            3) show_onion_address ;;
            4)
                clear
                p "${GRN}  SecureChat closed. No logs. No history. No trace.${RST}"
                exit 0
                ;;
            *) p "${RED}  Invalid choice.${RST}" ;;
        esac
    done
}

main
