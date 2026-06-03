#!/usr/bin/env bash

cd "$(dirname "$0")"

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

p() { printf "%b\n" "$@"; }

detect_torrc() {
    local candidates=(
        "/etc/tor/instances/default/torrc"   # Debian/Kali systemd instance
        "/etc/tor/torrc"                     # Standard Debian/Ubuntu
        "/usr/local/etc/tor/torrc"           # macOS Homebrew
        "/opt/homebrew/etc/tor/torrc"        # macOS Apple Silicon Homebrew
        "/etc/tor/torrc.d/securechat.conf"   # Drop-in config dir
    )
    for path in "${candidates[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    if command -v tor &>/dev/null; then
        local tor_defaults
        tor_defaults=$(tor --verify-config 2>&1 | grep -oP '(?<=Read configuration file ")\S+(?=")' | head -1)
        [ -n "$tor_defaults" ] && echo "$tor_defaults" && return 0
    fi
    echo ""
    return 1
}
# Auto-detect hidden service hostname file
detect_hostname_file() {
    local candidates=(
        "/var/lib/tor/securechat/hostname"
        "/var/lib/tor/hidden_service/hostname"
        "/var/lib/tor/services/securechat/hostname"
        "$HOME/.tor/securechat/hostname"
    )
    for path in "${candidates[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    echo ""
    return 1
}

# Dependency checks

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

# Banner
show_banner() {
    clear
    printf "%b\n" "${GRN}"
    printf "%s\n" " ============================================================"
    printf "%s\n" " SECURECHAT -- Tor Hidden Service Mode"
    printf "%s\n" " AES-256-GCM | One-time code | Zero logs | Timestamps"
    printf "%s\n" " ============================================================"
    printf "%b\n" "${RST}"
}
# Menu
show_menu() {
    printf "\n"
    printf "%b\n" "${CYN} Select an option:${RST}"
    printf "\n"
    printf "%b\n" " ${GRN}[1]${RST} Host a session"
    printf "%b\n" " ${GRN}[2]${RST} Join a session"
    printf "%b\n" " ${GRN}[3]${RST} Show my onion address"
    printf "%b\n" " ${GRN}[4]${RST} Exit"
    printf "%b\n" " ${GRN}[5]${RST} ${YEL}Setup hidden service (first time)${RST}"
    printf "\n"
}

# Show the onion address

show_onion_address() {
    clear
    p "${CYN} === YOUR ONION ADDRESS ===${RST}"
    printf "\n"

    local hostname_file
    hostname_file=$(detect_hostname_file)

    if [ -n "$hostname_file" ]; then
        local onion
        onion=$(sudo cat "$hostname_file" | tr -d '[:space:]')
        printf "\n"
        printf "%b\n" "${YEL} +----------------------------------------------------------+"
        printf "%b\n" " | |"
        printf " | ${CYN}%-58s${YEL}| \n" "$onion"
        printf "%b\n" " | |"
        printf "%b\n" " +----------------------------------------------------------+${RST}"
        printf "\n"
        p "${DIM} Copy the address above. You will paste it when you start host mode.${RST}"
    else
        printf "\n"
        p "${RED} [!] No onion address found yet.${RST}"
        p "${YEL} Choose option 5 from the menu to run first-time setup automatically.${RST}"
    fi

    printf "\n"
    printf " Press Enter to return to menu..."
    read -r _
}
auto_setup_hidden_service() {
    clear
    p "${CYN} === HIDDEN SERVICE AUTO-SETUP ===${RST}"
    printf "\n"
    p "${DIM} This will configure a Tor hidden service for SecureChat on port 57311.${RST}"
    p "${DIM} It requires sudo. Your onion address will be permanent as long as${RST}"
    p "${DIM} you keep the keys in the hidden service directory.${RST}"
    printf "\n"
    printf " Continue? [y/N]: "
    read -r confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && p "${YEL} Cancelled.${RST}" && sleep 1 && return

    # Detect torrc
    local TORRC
    TORRC=$(detect_torrc)

    if [ -z "$TORRC" ]; then
        p "${RED}[!] Could not locate torrc. Trying /etc/tor/torrc as fallback.${RST}"
        TORRC="/etc/tor/torrc"
    fi

    p "${GRN}[+] Using torrc: ${TORRC}${RST}"

    # Check if already configured
    if sudo grep -q "HiddenServiceDir.*securechat" "$TORRC" 2>/dev/null; then
        p "${YEL}[!] Hidden service already configured in ${TORRC}.${RST}"
        p "${DIM}    Skipping torrc edit. Restarting Tor to ensure keys are generated...${RST}"
    else
        p "${DIM}[*] Adding hidden service config to ${TORRC}...${RST}"
        sudo bash -c "printf '\n# SecureChat hidden service\nHiddenServiceDir /var/lib/tor/securechat\nHiddenServicePort 57311 127.0.0.1:57311\n' >> \"$TORRC\""
        p "${GRN}[+] Config written.${RST}"
    fi

    # Create directory with correct permissions
    p "${DIM}[*] Creating hidden service directory...${RST}"
    sudo mkdir -p /var/lib/tor/securechat

    # Determine correct tor user (debian-tor on Debian/Kali, _tor on macOS, tor on others)
    local TOR_USER="debian-tor"
    if ! id "$TOR_USER" &>/dev/null; then
        TOR_USER=$(ps aux | grep -E '\btor\b' | grep -v grep | awk '{print $1}' | head -1)
    fi
    [ -z "$TOR_USER" ] && TOR_USER="tor"

    sudo chown "${TOR_USER}:${TOR_USER}" /var/lib/tor/securechat 2>/dev/null \
        || sudo chown "${TOR_USER}" /var/lib/tor/securechat
    sudo chmod 700 /var/lib/tor/securechat
    p "${GRN}[+] Directory created and permissioned (owner: ${TOR_USER}).${RST}"

    # Restart Tor
    p "${DIM}[*] Restarting Tor to generate keys...${RST}"
    sudo systemctl restart tor@default 2>/dev/null || sudo systemctl restart tor
    p "${DIM}[*] Waiting 20 seconds for Tor circuit and key generation...${RST}"

    # Animated wait
    for i in $(seq 1 20); do
        printf "\r ${YEL}[*] Waiting... %2d/20s${RST}" "$i"
        sleep 1
    done
    printf "\n"

    # Read and display onion address
    local hostname_file
    hostname_file=$(detect_hostname_file)

    if [ -n "$hostname_file" ]; then
        local onion
        onion=$(sudo cat "$hostname_file" | tr -d '[:space:]')
        printf "\n"
        p "${GRN} ✓ Setup complete! Your onion address:${RST}"
        printf "\n"
        printf "%b\n" "${YEL} +----------------------------------------------------------+"
        printf "%b\n" " | |"
        printf " | ${CYN}%-58s${YEL}| \n" "$onion"
        printf "%b\n" " | |"
        printf "%b\n" " +----------------------------------------------------------+${RST}"
        printf "\n"
        p "${DIM} Save this address. Share it with guests via Signal or phone.${RST}"
    else
        p "${RED}[!] Hostname file not found yet. Try waiting another 30s and choose option 3.${RST}"
        p "${DIM}    If the problem persists, check: sudo journalctl -u tor --no-pager | tail -20${RST}"
    fi

    printf "\n Press Enter to return to menu..."
    read -r _
}

# ---------------------------------------------------------------------------
# HOST MODE
# ---------------------------------------------------------------------------
host_mode() {
    clear
    p "${GRN} === HOST MODE ===${RST}"
    printf "\n"
    p "${DIM} You need your onion address before continuing.${RST}"
    p "${DIM} If you don't have it yet, press Ctrl+C, choose option 3 first.${RST}"
    printf "\n"

    printf " Paste your onion address (.onion) : "
    read -r HOST_ONION
    HOST_ONION=$(printf "%s" "$HOST_ONION" | tr -d '[:space:]')

    if [[ ! "$HOST_ONION" =~ \.onion$ ]]; then
        p "${RED}[!] That doesn't look like a valid .onion address.${RST}"
        sleep 2
        return
    fi

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
        p "${RED} Make sure securechat/crypto.py exists in this directory.${RST}"
        sleep 3
        return
    fi

    printf "\n"
    p "${GRN} Send BOTH of these to your guest via phone/Signal/any out-of-band channel:${RST}"
    printf "\n"
    printf "%b\n" "${YEL} +----------------------------------------------------------+"
    printf "%b\n" " | |"
    printf " | Onion address : ${CYN}%-38s${YEL}| \n" "$HOST_ONION"
    printf " | Session code  : ${CYN}%-38s${YEL}| \n" "$SESSION_CODE"
    printf "%b\n" " | |"
    printf "%b\n" " +----------------------------------------------------------+${RST}"
    printf "\n"
    p "${RED} Do NOT send these over unencrypted channels.${RST}"
    printf "\n"
    p "${YEL} Waiting for guest to connect... (Ctrl+C to cancel)${RST}"
    printf "\n"

    export SECURECHAT_TOR_MODE=1
    export SECURECHAT_SESSION_CODE="$SESSION_CODE"
    export ONION="$HOST_ONION"
    export SECURECHAT_TIMESTAMPS=1   # [IMPROVEMENT 5] Enable [HH:MM] timestamps

    # [IMPROVEMENT 4] Reconnect on drop — retry once if Python exits unexpectedly
    local attempt=0
    local max_reconnects=1
    while true; do
        python3 -m securechat host --port 57311
        EXIT_CODE=$?
        # Clean exit (0) or user quit (130 = Ctrl+C) — don't reconnect
        if [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 130 ]; then
            break
        fi
        if [ "$attempt" -ge "$max_reconnects" ]; then
            p "${RED}[!] Session ended (exit code ${EXIT_CODE}). Max reconnect attempts reached.${RST}"
            break
        fi
        attempt=$((attempt + 1))
        p "${YEL}[!] Connection dropped (exit code ${EXIT_CODE}). Attempting reconnect ${attempt}/${max_reconnects}...${RST}"
        sleep 3
    done
}

# ---------------------------------------------------------------------------
# [IMPROVEMENT 3 + 4] GUEST / CONNECT MODE with timeout, retry, and reconnect
# ---------------------------------------------------------------------------
connect_mode() {
    clear
    p "${GRN} === CONNECT MODE ===${RST}"
    printf "\n"
    p " Enter the details sent to you by the host:"
    printf "\n"

    printf " Onion address (xxxx...xxxx.onion) : "
    read -r GUEST_ONION
    GUEST_ONION=$(printf "%s" "$GUEST_ONION" | tr -d '[:space:]')

    if [[ ! "$GUEST_ONION" =~ \.onion$ ]]; then
        p "${RED}[!] That doesn't look like a valid .onion address.${RST}"
        sleep 2
        return
    fi

    printf " Session code (XXXX-XXXX-XXXX) : "
    read -r GUEST_CODE
    GUEST_CODE=$(printf "%s" "$GUEST_CODE" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')

    if [ -z "$GUEST_CODE" ]; then
        p "${RED}[!] No session code entered.${RST}"
        sleep 2
        return
    fi

    export SECURECHAT_PEER_HOST="$GUEST_ONION"
    export SECURECHAT_PEER_CODE="$GUEST_CODE"
    export SECURECHAT_TIMESTAMPS=1   # [IMPROVEMENT 5] Enable [HH:MM] timestamps

    # [IMPROVEMENT 3] Retry loop — up to 3 connection attempts, 60s timeout each
    local MAX_ATTEMPTS=3
    local TIMEOUT_SEC=60
    local attempt=1

    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
        printf "\n"
        p "${YEL} Connecting to ${GUEST_ONION} via Tor... (attempt ${attempt}/${MAX_ATTEMPTS})${RST}"
        p "${DIM} Circuit build may take up to ${TIMEOUT_SEC}s. Please wait.${RST}"
        printf "\n"

        # Run with timeout; torsocks wraps the Python process
        timeout "$TIMEOUT_SEC" torsocks python3 -m securechat connect --port 57311
        EXIT_CODE=$?

        # 0 = clean exit, 130 = Ctrl+C — stop looping
        if [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 130 ]; then
            # [IMPROVEMENT 4] If session connected then dropped, offer one reconnect
            if [ "$EXIT_CODE" -ne 0 ] && [ "$EXIT_CODE" -ne 130 ]; then
                p "${YEL}[!] Session dropped. Reconnecting once...${RST}"
                sleep 3
                timeout "$TIMEOUT_SEC" torsocks python3 -m securechat connect --port 57311
            fi
            break
        fi

        # 124 = timed out
        if [ "$EXIT_CODE" -eq 124 ]; then
            p "${YEL}[!] Connection timed out after ${TIMEOUT_SEC}s.${RST}"
        else
            p "${YEL}[!] Connection failed (exit code ${EXIT_CODE}).${RST}"
        fi

        if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
            p "${DIM} Retrying in 5 seconds... (${attempt}/${MAX_ATTEMPTS})${RST}"
            sleep 5
        else
            p "${RED}[!] Could not connect after ${MAX_ATTEMPTS} attempts.${RST}"
            p "${DIM} Make sure:${RST}"
            p "${DIM}   • The host is running and waiting${RST}"
            p "${DIM}   • The onion address and session code are correct${RST}"
            p "${DIM}   • Your Tor daemon is running (sudo systemctl status tor)${RST}"
        fi

        attempt=$((attempt + 1))
    done

    printf "\n Press Enter to return to menu..."
    read -r _
}

# ---------------------------------------------------------------------------
# Handle --setup flag (non-interactive first-time setup)
# Usage: bash run_tor.sh --setup
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--setup" ]; then
    check_tor
    auto_setup_hidden_service
    exit 0
fi

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
        printf " Choice [1/2/3/4/5]: "
        read -r choice

        case "$choice" in
            1) host_mode ;;
            2) connect_mode ;;
            3) show_onion_address ;;
            4)
                clear
                p "${GRN} SecureChat closed. No logs. No history. No trace.${RST}"
                exit 0
                ;;
            5) auto_setup_hidden_service ;;
            *) p "${RED} Invalid choice.${RST}" ;;
        esac
    done
}

main
