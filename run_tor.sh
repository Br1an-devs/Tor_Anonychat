#!/usr/bin/env bash
# =============================================================================
# SecureChat over Tor — run_tor.sh
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

p() { printf "%b\n" "$@"; }

# ── Auto-detect torrc path ────────────────────────────────────────────────────
detect_torrc() {
    local candidates=(
        "/etc/tor/instances/default/torrc"
        "/etc/tor/torrc"
        "/usr/local/etc/tor/torrc"
        "/opt/homebrew/etc/tor/torrc"
    )
    for f in "${candidates[@]}"; do
        [ -f "$f" ] && echo "$f" && return 0
    done
    # Ask tor itself as last resort
    if command -v tor &>/dev/null; then
        local rc
        rc=$(tor --verify-config 2>&1 \
            | grep -oP '(?<=Read configuration file ")\S+(?=")' \
            | head -1)
        [ -n "$rc" ] && echo "$rc" && return 0
    fi
    echo ""
    return 1
}

# ── Auto-detect hostname file ─────────────────────────────────────────────────
# Searches all likely Tor data directories for a hostname file.
detect_hostname_file() {
    local candidates=(
        "/var/lib/tor/securechat/hostname"
        "/var/lib/tor/hidden_service/hostname"
        "/var/lib/tor/services/securechat/hostname"
        "$HOME/.tor/securechat/hostname"
    )
    for f in "${candidates[@]}"; do
        if sudo test -f "$f" 2>/dev/null; then
            echo "$f"
            return 0
        fi
    done
    # Broader search: any hostname file under /var/lib/tor
    local found
    found=$(sudo find /var/lib/tor -name "hostname" 2>/dev/null | head -1)
    [ -n "$found" ] && echo "$found" && return 0

    echo ""
    return 1
}

# ── Read onion address ────────────────────────────────────────────────────────
read_onion() {
    local hf
    hf=$(detect_hostname_file)
    if [ -n "$hf" ]; then
        sudo cat "$hf" 2>/dev/null | tr -d '[:space:]'
    else
        echo ""
    fi
}

# ── Dependency checks ─────────────────────────────────────────────────────────
check_python() {
    if ! command -v python3 &>/dev/null; then
        p "${RED}[!] python3 not found — install Python 3.8+${RST}"
        exit 1
    fi
    if ! python3 -c \
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" \
        2>/dev/null; then
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
    if systemctl is-active --quiet tor@default 2>/dev/null; then
        p "${GRN}[+] Tor is running (tor@default)${RST}"
    elif systemctl is-active --quiet tor 2>/dev/null; then
        p "${GRN}[+] Tor is running${RST}"
    else
        p "${YEL}[!] Starting Tor...${RST}"
        sudo systemctl start tor@default 2>/dev/null \
            || sudo systemctl start tor
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

# ── Banner ────────────────────────────────────────────────────────────────────
show_banner() {
    clear
    printf "%b\n" "${GRN}"
    printf "%s\n" " ============================================================"
    printf "%s\n" " SECURECHAT  —  Tor Hidden Service Mode"
    printf "%s\n" " AES-256-GCM  |  One-time code  |  Zero logs"
    printf "%s\n" " ============================================================"
    printf "%b\n" "${RST}"
}

# ── Menu ──────────────────────────────────────────────────────────────────────
show_menu() {
    printf "\n"
    printf "%b\n" "${CYN} Select an option:${RST}"
    printf "\n"
    printf "%b\n" " ${GRN}[1]${RST} Host a session"
    printf "%b\n" " ${GRN}[2]${RST} Join a session"
    printf "%b\n" " ${GRN}[3]${RST} Show my onion address"
    printf "%b\n" " ${GRN}[4]${RST} Exit"
    printf "%b\n" " ${GRN}[5]${RST} ${YEL}First-time setup (generate onion address)${RST}"
    printf "\n"
}

# ── Show onion address ────────────────────────────────────────────────────────
show_onion_address() {
    clear
    p "${CYN} === YOUR ONION ADDRESS ===${RST}"
    printf "\n"

    local onion
    onion=$(read_onion)

    if [ -n "$onion" ]; then
        printf "\n"
        printf "%b\n" "${YEL} +------------------------------------------------------------+"
        printf "%b\n" " |                                                            |"
        printf " |  ${CYN}%-58s${YEL}  |\n" "$onion"
        printf "%b\n" " |                                                            |"
        printf "%b\n" " +------------------------------------------------------------+${RST}"
        printf "\n"
        p "${DIM} Share this address with your guest via Signal or phone.${RST}"
    else
        printf "\n"
        p "${RED} [!] No onion address found.${RST}"
        p "${YEL}     Run option [5] to set up your hidden service first.${RST}"
    fi

    printf "\n"
    printf " Press Enter to return to menu..."
    read -r _
}

# ── First-time setup ──────────────────────────────────────────────────────────
auto_setup_hidden_service() {
    clear
    p "${CYN} === FIRST-TIME SETUP ===${RST}"
    printf "\n"
    p "${DIM} Configures a Tor hidden service for SecureChat on port 57311.${RST}"
    p "${DIM} Requires sudo. Your .onion address will be permanent.${RST}"
    printf "\n"
    printf " Continue? [y/N]: "
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        p "${YEL} Cancelled.${RST}"
        sleep 1
        return
    fi

    # Detect torrc
    local TORRC
    TORRC=$(detect_torrc)
    if [ -z "$TORRC" ]; then
        p "${RED}[!] Could not locate torrc — using /etc/tor/torrc${RST}"
        TORRC="/etc/tor/torrc"
    fi
    p "${GRN}[+] Using torrc: ${TORRC}${RST}"

    # Add config if not already there
    if sudo grep -q "HiddenServiceDir.*securechat" "$TORRC" 2>/dev/null; then
        p "${YEL}[!] Hidden service already configured in torrc — skipping edit.${RST}"
    else
        p "${DIM}[*] Writing hidden service config...${RST}"
        sudo bash -c "printf '\n# SecureChat hidden service\nHiddenServiceDir /var/lib/tor/securechat\nHiddenServicePort 57311 127.0.0.1:57311\n' >> \"$TORRC\""
        p "${GRN}[+] Config written.${RST}"
    fi

    # Create directory with correct ownership
    sudo mkdir -p /var/lib/tor/securechat

    # Detect tor user (debian-tor on Debian/Kali, _tor on macOS, tor elsewhere)
    local TOR_USER="debian-tor"
    if ! id "$TOR_USER" &>/dev/null; then
        TOR_USER=$(ps aux | grep -E '\btor\b' | grep -v grep \
            | awk '{print $1}' | head -1)
        [ -z "$TOR_USER" ] && TOR_USER="tor"
    fi

    sudo chown -R "${TOR_USER}:${TOR_USER}" /var/lib/tor/securechat 2>/dev/null \
        || sudo chown -R "${TOR_USER}" /var/lib/tor/securechat
    sudo chmod 700 /var/lib/tor/securechat
    p "${GRN}[+] Directory ready (owner: ${TOR_USER}).${RST}"

    # Restart Tor
    p "${DIM}[*] Restarting Tor...${RST}"
    sudo systemctl restart tor@default 2>/dev/null \
        || sudo systemctl restart tor

    # Wait for hostname file to appear (up to 30s)
    p "${DIM}[*] Waiting for Tor to generate your onion address...${RST}"
    local i=0
    local onion=""
    while [ "$i" -lt 30 ]; do
        onion=$(read_onion)
        [ -n "$onion" ] && break
        printf "\r ${YEL}[*] Waiting... %2d/30s${RST}" "$((i+1))"
        sleep 1
        i=$((i+1))
    done
    printf "\n"

    if [ -n "$onion" ]; then
        printf "\n"
        p "${GRN} ✓ Setup complete! Your onion address:${RST}"
        printf "\n"
        printf "%b\n" "${YEL} +------------------------------------------------------------+"
        printf "%b\n" " |                                                            |"
        printf " |  ${CYN}%-58s${YEL}  |\n" "$onion"
        printf "%b\n" " |                                                            |"
        printf "%b\n" " +------------------------------------------------------------+${RST}"
        printf "\n"
        p "${DIM} Save this address. Share it with guests via Signal or a phone call.${RST}"
    else
        p "${RED}[!] Hostname file not found after 30s.${RST}"
        p "${DIM}    Check: sudo journalctl -u tor --no-pager | tail -20${RST}"
    fi

    printf "\n Press Enter to return to menu..."
    read -r _
}

# ── HOST MODE ─────────────────────────────────────────────────────────────────
host_mode() {
    clear
    p "${GRN} === HOST MODE ===${RST}"
    printf "\n"

    # Auto-detect the onion address — no manual paste needed
    local HOST_ONION
    HOST_ONION=$(read_onion)

    if [ -z "$HOST_ONION" ]; then
        p "${RED}[!] Could not detect your onion address automatically.${RST}"
        p "${YEL}    Run option [5] first to set up your hidden service.${RST}"
        p "${DIM}    Or check: sudo cat /var/lib/tor/securechat/hostname${RST}"
        printf "\n"
        printf " Paste onion address manually (or press Enter to cancel): "
        read -r HOST_ONION
        HOST_ONION=$(printf "%s" "$HOST_ONION" | tr -d '[:space:]')
        if [[ -z "$HOST_ONION" || ! "$HOST_ONION" =~ \.onion$ ]]; then
            p "${RED}[!] No valid onion address — returning to menu.${RST}"
            sleep 2
            return
        fi
    else
        p "${GRN}[+] Onion address detected:${RST}"
        printf "\n"
        printf "%b\n" "${YEL} +------------------------------------------------------------+"
        printf "%b\n" " |                                                            |"
        printf " |  ${CYN}%-58s${YEL}  |\n" "$HOST_ONION"
        printf "%b\n" " |                                                            |"
        printf "%b\n" " +------------------------------------------------------------+${RST}"
        printf "\n"
    fi

    # Generate session code via Python
    local SESSION_CODE
    SESSION_CODE=$(python3 -c "
import sys; sys.path.insert(0, '.')
from securechat.crypto import generate_session_code
print(generate_session_code())
" 2>/dev/null)

    if [ -z "$SESSION_CODE" ]; then
        p "${RED}[!] Failed to generate session code.${RST}"
        p "${RED}    Make sure securechat/crypto.py exists in this directory.${RST}"
        sleep 3
        return
    fi

    printf "\n"
    p "${GRN} Share BOTH of these with your guest (Signal, phone call — NOT plaintext):${RST}"
    printf "\n"
    printf "%b\n" "${YEL} +------------------------------------------------------------+"
    printf "%b\n" " |                                                            |"
    printf " |  Onion  : ${CYN}%-48s${YEL}  |\n" "$HOST_ONION"
    printf " |  Code   : ${CYN}%-48s${YEL}  |\n" "$SESSION_CODE"
    printf "%b\n" " |                                                            |"
    printf "%b\n" " +------------------------------------------------------------+${RST}"
    printf "\n"
    p "${YEL} Waiting for guest... (Ctrl+C to cancel)${RST}"
    printf "\n"

    export SECURECHAT_TOR_MODE=1
    export SECURECHAT_SESSION_CODE="$SESSION_CODE"
    export ONION="$HOST_ONION"

    # Run Python. If it exits non-zero (crash, not user quit), retry once.
    python3 -m securechat host --port 57311
    local EXIT_CODE=$?

    if [ "$EXIT_CODE" -ne 0 ] && [ "$EXIT_CODE" -ne 130 ]; then
        printf "\n"
        p "${YEL}[!] Session ended unexpectedly (exit ${EXIT_CODE}). Reconnecting once...${RST}"
        sleep 3
        python3 -m securechat host --port 57311 || true
    fi
}

# ── GUEST / CONNECT MODE ──────────────────────────────────────────────────────
connect_mode() {
    clear
    p "${GRN} === CONNECT MODE ===${RST}"
    printf "\n"
    p " Enter the details sent to you by the host:"
    printf "\n"

    printf " Onion address (.onion): "
    read -r GUEST_ONION
    GUEST_ONION=$(printf "%s" "$GUEST_ONION" | tr -d '[:space:]')

    if [[ ! "$GUEST_ONION" =~ \.onion$ ]]; then
        p "${RED}[!] Invalid onion address.${RST}"
        sleep 2
        return
    fi

    printf " Session code (XXXX-XXXX-XXXX): "
    read -r GUEST_CODE
    GUEST_CODE=$(printf "%s" "$GUEST_CODE" \
        | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')

    if [ -z "$GUEST_CODE" ]; then
        p "${RED}[!] No session code entered.${RST}"
        sleep 2
        return
    fi

    export SECURECHAT_PEER_HOST="$GUEST_ONION"
    export SECURECHAT_PEER_CODE="$GUEST_CODE"

    # ── Retry loop ────────────────────────────────────────────────────────────
    # CRITICAL: We only use `timeout` to limit the *connection + handshake*
    # phase. Once Python is actually running an active session it must NOT be
    # killed by a shell timeout. We detect this via exit codes:
    #
    #   0   — clean session end (user /quit or 15-min limit hit)
    #   130 — Ctrl+C
    #   124 — timed out before connecting (connection phase only)
    #   1   — handshake rejected / host not ready
    #   other non-zero — crash after connecting
    #
    # Exit codes 0 and 130 mean "session ran OK" — we stop retrying.
    # Exit code 124 means "never got through" — we retry.
    # Other non-zero with connected=1 means mid-session crash — reconnect once.
    # ─────────────────────────────────────────────────────────────────────────

    local MAX_ATTEMPTS=3
    local CONNECT_TIMEOUT=90   # seconds allowed for Tor circuit + handshake
    local attempt=1
    local session_ran=0        # did we ever get past the handshake?

    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
        printf "\n"
        p "${YEL} Connecting... (attempt ${attempt}/${MAX_ATTEMPTS}, up to ${CONNECT_TIMEOUT}s)${RST}"
        p "${DIM} Tor circuits can take 15-30s to build. Please wait.${RST}"
        printf "\n"

        # timeout wraps only the initial connection attempt.
        # Python's own timeout=900 (15 min) controls the session duration.
        timeout "$CONNECT_TIMEOUT" \
            torsocks python3 -m securechat connect --port 57311
        local EXIT_CODE=$?

        # User quit cleanly or session ended normally
        if [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 130 ]; then
            session_ran=1
            break
        fi

        # Connection timed out before handshake completed
        if [ "$EXIT_CODE" -eq 124 ]; then
            p "${YEL}[!] Timed out after ${CONNECT_TIMEOUT}s — host may not be ready.${RST}"
        else
            # Any other non-zero: could be mid-session crash if we got through
            # once (session_ran=1). For now treat all as pre-connect failure.
            p "${YEL}[!] Connection failed (exit ${EXIT_CODE}).${RST}"
        fi

        if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
            p "${DIM} Retrying in 5 seconds...${RST}"
            sleep 5
        else
            printf "\n"
            p "${RED}[!] Could not connect after ${MAX_ATTEMPTS} attempts.${RST}"
            p "${DIM} Check:${RST}"
            p "${DIM}   • Host is running and showing 'Waiting for guest...'${RST}"
            p "${DIM}   • Onion address and session code are correct${RST}"
            p "${DIM}   • Tor is running: sudo systemctl status tor${RST}"
        fi

        attempt=$((attempt + 1))
    done

    # If we got into a session but crashed mid-chat, offer one reconnect
    if [ "$session_ran" -eq 0 ] && [ "${EXIT_CODE:-0}" -ne 0 ] \
        && [ "${EXIT_CODE:-0}" -ne 130 ] && [ "${EXIT_CODE:-0}" -ne 124 ]; then
        printf "\n"
        p "${YEL}[!] Session dropped. Reconnecting once...${RST}"
        sleep 3
        torsocks python3 -m securechat connect --port 57311 || true
    fi

    printf "\n Press Enter to return to menu..."
    read -r _
}

# ── --setup flag ──────────────────────────────────────────────────────────────
if [ "${1:-}" = "--setup" ]; then
    check_tor
    auto_setup_hidden_service
    exit 0
fi

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    show_banner
    sudo -v
    check_python
    check_tor
    check_torsocks

    while true; do
        show_menu
        printf " Choice [1-5]: "
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
