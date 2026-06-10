#!/usr/bin/env python3
"""
securechat/securechat.py  —  Main launcher
════════════════════════════════════════════
Entry point: bash run_tor.sh

Direct usage:
  python3 -m securechat host     [--port N]
  python3 -m securechat connect  [--port N]
  python3 -m securechat          (interactive menu)
"""

import sys
import os
import argparse
import time
import signal

# Silence shell history
os.environ["HISTFILE"]     = "/dev/null"
os.environ["HISTSIZE"]     = "0"
os.environ["HISTFILESIZE"] = "0"

from . import crypto, network, protocol
from .session import Session
from .protocol import Message, MsgType
from .ui import ChatUI, make_outgoing_msg
from .network import DEFAULT_PORT, get_local_ip
from .filetransfer import FileTransferChannel

# ANSI helpers (pre-curses phase only)
G   = "\033[0;32m"
GB  = "\033[1;32m"
Y   = "\033[1;33m"
C   = "\033[0;36m"
CB  = "\033[1;36m"
DIM = "\033[2m"
RE  = "\033[0;31m"
R   = "\033[0m"


def _p(text=""):
    print(text, flush=True)


def is_onion(addr: str) -> bool:
    return addr.strip().lower().endswith(".onion")


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ═══════════════════════════════════════════════════════════════════════════════
#  HOST MODE
# ═══════════════════════════════════════════════════════════════════════════════

def run_host(port: int) -> None:
    tor_mode   = os.environ.get("SECURECHAT_TOR_MODE", "").strip() == "1"
    ext_code   = os.environ.get("SECURECHAT_SESSION_CODE", "").strip()
    onion_addr = os.environ.get("ONION", "").strip()

    code = ext_code if ext_code else crypto.generate_session_code()

    clear()
    _p(GB + "  SecureChat — Waiting for guest" + R)
    _p(DIM + "  ─────────────────────────────────────────────────" + R)
    _p()

    if tor_mode and onion_addr:
        _p(G  + "  Onion : " + CB + onion_addr + R)
        _p(G  + "  Code  : " + CB + code + R)
        _p()
        _p(DIM + "  (send both to your guest over a secure channel)" + R)
    else:
        _p(G  + "  Your IP : " + CB + get_local_ip() + R)
        _p(G  + "  Code    : " + CB + code + R)
        _p()
        _p(DIM + "  (share both with your guest)" + R)

    _p()
    _p(DIM + "  Port: " + str(port) + "  |  Auto-timeout: 15 minutes" + R)
    _p()

    def on_waiting(elapsed: int):
        remaining = max(0, 900 - elapsed)
        m, s = divmod(remaining, 60)
        print(
            f"\r  {Y}Waiting for guest...{R}  "
            f"{DIM}Time remaining: {m:02d}:{s:02d}{R}   ",
            end="", flush=True,
        )

    try:
        conn = network.host_listen(
            code=code,
            port=port,
            on_waiting=on_waiting,
            timeout=900,
        )
    except TimeoutError:
        _p("\n")
        _p(RE + "  No guest connected within 15 minutes. Exiting." + R)
        sys.exit(1)
    except OSError as e:
        _p("\n")
        _p(RE + f"  Error: {e}" + R)
        sys.exit(1)

    _p("\n")
    _p(GB + "  Guest connected and authenticated!" + R)
    _p()
    time.sleep(0.6)

    _run_chat(
        conn=conn,
        key=crypto.derive_key(code),
        role="host",
        you_label="You (Host)",
        peer_label="Guest",
        via_tor=tor_mode,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  CONNECT (GUEST) MODE
# ═══════════════════════════════════════════════════════════════════════════════

def run_connect(port: int) -> None:
    clear()
    _p(GB + "  SecureChat — Connect to Host" + R)
    _p(DIM + "  ─────────────────────────────────────────────────" + R)
    _p()

    env_host = os.environ.get("SECURECHAT_PEER_HOST", "").strip()
    env_code = os.environ.get("SECURECHAT_PEER_CODE", "").strip()

    if env_host:
        host_addr = env_host
        _p(G + "  Host address : " + CB + host_addr + R)
    else:
        host_addr = input(G + "  Host address (IP or .onion) : " + R).strip()

    via_tor = is_onion(host_addr)

    if env_code:
        code = env_code.upper().replace(" ", "")
        _p(G + "  Session code : " + CB + code + R)
    else:
        raw  = input(G + "  Session code (XXXX-XXXX-XXXX): " + R).strip()
        code = raw.upper().replace(" ", "")

    if not code:
        _p(RE + "  No session code entered. Exiting." + R)
        sys.exit(1)

    _p()
    if via_tor:
        _p(Y + "  Routing through Tor — may take 15-30 seconds..." + R)
    else:
        _p(Y + "  Connecting to " + host_addr + "..." + R)
    _p()

    def on_status(msg: str):
        _p(DIM + "  " + msg + R)

    try:
        conn = network.peer_connect(
            host_ip=host_addr,
            code=code,
            port=port,
            on_status=on_status,
            timeout=900,
            via_tor=via_tor,
        )
    except ValueError as e:
        _p("\n" + RE + "  Handshake failed: " + str(e) + R)
        sys.exit(1)
    except TimeoutError:
        _p("\n" + RE + "  Timed out after 15 minutes." + R)
        sys.exit(1)
    except Exception as e:
        _p("\n" + RE + "  Error: " + str(e) + R)
        sys.exit(1)

    _p()
    _p(GB + "  Connected and authenticated!" + R)
    _p()
    time.sleep(0.6)

    _run_chat(
        conn=conn,
        key=crypto.derive_key(code),
        role="guest",
        you_label="You (Guest)",
        peer_label="Host",
        via_tor=via_tor,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED: start Session + ChatUI + FileTransferChannel
# ═══════════════════════════════════════════════════════════════════════════════

def _run_chat(
    conn,
    key: bytes,
    role: str,
    you_label: str,
    peer_label: str,
    via_tor: bool = False,
) -> None:

    ui = ChatUI(
        session=None,
        role=role,
        you_label=you_label,
        peer_label=peer_label,
        via_tor=via_tor,
    )

    def on_message(msg: Message):
        ui.push_message(msg)

    def on_close(reason: str):
        ui.push_system("Connection closed: " + reason)
        ui.signal_closed(reason)

    session = Session(
        sock=conn,
        key=key,
        role=role,
        on_message=on_message,
        on_close=on_close,
    )
    ui._session = session

    # ── File transfer channel ─────────────────────────────────────────────────
    ft = FileTransferChannel(
        session=session,
        key=key,
        push_system=ui.push_system,
    )
    ft.install()

    # ── Patch send_text to echo locally ──────────────────────────────────────
    # ui.py's _handle_enter already calls session.send_text() directly.
    # We patch it here so outgoing messages are echoed in the UI as "You:".
    # NOTE: ui.py's _handle_enter must NOT echo locally itself — it relies on
    # this patch exclusively. Check ui.py: _handle_enter calls send_text then
    # pushes make_outgoing_msg. We override _handle_enter below to prevent that
    # double-echo.
    _orig_send = session.send_text

    def _patched_send(text: str):
        _orig_send(text)
        ui.push_message(make_outgoing_msg(text))

    session.send_text = _patched_send

    # ── Override _handle_enter to add file commands and fix double-echo ───────
    # ui.py's original _handle_enter echoes the message itself AND calls
    # session.send_text (which via _patched_send echoes again). We replace it
    # entirely so the flow is:
    #   type message → _patched_send → wire + echo once. Done.
    def _handle_enter(self=ui):
        buf = "".join(self._input_buf).strip()
        self._input_buf.clear()
        self._cursor = 0

        if not buf:
            return None

        low = buf.lower()

        # ── Built-in commands ─────────────────────────────────────────────────
        if low in ("/quit", "/exit", "/q"):
            return "quit"

        if low == "/help":
            self.push_system(
                "Commands: /quit  /clear  /help  |  ↑↓ scroll  |  Ctrl-W clear input"
            )
            self.push_system(
                "File transfer: /sendfile <path>   /accept   /reject"
            )
            self.push_system(
                "Received files → ~/securechat_received/"
            )
            return None

        if low == "/clear":
            with self._msg_lock:
                self._messages.clear()
            self._scroll = 0
            self._dirty.set()
            return None

        # ── File transfer commands ────────────────────────────────────────────
        if low.startswith("/sendfile"):
            parts = buf.split(None, 1)
            if len(parts) < 2 or not parts[1].strip():
                self.push_system(
                    "Usage: /sendfile <path>  e.g. /sendfile ~/docs/report.pdf"
                )
                return None
            if not session.is_alive:
                self.push_system("Session is closed — cannot send files.")
                return None
            ft.send_file(parts[1].strip())
            return None

        if low in ("/accept", "/accept file"):
            if not ft.has_pending_offer():
                self.push_system("No pending file offer to accept.")
                return None
            ft.accept_offer()
            return None

        if low.startswith("/reject"):
            if not ft.has_pending_offer():
                self.push_system("No pending file offer to reject.")
                return None
            parts  = buf.split(None, 1)
            reason = parts[1].strip() if len(parts) > 1 else "declined"
            ft.reject_offer(reason)
            return None

        # ── Regular chat message ──────────────────────────────────────────────
        # _patched_send writes to the wire AND echoes locally — no extra push here.
        if session.is_alive:
            try:
                session.send_text(buf)
            except Exception as e:
                self.push_system("Send error: " + str(e))
        else:
            self.push_system("Session is closed — cannot send messages.")

        return None

    ui._handle_enter = _handle_enter

    # ── Start everything ──────────────────────────────────────────────────────
    session.start()
    tor_note = "  [via Tor]" if via_tor else ""
    ui.push_system(
        "Secure channel open" + tor_note
        + " — AES-256-GCM — 15 min limit — /help for commands"
    )
    ui.push_system(
        "Send files: /sendfile <path>  |  saved to ~/securechat_received/"
    )

    try:
        ui.run()
    finally:
        session.close("UI closed")
        session.join()
        _wipe_and_exit()


# ═══════════════════════════════════════════════════════════════════════════════
#  CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

def _wipe_and_exit() -> None:
    clear()
    _p(GB + "\n  SecureChat session ended." + R)
    _p(DIM + "  No logs. No history. No trace.\n" + R)
    time.sleep(1.2)
    clear()


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU  (direct invocation without run_tor.sh)
# ═══════════════════════════════════════════════════════════════════════════════

def interactive_menu(port: int) -> None:
    clear()
    _p()
    _p(CB + "  SecureChat  —  Ephemeral Encrypted Terminal Chat" + R)
    _p(DIM + "  AES-256-GCM  |  One-time code  |  Zero logs" + R)
    _p()
    _p(G + "  [1]" + R + "  Host a session   (generate code, wait for guest)")
    _p(G + "  [2]" + R + "  Join a session   (enter host address + code)")
    _p(G + "  [3]" + R + "  Exit")
    _p()
    choice = input("  Choice [1/2/3]: ").strip()
    if choice == "1":
        run_host(port)
    elif choice == "2":
        run_connect(port)
    else:
        clear()
        sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if sys.version_info < (3, 8):
        print("SecureChat requires Python 3.8+")
        sys.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except ImportError:
        print("Missing dependency: pip install cryptography")
        sys.exit(1)

    parser = argparse.ArgumentParser(prog="securechat")
    parser.add_argument(
        "mode", nargs="?", choices=["host", "connect"],
        help="host = start session | connect = join session",
    )
    parser.add_argument(
        "--port", "-p", type=int, default=DEFAULT_PORT,
        help=f"TCP port (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args()

    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        pass  # Windows

    # Ensure curses always restores the terminal even when killed externally
    # (e.g. by a shell `timeout` command or a process manager sending SIGTERM).
    # Without this, SIGTERM bypasses curses.wrapper's finally block and leaves
    # the terminal in raw mode, making every subsequent shell output invisible.
    def _sigterm_handler(signum, frame):
        try:
            import curses as _curses
            _curses.endwin()
        except Exception:
            pass
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, _sigterm_handler)
    except (AttributeError, OSError):
        pass  # Windows / restricted environments

    if args.mode == "host":
        run_host(args.port)
    elif args.mode == "connect":
        run_connect(args.port)
    else:
        interactive_menu(args.port)


if __name__ == "__main__":
    main()
