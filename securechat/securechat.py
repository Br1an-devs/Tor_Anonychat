#!/usr/bin/env python3
"""
securechat/securechat.py  —  Main launcher
════════════════════════════════════════════
Entry point: bash run_tor.sh

Direct usage:
  python3 -m securechat host     [--port N] [--nick NAME]
  python3 -m securechat connect  [--port N] [--nick NAME]
  python3 -m securechat          (interactive menu)

Multi-user group chat
─────────────────────
• Host starts the room.  Guests are HELD in a waiting lobby until the
  host types /admit <nick> in the chat UI.  The host can also /deny
  or /kick at any time.
• Guests see a "Waiting for host to accept…" spinner until admitted or
  denied.  Once admitted they join a live group chat where every
  message is broadcast to everyone.
• Up to 10 simultaneous participants (1 host + 9 guests).  Adjustable
  via MAX_USERS in network.py.
"""

import sys
import os
import argparse
import time
import threading
import signal

os.environ["HISTFILE"]     = "/dev/null"
os.environ["HISTSIZE"]     = "0"
os.environ["HISTFILESIZE"] = "0"

from . import crypto, network, protocol
from .session import Session, GroupSession
from .protocol import Message, MsgType
from .ui import ChatUI
from .network import DEFAULT_PORT, get_local_ip
from .filetransfer import FileTransferChannel

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
    try:
        import curses as _curses
        _curses.endwin()
    except Exception:
        pass
    os.system("cls" if os.name == "nt" else "clear")


# ═══════════════════════════════════════════════════════════════════════════════
#  HOST MODE  — multi-user group room
# ═══════════════════════════════════════════════════════════════════════════════

def run_host(port: int, host_nick: str) -> None:
    tor_mode   = os.environ.get("SECURECHAT_TOR_MODE", "").strip() == "1"
    ext_code   = os.environ.get("SECURECHAT_SESSION_CODE", "").strip()
    onion_addr = os.environ.get("ONION", "").strip()

    code = ext_code if ext_code else crypto.generate_session_code()
    key  = crypto.derive_key(code)

    clear()
    _p(GB + "  SecureChat — Group Room (Host)" + R)
    _p(DIM + "  ─────────────────────────────────────────────────" + R)
    _p()

    if tor_mode and onion_addr:
        _p(G  + "  Onion : " + CB + onion_addr + R)
        _p(G  + "  Code  : " + CB + code + R)
        _p()
        _p(DIM + "  (send both to guests over a secure channel)" + R)
    else:
        _p(G  + "  Your IP : " + CB + get_local_ip() + R)
        _p(G  + "  Code    : " + CB + code + R)
        _p()
        _p(DIM + "  (share both with your guests)" + R)

    _p()
    _p(DIM + f"  Host nickname : {CB}{host_nick}{R}")
    _p(DIM + "  Port: " + str(port) + "  |  Press Ctrl+C to stop" + R)
    _p()
    _p(Y + "  Waiting for guests to connect…" + R)
    _p(DIM + "  Guests will be held in a lobby until you /admit them." + R)
    _p()

    # Open the TCP listener
    try:
        srv = network.host_start_listener(key, port)
    except OSError as e:
        _p(RE + f"  Error: {e}" + R)
        sys.exit(1)

    _p(GB + "  Listening — press Enter to open chat panel now" + R)
    _p()
    time.sleep(1.0)

    # ── Set up the GroupSession and UI ──────────────────────────────────────

    ui = ChatUI(
        session=None,    # filled below
        role="host",
        you_label=f"{host_nick} (host)",
        peer_label="Guest",
        via_tor=tor_mode,
        is_group=True,
        host_nickname=host_nick,
    )

    def on_group_message(msg: Message, from_nick: str):
        ui.push_message(msg)

    def on_group_close(reason: str):
        ui.push_system("Room closed: " + reason)
        ui.signal_closed(reason)

    def on_join_request(nickname: str):
        ui.add_pending_request(nickname)

    group = GroupSession(
        key=key,
        host_nickname=host_nick,
        on_message=on_group_message,
        on_close=on_group_close,
        on_join_request=on_join_request,
    )
    ui._session = group

    # ── Background thread: accept new TCP connections continuously ──────────

    def _acceptor():
        """Accept guests in the background until the group session closes."""
        while group.is_alive:
            conn, nickname = network.accept_one_guest(srv, key)
            if conn is None:
                continue   # timeout — keep looping
            # Register as pending; host must /admit
            final_nick = group.add_pending(conn, nickname)
            # (UI notification is done inside add_pending via on_join_request)

    acceptor_thread = threading.Thread(target=_acceptor, daemon=True)
    acceptor_thread.start()

    # ── Start the session and UI ────────────────────────────────────────────

    group.start()

    group_info = (
        f"Group room open — AES-256-GCM"
        + (" [via Tor]" if tor_mode else "")
        + " — /help for commands — Ctrl+C to quit"
    )
    ui.push_system(group_info)
    ui.push_system(
        "Guests will appear in the 🔔 bar — type /admit <nick> to let them in"
    )

    try:
        ui.run()
    finally:
        try:
            srv.close()
        except Exception:
            pass
        group.close("Host ended the session")
        group.join()
        _wipe_and_exit()


# ═══════════════════════════════════════════════════════════════════════════════
#  CONNECT (GUEST) MODE
# ═══════════════════════════════════════════════════════════════════════════════

def run_connect(port: int, guest_nick: str) -> None:
    clear()
    _p(GB + "  SecureChat — Connect to Group Room" + R)
    _p(DIM + "  ─────────────────────────────────────────────────" + R)
    _p()

    env_host = os.environ.get("SECURECHAT_PEER_HOST", "").strip()
    env_code = os.environ.get("SECURECHAT_PEER_CODE", "").strip()
    env_nick = os.environ.get("SECURECHAT_NICKNAME", "").strip()

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

    # Determine nickname
    if env_nick:
        nickname = env_nick
    elif guest_nick:
        nickname = guest_nick
    else:
        nickname = input(G + "  Your nickname (leave blank for 'Guest'): " + R).strip()
        if not nickname:
            nickname = "Guest"

    nickname = nickname[:20]   # server also caps at 20; be consistent

    _p()
    _p(Y + "  Connecting to " + host_addr + " — Press Ctrl+C to cancel" + R)
    _p()

    def on_status(msg: str):
        _p(DIM + "  " + msg + R)

    key = crypto.derive_key(code)

    try:
        conn = network.peer_connect(
            host_ip=host_addr,
            key=key,
            nickname=nickname,
            port=port,
            on_status=on_status,
            timeout=0,      # infinite — Ctrl+C to stop
            via_tor=via_tor,
        )
    except ValueError as e:
        _p("\n" + RE + "  " + str(e) + R)
        sys.exit(1)
    except TimeoutError:
        _p("\n" + RE + "  Connection window expired." + R)
        sys.exit(1)
    except Exception as e:
        _p("\n" + RE + "  Error: " + str(e) + R)
        sys.exit(1)

    _p()
    _p(GB + "  Admitted to room!" + R)
    _p()
    time.sleep(0.6)

    _run_guest_chat(
        conn=conn,
        key=key,
        nickname=nickname,
        via_tor=via_tor,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED: start Session + ChatUI for guests
# ═══════════════════════════════════════════════════════════════════════════════

def _run_guest_chat(
    conn,
    key: bytes,
    nickname: str,
    via_tor: bool = False,
) -> None:

    ui = ChatUI(
        session=None,
        role="guest",
        you_label=nickname,
        peer_label="Room",
        via_tor=via_tor,
        is_group=True,      # guest also shows group-mode UI
        host_nickname=None,
    )

    def on_message(msg: Message):
        ui.push_message(msg)

    def on_close(reason: str):
        ui.push_system("Connection closed: " + reason)
        ui.signal_closed(reason)

    session = Session(
        sock=conn,
        key=key,
        role="guest",
        on_message=on_message,
        on_close=on_close,
    )

    # Override send_text to stamp the sender field so the host can relay it
    _orig_send = session.send_text
    def _send_with_nick(text: str, sender: str = None):
        from .protocol import Message as _Msg, MsgType as _MT
        import queue as _q
        if not session._alive.is_set():
            from .session import SessionClosedError
            raise SessionClosedError("Session is closed")
        msg = _Msg(mtype=_MT.MSG, body=text, sender=nickname)
        session._outbound.put(msg)
    session.send_text = _send_with_nick

    ui._session = session

    # File transfer not supported in group mode (would need addressing layer)
    # — omitted intentionally; the socket is shared/hub-based.

    session.start()
    tor_note = "  [via Tor]" if via_tor else ""
    ui.push_system(
        f"Joined as '{nickname}'" + tor_note
        + " — AES-256-GCM — /help for commands — Ctrl+C to quit"
    )

    try:
        ui.run()
    finally:
        session.close("Guest quit")
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
#  INTERACTIVE MENU
# ═══════════════════════════════════════════════════════════════════════════════

def interactive_menu(port: int) -> None:
    clear()
    _p()
    _p(CB + "  SecureChat  —  Ephemeral Encrypted Group Chat" + R)
    _p(DIM + "  AES-256-GCM  |  One-time code  |  Zero logs  |  Multi-user" + R)
    _p()
    _p(G + "  [1]" + R + "  Host a room   (generate code, approve guests)")
    _p(G + "  [2]" + R + "  Join a room   (enter host address + code + nickname)")
    _p(G + "  [3]" + R + "  Exit")
    _p()
    choice = input("  Choice [1/2/3]: ").strip()
    if choice == "1":
        nick = input(G + "  Your host nickname (leave blank for 'Host'): " + R).strip()
        if not nick:
            nick = "Host"
        run_host(port, nick)
    elif choice == "2":
        run_connect(port, "")
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
        help="host = start room | connect = join room",
    )
    parser.add_argument(
        "--port", "-p", type=int, default=DEFAULT_PORT,
        help=f"TCP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--nick", "-n", type=str, default="",
        help="Your display nickname (default: 'Host' or 'Guest')",
    )
    args = parser.parse_args()

    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        pass

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
        pass

    def _sigint_handler(signum, frame):
        try:
            import curses as _curses
            _curses.endwin()
        except Exception:
            pass
        sys.exit(130)

    try:
        signal.signal(signal.SIGINT, _sigint_handler)
    except (AttributeError, OSError):
        pass

    if args.mode == "host":
        nick = args.nick or "Host"
        run_host(args.port, nick)
    elif args.mode == "connect":
        run_connect(args.port, args.nick)
    else:
        interactive_menu(args.port)


if __name__ == "__main__":
    main()
