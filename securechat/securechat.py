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
import threading
import signal

# Silence shell history
os.environ["HISTFILE"]     = "/dev/null"
os.environ["HISTSIZE"]     = "0"
os.environ["HISTFILESIZE"] = "0"

from . import crypto, network, protocol
from .session import Session, GroupSession
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
#  HOST MODE  (group session — supports 1-to-N guests)
# ═══════════════════════════════════════════════════════════════════════════════

def run_host(port: int) -> None:
    tor_mode   = os.environ.get("SECURECHAT_TOR_MODE", "").strip() == "1"
    ext_code   = os.environ.get("SECURECHAT_SESSION_CODE", "").strip()
    onion_addr = os.environ.get("ONION", "").strip()

    code = ext_code if ext_code else crypto.generate_session_code()
    key  = crypto.derive_key(code)

    # Optional host nickname
    env_nick = os.environ.get("SECURECHAT_NICKNAME", "").strip()
    host_nick = (env_nick[:20] if env_nick else None) or "Host"

    clear()
    _p(GB + "  SecureChat — Host Session" + R)
    _p(DIM + "  ─────────────────────────────────────────────────" + R)
    _p()

    if tor_mode and onion_addr:
        _p(G  + "  Onion : " + CB + onion_addr + R)
        _p(G  + "  Code  : " + CB + code + R)
        _p()
        _p(DIM + "  (send both to your guests over a secure channel)" + R)
    else:
        _p(G  + "  Your IP : " + CB + get_local_ip() + R)
        _p(G  + "  Code    : " + CB + code + R)
        _p()
        _p(DIM + "  (share both with your guests)" + R)

    _p()
    _p(DIM + "  Port: " + str(port) + "  |  Waiting for connections…" + R)
    _p()

    # Bind the server socket — stays open for the entire session
    try:
        srv = network.host_start_listener(key=key, port=port)
    except OSError as e:
        _p(RE + f"  Error: {e}" + R)
        sys.exit(1)

    _p(GB + "  Listening — waiting for first guest…" + R)
    _p()

    # ── Wire up GroupSession + ChatUI ─────────────────────────────────────────
    ui = ChatUI(
        session=None,
        role="host",
        you_label=f"You ({host_nick})",
        peer_label="Guest",
        via_tor=tor_mode,
        is_group=True,
        host_nickname=host_nick,
    )

    def on_message(msg: Message, from_nick: str):
        ui.push_message(msg)

    def on_close(reason: str):
        ui.push_system("Session ended: " + reason)
        ui.signal_closed(reason)

    def on_join_request(nickname: str):
        ui.add_pending_request(nickname)

    group = GroupSession(
        key=key,
        host_nickname=host_nick,
        on_message=on_message,
        on_close=on_close,
        on_join_request=on_join_request,
    )
    ui._session = group

    # ── Accept-loop thread — runs alongside the UI ────────────────────────────
    _srv_closed = threading.Event()

    def _accept_loop():
        """Background thread: accept new TCP connections and add them as pending."""
        while not _srv_closed.is_set() and group.is_alive:
            conn, nickname = network.accept_one_guest(srv, key)
            if conn is None:
                continue   # timeout or bad handshake — keep accepting
            # Deduplicate nickname and queue the guest for host approval
            final_nick = group.add_pending(conn, nickname)
            # add_pending already fires on_join_request → ui.add_pending_request
            # Notify from here too in case the UI missed it (belt-and-suspenders)
            _ = final_nick  # used only for the callback

    accept_thread = threading.Thread(target=_accept_loop, daemon=True)
    accept_thread.start()

    # ── Store room info for /roominfo ─────────────────────────────────────────
    _room_onion = onion_addr
    _room_code  = code

    # ── Override _handle_enter for host group-mode commands ──────────────────
    def _handle_enter(self=ui):
        buf = "".join(self._input_buf).strip()
        self._input_buf.clear()
        self._cursor = 0

        if not buf:
            return None

        low = buf.lower()

        # ── Universal commands ────────────────────────────────────────────────
        if low in ("/quit", "/exit", "/q"):
            return "quit"

        if low == "/help":
            self.push_system(
                "Commands: /quit  /clear  /help  /roominfo  |  ↑↓ scroll  |  Ctrl-W clear input"
            )
            self.push_system(
                "Group (host): /admit <nick>  /deny <nick>  /kick <nick>  /who"
            )
            return None

        if low in ("/roominfo", "/info", "/room"):
            self.push_system("─── Room Info ─────────────────────────────")
            if _room_onion:
                self.push_system(f"Onion : {_room_onion}")
            else:
                self.push_system("Onion : (not available — direct connection)")
            self.push_system(f"Code  : {_room_code}")
            self.push_system(f"Host  : {host_nick}")
            self.push_system("───────────────────────────────────────────")
            return None

        if low == "/clear":
            with self._msg_lock:
                self._messages.clear()
            self._scroll = 0
            self._dirty.set()
            return None

        if low.startswith("/admit"):
            parts = buf.split(None, 1)
            if len(parts) < 2:
                self.push_system("Usage: /admit <nickname>")
                return None
            nick = parts[1].strip()
            ok = group.admit_pending(nick)
            if ok:
                self.remove_pending(nick)
                self.push_system(f"✔  Admitted '{nick}' to the room.")
            else:
                self.push_system(f"No pending request from '{nick}'.")
            return None

        if low.startswith("/deny"):
            parts = buf.split(None, 1)
            if len(parts) < 2:
                self.push_system("Usage: /deny <nickname>  [reason]")
                return None
            rest   = parts[1].strip()
            tokens = rest.split(None, 1)
            nick   = tokens[0]
            reason = tokens[1] if len(tokens) > 1 else "Request denied by host"
            ok = group.deny_pending(nick, reason)
            if ok:
                self.remove_pending(nick)
                self.push_system(f"✘  Denied '{nick}'.")
            else:
                self.push_system(f"No pending request from '{nick}'.")
            return None

        if low.startswith("/kick"):
            parts = buf.split(None, 1)
            if len(parts) < 2:
                self.push_system("Usage: /kick <nickname>")
                return None
            nick = parts[1].strip()
            # Mark dead BEFORE closing socket so _guest_reader exits without
            # a second "left the room" broadcast.
            with group._guests_lock:
                handle = group._guests.get(nick)
            if handle:
                handle.alive = False
                try:
                    handle.close("Kicked by host")
                except Exception:
                    pass
                with group._guests_lock:
                    group._guests.pop(nick, None)
                kick_text = f"⟵  {nick} was removed by the host."
                self.push_system(f"⟵  Kicked '{nick}' from the room.")
                group._broadcast_system(kick_text)
                try:
                    group._on_message(Message(MsgType.SYS, kick_text), "system")
                except Exception:
                    pass
            else:
                self.push_system(f"No connected user named '{nick}'.")
            return None

        if low == "/who":
            nicks   = group.admitted_nicknames()
            pending = group.pending_nicknames()
            self.push_system(
                f"Room: {host_nick} (host)"
                + (", " + ", ".join(nicks) if nicks else "  (no guests yet)")
            )
            if pending:
                self.push_system(f"Waiting: {', '.join(pending)}")
            return None

        # ── Regular chat message ──────────────────────────────────────────────
        if group.is_alive:
            try:
                # GroupSession.send_text echoes via on_message → ui.push_message
                group.send_text(buf)
            except Exception as e:
                self.push_system(f"Send error: {e}")
        else:
            self.push_system("Session is closed — cannot send messages.")
        return None

    ui._handle_enter = _handle_enter

    # ── Start everything ──────────────────────────────────────────────────────
    group.start()
    tor_note = "  [via Tor]" if tor_mode else ""
    ui.push_system(
        f"Group room open{tor_note} — AES-256-GCM"
        " — /admit <nick> to let guests in — /help for commands"
    )

    time.sleep(0.4)

    try:
        ui.run()
    finally:
        _srv_closed.set()
        try:
            srv.close()
        except Exception:
            pass
        group.close("Host closed the session")
        group.join()
        _wipe_and_exit()


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

    env_nick = os.environ.get("SECURECHAT_NICKNAME", "").strip()
    if env_nick:
        nickname = env_nick[:20]
        _p(G + "  Nickname : " + CB + nickname + R)
    else:
        raw_nick = input(G + "  Your nickname (max 20 chars): " + R).strip()[:20]
        nickname  = raw_nick if raw_nick else "Guest"

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
            key=crypto.derive_key(code),
            nickname=nickname,
            port=port,
            on_status=on_status,
            timeout=900,
            via_tor=via_tor,
        )
    except ValueError as e:
        _p("\n" + RE + "  Connection failed: " + str(e) + R)
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
        you_label=f"You ({nickname})",
        peer_label="Host",
        via_tor=via_tor,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  GUEST CHAT: start Session + ChatUI + FileTransferChannel
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
        is_group=False,
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

    # ── Patch send_text to echo outgoing messages in the UI ──────────────────
    _orig_send = session.send_text

    def _patched_send(text: str):
        _orig_send(text)
        ui.push_message(make_outgoing_msg(text))

    session.send_text = _patched_send

    # ── Override _handle_enter for guest ─────────────────────────────────────
    # Replaces the default ui.py handler so we can inject /roominfo and avoid
    # the double-echo that the default handler would produce.
    _room_onion = os.environ.get("ONION", "").strip()
    _room_code  = os.environ.get("SECURECHAT_SESSION_CODE", "").strip() \
                  or os.environ.get("SECURECHAT_PEER_CODE", "").strip()

    def _handle_enter(self=ui):
        buf = "".join(self._input_buf).strip()
        self._input_buf.clear()
        self._cursor = 0

        if not buf:
            return None

        low = buf.lower()

        if low in ("/quit", "/exit", "/q"):
            return "quit"

        if low == "/help":
            self.push_system(
                "Commands: /quit  /clear  /help  /roominfo  |  ↑↓ scroll  |  Ctrl-W clear input"
            )
            self.push_system(
                "File transfer: /sendfile <path>   /accept   /reject"
            )
            self.push_system(
                "Received files → ~/securechat_received/"
            )
            return None

        if low in ("/roominfo", "/info", "/room"):
            self.push_system("─── Room Info ─────────────────────────────")
            if _room_onion:
                self.push_system(f"Onion : {_room_onion}")
            else:
                self.push_system("Onion : (not available — direct connection)")
            if _room_code:
                self.push_system(f"Code  : {_room_code}")
            else:
                self.push_system("Code  : (not available)")
            self.push_system(f"Role  : {you_label}")
            self.push_system("───────────────────────────────────────────")
            return None

        if low == "/clear":
            with self._msg_lock:
                self._messages.clear()
            self._scroll = 0
            self._dirty.set()
            return None

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

        # Regular chat — _patched_send writes to wire AND echoes locally.
        if session.is_alive:
            try:
                session.send_text(buf)
            except Exception as e:
                self.push_system(f"Send error: {e}")
        else:
            self.push_system("Session is closed — cannot send messages.")
        return None

    ui._handle_enter = _handle_enter

    # ── Start session and UI ──────────────────────────────────────────────────
    session.start()
    tor_note = "  [via Tor]" if via_tor else ""
    ui.push_system(
        "Secure channel open" + tor_note
        + " — AES-256-GCM — /help for commands"
    )
    ui.push_system(
        "Send files: /sendfile <path>  |  /roominfo to see room details"
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
    _p(G + "  [1]" + R + "  Host a session   (generate code, wait for guests)")
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

    if args.mode == "host":
        run_host(args.port)
    elif args.mode == "connect":
        run_connect(args.port)
    else:
        interactive_menu(args.port)


if __name__ == "__main__":
    main()
