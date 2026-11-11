"""
securechat/network.py
─────────────────────
TCP socket management for host (listener) and peer (connector).

  Host   : binds to 0.0.0.0:PORT, accepts multiple connections up to MAX_USERS,
           performs the encrypted handshake for each, then holds them in a
           pending queue waiting for host approval.

  Peer   : connects to HOST:PORT, performs the encrypted handshake,
           sends JOIN request with nickname, then waits for ADMIT or DENY.

Both sides derive the AES-256 key from the session code before
the handshake, so the very first byte exchanged is already encrypted.
No plaintext ever travels the wire.
"""

import os
import socket
import time
import sys

from . import protocol
from .protocol import Message, MsgType, send_msg, recv_msg


DEFAULT_PORT  = 57311     # Unlikely to be in use; well above 1024
CONNECT_RETRY = 3         # seconds between connection retries
MAX_USERS     = 10        # hard ceiling on simultaneous participants


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Best-effort: get the LAN IP of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── Host ─────────────────────────────────────────────────────────────────────

def host_listen(
    key: bytes,
    port: int = DEFAULT_PORT,
    on_waiting: callable = None,
    timeout: int = 900,
) -> socket.socket:
    """
    Bind and listen for one authenticated connection (2-user mode).

    After the encrypted handshake succeeds, we read the guest's JOIN message
    and send back ADMIT so that peer_connect() can complete cleanly.

    Bad connections (wrong key, scanner traffic, failed handshake) are logged
    and discarded — the host keeps waiting for the next attempt.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        raise OSError(
            f"Cannot bind to port {port}: {e}\n"
            f"Try a different port with --port, or free the port."
        ) from e

    srv.listen(5)
    srv.settimeout(1.0)

    start   = time.monotonic()

    try:
        while True:
            elapsed = int(time.monotonic() - start)
            if timeout > 0 and elapsed >= timeout:
                raise TimeoutError("No peer connected within the timeout window")

            if on_waiting:
                on_waiting(elapsed)

            try:
                conn, _addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                continue

            # Give each inbound connection a short window to complete auth.
            # Failures are logged and skipped — the host keeps waiting.
            conn.settimeout(60)
            try:
                ok = protocol.perform_handshake_host(conn, key)
                if not ok:
                    conn.close()
                    continue

                # Read the JOIN message that peer_connect() sends after handshake
                msg = recv_msg(conn, key)
                if msg.mtype != MsgType.JOIN or not msg.body:
                    conn.close()
                    continue

                # Acknowledge — sends ADMIT so peer_connect() unblocks
                send_msg(conn, Message(MsgType.ADMIT, "connected"), key)

            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                continue

            srv.close()
            conn.settimeout(None)
            return conn

    finally:
        try:
            srv.close()
        except Exception:
            pass


def host_start_listener(
    key: bytes,
    port: int = DEFAULT_PORT,
) -> socket.socket:
    """
    Create and bind the server socket for multi-user mode.
    Returns the listening server socket (not yet accepting).
    Caller owns the lifecycle; call .close() when done.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        raise OSError(
            f"Cannot bind to port {port}: {e}\n"
            f"Try a different port with --port, or free the port."
        ) from e
    srv.listen(MAX_USERS)
    srv.settimeout(1.0)
    return srv


def accept_one_guest(
    srv: socket.socket,
    key: bytes,
) -> tuple:
    """
    Accept a single new TCP connection, perform handshake, read JOIN message.
    Returns (conn, nickname) on success, or (None, None) on failure/timeout.
    Does NOT block the caller for more than ~2 s (handshake timeout is generous
    but the srv socket already has a 1 s accept timeout).

    The JOIN flow:
      guest → HELLO  (handshake)
      host  → CONFIRM
      guest → MSG{JOIN, nickname}
      [host will later send ADMIT or DENY via the connection]
    """
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        return None, None
    except Exception:
        return None, None

    conn.settimeout(30)
    try:
        ok = protocol.perform_handshake_host(conn, key)
        if not ok:
            conn.close()
            return None, None

        # Read the JOIN message to get the requested nickname
        msg = recv_msg(conn, key)
        if msg.mtype != MsgType.JOIN or not msg.body:
            conn.close()
            return None, None

        nickname = msg.body.strip()[:20]  # cap at 20 chars
        if not nickname:
            conn.close()
            return None, None

        conn.settimeout(None)
        return conn, nickname

    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return None, None


def admit_guest(conn: socket.socket, key: bytes, room_info: str) -> None:
    """Send ADMIT to a pending guest socket."""
    send_msg(conn, Message(MsgType.ADMIT, room_info), key)


def deny_guest(conn: socket.socket, key: bytes, reason: str = "Request denied by host") -> None:
    """Send DENY to a pending guest socket and close it."""
    try:
        send_msg(conn, Message(MsgType.DENY, reason), key)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── Peer ─────────────────────────────────────────────────────────────────────

def peer_connect(
    host_ip: str,
    key: bytes,
    nickname: str,
    port: int = DEFAULT_PORT,
    on_status: callable = None,
    timeout: int = 900,
    via_tor: bool = False,
) -> socket.socket:
    """
    Connect to the host, perform the encrypted handshake, send JOIN request,
    and wait for ADMIT or DENY.

    Returns the authenticated socket on ADMIT, or raises:
      - ValueError  if handshake fails or host sends DENY
      - TimeoutError if the overall timeout is exceeded

    Parameters
    ----------
    host_ip   : IP address or .onion hostname of the host
    key       : 32-byte AES-256 session key (from crypto.derive_key)
    nickname  : the display name this peer wants to use
    port      : TCP port of the host
    on_status : optional callback(message: str) for status updates
    timeout   : seconds before giving up
    via_tor   : True when connecting via torsocks
    """
    _slow = os.environ.get("SECURECHAT_SLOW_NETWORK", "").strip() == "1"
    handshake_timeout = 120 if (_slow or via_tor) else 30
    connect_timeout   = 60  if (_slow or via_tor) else 20

    # Admission can take a long time if the host is slow to respond —
    # give it up to 10 minutes while we poll for ADMIT/DENY.
    admit_timeout = 600

    start = time.monotonic()

    def _status(msg):
        if on_status:
            on_status(msg)

    while True:
        elapsed = time.monotonic() - start
        if timeout > 0 and elapsed >= timeout:
            raise TimeoutError("Could not connect within the timeout window")

        if via_tor:
            _status(f"[TOR] Routing to {host_ip}:{port} via Tor circuit...")
        else:
            _status(f"Connecting to {host_ip}:{port}...")

        try:
            conn = socket.create_connection((host_ip, port), timeout=connect_timeout)
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            _status(f"Not reachable yet ({e}) — retrying in {CONNECT_RETRY}s...")
            time.sleep(CONNECT_RETRY)
            continue

        if via_tor:
            _status("Tor circuit established — authenticating session code...")
        else:
            _status("TCP connected — authenticating session code...")

        conn.settimeout(handshake_timeout)
        ok = protocol.perform_handshake_peer(conn, key)
        if not ok:
            conn.close()
            raise ValueError(
                "Handshake failed — wrong session code, or host rejected the connection."
            )

        # Send JOIN request with chosen nickname
        _status(f"Sending join request as '{nickname}'...")
        try:
            send_msg(conn, Message(MsgType.JOIN, nickname), key)
        except Exception as e:
            conn.close()
            raise ValueError(f"Failed to send join request: {e}") from e

        # Wait for ADMIT or DENY — this blocks until host decides
        _status("Waiting for host to accept your request...")
        conn.settimeout(admit_timeout)
        try:
            reply = recv_msg(conn, key)
        except socket.timeout:
            conn.close()
            raise TimeoutError("Host did not respond to join request in time.")
        except Exception as e:
            conn.close()
            raise ValueError(f"Connection lost while waiting for admission: {e}") from e

        if reply.mtype == MsgType.ADMIT:
            conn.settimeout(None)
            _status("Admitted to room!")
            return conn

        elif reply.mtype == MsgType.DENY:
            conn.close()
            reason = reply.body or "No reason given"
            raise ValueError(f"Join request denied: {reason}")

        else:
            conn.close()
            raise ValueError(f"Unexpected message from host during join: {reply.mtype}")
