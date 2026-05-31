"""
securechat/session.py
─────────────────────
Manages a live bidirectional encrypted session.

Architecture
  ┌─────────────┐    reader thread    ┌──────────────┐
  │  Session    │ ◄──────────────────  │  remote peer │
  │  .run()     │                      │              │
  │             │ ──────────────────►  │              │
  └─────────────┘    writer thread    └──────────────┘

The session exposes two queues:
  inbound  – messages received from remote peer (read by the UI)
  outbound – messages to send (written by the UI)

The keepalive thread sends PING every 30 s and expects PONG within 10 s.
If no PONG arrives within that window the session is torn down.

Timeout: if no message (including PING/PONG) is received for IDLE_TIMEOUT
seconds, the session self-destructs.
"""

import socket
import threading
import queue
import time
import logging

from . import protocol
from .protocol import Message, MsgType, send_msg, recv_msg


log = logging.getLogger("securechat.session")

KEEPALIVE_INTERVAL = 30     # seconds between PINGs
KEEPALIVE_TIMEOUT  = 10     # seconds to wait for PONG
IDLE_TIMEOUT       = 900    # 15 minutes — session hard limit
SOCK_TIMEOUT       = 5      # socket read timeout (allows clean shutdown)


class SessionClosedError(Exception):
    """Raised when the session has been terminated."""
    pass


class Session:
    """
    Full-duplex encrypted session over a connected TCP socket.

    Parameters
    ----------
    sock : socket.socket
        An already-connected (and handshaked) TCP socket.
    key  : bytes
        The 32-byte AES-256 session key.
    role : str
        "host" or "peer" — only used for display.
    on_message : callable(Message) -> None
        Called from the reader thread for every incoming MSG/SYS.
    on_close   : callable(reason: str) -> None
        Called when the session ends for any reason.
    """

    def __init__(self, sock, key, role, on_message, on_close):
        self._sock        = sock
        self._key         = key
        self.role         = role
        self._on_message  = on_message
        self._on_close    = on_close

        self._outbound    = queue.Queue(maxsize=256)
        self._alive       = threading.Event()
        self._alive.set()
        self._close_once  = threading.Lock()
        self._close_reason = ""

        self._last_recv   = time.monotonic()
        self._pong_event  = threading.Event()

        # Set a read timeout so threads can periodically check _alive
        self._sock.settimeout(SOCK_TIMEOUT)

        self._threads = []

    # ── Public API ────────────────────────────────────────────────────────────

    def send_text(self, text: str) -> None:
        """Queue a chat message for sending."""
        if not self._alive.is_set():
            raise SessionClosedError("Session is closed")
        msg = Message(mtype=MsgType.MSG, body=text)
        self._outbound.put(msg)

    def send_system(self, text: str) -> None:
        """Queue a system notice for sending (shown in grey on the remote side)."""
        msg = Message(mtype=MsgType.SYS, body=text)
        self._outbound.put(msg)

    def close(self, reason: str = "Connection closed") -> None:
        """Initiate an orderly shutdown."""
        with self._close_once:
            if not self._alive.is_set():
                return
            self._close_reason = reason
            self._alive.clear()
        # Best-effort BYE
        try:
            send_msg(self._sock, Message(MsgType.BYE, reason), self._key)
        except Exception:
            pass

    def start(self) -> None:
        """Start background threads. Returns immediately."""
        for target in (self._reader, self._writer, self._keepalive, self._watchdog):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def join(self) -> None:
        """Block until all threads have finished."""
        for t in self._threads:
            t.join(timeout=SOCK_TIMEOUT + 2)

    # ── Background threads ────────────────────────────────────────────────────

    def _reader(self):
        """Receive messages from the remote peer."""
        try:
            while self._alive.is_set():
                try:
                    msg = recv_msg(self._sock, self._key)
                except socket.timeout:
                    continue
                except ConnectionError as e:
                    self._teardown(f"Connection lost: {e}")
                    return
                except Exception as e:
                    self._teardown(f"Decryption error: {e}")
                    return

                self._last_recv = time.monotonic()

                if msg.mtype == MsgType.BYE:
                    self._teardown(f"Remote peer closed the session: {msg.body or ''}")
                    return
                elif msg.mtype == MsgType.PING:
                    self._outbound.put(Message(MsgType.PONG, None))
                elif msg.mtype == MsgType.PONG:
                    self._pong_event.set()
                elif msg.mtype in (MsgType.MSG, MsgType.SYS):
                    try:
                        self._on_message(msg)
                    except Exception:
                        pass
        except Exception as e:
            self._teardown(str(e))

    def _writer(self):
        """Send messages from the outbound queue."""
        try:
            while self._alive.is_set():
                try:
                    msg = self._outbound.get(timeout=1)
                except queue.Empty:
                    continue
                try:
                    send_msg(self._sock, msg, self._key)
                except Exception as e:
                    self._teardown(f"Send failed: {e}")
                    return
        except Exception as e:
            self._teardown(str(e))

    def _keepalive(self):
        """Send periodic PINGs to detect dead connections."""
        while self._alive.is_set():
            time.sleep(KEEPALIVE_INTERVAL)
            if not self._alive.is_set():
                break
            self._pong_event.clear()
            self._outbound.put(Message(MsgType.PING, None))
            if not self._pong_event.wait(timeout=KEEPALIVE_TIMEOUT):
                self._teardown("Keepalive timeout — peer unreachable")
                return

    def _watchdog(self):
        """Hard timeout: terminate if session exceeds IDLE_TIMEOUT."""
        deadline = time.monotonic() + IDLE_TIMEOUT
        while self._alive.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._teardown(
                    f"Session expired after {IDLE_TIMEOUT // 60} minutes"
                )
                return
            # Warn at 5 minutes remaining
            if remaining < 300 and remaining > 295:
                try:
                    self._on_message(Message(
                        MsgType.SYS,
                        "⚠  Session expires in 5 minutes",
                    ))
                except Exception:
                    pass
            time.sleep(5)

    # ── Internal teardown ─────────────────────────────────────────────────────

    def _teardown(self, reason: str):
        with self._close_once:
            if not self._alive.is_set():
                return
            self._close_reason = reason
            self._alive.clear()
        try:
            self._sock.close()
        except Exception:
            pass
        try:
            self._on_close(reason)
        except Exception:
            pass

    @property
    def is_alive(self) -> bool:
        return self._alive.is_set()

    @property
    def close_reason(self) -> str:
        return self._close_reason
