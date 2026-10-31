"""
securechat/session.py
─────────────────────
Manages live bidirectional encrypted sessions for both 2-user and
multi-user (group chat) modes.

Lifetime guarantee
──────────────────
The room (GroupSession) stays alive as long as there is at least one
participant (host + any guests).  Individual guest disconnects remove
only that guest — other participants and the room itself are unaffected.
The room only closes when:
  • The host explicitly quits (Ctrl+C or /quit) — this sends BYE to
    every connected guest before closing.
  • A fatal, unrecoverable error in the host process (OS signals, etc.).

A guest session (Session, peer side) closes when:
  • The guest quits (Ctrl+C or /quit) — sends BYE to host/room.
  • The host sends a BYE (room closed or guest was /kicked).
  • A genuine socket-level error (not a temporary timeout).

Keepalive
─────────
• Guest-side Session: sends PING every 30 s, warns on missed PONGs
  but never tears down from keepalive alone (slow/Tor links can miss).
• Host-side GroupSession: sends PING to each guest every 30 s; if a
  guest misses MAX_MISSED_PINGS (3) consecutive PONGs it is treated as
  dead and reaped, notifying remaining participants.

Multi-user architecture (host side)
────────────────────────────────────
  ┌──────────────────────┐
  │  GroupSession (host) │
  │                      │  reader + keepalive thread per guest
  │  guests: [G1, G2 …]  │ ◄──────── G1 socket
  │                      │ ◄──────── G2 socket
  │  broadcaster         │ ──────► G1, G2  (relay every message to all)
  └──────────────────────┘
"""

import socket
import threading
import queue
import time
import logging

from . import protocol
from .protocol import Message, MsgType, send_msg, recv_msg


log = logging.getLogger("securechat.session")

KEEPALIVE_INTERVAL = 30      # seconds between PINGs
KEEPALIVE_TIMEOUT  = 15      # seconds to wait for PONG reply
MAX_MISSED_PINGS   = 3       # consecutive missed PONGs before reaping a guest
SOCK_TIMEOUT       = 5       # socket read timeout (allows clean shutdown loop)


class SessionClosedError(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  Original two-party Session (kept for backward compat + guest-side use)
# ─────────────────────────────────────────────────────────────────────────────

class Session:
    """
    Full-duplex encrypted session over a connected TCP socket.
    Used by guests (peer side) and as the host session in 2-user mode.

    The session runs indefinitely until:
      • the user explicitly quits (close() is called)
      • the remote peer sends BYE
      • a genuine socket-level error occurs (ConnectionError, etc.)

    Transient conditions that do NOT close the session:
      • socket.timeout  (SOCK_TIMEOUT poll — normal)
      • missed keepalive PONGs (warns only)
      • decryption errors below MAX_AUTH_FAILURES (warns and retries)
    """

    def __init__(self, sock, key, role, on_message, on_close):
        self._sock        = sock
        self._key         = key
        self.role         = role
        self._on_message  = on_message
        self._on_close    = on_close

        self._outbound    = queue.Queue(maxsize=4096)
        self._alive       = threading.Event()
        self._alive.set()
        self._close_once  = threading.Lock()
        self._close_reason = ""

        self._last_recv   = time.monotonic()
        self._pong_event  = threading.Event()

        self._sock.settimeout(SOCK_TIMEOUT)
        self._threads = []

    # ── Public API ────────────────────────────────────────────────────────────

    def send_text(self, text: str, sender: str = None) -> None:
        if not self._alive.is_set():
            raise SessionClosedError("Session is closed")
        msg = Message(mtype=MsgType.MSG, body=text, sender=sender)
        self._outbound.put(msg)

    def send_system(self, text: str) -> None:
        msg = Message(mtype=MsgType.SYS, body=text)
        self._outbound.put(msg)

    def close(self, reason: str = "Connection closed") -> None:
        """
        Initiate an orderly shutdown.  Sends BYE to the remote peer,
        then stops all background threads.  Safe to call multiple times.
        """
        with self._close_once:
            if not self._alive.is_set():
                return
            self._close_reason = reason
            self._alive.clear()
        try:
            send_msg(self._sock, Message(MsgType.BYE, reason), self._key)
        except Exception:
            pass

    def start(self) -> None:
        for target in (self._reader, self._writer, self._keepalive):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def join(self) -> None:
        for t in self._threads:
            t.join(timeout=SOCK_TIMEOUT + 2)

    # ── Background threads ────────────────────────────────────────────────────

    def _reader(self):
        """
        Receive messages from the remote peer.
        Only tears down on:
          • ConnectionError (peer closed TCP)
          • >= MAX_AUTH_FAILURES consecutive decryption errors
          • BYE message from peer
        socket.timeout is a normal poll event — loop continues.
        """
        auth_failures   = 0
        MAX_AUTH_FAILURES = 5
        try:
            while self._alive.is_set():
                try:
                    msg = recv_msg(self._sock, self._key)
                except socket.timeout:
                    continue   # normal poll — keep alive
                except ConnectionError as e:
                    self._teardown(f"Connection lost: {e}")
                    return
                except Exception as e:
                    auth_failures += 1
                    if auth_failures >= MAX_AUTH_FAILURES:
                        self._teardown(f"Decryption error: {e}")
                        return
                    try:
                        self._on_message(Message(MsgType.SYS,
                            "⚠  Received a corrupted frame — retrying"))
                    except Exception:
                        pass
                    continue

                auth_failures      = 0
                self._last_recv    = time.monotonic()

                if msg.mtype == MsgType.BYE:
                    self._teardown(f"Remote peer closed the session: {msg.body or ''}")
                    return
                elif msg.mtype == MsgType.PING:
                    self._outbound.put(Message(MsgType.PONG, None))
                elif msg.mtype == MsgType.PONG:
                    self._pong_event.set()
                elif msg.mtype in (MsgType.MSG, MsgType.SYS, MsgType.LEAVE):
                    try:
                        self._on_message(msg)
                    except Exception:
                        pass
        except Exception as e:
            self._teardown(str(e))

    def _writer(self):
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
        """
        Send periodic PINGs to verify the connection is still live.
        Warns on missed PONGs but NEVER disconnects from keepalive alone —
        over Tor / proxychains a PONG can arrive far outside the window.
        Only a genuine socket-level error (caught in _reader/_writer) ends
        the session.
        """
        missed = 0
        while self._alive.is_set():
            time.sleep(KEEPALIVE_INTERVAL)
            if not self._alive.is_set():
                break
            self._pong_event.clear()
            self._outbound.put(Message(MsgType.PING, None))
            if not self._pong_event.wait(timeout=KEEPALIVE_TIMEOUT):
                missed += 1
                try:
                    self._on_message(Message(
                        MsgType.SYS,
                        f"⚠  Keepalive missed ({missed}) — peer may be slow/unreachable",
                    ))
                except Exception:
                    pass
                continue
            missed = 0

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


# ─────────────────────────────────────────────────────────────────────────────
#  GroupSession — multi-user hub (host side)
# ─────────────────────────────────────────────────────────────────────────────

class GuestHandle:
    """Represents one connected guest on the host side."""
    def __init__(self, conn: socket.socket, key: bytes, nickname: str):
        self.conn      = conn
        self.key       = key
        self.nickname  = nickname
        self._lock     = threading.Lock()
        self.alive     = True
        # Per-guest PONG tracking for host-side keepalive
        self.pong_event   = threading.Event()
        self.missed_pings = 0

    def send(self, msg: Message) -> bool:
        """Thread-safe send. Returns False if the guest socket is dead."""
        if not self.alive:
            return False
        with self._lock:
            if not self.alive:
                return False
            try:
                send_msg(self.conn, msg, self.key)
                return True
            except Exception:
                self.alive = False
                return False

    def close(self, reason: str = ""):
        self.alive = False
        try:
            send_msg(self.conn, Message(MsgType.BYE, reason), self.key)
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass


class GroupSession:
    """
    Host-side multi-user session hub.

    Room lifetime
    ─────────────
    The room is alive from start() until close() is explicitly called.
    Individual guest disconnects only remove that guest — the room and
    all remaining participants continue uninterrupted.
    The room closes ONLY when the host:
      • types /quit or presses Ctrl+C  →  securechat.py calls group.close()
      • the host process is killed     →  SIGTERM handler calls sys.exit()

    Responsibilities
    ─────────────────
    • Relay every incoming message from any guest to all other guests
      (and to the host's own UI).
    • Broadcast host messages to all guests.
    • Track join-requests in a pending queue; expose them for host approval.
    • Per-guest keepalive: ping each guest every 30 s; reap after
      MAX_MISSED_PINGS (3) consecutive no-replies.
    • Clean up dead guest sockets automatically.

    Thread model
    ─────────────
    One reader thread per admitted guest.
    One keepalive thread shared across all guests.
    One broadcaster thread draining the relay_queue.
    """

    def __init__(
        self,
        key: bytes,
        host_nickname: str,
        on_message,       # callable(msg: Message, from_nickname: str)
        on_close,         # callable(reason: str)
        on_join_request,  # callable(nickname: str)
    ):
        self._key              = key
        self._host_nickname    = host_nickname
        self._on_message       = on_message
        self._on_close         = on_close
        self._on_join_request  = on_join_request

        # Admitted guests: nickname → GuestHandle
        self._guests: dict     = {}
        self._guests_lock      = threading.RLock()

        # Pending (waiting for host approval): nickname → socket
        self._pending: dict    = {}
        self._pending_lock     = threading.Lock()

        # Relay queue: (Message, origin_nickname)
        self._relay_q          = queue.Queue(maxsize=8192)

        self._alive            = threading.Event()
        self._alive.set()
        self._close_once       = threading.Lock()
        self._close_reason     = ""

        self._threads          = []

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start broadcaster and shared keepalive threads."""
        for target in (self._broadcaster, self._guest_keepalive):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def admit_pending(self, nickname: str) -> bool:
        """
        Admit a pending guest by nickname.
        The guest's socket moves from _pending → _guests.
        A reader thread is started for the newly admitted guest.
        Returns True if found and admitted.
        """
        with self._pending_lock:
            conn = self._pending.pop(nickname, None)
        if conn is None:
            return False

        handle = GuestHandle(conn, self._key, nickname)

        participants = self._participant_list()
        from . import network as _net
        _net.admit_guest(conn, self._key, participants)

        with self._guests_lock:
            self._guests[nickname] = handle

        self._broadcast_system(f"⟶  {nickname} joined the room", exclude=nickname)
        self._on_message(Message(MsgType.SYS, f"⟶  {nickname} joined the room"), "system")

        t = threading.Thread(target=self._guest_reader, args=(handle,), daemon=True)
        t.start()
        self._threads.append(t)
        return True

    def deny_pending(self, nickname: str, reason: str = "Request denied by host") -> bool:
        """Deny a pending guest and close their connection."""
        with self._pending_lock:
            conn = self._pending.pop(nickname, None)
        if conn is None:
            return False
        from . import network as _net
        _net.deny_guest(conn, self._key, reason)
        return True

    def pending_nicknames(self) -> list:
        with self._pending_lock:
            return list(self._pending.keys())

    def admitted_nicknames(self) -> list:
        with self._guests_lock:
            return list(self._guests.keys())

    def add_pending(self, conn, nickname: str) -> str:
        """
        Register a newly-connected guest as pending.
        Deduplicates nickname if needed.  Returns the final nickname used.
        The room stays open and keeps accepting connections regardless of
        how many guests are in the pending or admitted lists.
        """
        final_nick = self._unique_nick(nickname)
        with self._pending_lock:
            self._pending[final_nick] = conn
        try:
            self._on_join_request(final_nick)
        except Exception:
            pass
        return final_nick

    def send_text(self, text: str) -> None:
        """Host sends a chat message — relay to all guests."""
        if not self._alive.is_set():
            raise SessionClosedError("Session is closed")
        msg = Message(mtype=MsgType.MSG, body=text, sender=self._host_nickname)
        self._on_message(msg, self._host_nickname)
        self._relay_q.put((msg, self._host_nickname))

    def send_system(self, text: str) -> None:
        msg = Message(mtype=MsgType.SYS, body=text)
        self._relay_q.put((msg, "system"))

    def close(self, reason: str = "Host closed the session") -> None:
        """
        Shut down the entire room.
        Sends BYE to every connected guest, denies every pending guest,
        then stops all threads.  Only called when the host explicitly quits.
        """
        with self._close_once:
            if not self._alive.is_set():
                return
            self._close_reason = reason
            self._alive.clear()

        # Deny all pending guests
        with self._pending_lock:
            for nick, conn in list(self._pending.items()):
                try:
                    send_msg(conn, Message(MsgType.DENY, reason), self._key)
                    conn.close()
                except Exception:
                    pass
            self._pending.clear()

        # Close all admitted guests with BYE
        with self._guests_lock:
            for handle in list(self._guests.values()):
                handle.close(reason)
            self._guests.clear()

    def join(self) -> None:
        for t in self._threads:
            t.join(timeout=SOCK_TIMEOUT + 2)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _participant_list(self) -> str:
        with self._guests_lock:
            nicks = [self._host_nickname] + list(self._guests.keys())
        return ", ".join(nicks)

    def _unique_nick(self, wanted: str) -> str:
        taken = {self._host_nickname}
        with self._guests_lock:
            taken.update(self._guests.keys())
        with self._pending_lock:
            taken.update(self._pending.keys())
        if wanted not in taken:
            return wanted
        for i in range(2, 100):
            candidate = f"{wanted}_{i}"
            if candidate not in taken:
                return candidate
        import secrets
        return f"{wanted}_{secrets.token_hex(2)}"

    def _broadcast(self, msg: Message, exclude: str = None) -> None:
        """Send msg to all admitted guests except exclude. Reap dead sockets."""
        with self._guests_lock:
            handles = list(self._guests.values())
        dead = []
        for h in handles:
            if exclude and h.nickname == exclude:
                continue
            if not h.send(msg):
                dead.append(h.nickname)
        if dead:
            self._reap_dead(dead)

    def _broadcast_system(self, text: str, exclude: str = None) -> None:
        self._broadcast(Message(MsgType.SYS, text), exclude=exclude)

    def _reap_dead(self, nicknames: list) -> None:
        """
        Remove dead guests from the room.
        This does NOT close the room — remaining participants continue.
        """
        for nick in nicknames:
            with self._guests_lock:
                handle = self._guests.pop(nick, None)
            if handle:
                handle.alive = False
                try:
                    handle.conn.close()
                except Exception:
                    pass
                leave = f"✗  {nick} disconnected"
                self._broadcast_system(leave)
                try:
                    self._on_message(Message(MsgType.SYS, leave), "system")
                except Exception:
                    pass

    def _broadcaster(self) -> None:
        """Drain the relay queue and fan out to all current guests."""
        while self._alive.is_set():
            try:
                item = self._relay_q.get(timeout=1)
            except queue.Empty:
                continue
            msg, origin_nick = item
            self._broadcast(msg, exclude=origin_nick)

    def _guest_keepalive(self) -> None:
        """
        Shared keepalive: ping every admitted guest every KEEPALIVE_INTERVAL s.
        A guest that misses MAX_MISSED_PINGS consecutive PONGs is reaped.
        This detects crashed/network-dead guests without killing the room.
        Guests on slow links (Tor, proxychains) need the generous timeout.
        """
        while self._alive.is_set():
            time.sleep(KEEPALIVE_INTERVAL)
            if not self._alive.is_set():
                break

            with self._guests_lock:
                handles = list(self._guests.values())

            dead = []
            for h in handles:
                if not h.alive:
                    dead.append(h.nickname)
                    continue
                h.pong_event.clear()
                # Send PING; if the socket is already dead, send() returns False
                if not h.send(Message(MsgType.PING, None)):
                    dead.append(h.nickname)
                    continue
                if not h.pong_event.wait(timeout=KEEPALIVE_TIMEOUT):
                    h.missed_pings += 1
                    if h.missed_pings >= MAX_MISSED_PINGS:
                        dead.append(h.nickname)
                else:
                    h.missed_pings = 0   # reset on any successful PONG

            if dead:
                self._reap_dead(dead)

    def _guest_reader(self, handle: GuestHandle) -> None:
        """
        Read messages from one guest.
        Relays MSG frames to all other participants.
        Only removes THIS guest on error/BYE — the room and others are unaffected.
        socket.timeout is a normal poll — loop continues without tearing down.
        """
        sock = handle.conn
        sock.settimeout(SOCK_TIMEOUT)
        auth_failures = 0
        MAX_AUTH      = 5

        while self._alive.is_set() and handle.alive:
            try:
                msg = recv_msg(sock, self._key)
            except socket.timeout:
                continue   # normal poll — connection still alive
            except ConnectionError:
                break      # genuine TCP disconnect
            except Exception:
                auth_failures += 1
                if auth_failures >= MAX_AUTH:
                    break
                continue

            auth_failures = 0

            if msg.mtype == MsgType.BYE:
                break   # guest quit cleanly
            elif msg.mtype == MsgType.PING:
                handle.send(Message(MsgType.PONG, None))
            elif msg.mtype == MsgType.PONG:
                handle.pong_event.set()
                handle.missed_pings = 0
            elif msg.mtype == MsgType.MSG:
                stamped = Message(mtype=MsgType.MSG, body=msg.body,
                                  sender=handle.nickname)
                try:
                    self._on_message(stamped, handle.nickname)
                except Exception:
                    pass
                self._relay_q.put((stamped, handle.nickname))
            # SYS frames from guests are ignored (guests cannot inject system messages)

        # ── Guest has left or socket died ────────────────────────────────────
        nick       = handle.nickname
        handle.alive = False
        try:
            sock.close()
        except Exception:
            pass

        # Remove from admitted set — room stays alive
        with self._guests_lock:
            self._guests.pop(nick, None)

        leave_text = f"✗  {nick} left the room"
        try:
            self._on_message(Message(MsgType.SYS, leave_text), "system")
        except Exception:
            pass
        self._broadcast_system(leave_text)

    @property
    def is_alive(self) -> bool:
        return self._alive.is_set()

    @property
    def close_reason(self) -> str:
        return self._close_reason

    @property
    def guest_count(self) -> int:
        with self._guests_lock:
            return len(self._guests)
