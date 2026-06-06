"""
securechat/filetransfer.py
──────────────────────────
Encrypted peer-to-peer file transfer over the existing session.

Design
  • Runs entirely in-band on the existing socket — no second port.
  • All sends go through session._outbound (the queue the writer thread owns),
    never directly to the socket. This eliminates the race condition where
    a direct sock.sendall() from a file-transfer thread would interleave bytes
    with the session's _writer thread.
  • Every 32 KB chunk is independently AES-256-GCM encrypted by the session
    layer (frames pass through session.send_text → _patched_send → protocol).
  • File-transfer frames are normal MSG frames whose JSON body starts with
    '{"ft":'. The FileTransferChannel intercepts them before the chat UI sees
    them, so the UI stays clean.
  • SHA-256 integrity is verified after reassembly. Corrupted files are deleted.
  • Received files land in ~/securechat_received/ (auto-created, never logged).

Wire messages (all carried as MSG body JSON):
  OFFER  {ft, name, size, sha256, chunks, chunk_size}
  ACCEPT {ft}
  REJECT {ft, reason}
  CHUNK  {ft, idx, data}   ← data is base64-encoded chunk bytes
  DONE   {ft, sha256}
  ACK    {ft}
  ERROR  {ft, reason}

User commands (handled in securechat.py _handle_enter):
  /sendfile <path>
  /accept
  /reject [reason]
"""

import os
import math
import json
import time
import hashlib
import base64
import threading
import pathlib
from typing import Callable, Optional

from .protocol import Message, MsgType

# ── Config ────────────────────────────────────────────────────────────────────
CHUNK_SIZE    = 32 * 1024           # 32 KB per chunk
MAX_FILE_SIZE = 256 * 1024 * 1024  # 256 MB hard cap
RECV_DIR      = pathlib.Path.home() / "securechat_received"

# ── Frame-type discriminator ──────────────────────────────────────────────────
# Any MSG whose body starts with '{"ft":' is a file-transfer control frame.
_FT_PREFIX = '{"ft":'


# ═══════════════════════════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════════════════════════

def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


def _unique_path(path: pathlib.Path) -> pathlib.Path:
    """Avoid overwriting existing files by appending (1), (2), …"""
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    i = 1
    while True:
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
        i += 1


# ═══════════════════════════════════════════════════════════════════════════════
#  FileTransferChannel
# ═══════════════════════════════════════════════════════════════════════════════

class FileTransferChannel:
    """
    Multiplexes file-transfer frames with chat on a single session.

    Install immediately after creating the Session, before session.start():

        ft = FileTransferChannel(session, key, ui.push_system)
        ft.install()
        session.start()

    Sending a file (from the UI command handler):
        ft.send_file("/path/to/file.pdf")   # non-blocking, runs in a thread

    Accepting / rejecting an incoming offer:
        ft.accept_offer()
        ft.reject_offer("not now")
    """

    def __init__(
        self,
        session,
        key: bytes,
        push_system: Callable[[str], None],
    ):
        self._session     = session
        self._key         = key
        self._push        = push_system

        # Pending incoming offer (set by _handle_offer, cleared by accept/reject)
        self._offer_lock    = threading.Lock()
        self._offer_payload: Optional[dict] = None

        # Only one active transfer at a time (in either direction)
        self._transfer_lock = threading.Lock()

        # Response events used during the OFFER→ACCEPT/REJECT and DONE→ACK/ERROR
        # handshake steps.  A dict so we can pass the payload back easily.
        self._response_lock    = threading.Lock()
        self._response_event   = threading.Event()
        self._response_payload: Optional[dict] = None

        # Chunk accumulation during receive
        self._chunk_lock   = threading.Lock()
        self._chunks: dict = {}       # idx → bytes
        self._chunk_event  = threading.Event()
        self._done_payload: Optional[dict] = None

        RECV_DIR.mkdir(parents=True, exist_ok=True)

    # ── Install ───────────────────────────────────────────────────────────────

    def install(self) -> None:
        """
        Wrap session._on_message so that FT frames are routed here.
        All non-FT messages pass through to the original handler unchanged.
        """
        _orig = self._session._on_message

        def _intercept(msg: Message) -> None:
            if (
                msg.mtype == MsgType.MSG
                and isinstance(msg.body, str)
                and msg.body.startswith(_FT_PREFIX)
            ):
                try:
                    payload = json.loads(msg.body)
                    if "ft" in payload:
                        self._dispatch(payload)
                        return
                except (json.JSONDecodeError, KeyError):
                    pass
            _orig(msg)

        self._session._on_message = _intercept

    # ── Dispatch inbound FT frames ────────────────────────────────────────────

    def _dispatch(self, p: dict) -> None:
        ft = p.get("ft")

        if ft == "OFFER":
            self._handle_offer(p)

        elif ft in ("ACCEPT", "REJECT", "ACK", "ERROR"):
            # These are responses to something we sent — signal the waiting thread
            with self._response_lock:
                self._response_payload = p
                self._response_event.set()

        elif ft == "CHUNK":
            with self._chunk_lock:
                idx  = p.get("idx", -1)
                data = base64.b64decode(p.get("data", ""))
                self._chunks[idx] = data
            self._chunk_event.set()

        elif ft == "DONE":
            with self._chunk_lock:
                self._done_payload = p
            self._chunk_event.set()

    # ── Inbound offer ─────────────────────────────────────────────────────────

    def _handle_offer(self, p: dict) -> None:
        name = p.get("name", "unknown")
        size = p.get("size", 0)
        with self._offer_lock:
            self._offer_payload = p
        self._push(
            f"📁  Peer wants to send: {name}  ({_human_size(size)})"
            f"  — type /accept or /reject"
        )

    def has_pending_offer(self) -> bool:
        with self._offer_lock:
            return self._offer_payload is not None

    def accept_offer(self) -> None:
        with self._offer_lock:
            payload = self._offer_payload
            self._offer_payload = None
        if payload is None:
            self._push("No pending file offer.")
            return
        t = threading.Thread(
            target=self._receive_worker, args=(payload,), daemon=True
        )
        t.start()

    def reject_offer(self, reason: str = "declined") -> None:
        with self._offer_lock:
            self._offer_payload = None
        self._send_ft({"ft": "REJECT", "reason": reason})
        self._push("File offer rejected.")

    # ── Send ──────────────────────────────────────────────────────────────────

    def send_file(self, path_str: str) -> None:
        """Start a file transfer in a background thread (non-blocking)."""
        t = threading.Thread(
            target=self._send_worker, args=(path_str,), daemon=True
        )
        t.start()

    def _send_worker(self, path_str: str) -> None:
        if not self._transfer_lock.acquire(blocking=False):
            self._push("A transfer is already in progress — please wait.")
            return
        try:
            self._do_send(path_str)
        finally:
            self._transfer_lock.release()

    def _do_send(self, path_str: str) -> None:
        path = pathlib.Path(path_str).expanduser().resolve()

        if not path.exists():
            self._push(f"File not found: {path}")
            return
        if not path.is_file():
            self._push(f"Not a regular file: {path}")
            return

        size = path.stat().st_size
        if size == 0:
            self._push("Cannot send an empty file.")
            return
        if size > MAX_FILE_SIZE:
            self._push(
                f"File too large: {_human_size(size)} "
                f"(limit: {_human_size(MAX_FILE_SIZE)})"
            )
            return

        n_chunks = math.ceil(size / CHUNK_SIZE)
        sha256   = _sha256_file(path)
        name     = path.name

        self._push(
            f"📤  Offering '{name}' ({_human_size(size)}, "
            f"{n_chunks} chunk{'s' if n_chunks != 1 else ''}) — waiting for peer..."
        )

        # Send OFFER and wait for ACCEPT or REJECT
        self._clear_response()
        self._send_ft({
            "ft":         "OFFER",
            "name":       name,
            "size":       size,
            "sha256":     sha256,
            "chunks":     n_chunks,
            "chunk_size": CHUNK_SIZE,
        })
        response = self._wait_response(timeout=120)

        if response is None:
            self._push("Offer timed out — no response from peer.")
            return
        if response.get("ft") == "REJECT":
            self._push(f"Peer rejected the file: {response.get('reason', 'declined')}")
            return
        if response.get("ft") != "ACCEPT":
            self._push("Unexpected response from peer.")
            return

        # Send chunks
        self._push(f"📤  Sending '{name}'...")
        start = time.monotonic()
        sent  = 0

        with open(path, "rb") as f:
            for idx in range(n_chunks):
                if not self._session.is_alive:
                    self._push("Transfer aborted — session closed.")
                    return
                chunk = f.read(CHUNK_SIZE)
                self._send_ft({
                    "ft":   "CHUNK",
                    "idx":  idx,
                    "data": base64.b64encode(chunk).decode("ascii"),
                })
                sent += len(chunk)
                if idx % 10 == 0 or idx == n_chunks - 1:
                    pct   = int(sent / size * 100)
                    elapsed = max(time.monotonic() - start, 0.01)
                    speed = _human_size(int(sent / elapsed)) + "/s"
                    self._push(
                        f"  📤  {name}: {pct}%  "
                        f"{_human_size(sent)}/{_human_size(size)}  @ {speed}"
                    )

        # Send DONE and wait for ACK or ERROR
        self._clear_response()
        self._send_ft({"ft": "DONE", "sha256": sha256})
        ack = self._wait_response(timeout=60)

        elapsed = time.monotonic() - start
        if ack and ack.get("ft") == "ACK":
            speed = _human_size(int(size / max(elapsed, 0.01))) + "/s"
            self._push(
                f"✅  '{name}' sent in {elapsed:.1f}s  ({speed} avg)"
            )
        elif ack and ack.get("ft") == "ERROR":
            self._push(f"❌  Transfer failed: {ack.get('reason', 'unknown error')}")
        else:
            self._push("⚠  No ACK received — transfer may have failed.")

    # ── Receive ───────────────────────────────────────────────────────────────

    def _receive_worker(self, offer: dict) -> None:
        if not self._transfer_lock.acquire(blocking=False):
            self._push("A transfer is already in progress.")
            self._send_ft({"ft": "REJECT", "reason": "busy"})
            return
        try:
            self._do_receive(offer)
        finally:
            self._transfer_lock.release()

    def _do_receive(self, offer: dict) -> None:
        name     = offer.get("name", "received_file")
        size     = offer.get("size", 0)
        expected = offer.get("sha256", "")
        n_chunks = offer.get("chunks", 1)

        # Sanitise: strip any path component so peers can't write outside RECV_DIR
        safe_name = pathlib.Path(name).name or "received_file"
        dest      = _unique_path(RECV_DIR / safe_name)

        self._send_ft({"ft": "ACCEPT"})
        self._push(f"📥  Receiving '{safe_name}' ({_human_size(size)})...")

        # Reset chunk state
        with self._chunk_lock:
            self._chunks     = {}
            self._done_payload = None
        self._chunk_event.clear()

        start      = time.monotonic()
        last_prog  = 0

        # Wait for all chunks + DONE.
        # We poll the event; each CHUNK dispatch calls _chunk_event.set().
        per_chunk_timeout = max(120, n_chunks * 3)
        deadline = time.monotonic() + per_chunk_timeout

        while True:
            self._chunk_event.wait(timeout=2)
            self._chunk_event.clear()

            with self._chunk_lock:
                n_rcvd  = len(self._chunks)
                is_done = self._done_payload is not None

            if is_done and n_rcvd >= n_chunks:
                break

            if time.monotonic() > deadline:
                self._push("❌  Receive timed out — incomplete transfer.")
                self._send_ft({"ft": "ERROR", "reason": "timeout"})
                return

            if not self._session.is_alive:
                self._push("❌  Session closed during transfer.")
                return

            # Progress report
            rcvd_bytes = sum(len(v) for v in self._chunks.values())
            if rcvd_bytes - last_prog >= 10 * CHUNK_SIZE or is_done:
                pct   = int(rcvd_bytes / max(size, 1) * 100)
                elapsed = max(time.monotonic() - start, 0.01)
                speed = _human_size(int(rcvd_bytes / elapsed)) + "/s"
                self._push(
                    f"  📥  {safe_name}: {pct}%  "
                    f"{_human_size(rcvd_bytes)}/{_human_size(size)}  @ {speed}"
                )
                last_prog = rcvd_bytes

        # Verify we have every chunk
        with self._chunk_lock:
            chunks_copy = dict(self._chunks)

        missing = [i for i in range(n_chunks) if i not in chunks_copy]
        if missing:
            msg = f"Missing chunks: {missing[:5]}{'...' if len(missing) > 5 else ''}"
            self._push(f"❌  {msg}")
            self._send_ft({"ft": "ERROR", "reason": msg})
            return

        # Reassemble
        try:
            with open(dest, "wb") as f:
                for i in range(n_chunks):
                    f.write(chunks_copy[i])
        except OSError as e:
            self._push(f"❌  Could not write file: {e}")
            self._send_ft({"ft": "ERROR", "reason": str(e)})
            return

        # Integrity check
        actual = _sha256_file(dest)
        if expected and actual != expected:
            dest.unlink(missing_ok=True)
            msg = "SHA-256 mismatch — file corrupted or tampered"
            self._push(f"❌  {msg}")
            self._send_ft({"ft": "ERROR", "reason": msg})
            return

        elapsed = time.monotonic() - start
        self._send_ft({"ft": "ACK"})
        self._push(
            f"✅  '{safe_name}' saved to ~/securechat_received/  "
            f"({_human_size(size)}, {elapsed:.1f}s, SHA-256 verified)"
        )

    # ── Send helper — uses session outbound queue, never touches socket directly
    def _send_ft(self, payload: dict) -> None:
        """
        Encode payload as a MSG and put it in the session's outbound queue.
        The session's _writer thread sends it — no direct socket access here.
        """
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        msg  = Message(mtype=MsgType.MSG, body=body)
        try:
            self._session._outbound.put_nowait(msg)
        except Exception as e:
            self._push(f"FT queue error: {e}")

    # ── Response wait helpers ─────────────────────────────────────────────────

    def _clear_response(self) -> None:
        with self._response_lock:
            self._response_payload = None
            self._response_event.clear()

    def _wait_response(self, timeout: float) -> Optional[dict]:
        self._response_event.wait(timeout=timeout)
        with self._response_lock:
            result = self._response_payload
            self._response_payload = None
            self._response_event.clear()
        return result
