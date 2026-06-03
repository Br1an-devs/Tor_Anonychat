
import os
import math
import json
import time
import hashlib
import base64
import threading
import struct
import pathlib
from typing import Callable, Optional

from . import crypto

# ── Config ───────────────────────────────────────────────────────────────────
CHUNK_SIZE      = 32 * 1024          # 32 KB per chunk
MAX_FILE_SIZE   = 256 * 1024 * 1024  # 256 MB hard cap
RECV_DIR        = pathlib.Path.home() / "securechat_received"
FT_SOCK_TIMEOUT = 60                 # seconds per chunk (Tor latency headroom)

FT_KEY = "ft"

def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _send_ft_frame(sock, payload: dict, key: bytes) -> None:
    """Encrypt and send a file-transfer control/data frame."""
    raw       = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    encrypted = crypto.encrypt(raw, key)
    frame     = crypto.pack_frame(encrypted)
    sock.sendall(frame)


def _recv_ft_frame(sock, key: bytes) -> dict:
    """Receive and decrypt one file-transfer frame. Returns the dict."""
    blob = crypto.unpack_frame_from_socket(sock)
    raw  = crypto.decrypt(blob, key)
    return json.loads(raw.decode("utf-8"))
 #FileTransferChannel
#  Installed on the Session; intercepts inbound FT frames transparently.

class FileTransferChannel:
 
    def __init__(
        self,
        session,             # Session instance
        key: bytes,
        push_system: Callable[[str], None],   # ui.push_system equivalent
        push_progress: Optional[Callable[[str], None]] = None,
        on_file_received: Optional[Callable[[pathlib.Path], None]] = None,
    ):
        self._session        = session
        self._key            = key
        self._push_sys       = push_system
        self._push_prog      = push_progress or push_system
        self._on_received    = on_file_received

        # Inbound offer handling
        self._offer_event    = threading.Event()
        self._offer_payload  = None
        self._offer_lock     = threading.Lock()

        # Transfer mutex — only one transfer at a time
        self._transfer_lock  = threading.Lock()

        # Ensure receive directory exists
        RECV_DIR.mkdir(parents=True, exist_ok=True)

    # ── Installation (patches session._reader indirectly via on_message) ──────

    def install(self) -> None:
        """
        Patches the session so that inbound file-transfer frames are
        routed here instead of the chat UI's on_message callback.

        Works by wrapping session._on_message; the original remains intact
        for all non-FT messages.
        """
        original_on_msg = self._session._on_message

        def _interceptor(msg):
            # msg is a protocol.Message; body may carry a ft JSON payload
            from .protocol import MsgType
            if msg.mtype == MsgType.MSG and msg.body and msg.body.startswith('{"ft":'):
                try:
                    payload = json.loads(msg.body)
                    if FT_KEY in payload:
                        self._handle_inbound(payload)
                        return   # consumed — don't pass to UI
                except (json.JSONDecodeError, KeyError):
                    pass
            original_on_msg(msg)   # normal chat message

        self._session._on_message = _interceptor

    # ── Inbound frame dispatcher

    def _handle_inbound(self, payload: dict) -> None:
        ft_type = payload.get(FT_KEY)
        if ft_type == "OFFER":
            self._handle_offer(payload)

    def _handle_offer(self, payload: dict) -> None:
        """Received a file offer from the peer."""
        name   = payload.get("name", "unknown")
        size   = payload.get("size", 0)
        sha256 = payload.get("sha256", "")
        chunks = payload.get("chunks", 0)
        csize  = payload.get("chunk_size", CHUNK_SIZE)

        size_str = _human_size(size)
        self._push_sys(
            f"📁  Peer wants to send: {name}  ({size_str})  "
            f"— type /accept or /reject"
        )

        with self._offer_lock:
            self._offer_payload = payload
            self._offer_event.set()

    def accept_offer(self) -> None:
        """Called by the UI when the user types /accept."""
        with self._offer_lock:
            payload = self._offer_payload
            self._offer_payload = None
            self._offer_event.clear()

        if not payload:
            self._push_sys("No pending file offer to accept.")
            return

        t = threading.Thread(
            target=self._receive_file,
            args=(payload,),
            daemon=True,
        )
        t.start()

    def reject_offer(self, reason: str = "User declined") -> None:
        """Called by the UI when the user types /reject."""
        with self._offer_lock:
            self._offer_payload = None
            self._offer_event.clear()

        self._send_ft({"ft": "REJECT", "reason": reason})
        self._push_sys(f"File offer rejected.")

    def has_pending_offer(self) -> bool:
        return self._offer_event.is_set()

    # ── Send ──────────────────────────────────────────────────────────────────

    def send_file(self, path_str: str) -> None:
        """
        Initiate a file transfer (runs in a background thread).
        path_str: raw path string, ~ expanded.
        """
        t = threading.Thread(
            target=self._send_file_worker,
            args=(path_str,),
            daemon=True,
        )
        t.start()

    def _send_file_worker(self, path_str: str) -> None:
        if not self._transfer_lock.acquire(blocking=False):
            self._push_sys("A transfer is already in progress. Please wait.")
            return
        try:
            self._do_send(path_str)
        finally:
            self._transfer_lock.release()

    def _do_send(self, path_str: str) -> None:
        path = pathlib.Path(path_str).expanduser().resolve()

        # Validation
        if not path.exists():
            self._push_sys(f"File not found: {path}")
            return
        if not path.is_file():
            self._push_sys(f"Not a file: {path}")
            return

        size = path.stat().st_size
        if size == 0:
            self._push_sys("Cannot send an empty file.")
            return
        if size > MAX_FILE_SIZE:
            self._push_sys(
                f"File too large: {_human_size(size)} "
                f"(limit: {_human_size(MAX_FILE_SIZE)})"
            )
            return

        name      = path.name
        n_chunks  = math.ceil(size / CHUNK_SIZE)
        sha256    = _sha256_file(path)

        self._push_sys(
            f"📤  Offering {name} ({_human_size(size)}, "
            f"{n_chunks} chunk{'s' if n_chunks != 1 else ''}) — waiting for peer..."
        )

        # Send OFFER and wait for ACCEPT/REJECT
        self._send_ft({
            "ft":         "OFFER",
            "name":       name,
            "size":       size,
            "sha256":     sha256,
            "chunks":     n_chunks,
            "chunk_size": CHUNK_SIZE,
        })

        # Poll inbound session messages for ACCEPT/REJECT
        # We use a small dedicated event set by _handle_inbound
        response = self._wait_for_response(timeout=120)

        if response is None:
            self._push_sys("File offer timed out — no response from peer.")
            return
        if response.get("ft") == "REJECT":
            reason = response.get("reason", "declined")
            self._push_sys(f"Peer rejected the file: {reason}")
            return
        if response.get("ft") != "ACCEPT":
            self._push_sys("Unexpected response from peer.")
            return

        # Send chunks
        self._push_sys(f"  Sending {name}...")
        sock    = self._session._sock
        start   = time.monotonic()
        sent    = 0

        with open(path, "rb") as f:
            for idx in range(n_chunks):
                if not self._session.is_alive:
                    self._push_sys("Transfer aborted — session closed.")
                    return

                chunk = f.read(CHUNK_SIZE)
                self._send_ft({
                    "ft":   "CHUNK",
                    "idx":  idx,
                    "data": base64.b64encode(chunk).decode("ascii"),
                })
                sent += len(chunk)

                # Progress every 10 chunks or on last chunk
                if idx % 10 == 0 or idx == n_chunks - 1:
                    pct     = int(sent / size * 100)
                    elapsed = time.monotonic() - start
                    speed   = _human_size(int(sent / max(elapsed, 0.1))) + "/s"
                    self._push_prog(
                        f"    {name}: {pct}%  {_human_size(sent)}/{_human_size(size)}"
                        f"  @ {speed}"
                    )

        # Send DONE with final hash
        self._send_ft({"ft": "DONE", "sha256": sha256})

        # Wait for ACK or ERROR
        ack = self._wait_for_response(timeout=30)
        if ack and ack.get("ft") == "ACK":
            elapsed = time.monotonic() - start
            self._push_sys(
                f"  {name} sent successfully in {elapsed:.1f}s "
                f"({_human_size(int(size / max(elapsed, 0.1)))}/s avg)"
            )
        elif ack and ack.get("ft") == "ERROR":
            self._push_sys(f"  Transfer failed: {ack.get('reason', 'unknown error')}")
        else:
            self._push_sys(f"⚠  No ACK received — transfer may have failed.")

    #  Receive

    def _receive_file(self, offer: dict) -> None:
        if not self._transfer_lock.acquire(blocking=False):
            self._push_sys("A transfer is already in progress.")
            self._send_ft({"ft": "REJECT", "reason": "busy"})
            return
        try:
            self._do_receive(offer)
        finally:
            self._transfer_lock.release()

    def _do_receive(self, offer: dict) -> None:
        name      = offer.get("name", "received_file")
        size      = offer.get("size", 0)
        expected  = offer.get("sha256", "")
        n_chunks  = offer.get("chunks", 1)

        # Sanitise filename — strip any path components
        safe_name = pathlib.Path(name).name or "received_file"
        # Avoid overwriting existing files
        dest = _unique_path(RECV_DIR / safe_name)

        self._send_ft({"ft": "ACCEPT"})
        self._push_sys(f"📥  Receiving {safe_name} ({_human_size(size)})...")

        received_chunks = {}
        start           = time.monotonic()

        
        chunk_event = threading.Event()
        pending     = {"count": 0, "error": None}

        original_intercept = self._session._on_message

        def _chunk_interceptor(msg):
            from .protocol import MsgType
            if msg.mtype == MsgType.MSG and msg.body and msg.body.startswith('{"ft":'):
                try:
                    p = json.loads(msg.body)
                    ft = p.get("ft")
                    if ft == "CHUNK":
                        idx  = p["idx"]
                        data = base64.b64decode(p["data"])
                        received_chunks[idx] = data
                        pending["count"] += 1

                        if pending["count"] % 10 == 0 or pending["count"] == n_chunks:
                            rcvd = sum(len(v) for v in received_chunks.values())
                            pct  = int(rcvd / max(size, 1) * 100)
                            elapsed = time.monotonic() - start
                            speed   = _human_size(int(rcvd / max(elapsed, 0.1))) + "/s"
                            self._push_prog(
                                f"    {safe_name}: {pct}%  "
                                f"{_human_size(rcvd)}/{_human_size(size)}  @ {speed}"
                            )
                        if pending["count"] >= n_chunks:
                            chunk_event.set()
                        return
                    elif ft == "DONE":
                        pending["done_sha"] = p.get("sha256", "")
                        chunk_event.set()
                        return
                    elif ft == "ERROR":
                        pending["error"] = p.get("reason", "sender error")
                        chunk_event.set()
                        return
                except Exception as e:
                    pending["error"] = str(e)
                    chunk_event.set()
                    return
            original_intercept(msg)

        self._session._on_message = _chunk_interceptor

        # Wait for all chunks (generous timeout for large files over Tor)
        per_chunk_timeout = max(FT_SOCK_TIMEOUT, n_chunks * 2)
        chunk_event.wait(timeout=per_chunk_timeout)

        # Restore original interceptor
        self._session._on_message = original_intercept

        if pending.get("error"):
            self._push_sys(f"  Transfer error: {pending['error']}")
            self._send_ft({"ft": "ERROR", "reason": pending["error"]})
            return

        if len(received_chunks) < n_chunks:
            msg = f"Incomplete: got {len(received_chunks)}/{n_chunks} chunks"
            self._push_sys(f"  {msg}")
            self._send_ft({"ft": "ERROR", "reason": msg})
            return

        # Reassemble in order
        try:
            with open(dest, "wb") as f:
                for i in range(n_chunks):
                    f.write(received_chunks[i])
        except OSError as e:
            self._push_sys(f"  Could not write file: {e}")
            self._send_ft({"ft": "ERROR", "reason": str(e)})
            return

        # Verify integrity
        actual_sha = _sha256_file(dest)
        if expected and actual_sha != expected:
            dest.unlink(missing_ok=True)
            msg = "SHA-256 mismatch — file corrupted or tampered"
            self._push_sys(f"  {msg}")
            self._send_ft({"ft": "ERROR", "reason": msg})
            return

        elapsed = time.monotonic() - start
        self._send_ft({"ft": "ACK"})
        self._push_sys(
            f" {safe_name} saved to ~/securechat_received/  "
            f"({_human_size(size)}, {elapsed:.1f}s, SHA-256 verified)"
        )

        if self._on_received:
            try:
                self._on_received(dest)
            except Exception:
                pass

    # ── Response queue (ACCEPT/REJECT/ACK/ERROR flow) 

    def _wait_for_response(self, timeout: float) -> Optional[dict]:
        """
        Temporarily intercept inbound messages to catch the next
        ACCEPT / REJECT / ACK / ERROR frame.  Chat messages are
        re-queued to the original handler.
        """
        result    = {"payload": None}
        evt       = threading.Event()
        orig      = self._session._on_message

        def _intercept(msg):
            from .protocol import MsgType
            if msg.mtype == MsgType.MSG and msg.body and msg.body.startswith('{"ft":'):
                try:
                    p = json.loads(msg.body)
                    ft = p.get("ft")
                    if ft in ("ACCEPT", "REJECT", "ACK", "ERROR"):
                        result["payload"] = p
                        evt.set()
                        return
                except Exception:
                    pass
            orig(msg)   # not a response frame — pass through

        self._session._on_message = _intercept
        evt.wait(timeout=timeout)
        self._session._on_message = orig
        return result["payload"]

    # ── Send helper 

    def _send_ft(self, payload: dict) -> None:
        
        from .protocol import Message, MsgType, send_msg
        body = json.dumps(payload, ensure_ascii=False)
        msg  = Message(mtype=MsgType.MSG, body=body)
        try:
            from . import protocol as _proto
            _proto.send_msg(self._session._sock, msg, self._key)
        except Exception as e:
            self._push_sys(f"FT send error: {e}")

#  Utilities

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n //= 1024
    return f"{n:.1f} TB"


def _unique_path(path: pathlib.Path) -> pathlib.Path:
    """If path already exists, append (1), (2), ... to the stem."""
    if not path.exists():
        return path
    stem   = path.stem
    suffix = path.suffix
    parent = path.parent
    i = 1
    while True:
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
        i += 1
