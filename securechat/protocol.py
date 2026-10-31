"""
securechat/protocol.py
──────────────────────
Message types and handshake state machine.

Every message sent over the wire is:
  1. Serialised to JSON  →  bytes
  2. Encrypted with AES-256-GCM
  3. Length-framed (2-byte big-endian header)

Message schema:
  { "t": <type>, "ts": <unix_timestamp_float>, "body": <str | null>, "from": <str | null> }

Types
  MSG   – normal chat message
  SYS   – system/status notice (shown in grey)
  PING  – keepalive (not shown)
  PONG  – keepalive reply (not shown)
  BYE   – orderly close notification
  JOIN  – join-request from guest (sent after handshake, before session starts)
  ADMIT – host admits the guest (guest proceeds to session)
  DENY  – host denies the guest
"""

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from . import crypto


class MsgType(str, Enum):
    MSG   = "MSG"
    SYS   = "SYS"
    PING  = "PING"
    PONG  = "PONG"
    BYE   = "BYE"
    # Multi-user lobby protocol
    JOIN  = "JOIN"    # guest → host: "I want to join, my nickname is X"
    ADMIT = "ADMIT"   # host → guest: "you are in, room has N users"
    DENY  = "DENY"    # host → guest: "request rejected"
    LEAVE = "LEAVE"   # broadcast: a user left


@dataclass
class Message:
    mtype:  MsgType
    body:   Optional[str]
    ts:     float = 0.0
    sender: Optional[str] = None   # nickname of sender, filled in by host relay

    def __post_init__(self):
        if self.ts == 0.0:
            self.ts = time.time()


# ── Serialisation ────────────────────────────────────────────────────────────

def encode_message(msg: Message) -> bytes:
    return json.dumps({
        "t":    msg.mtype.value,
        "ts":   msg.ts,
        "body": msg.body,
        "from": msg.sender,
    }, ensure_ascii=False).encode("utf-8")


def decode_message(raw: bytes) -> Message:
    d = json.loads(raw.decode("utf-8"))
    return Message(
        mtype=MsgType(d["t"]),
        body=d.get("body"),
        ts=float(d.get("ts", 0.0)),
        sender=d.get("from"),
    )


# ── Send / Receive helpers ───────────────────────────────────────────────────

def send_msg(sock, msg: Message, key: bytes) -> None:
    """Encode → encrypt → frame → send."""
    raw       = encode_message(msg)
    encrypted = crypto.encrypt(raw, key)
    frame     = crypto.pack_frame(encrypted)
    sock.sendall(frame)


def recv_msg(sock, key: bytes) -> Message:
    """Receive → decrypt → decode. Blocks until a full frame arrives."""
    blob = crypto.unpack_frame_from_socket(sock)
    raw  = crypto.decrypt(blob, key)
    return decode_message(raw)


# ── Handshake ────────────────────────────────────────────────────────────────

def perform_handshake_host(sock, key: bytes) -> bool:
    """
    Host side of the handshake.
    Waits for HELLO, replies with CONFIRM or REJECT.
    Returns True if handshake succeeded.
    """
    try:
        blob = crypto.unpack_frame_from_socket(sock)
        try:
            plaintext = crypto.decrypt(blob, key)
        except Exception:
            _send_raw_token(sock, crypto.HANDSHAKE_REJECT, key)
            return False

        if plaintext != crypto.HANDSHAKE_HELLO:
            _send_raw_token(sock, crypto.HANDSHAKE_REJECT, key)
            return False

        _send_raw_token(sock, crypto.HANDSHAKE_CONFIRM, key)
        return True
    except Exception:
        return False


def perform_handshake_peer(sock, key: bytes) -> bool:
    """
    Peer side of the handshake.
    Sends HELLO, waits for CONFIRM.
    Returns True if handshake succeeded.
    """
    try:
        _send_raw_token(sock, crypto.HANDSHAKE_HELLO, key)
        blob      = crypto.unpack_frame_from_socket(sock)
        plaintext = crypto.decrypt(blob, key)
        return plaintext == crypto.HANDSHAKE_CONFIRM
    except Exception:
        return False


def _send_raw_token(sock, token: bytes, key: bytes) -> None:
    encrypted = crypto.encrypt(token, key)
    frame     = crypto.pack_frame(encrypted)
    sock.sendall(frame)
