"""
securechat/crypto.py
────────────────────
Cryptographic primitives for SecureChat.

  Key derivation : PBKDF2-HMAC-SHA256, 310 000 iterations (OWASP 2023 minimum)
  Encryption     : AES-256-GCM  (authenticated, no separate MAC needed)
  Nonce          : 12 bytes, random per message (NIST SP 800-38D)
  Wire format    : [2-byte big-endian length][nonce(12)][ciphertext+tag(16)]

All secrets live only in RAM. Nothing is written to disk.
"""

import os
import struct
import secrets
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ── Constants ────────────────────────────────────────────────────────────────
NONCE_LEN      = 12          # bytes — GCM standard
TAG_LEN        = 16          # bytes — GCM authentication tag (appended by AESGCM)
KEY_LEN        = 32          # bytes — AES-256
PBKDF2_ITERS   = 310_000     # OWASP 2023 recommendation for PBKDF2-SHA256
KDF_SALT       = b"SecureChat_v2_KDF_Salt_2024\x00"   # static domain separator

# Maximum plaintext that can be sent in one frame (prevents memory bombs)
MAX_PLAINTEXT  = 4096        # bytes


# ── Key derivation ───────────────────────────────────────────────────────────

def derive_key(session_code: str) -> bytes:
    """
    Derive a 256-bit AES key from the human-readable session code.
    Uses PBKDF2-HMAC-SHA256 with a fixed domain-separation salt.
    Returns 32 raw bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=KDF_SALT,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(session_code.encode("utf-8"))


# ── Session code generation ───────────────────────────────────────────────────

def generate_session_code() -> str:
    """
    Generate a cryptographically random session code.
    Format: XXXX-XXXX-XXXX  (Base32 subset — unambiguous characters)
    Entropy: ~46 bits (sufficient for a single-use one-time code with 15-min window)
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/1/0 confusion
    def segment(n=4):
        return "".join(secrets.choice(alphabet) for _ in range(n))
    return f"{segment()}-{segment()}-{segment()}"


# ── Encryption / Decryption ───────────────────────────────────────────────────

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns: nonce (12 bytes) || ciphertext+tag
    """
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)   # no additional data
    return nonce + ct


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt and authenticate AES-256-GCM ciphertext.
    Raises cryptography.exceptions.InvalidTag on authentication failure.
    """
    nonce = ciphertext[:NONCE_LEN]
    ct    = ciphertext[NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ── Wire framing ─────────────────────────────────────────────────────────────
# Frame layout:  [uint16-BE length of encrypted blob] [encrypted blob]
# The length field covers only the encrypted bytes (nonce + ct + tag).

HEADER_FMT  = "!H"          # network-byte-order unsigned short
HEADER_LEN  = struct.calcsize(HEADER_FMT)   # 2 bytes


def pack_frame(encrypted_blob: bytes) -> bytes:
    """Prepend a 2-byte length header to an encrypted blob."""
    if len(encrypted_blob) > 65535:
        raise ValueError("Message too large to frame")
    return struct.pack(HEADER_FMT, len(encrypted_blob)) + encrypted_blob


def unpack_frame_from_socket(sock) -> bytes:
    """
    Read exactly one frame from a blocking socket.
    Returns the raw encrypted blob (nonce + ct + tag).
    Raises ConnectionError if the peer closes the connection.
    """
    header = _recv_exact(sock, HEADER_LEN)
    (blob_len,) = struct.unpack(HEADER_FMT, header)
    return _recv_exact(sock, blob_len)


def _recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from sock, blocking until available."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Peer disconnected")
        buf += chunk
    return buf


# ── Handshake tokens ─────────────────────────────────────────────────────────

HANDSHAKE_HELLO   = b"SECURECHAT_HELLO_v2"
HANDSHAKE_CONFIRM = b"SECURECHAT_CONFIRM_v2"
HANDSHAKE_REJECT  = b"SECURECHAT_REJECT_v2"
