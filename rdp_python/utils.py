"""Shared utilities for the Python RDP-like remote desktop app."""

from __future__ import annotations

import base64
import json
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Dict, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageGrab
from mss import mss

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5905
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "changeme"
DEFAULT_JPEG_QUALITY = 60
DEFAULT_FPS = 8
DEFAULT_RECONNECT_DELAY = 2.0
DEFAULT_KDF_ITERATIONS = 200_000
SOCKET_TIMEOUT_SECONDS = 5.0
MAX_FRAME_SIZE = 25 * 1024 * 1024


class ProtocolError(RuntimeError):
    """Raised when an incoming message cannot be decoded or verified."""


@dataclass(frozen=True)
class HandshakeChallenge:
    """Represents the plaintext challenge exchanged before encrypted traffic starts."""

    salt: str
    server_nonce: str
    iterations: int


def create_nonce() -> str:
    """Return a unique nonce for a handshake exchange."""

    return uuid.uuid4().hex


def json_dumps(data: Dict[str, Any]) -> bytes:
    """Serialize a dictionary to compact UTF-8 JSON bytes."""

    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def json_loads(payload: bytes) -> Dict[str, Any]:
    """Deserialize UTF-8 JSON bytes into a dictionary."""

    return json.loads(payload.decode("utf-8"))


def derive_fernet_key(password: str, salt_b64: str, client_nonce: str, server_nonce: str, iterations: int) -> Fernet:
    """Derive a Fernet instance from the shared password and handshake nonces."""

    salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + client_nonce.encode("utf-8") + server_nonce.encode("utf-8"),
        iterations=iterations,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def send_raw(sock: socket.socket, payload: bytes) -> None:
    """Send a length-prefixed payload over a socket."""

    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Receive exactly the requested number of bytes from a socket."""

    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ConnectionError("Socket closed while receiving data")
        chunks.extend(part)
    return bytes(chunks)


def recv_raw(sock: socket.socket) -> bytes:
    """Read a length-prefixed payload from a socket."""

    header = recv_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    if size < 0 or size > MAX_FRAME_SIZE:
        raise ProtocolError(f"Invalid payload size: {size}")
    return recv_exact(sock, size)


def send_plain_message(sock: socket.socket, message: Dict[str, Any]) -> None:
    """Send an unencrypted JSON message."""

    send_raw(sock, json_dumps(message))


def recv_plain_message(sock: socket.socket) -> Dict[str, Any]:
    """Receive an unencrypted JSON message."""

    return json_loads(recv_raw(sock))


def send_encrypted_message(sock: socket.socket, fernet: Fernet, message: Dict[str, Any]) -> None:
    """Encrypt and send a JSON message."""

    send_raw(sock, fernet.encrypt(json_dumps(message)))


def recv_encrypted_message(sock: socket.socket, fernet: Fernet) -> Dict[str, Any]:
    """Receive and decrypt a JSON message."""

    try:
        payload = recv_raw(sock)
        return json_loads(fernet.decrypt(payload))
    except Exception as exc:  # pragma: no cover - defensive network guard
        raise ProtocolError(f"Failed to read encrypted message: {exc}") from exc


def encode_screen_frame(image: Image.Image, jpeg_quality: int) -> bytes:
    """Compress a screenshot frame into JPEG bytes."""

    buffer = BytesIO()
    if image.mode != "RGB":
        image = image.convert("RGB")
    image.save(buffer, format="JPEG", quality=jpeg_quality, optimize=True)
    return buffer.getvalue()


def capture_screen_frame(monitor_index: int = 1, jpeg_quality: int = DEFAULT_JPEG_QUALITY) -> Tuple[bytes, int, int]:
    """Capture the primary screen and return JPEG bytes plus its dimensions."""

    try:
        with mss() as screen_source:
            monitor = screen_source.monitors[monitor_index]
            shot = screen_source.grab(monitor)
            image = Image.frombytes("RGB", shot.size, shot.rgb)
    except Exception:
        image = ImageGrab.grab()

    encoded = encode_screen_frame(image, jpeg_quality)
    return encoded, image.width, image.height


def decode_screen_frame(jpeg_bytes: bytes) -> Image.Image:
    """Decode JPEG bytes into a Pillow image."""

    return Image.open(BytesIO(jpeg_bytes)).convert("RGB")


def clamp(value: float, minimum: float, maximum: float) -> float:
    """Clamp a numeric value into a safe range."""

    return max(minimum, min(maximum, value))


def now_seconds() -> float:
    """Return the current time in seconds for lightweight timing logic."""

    return time.time()
