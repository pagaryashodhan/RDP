"""Threaded encrypted screen server for the Python RDP-like remote desktop app."""

from __future__ import annotations

import argparse
import base64
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from pynput import keyboard as pynput_keyboard
from pynput import mouse as pynput_mouse

from utils import (
    DEFAULT_FPS,
    DEFAULT_HOST,
    DEFAULT_JPEG_QUALITY,
    DEFAULT_PASSWORD,
    DEFAULT_PORT,
    DEFAULT_USERNAME,
    DEFAULT_KDF_ITERATIONS,
    DEFAULT_RECONNECT_DELAY,
    HandshakeChallenge,
    ProtocolError,
    capture_screen_frame,
    clamp,
    create_nonce,
    derive_fernet_key,
    recv_encrypted_message,
    recv_plain_message,
    send_encrypted_message,
    send_plain_message,
    SOCKET_TIMEOUT_SECONDS,
)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
LOGGER = logging.getLogger("rdp-server")


@dataclass
class ClientSession:
    """Holds the active client connection and its encryption state."""

    conn: socket.socket
    address: tuple[str, int]
    fernet: Fernet
    stop_event: threading.Event


class RDPServer:
    """Accept clients, stream screen frames, and apply remote input events."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        fps: int = DEFAULT_FPS,
        jpeg_quality: int = DEFAULT_JPEG_QUALITY,
    ) -> None:
        """Initialize the server with bind settings and access credentials."""

        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.fps = max(1, fps)
        self.jpeg_quality = max(10, min(95, jpeg_quality))
        self._server_socket: Optional[socket.socket] = None
        self._shutdown = threading.Event()
        self._session_lock = threading.Lock()
        self._session: Optional[ClientSession] = None
        self._mouse_controller = pynput_mouse.Controller()
        self._keyboard_controller = pynput_keyboard.Controller()
        self._pressed_keys: set[str] = set()

    def serve_forever(self) -> None:
        """Start listening for a single active client and handle reconnections."""

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        LOGGER.info("Server listening on %s:%s", self.host, self.port)

        try:
            while not self._shutdown.is_set():
                try:
                    conn, address = self._server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._shutdown.is_set():
                        break
                    raise

                LOGGER.info("Incoming connection from %s:%s", address[0], address[1])
                threading.Thread(target=self._handle_connection, args=(conn, address), daemon=True).start()
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the server and close any active connection."""

        self._shutdown.set()
        with self._session_lock:
            if self._session is not None:
                self._session.stop_event.set()
                try:
                    self._session.conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self._session.conn.close()
                except OSError:
                    pass
                self._session = None
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def _handle_connection(self, conn: socket.socket, address: tuple[str, int]) -> None:
        """Perform handshake, then start the screen and input worker loops."""

        conn.settimeout(SOCKET_TIMEOUT_SECONDS)
        stop_event = threading.Event()

        try:
            fernet = self._perform_handshake(conn)
            session = ClientSession(conn=conn, address=address, fernet=fernet, stop_event=stop_event)
            with self._session_lock:
                if self._session is not None:
                    LOGGER.info("Replacing existing client session")
                    self._session.stop_event.set()
                    try:
                        self._session.conn.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        self._session.conn.close()
                    except OSError:
                        pass
                self._session = session

            LOGGER.info("Client authenticated from %s:%s", address[0], address[1])
            screen_thread = threading.Thread(target=self._screen_sender_loop, args=(session,), daemon=True)
            input_thread = threading.Thread(target=self._input_receiver_loop, args=(session,), daemon=True)
            screen_thread.start()
            input_thread.start()
            screen_thread.join()
            input_thread.join()
        except (ConnectionError, ProtocolError, InvalidToken, OSError) as exc:
            LOGGER.info("Connection with %s:%s ended: %s", address[0], address[1], exc)
        finally:
            stop_event.set()
            try:
                conn.close()
            except OSError:
                pass
            with self._session_lock:
                if self._session is not None and self._session.conn is conn:
                    self._session = None

    def _perform_handshake(self, conn: socket.socket) -> Fernet:
        """Authenticate the client and derive the encrypted channel key."""

        hello = recv_plain_message(conn)
        if hello.get("type") != "hello":
            raise ProtocolError("Expected hello message")
        if hello.get("username") != self.username:
            send_plain_message(conn, {"type": "error", "message": "Invalid username"})
            raise ProtocolError("Username rejected")

        client_nonce = str(hello.get("client_nonce", ""))
        if not client_nonce:
            raise ProtocolError("Missing client nonce")

        salt = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
        challenge = HandshakeChallenge(salt=salt, server_nonce=create_nonce(), iterations=DEFAULT_KDF_ITERATIONS)
        send_plain_message(
            conn,
            {
                "type": "challenge",
                "salt": challenge.salt,
                "server_nonce": challenge.server_nonce,
                "iterations": challenge.iterations,
            },
        )

        fernet = derive_fernet_key(self.password, challenge.salt, client_nonce, challenge.server_nonce, challenge.iterations)
        auth = recv_encrypted_message(conn, fernet)
        if auth.get("type") != "auth" or auth.get("username") != self.username:
            raise ProtocolError("Authentication payload rejected")
        send_encrypted_message(conn, fernet, {"type": "auth_ok"})
        return fernet

    def _screen_sender_loop(self, session: ClientSession) -> None:
        """Capture the desktop and send compressed frames at a fixed rate."""

        frame_delay = 1.0 / float(self.fps)
        while not (session.stop_event.is_set() or self._shutdown.is_set()):
            started = time.perf_counter()
            try:
                jpeg_bytes, width, height = capture_screen_frame(jpeg_quality=self.jpeg_quality)
                send_encrypted_message(
                    session.conn,
                    session.fernet,
                    {
                        "type": "frame",
                        "width": width,
                        "height": height,
                        "jpeg": base64.b64encode(jpeg_bytes).decode("ascii"),
                    },
                )
            except (ConnectionError, OSError, ProtocolError, InvalidToken) as exc:
                LOGGER.info("Stopping screen stream for %s:%s: %s", session.address[0], session.address[1], exc)
                session.stop_event.set()
                break
            elapsed = time.perf_counter() - started
            if elapsed < frame_delay:
                time.sleep(frame_delay - elapsed)

    def _input_receiver_loop(self, session: ClientSession) -> None:
        """Receive encrypted input events and replay them on the server machine."""

        while not (session.stop_event.is_set() or self._shutdown.is_set()):
            try:
                message = recv_encrypted_message(session.conn, session.fernet)
            except (ConnectionError, OSError, ProtocolError, InvalidToken) as exc:
                LOGGER.info("Stopping input relay for %s:%s: %s", session.address[0], session.address[1], exc)
                session.stop_event.set()
                break
            self._dispatch_input(message)

    def _dispatch_input(self, message: dict) -> None:
        """Apply a single mouse or keyboard event to the server desktop."""

        message_type = message.get("type")
        if message_type == "mouse_move":
            self._mouse_controller.position = (int(message.get("x", 0)), int(message.get("y", 0)))
            return
        if message_type == "mouse_button":
            self._handle_mouse_button(message)
            return
        if message_type == "mouse_scroll":
            self._mouse_controller.scroll(int(message.get("dx", 0)), int(message.get("dy", 0)))
            return
        if message_type == "key_press":
            self._handle_key_press(message)
            return
        if message_type == "key_release":
            self._handle_key_release(message)
            return

    def _handle_mouse_button(self, message: dict) -> None:
        """Press or release a mouse button requested by the client."""

        button_name = str(message.get("button", "left")).lower()
        pressed = bool(message.get("pressed", False))
        button = getattr(pynput_mouse.Button, button_name, pynput_mouse.Button.left)
        if pressed:
            self._mouse_controller.press(button)
        else:
            self._mouse_controller.release(button)

    def _handle_key_press(self, message: dict) -> None:
        """Press a key or character on the local machine."""

        key_value = self._resolve_key(message)
        key_id = self._key_id(message)
        if key_id in self._pressed_keys:
            return
        self._pressed_keys.add(key_id)
        self._keyboard_controller.press(key_value)

    def _handle_key_release(self, message: dict) -> None:
        """Release a key or character on the local machine."""

        key_value = self._resolve_key(message)
        key_id = self._key_id(message)
        self._pressed_keys.discard(key_id)
        self._keyboard_controller.release(key_value)

    def _resolve_key(self, message: dict):
        """Convert a client key name into a pynput key object."""

        key_name = str(message.get("key", ""))
        char_value = str(message.get("char", ""))
        if key_name:
            normalized_name = self._normalize_key_name(key_name)
            if hasattr(pynput_keyboard.Key, normalized_name):
                return getattr(pynput_keyboard.Key, normalized_name)
        if char_value:
            return pynput_keyboard.KeyCode.from_char(char_value)
        if len(key_name) == 1:
            return pynput_keyboard.KeyCode.from_char(key_name)
        return pynput_keyboard.Key.space

    def _normalize_key_name(self, key_name: str) -> str:
        """Map Tk keysyms to pynput key attribute names."""

        aliases = {
            "backspace": "backspace",
            "caps_lock": "caps_lock",
            "control_l": "ctrl_l",
            "control_r": "ctrl_r",
            "delete": "delete",
            "down": "down",
            "end": "end",
            "escape": "esc",
            "home": "home",
            "insert": "insert",
            "left": "left",
            "page_down": "page_down",
            "page_up": "page_up",
            "return": "enter",
            "right": "right",
            "shift_l": "shift_l",
            "shift_r": "shift_r",
            "space": "space",
            "tab": "tab",
            "up": "up",
        }

        normalized = key_name.lower().replace(" ", "_")
        return aliases.get(normalized, normalized)

    def _key_id(self, message: dict) -> str:
        """Build a stable identifier for tracking held-down keys."""

        return f"{message.get('key', '')}:{message.get('char', '')}"


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for the server entry point."""

    parser = argparse.ArgumentParser(description="Python RDP-like server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS)
    parser.add_argument("--jpeg-quality", type=int, default=DEFAULT_JPEG_QUALITY)
    return parser


def main() -> None:
    """Run the remote desktop server from the command line."""

    args = build_parser().parse_args()
    server = RDPServer(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        fps=args.fps,
        jpeg_quality=args.jpeg_quality,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Server shutdown requested by user")
        server.stop()


if __name__ == "__main__":
    main()
