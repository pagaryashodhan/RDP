"""Reconnectable GUI client for the Python RDP-like remote desktop app."""

from __future__ import annotations

import argparse
import base64
import logging
import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from PIL import Image, ImageTk
from cryptography.fernet import Fernet, InvalidToken
from tkinter import BOTH, Canvas, Label, StringVar, Tk

from utils import (
    DEFAULT_HOST,
    DEFAULT_JPEG_QUALITY,
    DEFAULT_PASSWORD,
    DEFAULT_PORT,
    DEFAULT_RECONNECT_DELAY,
    DEFAULT_USERNAME,
    DEFAULT_KDF_ITERATIONS,
    ProtocolError,
    clamp,
    create_nonce,
    decode_screen_frame,
    derive_fernet_key,
    recv_encrypted_message,
    recv_plain_message,
    send_encrypted_message,
    send_plain_message,
    SOCKET_TIMEOUT_SECONDS,
)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
LOGGER = logging.getLogger("rdp-client")
DEFAULT_CLIENT_HOST = "127.0.0.1"


@dataclass
class ConnectionState:
    """Stores the live socket and encryption key for the current session."""

    conn: socket.socket
    fernet: Fernet
    server_size: Tuple[int, int]


class RDPClient:
    """Connect to the server, receive frames, and forward local input events."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        reconnect_delay: float = DEFAULT_RECONNECT_DELAY,
    ) -> None:
        """Initialize the GUI client and its connection settings."""

        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.reconnect_delay = reconnect_delay
        self._shutdown = threading.Event()
        self._connection_lock = threading.Lock()
        self._connection: Optional[ConnectionState] = None
        self._frame_queue: "queue.Queue[tuple[Image.Image, int, int]]" = queue.Queue(maxsize=2)
        self._latest_frame: Optional[Image.Image] = None
        self._latest_size: Tuple[int, int] = (1, 1)
        self._render_size: Tuple[int, int] = (1, 1)
        self._status_text: Optional[StringVar] = None
        self._window: Optional[Tk] = None
        self._canvas: Optional[Canvas] = None
        self._image_id: Optional[int] = None
        self._photo: Optional[ImageTk.PhotoImage] = None

    def run(self) -> None:
        """Start the network worker and enter the Tkinter event loop."""

        self._window = Tk()
        self._window.title("Python RDP Client")
        self._window.geometry("1280x720")
        self._window.configure(background="#111111")
        self._window.protocol("WM_DELETE_WINDOW", self.stop)
        self._status_text = StringVar(master=self._window, value="Disconnected")

        status_bar = Label(self._window, textvariable=self._status_text, anchor="w", background="#222222", foreground="#f0f0f0")
        status_bar.pack(fill="x")

        self._canvas = Canvas(self._window, background="#000000", highlightthickness=0)
        self._canvas.pack(fill=BOTH, expand=True)
        self._canvas.bind("<Motion>", self._on_mouse_move)
        self._canvas.bind("<ButtonPress-1>", lambda event: self._on_mouse_button(event, "left", True))
        self._canvas.bind("<ButtonRelease-1>", lambda event: self._on_mouse_button(event, "left", False))
        self._canvas.bind("<ButtonPress-2>", lambda event: self._on_mouse_button(event, "middle", True))
        self._canvas.bind("<ButtonRelease-2>", lambda event: self._on_mouse_button(event, "middle", False))
        self._canvas.bind("<ButtonPress-3>", lambda event: self._on_mouse_button(event, "right", True))
        self._canvas.bind("<ButtonRelease-3>", lambda event: self._on_mouse_button(event, "right", False))
        self._canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self._canvas.bind("<KeyPress>", self._on_key_press)
        self._canvas.bind("<KeyRelease>", self._on_key_release)
        self._canvas.focus_set()

        threading.Thread(target=self._connection_worker, daemon=True).start()
        self._pump_frames()
        self._window.mainloop()

    def stop(self) -> None:
        """Request shutdown and close the active connection."""

        self._shutdown.set()
        with self._connection_lock:
            if self._connection is not None:
                try:
                    self._connection.conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self._connection.conn.close()
                except OSError:
                    pass
                self._connection = None
        if self._window is not None:
            self._window.destroy()

    def _connection_worker(self) -> None:
        """Keep reconnecting until the user exits the application."""

        while not self._shutdown.is_set():
            try:
                self._connect_once()
                self._receive_loop()
            except (ConnectionError, ProtocolError, InvalidToken, OSError, socket.error) as exc:
                LOGGER.info("Connection dropped: %s", exc)
            finally:
                self._clear_connection()
            if not self._shutdown.is_set():
                self._set_status("Disconnected, retrying...")
                time.sleep(self.reconnect_delay)

    def _connect_once(self) -> None:
        """Open a socket, complete the handshake, and store the live session."""

        conn = socket.create_connection((self.host, self.port), timeout=SOCKET_TIMEOUT_SECONDS)
        conn.settimeout(SOCKET_TIMEOUT_SECONDS)
        client_nonce = create_nonce()
        send_plain_message(conn, {"type": "hello", "username": self.username, "client_nonce": client_nonce})
        challenge = recv_plain_message(conn)
        if challenge.get("type") != "challenge":
            raise ProtocolError("Unexpected handshake response")

        salt = str(challenge.get("salt", ""))
        server_nonce = str(challenge.get("server_nonce", ""))
        iterations = int(challenge.get("iterations", DEFAULT_KDF_ITERATIONS))
        fernet = derive_fernet_key(self.password, salt, client_nonce, server_nonce, iterations)
        send_encrypted_message(conn, fernet, {"type": "auth", "username": self.username, "proof": "ready"})
        response = recv_encrypted_message(conn, fernet)
        if response.get("type") != "auth_ok":
            raise ProtocolError("Authentication rejected")

        with self._connection_lock:
            self._connection = ConnectionState(conn=conn, fernet=fernet, server_size=(1, 1))
        self._set_status("Connected")
        LOGGER.info("Connected to %s:%s", self.host, self.port)

    def _receive_loop(self) -> None:
        """Receive encrypted frames from the server until the connection stops."""

        while not self._shutdown.is_set():
            with self._connection_lock:
                connection = self._connection
            if connection is None:
                raise ConnectionError("Connection state disappeared")

            message = recv_encrypted_message(connection.conn, connection.fernet)
            message_type = message.get("type")
            if message_type == "frame":
                jpeg_bytes = base64.b64decode(message.get("jpeg", ""))
                frame = decode_screen_frame(jpeg_bytes)
                width = int(message.get("width", frame.width))
                height = int(message.get("height", frame.height))
                self._store_frame(frame, width, height)
            elif message_type == "ping":
                continue

    def _store_frame(self, frame: Image.Image, width: int, height: int) -> None:
        """Keep only the newest frame so the GUI stays responsive."""

        self._latest_frame = frame
        self._latest_size = (max(1, width), max(1, height))
        if self._frame_queue.full():
            try:
                self._frame_queue.get_nowait()
            except queue.Empty:
                pass
        try:
            self._frame_queue.put_nowait((frame, width, height))
        except queue.Full:
            pass

    def _pump_frames(self) -> None:
        """Render the newest frame in the Tkinter event loop."""

        if self._window is None or self._canvas is None:
            return

        try:
            while True:
                frame, width, height = self._frame_queue.get_nowait()
                self._render_frame(frame, width, height)
        except queue.Empty:
            pass

        if not self._shutdown.is_set():
            self._window.after(16, self._pump_frames)

    def _render_frame(self, frame: Image.Image, width: int, height: int) -> None:
        """Draw the latest frame, scaling it to fit the current window size."""

        if self._canvas is None:
            return

        canvas_width = max(1, self._canvas.winfo_width())
        canvas_height = max(1, self._canvas.winfo_height())
        scale = min(canvas_width / float(width), canvas_height / float(height))
        render_width = max(1, int(width * scale))
        render_height = max(1, int(height * scale))
        resized = frame.resize((render_width, render_height), Image.LANCZOS)
        self._photo = ImageTk.PhotoImage(resized)
        self._render_size = (render_width, render_height)
        self._canvas.delete("frame")
        offset_x = (canvas_width - render_width) // 2
        offset_y = (canvas_height - render_height) // 2
        self._canvas.create_image(offset_x, offset_y, image=self._photo, anchor="nw", tags="frame")

    def _on_mouse_move(self, event) -> None:
        """Send mouse movement events to the server using the current frame scale."""

        x, y = self._map_event_position(event.x, event.y)
        self._send_control({"type": "mouse_move", "x": x, "y": y})

    def _on_mouse_button(self, event, button: str, pressed: bool) -> None:
        """Send mouse button presses and releases to the server."""

        x, y = self._map_event_position(event.x, event.y)
        self._send_control({"type": "mouse_move", "x": x, "y": y})
        self._send_control({"type": "mouse_button", "button": button, "pressed": pressed})

    def _on_mouse_wheel(self, event) -> None:
        """Send mouse wheel events to the server."""

        delta = int(clamp(event.delta // 120, -10, 10))
        self._send_control({"type": "mouse_scroll", "dx": 0, "dy": delta})

    def _on_key_press(self, event) -> None:
        """Send key press events to the server."""

        self._send_control({"type": "key_press", "key": event.keysym, "char": event.char or ""})

    def _on_key_release(self, event) -> None:
        """Send key release events to the server."""

        self._send_control({"type": "key_release", "key": event.keysym, "char": event.char or ""})

    def _map_event_position(self, x: int, y: int) -> Tuple[int, int]:
        """Convert canvas coordinates into original server screen coordinates."""

        frame_width, frame_height = self._latest_size
        render_width, render_height = self._render_size
        if render_width <= 0 or render_height <= 0:
            return 0, 0

        canvas_width = max(1, self._canvas.winfo_width() if self._canvas else render_width)
        canvas_height = max(1, self._canvas.winfo_height() if self._canvas else render_height)
        offset_x = (canvas_width - render_width) // 2
        offset_y = (canvas_height - render_height) // 2
        local_x = clamp(x - offset_x, 0, render_width)
        local_y = clamp(y - offset_y, 0, render_height)
        mapped_x = int((local_x / float(render_width)) * frame_width)
        mapped_y = int((local_y / float(render_height)) * frame_height)
        return mapped_x, mapped_y

    def _send_control(self, message: dict) -> None:
        """Transmit an input event if the client is currently connected."""

        with self._connection_lock:
            connection = self._connection
        if connection is None:
            return
        try:
            send_encrypted_message(connection.conn, connection.fernet, message)
        except (ConnectionError, OSError, ProtocolError, InvalidToken):
            self._clear_connection()

    def _clear_connection(self) -> None:
        """Release the active connection so the reconnect loop can try again."""

        with self._connection_lock:
            if self._connection is not None:
                try:
                    self._connection.conn.close()
                except OSError:
                    pass
            self._connection = None
        self._set_status("Disconnected")

    def _set_status(self, text: str) -> None:
        """Update the status bar text from any thread."""

        if self._window is None or self._status_text is None:
            return
        self._window.after(0, lambda: self._status_text.set(text))


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for the client entry point."""

    parser = argparse.ArgumentParser(description="Python RDP-like client")
    parser.add_argument("--host", default=DEFAULT_CLIENT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--reconnect-delay", type=float, default=DEFAULT_RECONNECT_DELAY)
    return parser


def main() -> None:
    """Run the GUI client from the command line."""

    args = build_parser().parse_args()
    client = RDPClient(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        reconnect_delay=args.reconnect_delay,
    )
    client.run()


if __name__ == "__main__":
    main()
