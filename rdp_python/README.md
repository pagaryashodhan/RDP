# Python RDP-like Remote Desktop

A small Python 3 remote desktop prototype that uses sockets, encrypted framed messages, JPEG-compressed screen capture, and threaded input handling.

## Features

- Socket-based server and client
- Real-time screen capture and streaming
- Mouse and keyboard control from the client
- JPEG compression for frames
- Threaded communication loops
- Username/password authentication
- Encrypted traffic using Fernet symmetric encryption
- Automatic client reconnection

## Files

- `server.py`: starts the remote desktop server and relays input to the host machine
- `client.py`: opens a GUI viewer/controller that reconnects automatically
- `utils.py`: shared protocol, encryption, and screen-capture helpers

## Required Libraries

Install these packages:

- `cryptography`
- `mss`
- `Pillow`
- `pynput`

## Installation

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks activation, run this once in the current session:

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
```

## Server Setup

1. Open a terminal on the machine you want to control.
2. Activate the virtual environment.
3. Start the server:

```powershell
python server.py --host 0.0.0.0 --port 5905 --username admin --password changeme
```

4. Keep the server machine unlocked and allow the Python process through the local firewall if needed.

## Client Setup

1. Open a terminal on the machine you will use to connect.
2. Activate the same virtual environment or install the same dependencies.
3. Start the client with the same credentials and server address:

```powershell
python client.py --host 192.168.1.50 --port 5905 --username admin --password changeme
```

## Usage Notes

- The client window will reconnect automatically if the server disconnects.
- The current implementation is a practical prototype, not a hardened production RDP replacement.
- Screen frames are JPEG-compressed before encryption to reduce bandwidth.
- The server accepts one active client session at a time.

## Security Notes

- Passwords are not sent in clear text after the initial handshake.
- The session key is derived from the shared password plus handshake nonces.
- For real deployments, use TLS and stronger identity verification in addition to the shared-secret scheme.

## Troubleshooting

- If the client exits with `ModuleNotFoundError: No module named '_tkinter'`, install a Python build that includes Tk support. On macOS, the python.org installer is the simplest option.
- If mouse or keyboard control does not work, make sure the server process has permission to inject input on the host machine.
- If the screen stays black, check that the user session on the server is unlocked and that screen capture is permitted.
- If the client cannot connect, verify the host IP, port, and Windows firewall rules.
