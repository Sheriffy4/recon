"""
FTP Protocol Generators

Utilities for generating realistic FTP file transfer conversations
for protocol mimicry attacks.
"""

import hashlib
import random
from typing import List


def _sanitize_ftp_field(value: str, default: str) -> str:
    # Prevent CRLF injection into FTP command lines / banners.
    from .protocol_utils import sanitize_token

    v = sanitize_token(value or "", default)
    return v.replace(" ", "") or default


def generate_ftp_conversation(
    payload: bytes, server: str, username: str, password: str, mode: str
) -> List[bytes]:
    """Generate complete FTP conversation."""
    server = _sanitize_ftp_field(server, "ftp.example.com")
    username = _sanitize_ftp_field(username, "anonymous")
    # Passwords may contain spaces, but we remove control chars anyway.
    from .protocol_utils import sanitize_token

    password = sanitize_token(password or "", "user@example.com")
    mode = (mode or "binary").strip().lower()

    packets = []
    packets.append(f"220 {server} FTP server ready\r\n".encode("utf-8"))
    packets.append(f"USER {username}\r\n".encode("utf-8"))
    if username == "anonymous":
        packets.append(b"331 Please specify the password\r\n")
    else:
        packets.append(b"331 Password required\r\n")
    packets.append(f"PASS {password}\r\n".encode("utf-8"))
    packets.append(b"230 Login successful\r\n")
    if mode == "binary":
        packets.append(b"TYPE I\r\n")
        packets.append(b"200 Switching to Binary mode\r\n")
    else:
        packets.append(b"TYPE A\r\n")
        packets.append(b"200 Switching to ASCII mode\r\n")
    packets.append(b"PASV\r\n")
    data_port = random.randint(20000, 30000)
    ip_parts = "192,168,1,100"
    port_high = data_port // 256
    port_low = data_port % 256
    packets.append(
        f"227 Entering Passive Mode ({ip_parts},{port_high},{port_low})\r\n".encode("utf-8")
    )
    filename = f"data_{hashlib.md5(payload).hexdigest()[:8]}.bin"
    packets.append(f"STOR {filename}\r\n".encode("utf-8"))
    packets.append(b"150 Ok to send data\r\n")
    packets.append(b"DATA_CONNECTION_ESTABLISHED\r\n")
    packets.append(payload)
    packets.append(b"DATA_CONNECTION_CLOSED\r\n")
    packets.append(b"226 Transfer complete\r\n")
    packets.append(b"QUIT\r\n")
    packets.append(b"221 Goodbye\r\n")
    return packets
