"""
SMTP Protocol Generators

Utilities for generating realistic SMTP email conversations
for protocol mimicry attacks.
"""

import base64
import random
import time
from typing import List


def _sanitize_email(value: str, default: str) -> str:
    from .protocol_utils import sanitize_token

    v = sanitize_token(value or "", default).strip()
    # Remove angle brackets if user supplied them.
    if v.startswith("<") and v.endswith(">") and len(v) > 2:
        v = v[1:-1].strip()
    return v or default


def generate_smtp_conversation(
    payload: bytes, server: str, sender: str, recipient: str, use_tls: bool
) -> List[bytes]:
    """Generate complete SMTP conversation."""
    from .protocol_utils import sanitize_hostname

    server = sanitize_hostname(server or "", "mail.example.com")
    sender = _sanitize_email(sender, "user@example.com")
    recipient = _sanitize_email(recipient, "recipient@example.com")

    packets = []
    packets.append(f"220 {server} ESMTP Ready\r\n".encode("utf-8"))
    packets.append("EHLO client.example.com\r\n".encode("utf-8"))
    capabilities = [
        f"250-{server} Hello client.example.com",
        "250-SIZE 52428800",
        "250-8BITMIME",
        "250-PIPELINING",
        "250-AUTH PLAIN LOGIN",
        "250-STARTTLS" if use_tls else "",
        "250 HELP",
    ]
    capabilities = [cap for cap in capabilities if cap]
    packets.append("\r\n".join(capabilities).encode("utf-8") + b"\r\n")
    if use_tls:
        packets.append(b"STARTTLS\r\n")
        packets.append(b"220 2.0.0 Ready to start TLS\r\n")
        packets.append(b"TLS_HANDSHAKE_SIMULATION")
    auth_string = base64.b64encode(f"\x00{sender}\x00password123".encode()).decode("ascii")
    packets.append(f"AUTH PLAIN {auth_string}\r\n".encode("utf-8"))
    packets.append(b"235 2.7.0 Authentication successful\r\n")
    packets.append(f"MAIL FROM:<{sender}>\r\n".encode("utf-8"))
    packets.append(b"250 2.1.0 OK\r\n")
    packets.append(f"RCPT TO:<{recipient}>\r\n".encode("utf-8"))
    packets.append(b"250 2.1.5 OK\r\n")
    packets.append(b"DATA\r\n")
    packets.append(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    email_content = generate_email_content(payload, sender, recipient)
    packets.append(email_content)
    packets.append(b".\r\n")
    packets.append(b"250 2.0.0 OK: queued\r\n")
    packets.append(b"QUIT\r\n")
    packets.append(b"221 2.0.0 Bye\r\n")
    return packets


def generate_email_content(payload: bytes, sender: str, recipient: str) -> bytes:
    """Generate email content with embedded payload."""
    encoded_payload = base64.b64encode(payload).decode("ascii")
    encoded_lines = []
    for i in range(0, len(encoded_payload), 76):
        encoded_lines.append(encoded_payload[i : i + 76])
    boundary = f"boundary_{random.randint(100000, 999999)}"
    date_str = time.strftime("%a, %d %b %Y %H:%M:%S %z")

    # SMTP DATA should be CRLF terminated.
    lines = [
        f"From: {sender}",
        f"To: {recipient}",
        "Subject: Document Attachment",
        f"Date: {date_str}",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        "",
        f"--{boundary}",
        "Content-Type: text/plain; charset=UTF-8",
        "Content-Transfer-Encoding: 7bit",
        "",
        "Please find the attached document.",
        "",
        "Best regards,",
        "User",
        "",
        f"--{boundary}",
        "Content-Type: application/octet-stream",
        "Content-Transfer-Encoding: base64",
        'Content-Disposition: attachment; filename="document.dat"',
        "",
        "\r\n".join(encoded_lines),
        "",
        f"--{boundary}--",
        "",
    ]
    return ("\r\n".join(lines)).encode("utf-8") + b"\r\n"
