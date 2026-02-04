"""
TLS Fake Message Generators

Functions for generating fake TLS handshake messages:
- Fake Certificate messages
- Fake ServerHello messages
- Fake handshake message injection
"""

from __future__ import annotations

import struct
import os
import logging

LOG = logging.getLogger(__name__)


def create_fake_certificate_message() -> bytes:
    """
    Create a fake Certificate handshake message.

    Structure:
    - TLS record header (type=22, version=0x0303, length)
    - Handshake header (type=11 Certificate, length)
    - Empty certificate data

    Returns:
        Complete TLS record with fake Certificate message
    """
    fake_cert_data = b"\x00\x00\x00"
    cert_msg = b"\x0b"  # Handshake type: Certificate
    cert_msg += struct.pack("!I", len(fake_cert_data))[1:]  # 3-byte length
    cert_msg += fake_cert_data

    tls_record = b"\x16"  # Content type: Handshake
    tls_record += b"\x03\x03"  # Version: TLS 1.2
    tls_record += struct.pack("!H", len(cert_msg))
    tls_record += cert_msg
    return tls_record


def create_fake_server_hello() -> bytes:
    """
    Create a fake ServerHello message.

    Structure:
    - TLS record header (type=22, version=0x0303, length)
    - Handshake header (type=2 ServerHello, length)
    - ServerHello data (version, random, session_id, cipher_suite, compression)

    Returns:
        Complete TLS record with fake ServerHello message
    """
    server_hello = b"\x02"  # Handshake type: ServerHello
    hello_data = b"\x03\x03"  # Version: TLS 1.2
    hello_data += os.urandom(32)  # Random
    hello_data += b"\x00"  # Session ID length (0)
    hello_data += b"\x00\x35"  # Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA
    hello_data += b"\x00"  # Compression method: null
    hello_data += b"\x00\x00"  # Extensions length (0)

    server_hello += struct.pack("!I", len(hello_data))[1:]  # 3-byte length
    server_hello += hello_data

    tls_record = b"\x16"  # Content type: Handshake
    tls_record += b"\x03\x03"  # Version: TLS 1.2
    tls_record += struct.pack("!H", len(server_hello))
    tls_record += server_hello
    return tls_record


def add_fake_handshake_messages(payload: bytes) -> bytes:
    """
    Add fake handshake messages after the original payload.

    Appends fake Certificate and ServerHello messages to confuse DPI
    that expects specific handshake sequences.

    Args:
        payload: Original TLS ClientHello payload

    Returns:
        Combined payload with fake messages appended
    """
    fake_cert = create_fake_certificate_message()
    fake_server_hello = create_fake_server_hello()
    return payload + fake_server_hello + fake_cert
