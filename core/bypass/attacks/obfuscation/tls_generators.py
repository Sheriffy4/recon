"""
TLS Protocol Generators

Utilities for generating realistic TLS handshake messages and encrypted data
for protocol mimicry attacks.
"""

import random
import secrets
import struct


def _randbytes(n: int) -> bytes:
    """
    Python 3.8+ compatible randomness (random.randbytes is 3.9+).
    """
    return secrets.token_bytes(n)


def get_tls_version_bytes(version: str) -> bytes:
    """Get TLS version bytes."""
    versions = {
        "1.0": b"\x03\x01",
        "1.1": b"\x03\x02",
        "1.2": b"\x03\x03",
        "1.3": b"\x03\x04",
    }
    return versions.get(version, b"\x03\x03")


def get_cipher_suites(cipher_suite: str = None) -> bytes:
    """
    Get cipher suites bytes.

    Args:
        cipher_suite: Specific cipher suite name (currently returns all suites)

    Returns:
        Bytes representing cipher suites

    Note: Parameter 'cipher_suite' is accepted for API compatibility but currently
    returns a standard set of cipher suites. Future enhancement could filter based
    on the parameter.
    """
    suites = [b"\x13\x01", b"\x13\x02", b"\x13\x03", b"\xc0\x2b", b"\xc0\x2f"]
    return b"".join(suites)


def get_cipher_suite_bytes(cipher_suite: str) -> bytes:
    """Get selected cipher suite bytes."""
    suites = {
        "TLS_AES_128_GCM_SHA256": b"\x13\x01",
        "TLS_AES_256_GCM_SHA384": b"\x13\x02",
        "TLS_CHACHA20_POLY1305_SHA256": b"\x13\x03",
    }
    return suites.get(cipher_suite, b"\x13\x02")


def generate_client_hello_extensions(server_name: str) -> bytes:
    """Generate Client Hello extensions."""
    extensions = b""
    sni_data = server_name.encode("utf-8")
    sni_length = len(sni_data)
    sni_ext = (
        b"\x00\x00"
        + struct.pack("!H", sni_length + 5)
        + struct.pack("!H", sni_length + 3)
        + b"\x00"
        + struct.pack("!H", sni_length)
        + sni_data
    )
    extensions += sni_ext
    groups_ext = b"\x00\n" + b"\x00\x08" + b"\x00\x06" + b"\x00\x17" + b"\x00\x18" + b"\x00\x19"
    extensions += groups_ext
    return extensions


def generate_server_hello_extensions() -> bytes:
    """Generate Server Hello extensions."""
    key_share_ext = b"\x003" + b"\x00$" + b"\x00\x17" + b"\x00 " + _randbytes(32)
    return key_share_ext


def generate_fake_certificate(server_name: str) -> bytes:
    """Generate fake X.509 certificate."""
    cert_header = b"0\x82\x03\x00"
    cert_body = (
        b"0\x82\x02\x00"
        + b"\xa0\x03\x02\x01\x02"
        + b"\x02\x08"
        + _randbytes(8)
        + b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00"
        + b"0\x101\x0e0\x0c\x06\x03U\x04\x03\x0c\x05"
        + b"TestCA"
        + b"0\x1e\x17\r"
        + b"231201000000Z"
        + b"\x17\r"
        + b"241201000000Z"
        + b"0 1\x1e0\x1c\x06\x03U\x04\x03\x0c\x15"
        + server_name.encode("utf-8")[:21]
        + b'0\x82\x01"'
        + _randbytes(290)
    )
    return cert_header + cert_body


def generate_client_hello(tls_version: str, cipher_suite: str, server_name: str) -> bytes:
    """Generate TLS Client Hello message."""
    record_type = 22
    version = get_tls_version_bytes(tls_version)
    handshake_type = 1
    client_version = version
    random_bytes = _randbytes(32)
    session_id_length = 0
    session_id = b""
    cipher_suites = get_cipher_suites(cipher_suite)
    cipher_suites_length = len(cipher_suites)
    compression_methods = b"\x01\x00"
    extensions = generate_client_hello_extensions(server_name)
    extensions_length = len(extensions)
    handshake_content = (
        client_version
        + random_bytes
        + bytes([session_id_length])
        + session_id
        + struct.pack("!H", cipher_suites_length)
        + cipher_suites
        + compression_methods
        + struct.pack("!H", extensions_length)
        + extensions
    )
    handshake_length = len(handshake_content)
    handshake_header = bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
    handshake_message = handshake_header + handshake_content
    record_length = len(handshake_message)
    record_header = bytes([record_type]) + version + struct.pack("!H", record_length)
    return record_header + handshake_message


def generate_server_hello(tls_version: str, cipher_suite: str) -> bytes:
    """Generate TLS Server Hello message."""
    record_type = 22
    version = get_tls_version_bytes(tls_version)
    handshake_type = 2
    server_version = version
    random_bytes = _randbytes(32)
    session_id_length = 32
    session_id = _randbytes(32)
    selected_cipher = get_cipher_suite_bytes(cipher_suite)
    compression_method = b"\x00"
    extensions = generate_server_hello_extensions()
    extensions_length = len(extensions)
    handshake_content = (
        server_version
        + random_bytes
        + bytes([session_id_length])
        + session_id
        + selected_cipher
        + compression_method
        + struct.pack("!H", extensions_length)
        + extensions
    )
    handshake_length = len(handshake_content)
    handshake_header = bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
    handshake_message = handshake_header + handshake_content
    record_length = len(handshake_message)
    record_header = bytes([record_type]) + version + struct.pack("!H", record_length)
    return record_header + handshake_message


def generate_certificate(server_name: str) -> bytes:
    """Generate TLS Certificate message."""
    record_type = 22
    version = b"\x03\x03"
    handshake_type = 11
    fake_cert = generate_fake_certificate(server_name)
    cert_length = len(fake_cert)
    cert_list = struct.pack("!I", cert_length)[1:] + fake_cert
    cert_list_length = len(cert_list)
    handshake_content = struct.pack("!I", cert_list_length)[1:] + cert_list
    handshake_length = len(handshake_content)
    handshake_header = bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
    handshake_message = handshake_header + handshake_content
    record_length = len(handshake_message)
    record_header = bytes([record_type]) + version + struct.pack("!H", record_length)
    return record_header + handshake_message


def generate_finished() -> bytes:
    """Generate TLS Finished message."""
    record_type = 22
    version = b"\x03\x03"
    handshake_type = 20
    verify_data = _randbytes(12)
    handshake_content = verify_data
    handshake_length = len(handshake_content)
    handshake_header = bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
    handshake_message = handshake_header + handshake_content
    record_length = len(handshake_message)
    record_header = bytes([record_type]) + version + struct.pack("!H", record_length)
    return record_header + handshake_message


def generate_encrypted_application_data(payload: bytes, tls_version: str) -> bytes:
    """Generate encrypted application data record."""
    record_type = 23
    version = get_tls_version_bytes(tls_version)
    encryption_key = _randbytes(32)
    encrypted_payload = bytearray()
    for i, byte in enumerate(payload):
        encrypted_payload.append(byte ^ encryption_key[i % len(encryption_key)])
    padding_length = random.randint(1, 16)
    padding = _randbytes(padding_length)
    encrypted_data = bytes(encrypted_payload) + padding
    record_length = len(encrypted_data)
    record_header = bytes([record_type]) + version + struct.pack("!H", record_length)
    return record_header + encrypted_data
