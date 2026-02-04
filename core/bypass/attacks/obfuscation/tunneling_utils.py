"""
Protocol Tunneling Utilities

Shared utilities for protocol tunneling attacks including encoding,
obfuscation, and protocol-specific packet builders.

This module extracts common functionality from tunneling attack classes
to reduce duplication and improve maintainability.
"""

import os
import random
import base64
import hashlib
import struct
import time
import json
import zlib
from typing import List, Dict, Any


# ============================================================================
# Parameter Extraction Utilities
# ============================================================================


def randbytes(n: int) -> bytes:
    """
    Compatibility helper for random bytes.

    random.randbytes() exists in Python 3.9+. For older versions, use os.urandom().
    """
    rb = getattr(random, "randbytes", None)
    return rb(n) if callable(rb) else os.urandom(n)


def extract_http_tunneling_params(context) -> Dict[str, Any]:
    """
    Extract and validate HTTP tunneling attack parameters.

    Args:
        context: AttackContext with parameters

    Returns:
        Dictionary with validated HTTP parameters
    """
    return {
        "method": context.params.get("method", "POST"),
        "encoding": context.params.get("encoding", "base64"),
        "obfuscation_level": context.params.get("obfuscation_level", "medium"),
        "user_agent": context.params.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ),
        "host_header": context.params.get("host_header", context.domain or "example.com"),
    }


def extract_vpn_tunneling_params(context) -> Dict[str, Any]:
    """
    Extract and validate VPN tunneling attack parameters.

    Args:
        context: AttackContext with parameters

    Returns:
        Dictionary with validated VPN parameters

    Raises:
        ValueError: If vpn_type is not supported
    """
    vpn_type = context.params.get("vpn_type", "openvpn")
    if vpn_type not in ["openvpn", "wireguard", "ipsec"]:
        raise ValueError(f"Invalid vpn_type: {vpn_type}")

    return {
        "vpn_type": vpn_type,
        "obfuscation_level": context.params.get("obfuscation_level", "medium"),
        "use_compression": context.params.get("use_compression", False),
    }


# ============================================================================
# Encoding & Obfuscation Utilities
# ============================================================================


def url_encode(data: bytes) -> str:
    """
    URL encode binary data.

    Args:
        data: Binary data to encode

    Returns:
        URL-encoded string
    """
    parts: List[str] = []
    for byte in data:
        if 32 <= byte <= 126 and byte not in [37, 38, 43, 61]:
            parts.append(chr(byte))
        else:
            parts.append(f"%{byte:02X}")
    return "".join(parts)


def generate_fake_token() -> str:
    """
    Generate fake authentication token for obfuscation.

    Returns:
        Base64-encoded random token
    """
    return base64.b64encode(randbytes(24)).decode("ascii")


def generate_fake_session() -> str:
    """
    Generate fake session ID for obfuscation.

    Returns:
        MD5 hash-based session ID
    """
    return hashlib.md5(str(random.random()).encode()).hexdigest()


def generate_fake_signature() -> str:
    """
    Generate fake signature for obfuscation.

    Returns:
        SHA256-based signature (truncated to 32 chars)
    """
    return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]


def split_data_into_chunks(data: str, min_size: int = 50, max_size: int = 200) -> List[str]:
    """
    Split data into random-sized chunks for obfuscation.

    Args:
        data: String data to split
        min_size: Minimum chunk size
        max_size: Maximum chunk size

    Returns:
        List of data chunks
    """
    chunk_size = random.randint(min_size, max_size)
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append(data[i : i + chunk_size])
    return chunks


# ============================================================================
# HTTP Request Builders
# ============================================================================


def create_http_post_request(data: str, host: str, user_agent: str, level: str = "medium") -> bytes:
    """
    Create obfuscated HTTP POST request.

    Args:
        data: Payload data (already encoded/obfuscated)
        host: Host header value
        user_agent: User-Agent header value
        level: Obfuscation level (low/medium/high)

    Returns:
        Complete HTTP POST request as bytes
    """
    body = data.encode("utf-8")
    content_type = "application/x-www-form-urlencoded"
    if level == "high":
        content_type = "application/json"

    headers = [
        "POST /api/v1/submit HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: application/json, text/plain, */*",
        "Accept-Language: en-US,en;q=0.9",
        "Accept-Encoding: gzip, deflate, br",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        f"Origin: https://{host}",
        f"Referer: https://{host}/form",
        "Connection: keep-alive",
        "Sec-Fetch-Dest: empty",
        "Sec-Fetch-Mode: cors",
        "Sec-Fetch-Site: same-origin",
    ]
    head = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")
    return head + body


def create_http_get_request(data: str, host: str, user_agent: str, level: str = "medium") -> bytes:
    """
    Create obfuscated HTTP GET request.

    Args:
        data: Payload data (already encoded/obfuscated)
        host: Host header value
        user_agent: User-Agent header value
        level: Obfuscation level (reserved for future use)

    Returns:
        Complete HTTP GET request as bytes
    """
    # Truncate data if too long for GET request
    if len(data) > 2000:
        data = data[:2000]

    paths = ["/search", "/api/query", "/data/fetch", "/content/load"]
    path = random.choice(paths)

    headers = [
        f"GET {path}?q={data}&t={int(time.time())}&r={random.randint(1000, 9999)} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
    ]
    request = "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")


def create_http_put_request(data: str, host: str, user_agent: str, level: str = "medium") -> bytes:
    """
    Create obfuscated HTTP PUT request.

    Args:
        data: Payload data (already encoded/obfuscated)
        host: Host header value
        user_agent: User-Agent header value
        level: Obfuscation level (reserved for future use)

    Returns:
        Complete HTTP PUT request as bytes
    """
    body = data.encode("utf-8")
    headers = [
        "PUT /api/v1/update HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: application/json",
        "Accept-Language: en-US,en;q=0.9",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        f"Authorization: Bearer {generate_fake_token()}",
        "Connection: keep-alive",
    ]
    head = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")
    return head + body


def apply_medium_obfuscation(data: str) -> str:
    """
    Apply medium-level obfuscation to data.

    Args:
        data: Data to obfuscate

    Returns:
        Obfuscated data string
    """
    fake_fields = [
        f"csrf_token={generate_fake_token()}",
        f"session_id={generate_fake_session()}",
        f"timestamp={int(time.time())}",
        f"data={data}",
        f"checksum={hashlib.md5(data.encode()).hexdigest()[:8]}",
    ]
    random.shuffle(fake_fields)
    return "&".join(fake_fields)


def apply_high_obfuscation(data: str) -> str:
    """
    Apply high-level obfuscation with JSON structure.

    Args:
        data: Data to obfuscate

    Returns:
        JSON-encoded obfuscated data
    """
    obfuscated = {
        "metadata": {
            "version": "1.0",
            "timestamp": int(time.time()),
            "client_id": generate_fake_token(),
            "session": generate_fake_session(),
        },
        "payload": {
            "type": "form_data",
            "encoding": "base64",
            "data": data,
            "chunks": split_data_into_chunks(data),
        },
        "verification": {
            "checksum": hashlib.sha256(data.encode()).hexdigest()[:16],
            "signature": generate_fake_signature(),
        },
    }
    return json.dumps(obfuscated, separators=(",", ":"))


# ============================================================================
# WebSocket Utilities
# ============================================================================


def create_websocket_frame(payload: bytes, opcode: int, fin: int) -> bytes:
    """
    Create WebSocket frame with masking.

    Args:
        payload: Frame payload data
        opcode: WebSocket opcode (0=continuation, 1=text, 2=binary, 8=close, 9=ping, 10=pong)
        fin: FIN bit (1=final fragment, 0=more fragments follow)

    Returns:
        Complete WebSocket frame as bytes
    """
    first_byte = fin << 7 | opcode
    payload_len = len(payload)
    mask = 1  # Client-to-server frames must be masked

    # Encode payload length
    if payload_len < 126:
        second_byte = mask << 7 | payload_len
        length_bytes = b""
    elif payload_len < 65536:
        second_byte = mask << 7 | 126
        length_bytes = struct.pack("!H", payload_len)
    else:
        second_byte = mask << 7 | 127
        length_bytes = struct.pack("!Q", payload_len)

    # Generate masking key and mask payload
    masking_key = randbytes(4)
    masked_payload = bytearray()
    for i, byte in enumerate(payload):
        masked_payload.append(byte ^ masking_key[i % 4])

    return bytes([first_byte, second_byte]) + length_bytes + masking_key + bytes(masked_payload)


def generate_websocket_padding(original_size: int) -> bytes:
    """
    Generate realistic padding data for WebSocket frames.

    Args:
        original_size: Size of original payload

    Returns:
        JSON-encoded padding data
    """
    padding_size = random.randint(10, 100)
    padding_data = {
        "metadata": {
            "size": original_size,
            "timestamp": int(time.time()),
            "version": "1.0",
        },
        "padding": "x" * max(0, (padding_size - 50)),
    }
    return json.dumps(padding_data).encode("utf-8")


def create_obfuscated_ws_handshake(host: str, path: str, ws_key: str, subprotocol: str) -> bytes:
    """
    Create obfuscated WebSocket handshake request.

    Args:
        host: Host header value
        path: WebSocket path
        ws_key: Base64-encoded WebSocket key
        subprotocol: WebSocket subprotocol

    Returns:
        Complete HTTP WebSocket upgrade request
    """
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Protocol: {subprotocol}",
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        f"Origin: https://{host}",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
    ]
    handshake = "\r\n".join(headers) + "\r\n\r\n"
    return handshake.encode("utf-8")


def create_fragmented_ws_frames(payload: bytes) -> List[bytes]:
    """
    Create fragmented WebSocket frames.

    Args:
        payload: Data to fragment

    Returns:
        List of WebSocket frames
    """
    frames = []
    chunk_size = random.randint(50, 200)
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        is_final = i + chunk_size >= len(payload)
        is_first = i == 0
        opcode = 2 if is_first else 0
        fin = 1 if is_final else 0
        frame = create_websocket_frame(chunk, opcode, fin)
        frames.append(frame)
    return frames


def create_padded_ws_frames(payload: bytes) -> List[bytes]:
    """
    Create padded WebSocket frames.

    Args:
        payload: Data to pad

    Returns:
        List of WebSocket frames with padding
    """
    frames = []
    padded_payload = payload + generate_websocket_padding(len(payload))
    frame = create_websocket_frame(padded_payload, 2, 1)
    frames.append(frame)
    return frames


def create_mixed_type_ws_frames(payload: bytes) -> List[bytes]:
    """
    Create mixed type WebSocket frames with fake messages.

    Args:
        payload: Actual data payload

    Returns:
        List of WebSocket frames including fake messages
    """
    frames = []
    fake_messages = [
        b'{"type":"ping","timestamp":' + str(int(time.time())).encode() + b"}",
        b'{"type":"status","status":"online"}',
        b'{"type":"heartbeat"}',
    ]
    for msg in fake_messages:
        frame = create_websocket_frame(msg, 1, 1)
        frames.append(frame)
    frame = create_websocket_frame(payload, 2, 1)
    frames.append(frame)
    return frames


def create_obfuscated_ws_frames(payload: bytes, method: str = "fragmentation") -> List[bytes]:
    """
    Create obfuscated WebSocket frames using specified method.

    Args:
        payload: Data to obfuscate
        method: Obfuscation method ("fragmentation", "padding", "mixed_types")

    Returns:
        List of obfuscated WebSocket frames
    """
    if method == "fragmentation":
        return create_fragmented_ws_frames(payload)
    elif method == "padding":
        return create_padded_ws_frames(payload)
    elif method == "mixed_types":
        return create_mixed_type_ws_frames(payload)
    else:
        return create_fragmented_ws_frames(payload)


# ============================================================================
# VPN Protocol Packet Builders
# ============================================================================


def create_openvpn_client_hello() -> bytes:
    """
    Create OpenVPN client hello packet.

    Returns:
        OpenVPN client hello packet
    """
    opcode = 56
    key_id = randbytes(3)
    packet_id = struct.pack("!I", random.randint(1, 1000000))
    tls_payload = (
        b"\x16\x03\x01\x00J"
        + b"\x01\x00\x00F"
        + b"\x03\x03"
        + randbytes(32)
        + b"\x00"
        + b"\x00\x02\x005"
        + b"\x01\x00"
    )
    return bytes([opcode]) + key_id + packet_id + tls_payload


def create_openvpn_server_hello() -> bytes:
    """
    Create OpenVPN server hello packet.

    Returns:
        OpenVPN server hello packet
    """
    opcode = 72
    key_id = randbytes(3)
    packet_id = struct.pack("!I", random.randint(1, 1000000))
    tls_payload = (
        b"\x16\x03\x01\x00J"
        + b"\x02\x00\x00F"
        + b"\x03\x03"
        + randbytes(32)
        + b" "
        + randbytes(32)
        + b"\x005"
        + b"\x00"
    )
    return bytes([opcode]) + key_id + packet_id + tls_payload


def create_wireguard_initiation() -> bytes:
    """
    Create WireGuard handshake initiation packet.

    Returns:
        WireGuard initiation packet
    """
    msg_type = b"\x01\x00\x00\x00"
    sender_index = randbytes(4)
    unencrypted_ephemeral = randbytes(32)
    encrypted_static = randbytes(48)
    encrypted_timestamp = randbytes(28)
    mac1 = randbytes(16)
    mac2 = randbytes(16)
    return (
        msg_type
        + sender_index
        + unencrypted_ephemeral
        + encrypted_static
        + encrypted_timestamp
        + mac1
        + mac2
    )


def create_wireguard_response() -> bytes:
    """
    Create WireGuard handshake response packet.

    Returns:
        WireGuard response packet
    """
    msg_type = b"\x02\x00\x00\x00"
    sender_index = randbytes(4)
    receiver_index = randbytes(4)
    unencrypted_ephemeral = randbytes(32)
    encrypted_nothing = randbytes(16)
    mac1 = randbytes(16)
    mac2 = randbytes(16)
    return (
        msg_type
        + sender_index
        + receiver_index
        + unencrypted_ephemeral
        + encrypted_nothing
        + mac1
        + mac2
    )


def create_ike_init() -> bytes:
    """
    Create IKE initialization packet (IPSec).

    Returns:
        IKE init packet
    """
    initiator_spi = randbytes(8)
    responder_spi = b"\x00" * 8
    next_payload = 34
    version = 32
    exchange_type = 34
    flags = 8
    message_id = b"\x00\x00\x00\x00"
    payload_data = randbytes(200)
    length = struct.pack("!I", 28 + len(payload_data))
    return (
        initiator_spi
        + responder_spi
        + bytes([next_payload, version, exchange_type, flags])
        + message_id
        + length
        + payload_data
    )


def create_ike_auth() -> bytes:
    """
    Create IKE authentication packet (IPSec).

    Returns:
        IKE auth packet
    """
    initiator_spi = randbytes(8)
    responder_spi = randbytes(8)
    next_payload = 35
    version = 32
    exchange_type = 35
    flags = 8
    message_id = b"\x00\x00\x00\x01"
    payload_data = randbytes(150)
    length = struct.pack("!I", 28 + len(payload_data))
    return (
        initiator_spi
        + responder_spi
        + bytes([next_payload, version, exchange_type, flags])
        + message_id
        + length
        + payload_data
    )


# ============================================================================
# Encryption Simulators
# ============================================================================


def openvpn_encrypt(data: bytes, level: str = "medium") -> bytes:
    """
    Simulate OpenVPN encryption.

    Args:
        data: Data to encrypt
        level: Encryption level (reserved for future complexity variations)

    Returns:
        Simulated encrypted data with IV prepended
    """
    key = randbytes(32)
    iv = randbytes(16)
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % len(key)] ^ iv[i % len(iv)])
    return iv + bytes(encrypted)


def wireguard_encrypt(data: bytes, level: str = "medium") -> bytes:
    """
    Simulate WireGuard encryption (ChaCha20-Poly1305).

    Args:
        data: Data to encrypt
        level: Encryption level (reserved for future complexity variations)

    Returns:
        Simulated encrypted data with auth tag appended
    """
    key = randbytes(32)
    # Preserve RNG consumption (nonce placeholder) but avoid unused-variable lint errors
    _ = randbytes(12)
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % len(key)])
    auth_tag = randbytes(16)
    return bytes(encrypted) + auth_tag


def ipsec_encrypt(data: bytes, level: str = "medium") -> bytes:
    """
    Simulate IPSec ESP encryption.

    Args:
        data: Data to encrypt
        level: Encryption level (reserved for future complexity variations)

    Returns:
        Simulated encrypted data with IV and auth tag
    """
    key = randbytes(32)
    iv = randbytes(12)
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % len(key)])
    auth_tag = randbytes(16)
    return iv + bytes(encrypted) + auth_tag


def simulate_ssh_encryption(data: bytes, method: str = "aes256-ctr") -> bytes:
    """
    Simulate SSH encryption.

    Args:
        data: Data to encrypt
        method: Encryption method (aes256-ctr, aes128-ctr, etc.)

    Returns:
        Simulated encrypted data
    """
    if method == "aes256-ctr":
        key = randbytes(32)
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)
    else:
        key = randbytes(16)
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)


# ============================================================================
# VPN Packet Generators
# ============================================================================


def generate_openvpn_packets(
    payload: bytes, obfuscation_level: str = "medium", use_compression: bool = False
) -> List[bytes]:
    """
    Generate complete OpenVPN packet sequence.

    Args:
        payload: Data payload to encapsulate
        obfuscation_level: Obfuscation level
        use_compression: Whether to compress payload

    Returns:
        List of OpenVPN packets (handshake + data)
    """
    packets = []
    client_hello = create_openvpn_client_hello()
    server_hello = create_openvpn_server_hello()
    packets.extend([client_hello, server_hello])

    if use_compression:
        compressed_payload = simulate_compression(payload)
    else:
        compressed_payload = payload

    # Create data packets
    chunk_size = 1200
    for i in range(0, len(compressed_payload), chunk_size):
        chunk = compressed_payload[i : i + chunk_size]
        opcode = 9
        key_id = randbytes(3)
        packet_id = struct.pack("!I", i // chunk_size + 1000)
        encrypted_chunk = openvpn_encrypt(chunk, obfuscation_level)
        packet = bytes([opcode]) + key_id + packet_id + encrypted_chunk
        packets.append(packet)

    return packets


def generate_wireguard_packets(payload: bytes, obfuscation_level: str = "medium") -> List[bytes]:
    """
    Generate complete WireGuard packet sequence.

    Args:
        payload: Data payload to encapsulate
        obfuscation_level: Obfuscation level

    Returns:
        List of WireGuard packets (handshake + data)
    """
    packets = []
    initiation = create_wireguard_initiation()
    response = create_wireguard_response()
    packets.extend([initiation, response])

    # Create data packets
    chunk_size = 1400
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        msg_type = b"\x04\x00\x00\x00"
        receiver_index = randbytes(4)
        counter = struct.pack("<Q", i // chunk_size)
        encrypted_chunk = wireguard_encrypt(chunk, obfuscation_level)
        packet = msg_type + receiver_index + counter + encrypted_chunk
        packets.append(packet)

    return packets


def generate_ipsec_packets(payload: bytes, obfuscation_level: str = "medium") -> List[bytes]:
    """
    Generate complete IPSec packet sequence.

    Args:
        payload: Data payload to encapsulate
        obfuscation_level: Obfuscation level

    Returns:
        List of IPSec packets (IKE handshake + ESP data)
    """
    packets = []
    ike_init = create_ike_init()
    ike_auth = create_ike_auth()
    packets.extend([ike_init, ike_auth])

    # Create ESP data packets
    chunk_size = 1300
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        spi = randbytes(4)
        sequence = struct.pack("!I", i // chunk_size + 1)
        encrypted_chunk = ipsec_encrypt(chunk, obfuscation_level)
        packet = spi + sequence + encrypted_chunk
        packets.append(packet)

    return packets


# ============================================================================
# DNS Utilities
# ============================================================================


def encode_payload_for_dns(payload: bytes, method: str = "base32") -> str:
    """
    Encode payload for DNS tunneling.

    Args:
        payload: Binary payload to encode
        method: Encoding method (base32, base64, hex)

    Returns:
        Encoded string suitable for DNS labels
    """
    if method == "base32":
        return base64.b32encode(payload).decode("ascii").lower().rstrip("=")
    elif method == "base64":
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        return encoded.replace("-", "x").replace("_", "y")
    elif method == "hex":
        return payload.hex()
    else:
        return base64.b32encode(payload).decode("ascii").lower().rstrip("=")


def create_dns_queries(encoded_data: str, max_label_length: int = 63) -> List[str]:
    """
    Create DNS queries from encoded data.

    Args:
        encoded_data: Encoded data string
        max_label_length: Maximum length per DNS label

    Returns:
        List of DNS query domain names
    """
    queries = []
    for i in range(0, len(encoded_data), max_label_length):
        chunk = encoded_data[i : i + max_label_length]
        subdomain_parts = []
        for j in range(0, len(chunk), 20):
            part = chunk[j : j + 20]
            if part:
                subdomain_parts.append(part)
        seq_num = f"s{i // max_label_length:04x}"
        checksum = f"c{(zlib.crc32(chunk.encode('ascii')) & 0xFFFF):04x}"
        query_domain = ".".join(subdomain_parts + [seq_num, checksum, "tunnel.example.com"])
        queries.append(query_domain)
    return queries


def create_dns_query_packet(domain: str) -> bytes:
    """
    Create DNS query packet.

    Args:
        domain: Domain name to query

    Returns:
        DNS query packet bytes
    """
    query_id = random.randint(1, 65535)
    flags = 256  # Standard query
    questions = 1
    answers = 0
    authority = 0
    additional = 0

    header = struct.pack(">HHHHHH", query_id, flags, questions, answers, authority, additional)

    question = b""
    for label in domain.split("."):
        if label:
            question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"
    question += struct.pack(">HH", 1, 1)  # Type A, Class IN

    return header + question


# ============================================================================
# SSH Utilities
# ============================================================================


def create_ssh_identification(version: str = "SSH-2.0-OpenSSH_8.9") -> bytes:
    """
    Create SSH identification string.

    Args:
        version: SSH version string

    Returns:
        SSH identification line
    """
    return f"{version}\r\n".encode("utf-8")


def create_realistic_kex_payload() -> bytes:
    """
    Create realistic SSH key exchange payload.

    Returns:
        SSH KEX payload bytes
    """
    msg_type = b"\x14"
    cookie = randbytes(16)

    algorithms = [
        b"diffie-hellman-group14-sha256,ecdh-sha2-nistp256",
        b"rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        b"aes256-ctr,aes192-ctr,aes128-ctr",
        b"aes256-ctr,aes192-ctr,aes128-ctr",
        b"hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        b"hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        b"none,zlib@openssh.com",
        b"none,zlib@openssh.com",
        b"",
        b"",
    ]

    payload = msg_type + cookie
    for alg_list in algorithms:
        payload += struct.pack("!I", len(alg_list)) + alg_list
    payload += b"\x00\x00\x00\x00\x00"

    return payload


def create_ssh_padding(length: int, realistic: bool = True) -> bytes:
    """
    Create SSH padding.

    Args:
        length: Padding length
        realistic: If True, use realistic padding pattern

    Returns:
        Padding bytes
    """
    if realistic:
        padding = bytearray()
        for i in range(length):
            if i % 4 == 0:
                padding.append(0)
            else:
                padding.append(random.randint(1, 255))
        return bytes(padding)
    else:
        return randbytes(length)


def create_obfuscated_ssh_kex_packet(obfuscation_level: str = "medium") -> bytes:
    """
    Create obfuscated SSH key exchange packet.

    Args:
        obfuscation_level: Obfuscation level ("low", "medium", "high")

    Returns:
        Complete SSH KEX packet with padding
    """
    if obfuscation_level == "high":
        kex_payload = create_realistic_kex_payload()
    else:
        kex_payload = b"\x14" + randbytes(32)

    padding_length = 8 - (len(kex_payload) + 1) % 8
    if padding_length < 4:
        padding_length += 8
    padding = randbytes(padding_length)
    packet_length = len(kex_payload) + 1 + padding_length

    return struct.pack("!I", packet_length) + bytes([padding_length]) + kex_payload + padding


def create_ssh_data_packet(encrypted_data: bytes, obfuscation_level: str = "medium") -> bytes:
    """
    Create SSH data packet.

    Args:
        encrypted_data: Encrypted payload data
        obfuscation_level: Obfuscation level ("low", "medium", "high")

    Returns:
        Complete SSH data packet with padding
    """
    msg_type = b"^"
    channel_number = struct.pack("!I", 0)
    data_length = struct.pack("!I", len(encrypted_data))
    payload = msg_type + channel_number + data_length + encrypted_data

    padding_length = 8 - (len(payload) + 1) % 8
    if padding_length < 4:
        padding_length += 8

    if obfuscation_level == "high":
        padding = create_ssh_padding(padding_length, realistic=True)
    else:
        padding = randbytes(padding_length)

    packet_length = len(payload) + 1 + padding_length
    return struct.pack("!I", packet_length) + bytes([padding_length]) + payload + padding


# ============================================================================
# Compression & Data Processing
# ============================================================================


def simulate_compression(data: bytes) -> bytes:
    """
    Simulate simple run-length encoding compression.

    Args:
        data: Data to compress

    Returns:
        Compressed data bytes
    """
    compressed = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        count = 1
        while i + count < len(data) and data[i + count] == byte and (count < 255):
            count += 1
        if count > 3:
            compressed.extend([255, count, byte])
        else:
            compressed.extend([byte] * count)
        i += count
    return bytes(compressed)


# ============================================================================
# Padding Generators (Unified)
# ============================================================================


def generate_realistic_padding(length: int, padding_type: str = "generic") -> bytes:
    """
    Generate realistic padding based on type.

    Args:
        length: Padding length
        padding_type: Type of padding (generic, ssh, websocket, vpn)

    Returns:
        Padding bytes
    """
    if padding_type == "ssh":
        # SSH-style padding with pattern
        padding = bytearray()
        for i in range(length):
            if i % 4 == 0:
                padding.append(0)
            else:
                padding.append(random.randint(1, 255))
        return bytes(padding)
    elif padding_type == "websocket":
        # WebSocket-style JSON padding
        if length < 50:
            return randbytes(length)
        padding_data = {
            "metadata": {"timestamp": int(time.time()), "version": "1.0"},
            "padding": "x" * (length - 40),
        }
        result = json.dumps(padding_data).encode("utf-8")
        return result[:length]
    elif padding_type == "vpn":
        # VPN-style random padding
        return randbytes(length)
    else:
        # Generic random padding
        return randbytes(length)
