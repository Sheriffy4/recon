"""
Protocol Utilities

Common utilities for protocol mimicry attacks including token generation,
user agent management, and packet type identification.
"""

import base64
import hashlib
import random
import secrets


def sanitize_token(value: str, default: str = "") -> str:
    """
    Minimal hardening against CRLF/control-char injection.

    - keeps only the first line
    - strips surrounding whitespace
    - removes NUL and CR chars; keeps unicode but drops other C0 controls
    """
    if not value:
        return default
    first = value.splitlines()[0].strip()
    if not first:
        return default
    # Remove NUL and carriage-return explicitly; drop other ASCII control chars except TAB.
    cleaned_chars = []
    for ch in first:
        if ch in ("\x00", "\r"):
            continue
        o = ord(ch)
        if o < 32 and ch != "\t":
            continue
        cleaned_chars.append(ch)
    cleaned = "".join(cleaned_chars).strip()
    return cleaned or default


def sanitize_hostname(value: str, default: str) -> str:
    """
    Normalize hostname-like values:
    - strips scheme
    - removes path part
    - applies sanitize_token
    """
    v = sanitize_token(value or "", default)
    v = v.replace("https://", "").replace("http://", "")
    v = v.split("/")[0].strip()
    return v or default


def generate_client_id() -> str:
    """Generate realistic client ID."""
    # Keep a short hex-like stable shape, but avoid md5/random.random dependency.
    return secrets.token_hex(8)[:16]


def generate_bearer_token() -> str:
    """Generate realistic bearer token."""
    return base64.b64encode(secrets.token_bytes(24)).decode("ascii")


def generate_csrf_token() -> str:
    """Generate CSRF token."""
    # Keep hex-like output length (32 chars).
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:32]


def get_user_agent(user_agent_type: str) -> str:
    """Get realistic user agent string."""
    user_agents = {
        "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    }
    return user_agents.get(user_agent_type, user_agents["chrome"])


def get_packet_type(protocol: str, packet_index: int, total_packets: int, **kwargs) -> str:
    """
    Get packet type description for various protocols.

    Args:
        protocol: Protocol name (smtp, ftp, tls)
        packet_index: Current packet index
        total_packets: Total number of packets
        **kwargs: Protocol-specific parameters (e.g., include_handshake for TLS)

    Returns:
        Packet type description string
    """
    if protocol == "smtp":
        if packet_index == 0:
            return "server_greeting"
        elif packet_index < total_packets // 2:
            return "handshake"
        elif packet_index < total_packets - 2:
            return "data_transfer"
        else:
            return "connection_close"

    elif protocol == "ftp":
        if packet_index == 0:
            return "server_welcome"
        elif packet_index < 6:
            return "authentication"
        elif packet_index < total_packets - 2:
            return "data_transfer"
        else:
            return "connection_close"

    elif protocol == "tls":
        include_handshake = kwargs.get("include_handshake", True)
        if include_handshake:
            types = [
                "client_hello",
                "server_hello",
                "certificate",
                "finished",
                "application_data",
            ]
            return types[min(packet_index, len(types) - 1)]
        else:
            return "application_data"

    return "unknown"


def calculate_realistic_delay(packet_index: int, mimicry_type: str) -> int:
    """Calculate realistic delay between HTTP packets."""
    if mimicry_type == "web_browsing":
        return random.randint(50, 200) if packet_index == 0 else random.randint(100, 500)
    elif mimicry_type == "api_call":
        return random.randint(10, 50) if packet_index == 0 else random.randint(20, 100)
    else:
        return random.randint(25, 150)
