"""
HTTP Request and Response Generators

Utilities for generating realistic HTTP requests and responses
for protocol mimicry attacks.
"""

import base64
import hashlib
import json
import random
import time
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.bypass.attacks.base import AttackContext


def _sanitize_host(value: str, default: str) -> str:
    """
    Minimal CRLF-injection hardening for header values (Host/Origin/Referer).
    Keeps interface unchanged; only normalizes unsafe inputs.
    """
    from .protocol_utils import sanitize_hostname

    # Keep previous behavior (remove spaces), but also normalize scheme/path.
    return sanitize_hostname((value or "").replace(" ", ""), default)


def generate_browsing_request(
    payload: bytes, user_agent_type: str, context: "AttackContext"
) -> bytes:
    """Generate web browsing request."""
    from .protocol_utils import get_user_agent

    user_agent = get_user_agent(user_agent_type)
    host = _sanitize_host(context.domain or "", "example.com")
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    paths = ["/search", "/page", "/content", "/view", "/article"]
    path = random.choice(paths)
    params = [
        f"q={encoded_payload[:100]}",
        f"t={int(time.time())}",
        f"r={random.randint(1000, 9999)}",
        "lang=en",
        "format=html",
    ]
    if len(encoded_payload) > 100:
        remaining = encoded_payload[100:]
        for i in range(0, len(remaining), 50):
            chunk = remaining[i : i + 50]
            params.append(f"p{i // 50}={chunk}")
    query_string = "&".join(params)
    headers = [
        f"GET {path}?{query_string} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        "DNT: 1",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "Cache-Control: max-age=0",
    ]
    request = "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")


def generate_api_request(
    payload: bytes, user_agent_type: str, content_type: str, context: "AttackContext"
) -> bytes:
    """Generate API request."""
    from .protocol_utils import (
        generate_bearer_token,
        generate_client_id,
        get_user_agent,
    )

    user_agent = get_user_agent(user_agent_type)
    host = _sanitize_host(context.domain or "", "api.example.com")
    if content_type == "auto":
        content_type = "application/json"
    if content_type == "application/json":
        encoded_payload = json.dumps(
            {
                "data": base64.b64encode(payload).decode("ascii"),
                "timestamp": int(time.time()),
                "version": "1.0",
                "client_id": generate_client_id(),
            }
        )
    else:
        encoded_payload = base64.b64encode(payload).decode("ascii")
    body_bytes = encoded_payload.encode("utf-8")
    headers = [
        "POST /api/v1/data HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: application/json, text/plain, */*",
        "Accept-Language: en-US,en;q=0.9",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body_bytes)}",
        f"Authorization: Bearer {generate_bearer_token()}",
        "X-Requested-With: XMLHttpRequest",
        f"Origin: https://{host}",
        f"Referer: https://{host}/dashboard",
        "Connection: keep-alive",
    ]
    return "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body_bytes


def generate_download_request(
    payload: bytes, user_agent_type: str, context: "AttackContext"
) -> bytes:
    """Generate file download request."""
    from .protocol_utils import get_user_agent

    user_agent = get_user_agent(user_agent_type)
    host = _sanitize_host(context.domain or "", "cdn.example.com")
    filename_hash = hashlib.md5(payload).hexdigest()[:8]
    file_extensions = [".pdf", ".zip", ".exe", ".dmg", ".tar.gz"]
    extension = random.choice(file_extensions)
    filename = f"file_{filename_hash}{extension}"
    headers = [
        f"GET /downloads/{filename} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        f"Referer: https://{host}/files",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
    ]
    request = "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")


def generate_form_request(payload: bytes, user_agent_type: str, context: "AttackContext") -> bytes:
    """Generate form submission request."""
    from .protocol_utils import generate_csrf_token, get_user_agent

    user_agent = get_user_agent(user_agent_type)
    host = _sanitize_host(context.domain or "", "forms.example.com")
    # Correct x-www-form-urlencoded encoding: base64 may contain '+' which otherwise becomes space.
    form_fields = {
        "name": f"user_{random.randint(1000, 9999)}",
        "email": "user@example.com",
        "message": base64.b64encode(payload).decode("ascii"),
        "csrf_token": generate_csrf_token(),
        "timestamp": str(int(time.time())),
    }
    form_body = urllib.parse.urlencode(form_fields)
    body_bytes = form_body.encode("utf-8")
    headers = [
        "POST /submit HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {len(body_bytes)}",
        f"Origin: https://{host}",
        f"Referer: https://{host}/form",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
    ]
    return "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body_bytes


def generate_html_response(payload: bytes) -> bytes:
    """Generate HTML response."""
    encoded_payload = base64.b64encode(payload).decode("ascii")
    html_content = f'<!DOCTYPE html>\n<html>\n<head>\n    <title>Example Page</title>\n    <meta charset="UTF-8">\n    <!-- {encoded_payload[:100]} -->\n</head>\n<body>\n    <h1>Welcome</h1>\n    <p>This is a sample page.</p>\n    <form style="display:none;">\n        <input type="hidden" name="data" value="{encoded_payload[100:]}">\n    </form>\n    <script>\n        // Analytics data: {encoded_payload[-50:]}\n        console.log("Page loaded");\n    </script>\n</body>\n</html>'
    body_bytes = html_content.encode("utf-8")
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=UTF-8",
        f"Content-Length: {len(body_bytes)}",
        "Server: Apache/2.4.41 (Ubuntu)",
        "Cache-Control: public, max-age=3600",
        'ETag: "' + hashlib.md5(body_bytes).hexdigest()[:16] + '"',
        "Connection: keep-alive",
    ]
    return "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body_bytes


def generate_json_response(payload: bytes) -> bytes:
    """Generate JSON API response."""
    response_data = {
        "status": "success",
        "data": {
            "result": base64.b64encode(payload).decode("ascii"),
            "timestamp": int(time.time()),
            "metadata": {
                "size": len(payload),
                "hash": hashlib.sha256(payload).hexdigest()[:16],
            },
        },
        "version": "1.0",
    }
    json_content = json.dumps(response_data, indent=2)
    body_bytes = json_content.encode("utf-8")
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        f"Content-Length: {len(body_bytes)}",
        "Server: nginx/1.18.0",
        "Access-Control-Allow-Origin: *",
        "Cache-Control: no-cache",
        "Connection: keep-alive",
    ]
    return "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body_bytes


def generate_file_response(payload: bytes) -> bytes:
    """Generate file download response."""
    file_header = b"PK\x03\x04"
    fake_file_content = file_header + payload + b"\x00" * 100
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: application/octet-stream",
        f"Content-Length: {len(fake_file_content)}",
        'Content-Disposition: attachment; filename="download.zip"',
        "Server: nginx/1.18.0",
        "Cache-Control: no-cache",
        "Connection: keep-alive",
    ]
    response = "\r\n".join(headers) + "\r\n\r\n"
    return response.encode("utf-8") + fake_file_content
