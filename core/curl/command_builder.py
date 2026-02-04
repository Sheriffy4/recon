from __future__ import annotations

# File: core/curl/command_builder.py
"""
Curl command building utilities.

This module provides focused functions for building curl commands with various options,
extracted from UnifiedBypassEngine to reduce method complexity and improve reusability.
"""

import sys
import logging
from typing import List, Optional

LOG = logging.getLogger("curl_command_builder")

# Browser-like cipher list for ClientHello inflation
BROWSER_CIPHER_LIST = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA:"
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:"
    "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES256-SHA256:EDH-RSA-DES-CBC3-SHA"
)


def add_protocol_options(
    cmd: List[str],
    http2: bool = True,
    tlsv1_2: bool = False,
    include_ciphers: bool = False,
) -> None:
    """
    Add protocol-related options to curl command.

    Args:
        cmd: Command list to append to
        http2: Enable HTTP/2 support
        tlsv1_2: Force TLS 1.2
        include_ciphers: Include browser-like cipher list
    """
    if http2:
        cmd.append("--http2")
    if tlsv1_2:
        cmd.append("--tlsv1.2")
    if include_ciphers:
        cmd.extend(["--ciphers", BROWSER_CIPHER_LIST])


def add_headers(
    cmd: List[str],
    user_agent: str,
    enhanced: bool = False,
) -> None:
    """
    Add HTTP headers to curl command.

    Args:
        cmd: Command list to append to
        user_agent: User-Agent header value
        enhanced: Add additional browser-like headers
    """
    cmd.extend(["-H", f"User-Agent: {user_agent}"])

    if enhanced:
        cmd.extend(
            [
                "-H",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "-H",
                "Accept-Language: en-US,en;q=0.5",
                "-H",
                "Accept-Encoding: gzip, deflate, br",
                "-H",
                "DNT: 1",
                "-H",
                "Connection: keep-alive",
                "-H",
                "Upgrade-Insecure-Requests: 1",
            ]
        )


def add_connection_options(
    cmd: List[str],
    timeout: float,
    insecure: bool = True,
    silent: bool = True,
) -> None:
    """
    Add connection-related options to curl command.

    Args:
        cmd: Command list to append to
        timeout: Connection timeout in seconds
        insecure: Allow insecure SSL connections
        silent: Silent mode (no progress bar)
    """
    if insecure:
        cmd.append("-k")
    # curl expects integer seconds; keep behavior but avoid invalid 0/negative values
    try:
        timeout_i = int(timeout)
    except Exception:
        timeout_i = 1
    if timeout_i <= 0:
        timeout_i = 1
    cmd.extend(["-m", str(timeout_i)])
    if silent:
        cmd.append("-s")


def add_output_options(
    cmd: List[str],
    output_devnull: bool = True,
    writeout: Optional[str] = "%{http_code}",
) -> None:
    """
    Add output-related options to curl command.

    Args:
        cmd: Command list to append to
        output_devnull: Redirect output to /dev/null
        writeout: Write-out format string
    """
    if output_devnull:
        devnull = "nul" if sys.platform == "win32" else "/dev/null"
        cmd.extend(["-o", devnull])
    if writeout:
        cmd.extend(["-w", writeout])


def build_resolve_curl_command(
    curl_executable: str,
    target_ip: str,
    domain: str,
    port: int,
    url: str,
    timeout: float,
    user_agent: str,
    *,
    http2: bool = True,
    tlsv1_2: bool = False,
    include_ciphers: bool = False,
    enhanced_headers: bool = False,
    insecure: bool = True,
    silent: bool = True,
    output_devnull: bool = True,
    writeout: str = "%{http_code}",
) -> List[str]:
    """
    Build curl command with --resolve for IP binding.

    This is the primary method for testing strategies as it allows binding
    to a specific IP while using the correct domain name for SNI.

    Args:
        curl_executable: Path to curl executable
        target_ip: Target IP address to bind to
        domain: Domain name for SNI
        port: Port number
        url: Full URL to request
        timeout: Connection timeout in seconds
        user_agent: User-Agent header value
        http2: Enable HTTP/2 support
        tlsv1_2: Force TLS 1.2
        include_ciphers: Include browser-like cipher list
        enhanced_headers: Add additional browser-like headers
        insecure: Allow insecure SSL connections
        silent: Silent mode
        output_devnull: Redirect output to /dev/null
        writeout: Write-out format string

    Returns:
        List of command arguments
    """
    # Format IP for --resolve (handle IPv6)
    if isinstance(target_ip, str) and target_ip.startswith("[") and target_ip.endswith("]"):
        # already bracketed IPv6
        resolve_ip = target_ip
    else:
        resolve_ip = f"[{target_ip}]" if ":" in str(target_ip) else str(target_ip)

    resolve_param = f"{domain}:{port}:{resolve_ip}"

    # Build command
    cmd = [curl_executable, "--resolve", resolve_param]

    # Add protocol options
    add_protocol_options(cmd, http2, tlsv1_2, include_ciphers)

    # Add headers
    add_headers(cmd, user_agent, enhanced_headers)

    # Add connection options
    add_connection_options(cmd, timeout, insecure, silent)

    # Add output options
    add_output_options(cmd, output_devnull, writeout)

    # Add URL
    cmd.append(url)

    return cmd


def build_direct_curl_command(
    curl_executable: str,
    url: str,
    timeout: float,
    user_agent: str,
    *,
    http2: bool = True,
    include_ciphers: bool = False,
    enhanced_headers: bool = False,
    insecure: bool = True,
    silent: bool = True,
    output_devnull: bool = True,
    writeout: str = "%{http_code}",
) -> List[str]:
    """
    Build curl command for direct URL access (no --resolve).

    Used as fallback when IP binding is not needed or not possible.

    Args:
        curl_executable: Path to curl executable
        url: Full URL to request
        timeout: Connection timeout in seconds
        user_agent: User-Agent header value
        http2: Enable HTTP/2 support
        include_ciphers: Include browser-like cipher list
        enhanced_headers: Add additional browser-like headers
        insecure: Allow insecure SSL connections
        silent: Silent mode
        output_devnull: Redirect output to /dev/null
        writeout: Write-out format string

    Returns:
        List of command arguments
    """
    # Build command
    cmd = [curl_executable]

    # Add protocol options
    add_protocol_options(cmd, http2, False, include_ciphers)

    # Add headers
    add_headers(cmd, user_agent, enhanced_headers)

    # Add connection options
    add_connection_options(cmd, timeout, insecure, silent)

    # Add output options
    add_output_options(cmd, output_devnull, writeout)

    # Add URL
    cmd.append(url)

    return cmd


# ============================================================================
# Curl Executable Resolution
# ============================================================================

import sys
from pathlib import Path


def resolve_curl_executable() -> str:
    """
    Resolve curl executable path with HTTP/2 support.

    On Windows, checks for bundled curl.exe in several locations:
    1. Repository root (parent of core/)
    2. core/ directory
    3. Current working directory

    Falls back to system curl if not found.

    Returns:
        str: Path to curl executable

    Examples:
        >>> exe = resolve_curl_executable()
        >>> exe in ['curl', 'curl.exe'] or exe.endswith('curl.exe')
        True

    Note:
        This function maintains backward compatibility by falling back
        to "curl.exe" or "curl" if no bundled version is found.
    """
    if sys.platform == "win32":
        # Try several common locations for bundled curl.exe
        candidates = [
            # repo_root/curl.exe (core/<this_file>.py => parents[2] is repo root)
            Path(__file__).resolve().parents[2] / "curl.exe",
            # core/curl.exe
            Path(__file__).resolve().parents[1] / "curl.exe",
            # current working dir
            Path("curl.exe"),
        ]
        for p in candidates:
            try:
                if p.exists():
                    return str(p)
            except (OSError, PermissionError):
                continue
        return "curl.exe"
    else:
        return "curl"


# ============================================================================
# URL Building Utilities
# ============================================================================


def parse_domain_and_port(domain: str, logger: Optional[logging.Logger] = None) -> tuple:
    """
    Parse domain and port from domain string.

    Handles various formats:
    - domain.com -> (domain.com, 443)
    - domain.com:8080 -> (domain.com, 8080)
    - [::1]:8080 -> ([::1], 8080) - IPv6 with port
    - [2001:db8::1] -> ([2001:db8::1], 443) - IPv6 without port

    Args:
        domain: Domain string (may include port)
        logger: Optional logger for warnings

    Returns:
        tuple: (domain_part, port)

    Examples:
        >>> parse_domain_and_port("example.com")
        ('example.com', 443)

        >>> parse_domain_and_port("example.com:8080")
        ('example.com', 8080)

        >>> parse_domain_and_port("[::1]:8080")
        ('[::1]', 8080)

        >>> parse_domain_and_port("[2001:db8::1]")
        ('[2001:db8::1]', 443)

    Requirements: 4.2
    """
    # Handle IPv6 addresses with ports: [::1]:8080
    if domain.startswith("[") and "]:" in domain:
        ipv6_end = domain.find("]:")
        domain_part = domain[: ipv6_end + 1]  # Include the closing bracket
        port_str = domain[ipv6_end + 2 :]
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                return domain_part, port
            else:
                if logger:
                    logger.warning(f"Invalid port {port}, using default 443")
                return domain_part, 443
        except ValueError:
            # Invalid port, use default
            return domain_part, 443

    # Handle IPv6 addresses without ports: [::1]
    if domain.startswith("[") and domain.endswith("]"):
        return domain, 443

    # Handle regular domain:port format
    if ":" in domain and not domain.startswith("["):
        parts = domain.rsplit(":", 1)  # Split from right to handle edge cases
        if len(parts) == 2:
            domain_part, port_str = parts
            try:
                port = int(port_str)
                # Validate port range
                if 1 <= port <= 65535:
                    return domain_part, port
                else:
                    if logger:
                        logger.warning(f"Invalid port {port}, using default 443")
                    return domain_part, 443
            except ValueError:
                # Not a valid port, treat as part of domain
                return domain, 443

    # No port specified, use default HTTPS port
    return domain, 443


def build_url(domain: str, port: int, path: str = "/") -> str:
    """
    Build URL with proper port handling.

    Standard ports (80, 443) are typically omitted from URLs.
    Custom ports are explicitly included.

    Args:
        domain: Domain name
        port: Port number
        path: URL path (default: "/")

    Returns:
        str: Complete URL

    Examples:
        >>> build_url("example.com", 443)
        'https://example.com/'

        >>> build_url("example.com", 8080)
        'https://example.com:8080/'

        >>> build_url("example.com", 443, "/api/v1")
        'https://example.com/api/v1'

        >>> build_url("[::1]", 8080, "/test")
        'https://[::1]:8080/test'

    Requirements: 4.2, 4.4, 4.5
    """
    safe_path = path if path and path.startswith("/") else "/"
    # Always use HTTPS for security and to match DPI bypass requirements
    if port == 443:
        # Standard HTTPS port, omit from URL
        return f"https://{domain}{safe_path}"
    else:
        # Custom port, include in URL
        return f"https://{domain}:{port}{safe_path}"


def get_enhanced_user_agent() -> str:
    """
    Get enhanced User-Agent header for realistic requests.

    Uses a modern browser User-Agent string to avoid detection
    and ensure realistic request patterns.

    Returns:
        str: Enhanced User-Agent string

    Examples:
        >>> ua = get_enhanced_user_agent()
        >>> "Chrome" in ua and "Windows" in ua
        True

    Requirements: 4.4
    """
    # Current Chrome User-Agent for Windows (update periodically)
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def format_ip_for_resolve(target_ip: str) -> str:
    """
    Format IP address for curl --resolve parameter.

    IPv6 addresses need to be bracketed for --resolve.
    IPv4 addresses are used as-is.

    Args:
        target_ip: IP address (v4 or v6)

    Returns:
        str: Formatted IP for --resolve

    Examples:
        >>> format_ip_for_resolve("1.1.1.1")
        '1.1.1.1'

        >>> format_ip_for_resolve("::1")
        '[::1]'

        >>> format_ip_for_resolve("[::1]")
        '[::1]'

        >>> format_ip_for_resolve("2001:db8::1")
        '[2001:db8::1]'
    """
    if not target_ip:
        return target_ip

    # Already bracketed
    if target_ip.startswith("[") and target_ip.endswith("]"):
        return target_ip

    # IPv6 detection (contains colon)
    if ":" in target_ip:
        return f"[{target_ip}]"

    # IPv4 or hostname
    return target_ip
