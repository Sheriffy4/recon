"""
Network probing utilities for domain connectivity testing.

This module provides utilities for testing domain connectivity
without full request/response cycles.
"""

import socket
import logging
from typing import Optional


def probe_domain_connection(
    domain: str, port: int = 443, timeout: float = 2.0, logger: Optional[logging.Logger] = None
) -> bool:
    """
    Generate minimal probe traffic to test domain connectivity.

    Attempts to establish a TCP connection to the specified domain and port,
    then immediately closes it. Used for triggering packet capture without
    performing full HTTP/TLS handshakes.

    Args:
        domain: Target domain name or IP address
        port: Target port (default: 443 for HTTPS)
        timeout: Connection timeout in seconds (default: 2.0)
        logger: Optional logger for debug messages

    Returns:
        True if connection succeeded, False otherwise

    Note:
        This function intentionally swallows connection errors as probe
        failures are expected for blocked/filtered domains.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        with socket.create_connection((domain, port), timeout=timeout):
            pass
        logger.debug(f"Probe traffic succeeded for {domain}:{port}")
        return True
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Probe traffic failed for {domain}:{port}: {e}")
        return False
