from __future__ import annotations

"""
CurlResponseAnalyzer - Enhanced response parsing for site accessibility testing.

This module provides centralized logic for parsing curl responses and determining
site accessibility. Key principle: ANY HTTP status code (including 4xx, 5xx errors)
indicates the site is accessible because connection was established. Only connection
timeouts and failures indicate DPI blocking.
"""

import re
import logging
from typing import Tuple, Optional
from dataclasses import dataclass


@dataclass
class AccessibilityTestResult:
    """Result of accessibility testing with detailed information."""

    is_accessible: bool
    reason: str
    method_used: str  # "curl", "tcp", "requests"
    http_status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    tls_established: bool = False
    redirects_followed: int = 0


class CurlResponseAnalyzer:
    """
    Centralized analyzer for curl responses to determine site accessibility.

    This class implements the enhanced response parsing logic required to fix
    the site accessibility testing bug where all sites were incorrectly
    classified as blocked.
    """

    # Any HTTP status code indicates the site is accessible (connection established)
    # Only connection timeouts/failures indicate DPI blocking
    # HTTP errors (4xx, 5xx) still mean the site is accessible, just the page has issues

    # TLS error patterns that indicate successful handshake despite cert issues
    TLS_SUCCESS_PATTERNS = [
        r"certificate verify failed",
        r"ssl certificate problem",
        r"certificate verification failed",
        r"unable to verify the first certificate",
        r"self signed certificate",
        r"certificate has expired",
    ]

    # Connection failure patterns that indicate blocking
    BLOCKING_PATTERNS = [
        r"connection timed out",
        r"timed out",
        r"timeout",
        r"connection refused",
        r"refused",
        r"couldn't resolve host",
        r"name resolution failed",
        r"host not found",
        r"network is unreachable",
        r"no route to host",
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the analyzer with optional logger."""
        self.logger = logger or logging.getLogger(__name__)

    def analyze_response(self, stdout: str, stderr: str, return_code: int) -> Tuple[bool, str]:
        """
        Analyze curl response and determine accessibility.

        Args:
            stdout: Standard output from curl command
            stderr: Standard error from curl command
            return_code: Exit code from curl command

        Returns:
            Tuple[bool, str]: (is_accessible, reason)
        """
        self.logger.debug(f"Analyzing curl response - return_code: {return_code}")
        self.logger.debug(f"stdout: {stdout[:200]}...")
        self.logger.debug(f"stderr: {stderr[:200]}...")

        # Check for HTTP status code in stdout
        # ANY HTTP status code means connection was established = site is accessible
        http_code = self._extract_http_status_code(stdout)
        if http_code is not None:
            self.logger.info(f"✅ Site accessible - HTTP {http_code} (connection established)")
            return True, f"HTTP {http_code} - connection established, site accessible"

        # Check for TLS handshake success despite certificate errors
        if self.is_tls_success(stderr):
            self.logger.info("✅ Site accessible - TLS handshake succeeded despite cert error")
            return True, "TLS handshake established (certificate error ignored)"

        # Check for blocking patterns in stderr
        if self._is_connection_blocked(stderr):
            blocking_reason = self._extract_blocking_reason(stderr)
            self.logger.info(f"❌ Site blocked - {blocking_reason}")
            return False, f"Connection blocked: {blocking_reason}"

        # If return code is 0 but no clear indicators, consider accessible
        if return_code == 0:
            self.logger.info("✅ Site accessible - curl succeeded with no errors")
            return True, "curl completed successfully"

        # Default to blocked for non-zero return codes without clear success indicators
        self.logger.info(f"❌ Site blocked - curl failed with return code {return_code}")
        return False, f"curl failed with return code {return_code}"

    def is_accessible_status_code(self, code: int) -> bool:
        """
        Check if HTTP status code indicates site accessibility.

        Any HTTP status code (including 4xx, 5xx errors) indicates that
        connection was established and site is accessible. Only connection
        timeouts/failures indicate DPI blocking.

        Args:
            code: HTTP status code

        Returns:
            bool: True if any valid HTTP status code (always True for 100-599)
        """
        return 100 <= code <= 599  # Any valid HTTP status code means accessible

    def is_tls_success(self, stderr: str) -> bool:
        """
        Check if TLS handshake succeeded despite certificate errors.

        Args:
            stderr: Standard error output from curl

        Returns:
            bool: True if TLS handshake succeeded
        """
        if not stderr:
            return False

        stderr_lower = stderr.lower()

        # Must contain SSL/TLS indicators
        if not any(keyword in stderr_lower for keyword in ["ssl", "tls", "certificate"]):
            return False

        # Check for certificate-related errors (which indicate successful handshake)
        for pattern in self.TLS_SUCCESS_PATTERNS:
            if re.search(pattern, stderr_lower):
                self.logger.debug(f"TLS success pattern matched: {pattern}")
                return True

        return False

    def _extract_http_status_code(self, stdout: str) -> Optional[int]:
        """Extract HTTP status code from curl stdout."""
        if not stdout:
            return None

        # curl -w "%{http_code}" outputs just the status code
        stdout_stripped = stdout.strip()
        if stdout_stripped.isdigit():
            code = int(stdout_stripped)
            if 100 <= code <= 599:  # Valid HTTP status code range
                return code

        # Try to find status code in response headers
        status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", stdout)
        if status_match:
            return int(status_match.group(1))

        return None

    def _is_connection_blocked(self, stderr: str) -> bool:
        """Check if stderr indicates connection blocking."""
        if not stderr:
            return False

        stderr_lower = stderr.lower()
        for pattern in self.BLOCKING_PATTERNS:
            if re.search(pattern, stderr_lower):
                return True

        return False

    def _extract_blocking_reason(self, stderr: str) -> str:
        """Extract specific blocking reason from stderr."""
        if not stderr:
            return "unknown error"

        stderr_lower = stderr.lower()

        if (
            "connection timed out" in stderr_lower
            or "timed out" in stderr_lower
            or "timeout" in stderr_lower
        ):
            return "connection timeout"
        elif "connection refused" in stderr_lower or "refused" in stderr_lower:
            return "connection refused"
        elif (
            "couldn't resolve host" in stderr_lower
            or "name resolution failed" in stderr_lower
            or "host not found" in stderr_lower
        ):
            return "DNS resolution failed"
        elif "network is unreachable" in stderr_lower:
            return "network unreachable"
        elif "no route to host" in stderr_lower:
            return "no route to host"
        else:
            # Return first 100 chars of stderr as reason
            return stderr[:100].strip()


class FallbackTestingManager:
    """
    Manager for fallback testing methods when curl is unavailable or fails.

    Provides alternative testing methods including TCP socket connectivity
    and Python requests library fallback.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the fallback manager with optional logger."""
        self.logger = logger or logging.getLogger(__name__)

    def test_tcp_connectivity(self, target_ip: str, port: int, timeout: float) -> Tuple[bool, str]:
        """
        Basic TCP connectivity test.

        Args:
            target_ip: Target IP address
            port: Target port (usually 443 for HTTPS)
            timeout: Connection timeout in seconds

        Returns:
            Tuple[bool, str]: (is_accessible, reason)
        """
        try:
            import socket

            self.logger.debug(f"Testing TCP connectivity to {target_ip}:{port}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                sock.connect((target_ip, port))
                sock.close()
                self.logger.info(f"✅ TCP connection successful to {target_ip}:{port}")
                return True, f"TCP connection successful to {target_ip}:{port}"
            except socket.timeout:
                self.logger.info(f"❌ TCP connection timeout to {target_ip}:{port}")
                return False, f"TCP connection timeout to {target_ip}:{port}"
            except socket.error as e:
                self.logger.info(f"❌ TCP connection failed to {target_ip}:{port}: {e}")
                return False, f"TCP connection failed: {e}"
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"TCP connectivity test error: {e}")
            return False, f"TCP test error: {e}"

    def test_with_requests(self, domain: str, timeout: float) -> Tuple[bool, str]:
        """
        HTTP test using Python requests library.

        Args:
            domain: Domain name to test
            timeout: Request timeout in seconds

        Returns:
            Tuple[bool, str]: (is_accessible, reason)
        """
        try:
            import requests
            from requests.exceptions import RequestException, Timeout, ConnectionError

            self.logger.debug(f"Testing HTTP connectivity to {domain} using requests")

            url = f"https://{domain}/"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=False,  # nosec B501 - Intentional for testing DPI bypass, not production
                    allow_redirects=True,
                )

                # Any HTTP status code means connection established = accessible
                self.logger.info(
                    f"✅ HTTP request successful - status {response.status_code} (connection established)"
                )
                return True, f"HTTP {response.status_code} via requests - connection established"

            except Timeout:
                self.logger.info(f"❌ HTTP request timeout to {domain}")
                return False, f"HTTP request timeout to {domain}"
            except ConnectionError as e:
                self.logger.info(f"❌ HTTP connection error to {domain}: {e}")
                return False, f"HTTP connection error: {e}"
            except RequestException as e:
                self.logger.info(f"❌ HTTP request error to {domain}: {e}")
                return False, f"HTTP request error: {e}"

        except ImportError:
            self.logger.warning("requests library not available for fallback testing")
            return False, "requests library not available"
        except Exception as e:
            self.logger.error(f"Requests fallback test error: {e}")
            return False, f"Requests test error: {e}"
