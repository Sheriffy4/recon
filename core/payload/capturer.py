"""
Payload capturer module.

This module provides functionality to capture real ClientHello packets
from target sites for use as fake payloads in DPI bypass strategies.

The capturer establishes TLS connections and intercepts the raw ClientHello
bytes before encryption, allowing them to be saved and reused.

Requirements: 2.1, 2.2, 2.3, 2.4
"""

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional

from .types import PayloadType
from .validator import PayloadValidator


logger = logging.getLogger(__name__)


class CaptureError(Exception):
    """Base exception for capture errors."""

    pass


class CaptureTimeoutError(CaptureError):
    """Raised when capture times out."""

    pass


class CaptureNetworkError(CaptureError):
    """Raised when network error occurs during capture."""

    pass


class CaptureValidationError(CaptureError):
    """Raised when captured data fails validation."""

    pass


@dataclass
class CaptureResult:
    """
    Result of a payload capture operation.

    Attributes:
        success: Whether the capture was successful
        payload: Captured payload bytes (None if failed)
        domain: Domain that was captured from
        error: Error message if capture failed
        attempts: Number of attempts made
    """

    success: bool
    payload: Optional[bytes]
    domain: str
    error: Optional[str] = None
    attempts: int = 1


class InterceptingSocket:
    """
    Socket wrapper that intercepts send() calls to capture ClientHello.

    This class wraps a socket to capture the raw ClientHello bytes
    that are sent during TLS handshake initiation.
    """

    def __init__(self, sock: socket.socket):
        """
        Initialize interceptor with underlying socket.

        Args:
            sock: Connected TCP socket
        """
        self._sock = sock
        self._captured_data: bytes = b""

    def send(self, data: bytes, flags: int = 0) -> int:
        """
        Intercept send calls to capture ClientHello.

        Args:
            data: Data being sent
            flags: Socket flags

        Returns:
            Number of bytes sent
        """
        # Capture the first send which should be ClientHello
        if not self._captured_data:
            self._captured_data = data
            logger.debug(f"Captured {len(data)} bytes of ClientHello")

        return self._sock.send(data, flags)

    def __getattr__(self, name):
        """Forward all other attributes to the underlying socket."""
        return getattr(self._sock, name)

    @property
    def captured_data(self) -> bytes:
        """Get the captured ClientHello data."""
        return self._captured_data


class PayloadCapturer:
    """
    Captures real ClientHello packets from target domains.

    Establishes TLS connections and intercepts the raw ClientHello
    bytes before encryption for use as fake payloads.

    Requirements: 2.1, 2.2, 2.3, 2.4
    """

    # Default configuration
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_BACKOFF_BASE = 1.0
    DEFAULT_TIMEOUT = 10.0
    DEFAULT_PORT = 443

    def __init__(
        self, max_retries: int = DEFAULT_MAX_RETRIES, backoff_base: float = DEFAULT_BACKOFF_BASE
    ):
        """
        Initialize PayloadCapturer.

        Args:
            max_retries: Maximum number of retry attempts (default: 3)
            backoff_base: Base delay for exponential backoff in seconds (default: 1.0)

        Requirements: 2.3
        """
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._validator = PayloadValidator()

    def _calculate_backoff(self, attempt: int) -> float:
        """
        Calculate exponential backoff delay.

        Args:
            attempt: Current attempt number (0-indexed)

        Returns:
            Delay in seconds
        """
        return self.backoff_base * (2**attempt)

    def _capture_clienthello_sync(self, domain: str, port: int, timeout: float) -> bytes:
        """
        Synchronously capture ClientHello from domain.

        This method creates a TCP connection and initiates TLS handshake,
        capturing the ClientHello bytes that are sent.

        Args:
            domain: Target domain name
            port: Target port (usually 443)
            timeout: Connection timeout in seconds

        Returns:
            Raw ClientHello bytes

        Raises:
            CaptureTimeoutError: If connection times out
            CaptureNetworkError: If network error occurs
        """
        sock = None
        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror as e:
                raise CaptureNetworkError(f"DNS resolution failed for {domain}: {e}")

            # Connect to server
            try:
                sock.connect((ip, port))
            except socket.timeout:
                raise CaptureTimeoutError(f"Connection to {domain}:{port} timed out")
            except socket.error as e:
                raise CaptureNetworkError(f"Connection to {domain}:{port} failed: {e}")

            # Create intercepting socket wrapper
            intercepting_sock = InterceptingSocket(sock)

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Wrap socket with SSL - this triggers ClientHello
            try:
                ssl_sock = context.wrap_socket(
                    intercepting_sock, server_hostname=domain, do_handshake_on_connect=True
                )
                # Close SSL socket after successful handshake
                ssl_sock.close()
            except ssl.SSLError as e:
                # SSL errors are expected in some cases, but we should
                # still have captured the ClientHello
                logger.debug(f"SSL error during handshake (expected): {e}")
            except socket.timeout:
                raise CaptureTimeoutError(f"TLS handshake with {domain} timed out")
            except socket.error as e:
                # Check if we captured data before the error
                if not intercepting_sock.captured_data:
                    raise CaptureNetworkError(f"TLS handshake failed: {e}")

            captured = intercepting_sock.captured_data
            if not captured:
                raise CaptureNetworkError("No ClientHello data captured")

            return captured

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    async def capture_clienthello(
        self, domain: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT
    ) -> CaptureResult:
        """
        Capture ClientHello from specified domain.

        Establishes a TLS connection and captures the ClientHello packet
        that is sent during handshake. Implements retry logic with
        exponential backoff.

        Args:
            domain: Target domain name (e.g., "www.google.com")
            port: Target port (default: 443)
            timeout: Connection timeout in seconds (default: 10.0)

        Returns:
            CaptureResult with captured payload or error information

        Requirements: 2.1, 2.2, 2.3, 2.4
        """
        domain = domain.strip().lower()

        # Remove protocol prefix if present
        if domain.startswith("https://"):
            domain = domain[8:]
        elif domain.startswith("http://"):
            domain = domain[7:]

        # Remove path if present
        if "/" in domain:
            domain = domain.split("/")[0]

        last_error: Optional[str] = None

        for attempt in range(self.max_retries):
            try:
                logger.info(
                    f"Capturing ClientHello from {domain}:{port} "
                    f"(attempt {attempt + 1}/{self.max_retries})"
                )

                # Run synchronous capture in thread pool
                loop = asyncio.get_event_loop()
                payload = await loop.run_in_executor(
                    None, self._capture_clienthello_sync, domain, port, timeout
                )

                # Validate captured payload
                validation = self._validator.validate_tls_clienthello(payload)

                if not validation.valid:
                    logger.warning(f"Captured payload failed validation: {validation.errors}")
                    # Still return it but log warning
                    for warning in validation.warnings:
                        logger.warning(f"Validation warning: {warning}")

                logger.info(
                    f"Successfully captured {len(payload)} bytes " f"ClientHello from {domain}"
                )

                return CaptureResult(
                    success=True, payload=payload, domain=domain, attempts=attempt + 1
                )

            except CaptureTimeoutError as e:
                last_error = str(e)
                logger.warning(f"Capture timeout (attempt {attempt + 1}): {e}")

            except CaptureNetworkError as e:
                last_error = str(e)
                logger.warning(f"Capture network error (attempt {attempt + 1}): {e}")

            except Exception as e:
                last_error = f"Unexpected error: {e}"
                logger.error(f"Unexpected capture error (attempt {attempt + 1}): {e}")

            # Apply exponential backoff before retry
            if attempt < self.max_retries - 1:
                backoff = self._calculate_backoff(attempt)
                logger.debug(f"Waiting {backoff:.1f}s before retry")
                await asyncio.sleep(backoff)

        # All retries exhausted
        return CaptureResult(
            success=False, payload=None, domain=domain, error=last_error, attempts=self.max_retries
        )

    def capture_clienthello_sync(
        self, domain: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT
    ) -> CaptureResult:
        """
        Synchronous version of capture_clienthello.

        Convenience method for non-async contexts.

        Args:
            domain: Target domain name
            port: Target port (default: 443)
            timeout: Connection timeout in seconds

        Returns:
            CaptureResult with captured payload or error information
        """
        return asyncio.run(self.capture_clienthello(domain, port, timeout))

    async def capture_http_request(
        self, domain: str, port: int = 80, path: str = "/"
    ) -> CaptureResult:
        """
        Capture HTTP request for specified domain.

        Creates a minimal HTTP GET request that can be used as fake payload.

        Args:
            domain: Target domain name
            port: Target port (default: 80)
            path: Request path (default: "/")

        Returns:
            CaptureResult with HTTP request payload
        """
        # Build HTTP request
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")

        # Validate the request
        validation = self._validator.validate_http_request(request)

        if not validation.valid:
            return CaptureResult(
                success=False,
                payload=None,
                domain=domain,
                error=f"Generated HTTP request invalid: {validation.errors}",
            )

        return CaptureResult(success=True, payload=request, domain=domain)

    async def capture_quic_initial(self, domain: str, port: int = 443) -> CaptureResult:
        """
        Capture QUIC Initial packet for specified domain.

        Note: QUIC capture is more complex and requires UDP handling.
        This is a placeholder for future implementation.

        Args:
            domain: Target domain name
            port: Target port (default: 443)

        Returns:
            CaptureResult indicating not implemented
        """
        # QUIC capture requires more complex UDP handling
        # For now, return not implemented
        return CaptureResult(
            success=False, payload=None, domain=domain, error="QUIC capture not yet implemented"
        )
