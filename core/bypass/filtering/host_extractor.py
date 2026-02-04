"""
Host Header Extractor component for runtime packet filtering.

This module provides functionality to extract Host header information
from HTTP requests with performance optimizations for domain-based filtering.
"""

import re
from typing import Optional
from functools import lru_cache


class HostHeaderExtractor:
    """
    Extracts Host header information from HTTP packets for runtime filtering.

    This class provides optimized methods to identify HTTP requests and extract
    the Host header value with fast-path processing for common cases.
    """

    # HTTP methods that typically contain Host headers (as bytes for faster comparison)
    HTTP_METHODS = {
        b"GET",
        b"POST",
        b"PUT",
        b"DELETE",
        b"HEAD",
        b"OPTIONS",
        b"PATCH",
        b"TRACE",
        b"CONNECT",
    }

    # Compiled regex patterns for efficient extraction
    HOST_HEADER_PATTERN = re.compile(
        rb"(?:^|\r\n)Host:\s*([^\r\n\s]+)(?:\s|$|\r\n)", re.IGNORECASE | re.MULTILINE
    )

    # Fast pattern for common case (Host header near beginning)
    FAST_HOST_PATTERN = re.compile(
        rb"^[^\r\n]*\r?\n(?:[^\r\n]*\r?\n)*?Host:\s*([^\r\n\s]+)", re.IGNORECASE | re.MULTILINE
    )

    def __init__(self):
        """Initialize Host Header Extractor with performance optimizations."""
        # Cache for fast HTTP method detection
        self._method_cache = {}
        self._cache_size_limit = 100

    def extract_host(self, payload: bytes) -> Optional[str]:
        """
        Extract Host header from HTTP requests with optimized parsing.

        Args:
            payload: Raw packet payload bytes

        Returns:
            Host header value if found, None otherwise

        Requirements: 1.2, 6.2, 6.3
        """
        if not payload or len(payload) < 16:  # Minimum HTTP request size
            return None

        # Fast rejection for non-HTTP traffic
        if not self._is_likely_http_fast(payload):
            return None

        try:
            # Try fast pattern first (Host header in first few lines)
            match = self.FAST_HOST_PATTERN.search(payload[:512])  # Search first 512 bytes
            if not match:
                # Fallback to full pattern search
                match = self.HOST_HEADER_PATTERN.search(payload)

            if match:
                host_bytes = match.group(1)

                # Remove port if present (e.g., "example.com:8080" -> "example.com")
                if b":" in host_bytes:
                    host_bytes = host_bytes.split(b":", 1)[0]

                # Decode to string and validate
                host_str = host_bytes.decode("utf-8", errors="ignore").strip()

                if self._is_valid_host(host_str):
                    return host_str

        except (UnicodeDecodeError, AttributeError):
            pass

        return None

    def _is_likely_http_fast(self, payload: bytes) -> bool:
        """
        Fast check if payload is likely an HTTP request.

        Args:
            payload: Raw packet payload bytes

        Returns:
            True if likely HTTP request, False otherwise
        """
        if len(payload) < 10:
            return False

        # Check cache for fast rejection
        prefix = payload[:8]
        if prefix in self._method_cache:
            return self._method_cache[prefix]

        # Fast check: look for HTTP method at start
        for method in self.HTTP_METHODS:
            if payload.startswith(method + b" "):
                result = True
                break
        else:
            result = False

        # Cache result (with size limit)
        if len(self._method_cache) < self._cache_size_limit:
            self._method_cache[prefix] = result

        return result

    def is_http_request(self, payload: bytes) -> bool:
        """
        Check if payload is an HTTP request with full validation.

        Args:
            payload: Raw packet payload bytes

        Returns:
            True if payload is HTTP request, False otherwise

        Requirements: 1.2, 6.2
        """
        if not self._is_likely_http_fast(payload):
            return False

        try:
            # Find first line end
            first_line_end = payload.find(b"\r\n")
            if first_line_end == -1:
                first_line_end = payload.find(b"\n")
            if first_line_end == -1:
                first_line_end = min(100, len(payload))  # Limit search

            first_line = payload[:first_line_end]

            # Split first line into parts
            parts = first_line.split(b" ", 2)
            if len(parts) < 3:
                return False

            method, path, version = parts

            # Check if method is valid HTTP method
            if method not in self.HTTP_METHODS:
                return False

            # Check if version looks like HTTP
            if not version.startswith(b"HTTP/"):
                return False

            # Check if path starts with / or is absolute URL
            if not (path.startswith(b"/") or path.startswith(b"http")):
                return False

            return True

        except (IndexError, ValueError):
            return False

    @lru_cache(maxsize=256)
    def _is_valid_host(self, host: str) -> bool:
        """
        Validate Host header value with caching for performance.

        Args:
            host: Host header value to validate

        Returns:
            True if host appears valid, False otherwise
        """
        if not host or len(host) > 253:
            return False

        # Check for valid characters (basic validation)
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(c in allowed_chars for c in host):
            return False

        # Check for valid structure
        if host.startswith(".") or host.endswith(".") or ".." in host:
            return False

        # Check for at least one dot (domain structure)
        if "." not in host:
            # Allow localhost and similar single names
            if host.lower() in ("localhost", "local"):
                return True
            return False

        return True

    def clear_cache(self) -> None:
        """Clear internal caches for memory management."""
        self._method_cache.clear()
        self._is_valid_host.cache_clear()
