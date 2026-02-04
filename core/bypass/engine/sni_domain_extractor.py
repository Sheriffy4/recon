"""
SNI Domain Extractor - ULTIMATE VERSION

This module implements domain extraction from network packets, supporting both
TLS SNI (Server Name Indication) and HTTP Host header extraction.

ULTIMATE FIXES:
- IP literal rejection (IPv4/IPv6)
- IDN normalization to punycode (A-label)
- Improved port handling
- Single unified extraction path
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import logging
import re
import ipaddress  # ULTIMATE FIX: Added for IP validation

logger = logging.getLogger(__name__)

try:
    # Optional fast TLS-only extractor (existing optimized implementation)
    from ..filtering.sni_extractor import SNIExtractor  # type: ignore
except Exception:  # pragma: no cover
    SNIExtractor = None


@dataclass(frozen=True)
class DomainExtractionResult:
    domain: Optional[str]
    source: str  # "tls_sni" | "http_host" | "none"


class SNIDomainExtractor:
    """
    Extracts domain names from TLS ClientHello packets (SNI) and HTTP requests (Host).

    Unified public API:
    - extract_from_payload(payload) -> DomainExtractionResult
    - extract_from_packet(packet) -> DomainExtractionResult

    Backward compatible API:
    - extract_domain_from_packet(packet) -> Optional[str]

    ULTIMATE VERSION: Proper validation with IP rejection and IDN normalization
    """

    def __init__(self, enable_fast_sni: bool = True):
        # Anchored Host header regex (multiline) to reduce false positives in binary payloads
        self.http_host_pattern = re.compile(rb"(?im)^\s*Host:\s*([^\r\n]+)\s*$")

        self._fast = None
        if enable_fast_sni and SNIExtractor is not None:
            try:
                self._fast = SNIExtractor()
            except Exception as e:
                logger.debug(f"Failed to init fast SNIExtractor: {e}")
                self._fast = None

        logger.debug("SNIDomainExtractor initialized (ULTIMATE VERSION)")

    # ---------------------------------------------------------------------
    # New unified API
    # ---------------------------------------------------------------------

    def extract_from_packet(self, packet) -> DomainExtractionResult:
        payload = getattr(packet, "payload", None)
        return self.extract_from_payload(payload)

    def extract_from_payload(self, payload: Optional[bytes]) -> DomainExtractionResult:
        if not payload:
            return DomainExtractionResult(domain=None, source="none")

        # 1) Fast TLS SNI extraction (if available)
        if self._fast is not None:
            try:
                d = self._fast.extract_sni(payload)
                d = self._validate_domain(d) if d else None
                if d:
                    return DomainExtractionResult(domain=d, source="tls_sni")
            except Exception as e:
                logger.debug(f"Fast SNI extractor error: {e}")

        # 2) Manual TLS ClientHello parsing (fallback)
        d = self._extract_sni_from_tls(payload)
        if d:
            return DomainExtractionResult(domain=d, source="tls_sni")

        # 3) HTTP Host header
        d = self.extract_host_from_http(payload)
        if d:
            return DomainExtractionResult(domain=d, source="http_host")

        return DomainExtractionResult(domain=None, source="none")

    # ---------------------------------------------------------------------
    # Backward compatible API
    # ---------------------------------------------------------------------

    def extract_domain_from_packet(self, packet) -> Optional[str]:
        """
        Backward compatible wrapper that returns only the domain string.
        """
        try:
            return self.extract_from_packet(packet).domain
        except Exception as e:
            logger.error(f"Error extracting domain from packet: {e}")
            return None

    # ---------------------------------------------------------------------
    # TLS SNI extraction (manual fallback)
    # ---------------------------------------------------------------------

    def _extract_sni_from_tls(self, payload: Optional[bytes]) -> Optional[str]:
        try:
            if not payload or len(payload) < 43:
                return None

            # TLS record type: Handshake (0x16)
            if payload[0] != 0x16:
                return None

            # Handshake type at payload[5] is commonly ClientHello (0x01)
            if len(payload) < 6 or payload[5] != 0x01:
                return None

            # Parse TLS ClientHello structure (best-effort, not a full TLS parser)
            pos = 9

            # Skip: client_version(2) + random(32)
            pos += 2 + 32
            if pos + 1 > len(payload):
                return None

            # Session ID
            sid_len = payload[pos]
            pos += 1 + sid_len
            if pos + 2 > len(payload):
                return None

            # Cipher suites
            cs_len = int.from_bytes(payload[pos : pos + 2], "big")
            pos += 2 + cs_len
            if pos + 1 > len(payload):
                return None

            # Compression methods
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return None

            # Extensions
            ext_len = int.from_bytes(payload[pos : pos + 2], "big")
            ext_start = pos + 2
            ext_end = min(len(payload), ext_start + ext_len)

            return self._parse_tls_extensions(payload, ext_start, ext_end)

        except Exception as e:
            logger.debug(f"Error extracting SNI from TLS: {e}")
            return None

    def _parse_tls_extensions(self, payload: bytes, ext_start: int, ext_end: int) -> Optional[str]:
        s = ext_start
        while s + 4 <= ext_end:
            etype = int.from_bytes(payload[s : s + 2], "big")
            elen = int.from_bytes(payload[s + 2 : s + 4], "big")
            epos = s + 4

            if epos + elen > ext_end:
                break

            # SNI extension type == 0
            if etype == 0 and elen >= 5:
                d = self._parse_sni_extension(payload, epos, elen)
                if d:
                    return d

            s = epos + elen

        return None

    def _parse_sni_extension(self, payload: bytes, epos: int, elen: int) -> Optional[str]:
        try:
            list_len = int.from_bytes(payload[epos : epos + 2], "big")
            npos = epos + 2

            if not (npos + list_len <= epos + elen and npos + 3 <= len(payload)):
                return None

            ntype = payload[npos]
            nlen = int.from_bytes(payload[npos + 1 : npos + 3], "big")
            nstart = npos + 3

            # host_name type == 0
            if ntype != 0 or nstart + nlen > len(payload):
                return None

            domain = payload[nstart : nstart + nlen].decode("idna", errors="strict")
            return self._validate_domain(domain)
        except Exception:
            return None

    # ---------------------------------------------------------------------
    # HTTP Host extraction
    # ---------------------------------------------------------------------

    def extract_host_from_http(self, payload: bytes) -> Optional[str]:
        try:
            # Simple heuristic to avoid parsing random binary as HTTP
            if not (
                payload.startswith(b"GET ")
                or payload.startswith(b"POST ")
                or payload.startswith(b"HEAD ")
                or payload.startswith(b"PUT ")
                or payload.startswith(b"DELETE ")
                or payload.startswith(b"OPTIONS ")
                or payload.startswith(b"CONNECT ")
                or payload.startswith(b"TRACE ")
                or payload.startswith(b"PATCH ")
            ):
                return None

            match = self.http_host_pattern.search(payload)
            if not match:
                return None

            host = match.group(1).decode("ascii", errors="ignore").strip()
            return self._validate_domain(host)

        except Exception as e:
            logger.debug(f"Error extracting HTTP Host: {e}")
            return None

    # ---------------------------------------------------------------------
    # Domain validation / normalization - ULTIMATE VERSION
    # ---------------------------------------------------------------------

    def _validate_domain(self, domain: Optional[str]) -> Optional[str]:
        """
        Validate and normalize domain name.

        ULTIMATE FIXES:
        - Rejects IP literals (IPv4/IPv6)
        - Normalizes IDN to punycode (A-label) for stable rule matching
        - Improved port handling (only removes if numeric)
        - Rejects whitespace and control characters
        """
        if not domain:
            return None

        try:
            # Basic normalization
            domain = domain.strip().lower().rstrip(".")

            # IPv6 literal in Host header: [::1]:443
            if domain.startswith("["):
                return None

            # Remove port if present (only if numeric after colon)
            if ":" in domain:
                host, port = domain.rsplit(":", 1)
                if port.isdigit():
                    domain = host

            # Basic validation
            if not domain or "." not in domain or len(domain) > 253:
                return None

            # Reject whitespace and control characters
            if any(c in domain for c in [" ", "\t", "\n", "\r", "\x00"]):
                return None

            # ULTIMATE FIX: Reject plain IP literals (IPv4/IPv6)
            try:
                ipaddress.ip_address(domain)
                # If we get here, it's a valid IP address - reject it
                logger.debug(f"Rejected IP literal as domain: {domain}")
                return None
            except ValueError:
                # Not an IP address - this is what we want
                pass

            # ULTIMATE FIX: Normalize IDN to A-label (punycode ASCII) for stable rule matching
            try:
                domain = domain.encode("idna").decode("ascii")
            except Exception:
                # Invalid IDN - reject
                logger.debug(f"Invalid IDN domain rejected: {domain}")
                return None

            # Final structural validation
            if domain.startswith(".") or domain.startswith("-"):
                return None
            if ".." in domain or ".-" in domain or "-." in domain:
                return None

            return domain

        except Exception as e:
            logger.debug(f"Domain validation error: {e}")
            return None
