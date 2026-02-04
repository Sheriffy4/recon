#!/usr/bin/env python3

from __future__ import annotations

import logging
import random
from typing import Any, Dict, Optional, Tuple

from ..attacks.metadata import SpecialParameterValues
from ..filtering.sni_extractor import SNIExtractor

logger = logging.getLogger(__name__)


class TLSConstants:
    """Константы для парсинга TLS ClientHello."""

    RECORD_HEADER_SIZE = 5
    HANDSHAKE_HEADER_SIZE = 4
    VERSION_SIZE = 2
    RANDOM_SIZE = 32
    MIN_CLIENT_HELLO_SIZE = 43  # до Session ID
    CONTENT_TYPE_HANDSHAKE = 0x16
    SNI_EXTENSION_TYPE = b"\x00\x00"  # extension_type = 0x0000 (SNI)

class TLSFieldLocator:

    def __init__(
        self,
        sni_extractor: Optional[SNIExtractor] = None,
        default_split_ratio: float = 0.5,
    ):
        """
        Initialize TLS Field Locator.

        Args:
            sni_extractor: Existing SNIExtractor instance (can be None for fallback)
            default_split_ratio: Default ratio for split position (0.0-1.0)

        Note:
            If sni_extractor is None, fallback methods will be used for SNI extraction.
            This allows explicit control over SNI extraction behavior without automatic
            instantiation of SNIExtractor.
        """
        self._sni_extractor = sni_extractor  # Can be None, will use fallback
        self._default_split_ratio = default_split_ratio

    def resolve_position(
        self,
        split_pos: Any,
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> int:
        """
        Resolve split position from various formats.

        Args:
            split_pos: Position specification (int, str like "cipher"/"sni"/"midsld"/"random", or None)
            payload: Packet payload bytes
            packet_info: Additional packet information

        Returns:
            Resolved position as integer (0 if payload too short)

        Requirements: 3.1, 3.2
        """
        payload_len = len(payload)

        # Guard: payload too short to split
        if payload_len < 2:
            logger.debug("Payload too short (%d bytes), cannot split", payload_len)
            return 0  # No meaningful split position

        default_pos = int(payload_len * self._default_split_ratio) or 1

        if split_pos is None:
            return default_pos

        if isinstance(split_pos, int):
            return max(1, min(split_pos, payload_len - 1))

        if isinstance(split_pos, str):
            token = split_pos.strip().lower()
            if token in (str(SpecialParameterValues.CIPHER).lower(), "cipher"):
                return self.find_cipher_position(payload)
            if token in (str(SpecialParameterValues.SNI).lower(), "sni"):
                return self.find_sni_position(payload)
            if token in (str(SpecialParameterValues.MIDSLD).lower(), "midsld"):
                return self.find_midsld_position(payload, packet_info)
            if token in (str(SpecialParameterValues.RANDOM).lower(), "random"):
                # nosec B311 - random is used for non-cryptographic DPI evasion, not security
                return random.randint(1, max(1, payload_len - 1))
            try:
                iv = int(token)
            except ValueError:
                logger.warning("Invalid split_pos %r, using default position", split_pos)
                return default_pos
            else:
                return max(1, min(iv, payload_len - 1))

        logger.warning("Unknown split_pos type %s, using default position", type(split_pos))
        return default_pos

    def find_cipher_position(self, payload: bytes) -> int:
        """
        Find position of cipher suites in TLS ClientHello.

        Args:
            payload: TLS ClientHello payload

        Returns:
            Position of cipher suites or middle of payload as fallback
        """
        try:
            if (
                len(payload) < TLSConstants.MIN_CLIENT_HELLO_SIZE
                or payload[0] != TLSConstants.CONTENT_TYPE_HANDSHAKE
            ):
                return len(payload) // 2

            pos = TLSConstants.MIN_CLIENT_HELLO_SIZE
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len

            if pos + 2 <= len(payload):
                return pos
        except Exception as e:
            logger.debug(f"Failed to find cipher position: {e}")

        return len(payload) // 2

    def find_sni_position(self, payload: bytes) -> int:
        """
        Find position of SNI hostname in TLS ClientHello.

        Uses proper TLS parsing via SNIExtractor instead of naive scanning.

        Args:
            payload: TLS ClientHello payload

        Returns:
            Position of SNI hostname or middle of payload as fallback

        Requirements: 3.1, 3.2
        """
        try:
            parsed = self._parse_sni_extension(payload)
            if parsed is not None:
                pos, hostname = parsed
                logger.debug(f"Found SNI hostname '{hostname}' position at {pos}")
                return pos
        except Exception as e:
            logger.warning(f"Failed to find SNI position with proper TLS parsing: {e}")

        # Fallback к середине payload
        fallback_pos = len(payload) // 2
        logger.debug(f"Using fallback SNI position: {fallback_pos}")
        return fallback_pos

    def find_midsld_position(
        self,
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> int:
        """
        Find position of middle of Second-Level Domain (SLD) in SNI.

        Args:
            payload: TLS ClientHello payload
            packet_info: Additional packet information (unused currently)

        Returns:
            Position of middle of SLD or middle of payload as fallback
        """
        try:
            domain = self.extract_domain_from_sni(payload)
            if not domain:
                return len(payload) // 2

            parts = domain.split(".")
            if len(parts) < 2:
                return len(payload) // 2

            sld = parts[-2]
            mid = len(sld) // 2

            domain_bytes = domain.encode("utf-8")
            domain_pos = payload.find(domain_bytes)
            if domain_pos == -1:
                return len(payload) // 2

            sld_start = domain_pos + domain.rfind(sld)
            return sld_start + mid

        except Exception as e:
            logger.debug(f"Failed to find midsld position: {e}")

        return len(payload) // 2

    def extract_domain_from_sni(self, payload: bytes) -> Optional[str]:
        """
        Extract hostname from SNI extension.

        Args:
            payload: TLS ClientHello payload

        Returns:
            Hostname string or None if not found
        """
        try:
            parsed = self._parse_sni_extension(payload)
            if parsed is None:
                return None
            _, hostname = parsed
            return hostname
        except Exception as e:
            logger.debug(f"Failed to extract domain from SNI: {e}")
            return None

    # ---------- Internal SNI parsing methods ----------

    def _parse_sni_extension(self, payload: bytes) -> Optional[Tuple[int, str]]:
        """
        Parse SNI extension in TLS ClientHello with proper TLS structure parsing.

        Replaces naive scanning approach with correct RFC-compliant parsing.

        Args:
            payload: TLS ClientHello payload

        Returns:
            Tuple of (hostname_offset, hostname) or None if not found
            hostname_offset is the offset of the first byte of the hostname

        Requirements: 3.1, 3.2, 3.3
        """
        try:
            extractor = self._sni_extractor
            if extractor is None:
                # No extractor provided, use legacy fallback
                logger.debug("No SNIExtractor available, using legacy parsing")
                return self._legacy_parse_sni_extension(payload)

            if not extractor.is_tls_clienthello(payload):
                logger.debug("Payload is not a valid TLS ClientHello")
                return None

            hostname = extractor.extract_sni(payload)
            if not hostname:
                logger.debug("No SNI found in TLS ClientHello")
                return None

            # Find hostname position in payload for backward compatibility
            hostname_offset = self._find_hostname_offset_in_payload(payload, hostname)
            if hostname_offset is None:
                # If we can't find exact position, use middle as fallback
                hostname_offset = len(payload) // 2
                logger.debug(
                    f"Could not find exact hostname offset, using fallback position {hostname_offset}"
                )

            logger.debug(f"Extracted SNI hostname '{hostname}' at offset {hostname_offset}")
            return hostname_offset, hostname

        except ImportError:
            logger.warning("SNIExtractor not available, falling back to legacy parsing")
            return self._legacy_parse_sni_extension(payload)
        except Exception as e:
            logger.debug(f"Failed to parse SNI extension with proper TLS parser: {e}")
            return None

    def _find_hostname_offset_in_payload(self, payload: bytes, hostname: str) -> Optional[int]:
        """
        Find exact offset of hostname in payload for backward compatibility.

        Args:
            payload: TLS ClientHello payload
            hostname: Extracted hostname

        Returns:
            Offset of hostname in payload or None if not found
        """
        try:
            hostname_bytes = hostname.encode("utf-8")
            offset = payload.find(hostname_bytes)
            if offset != -1:
                return offset

            # Try ASCII encoding
            hostname_bytes = hostname.encode("ascii")
            offset = payload.find(hostname_bytes)
            if offset != -1:
                return offset

        except Exception as e:
            logger.debug(f"Error finding hostname offset: {e}")

        return None

    def _legacy_parse_sni_extension(self, payload: bytes) -> Optional[Tuple[int, str]]:
        """
        Legacy SNI parsing method (fallback only).

        WARNING: This method uses naive scanning approach and may produce
        false matches. Only used if new parser is unavailable.

        Args:
            payload: TLS ClientHello payload

        Returns:
            Tuple of (hostname_offset, hostname) or None if not found
        """
        logger.warning("Using legacy SNI parsing - may produce false matches!")

        try:
            data = payload
            max_i = len(data) - 9
            if max_i <= 0:
                return None

            for i in range(max_i):
                # extension_type == 0x0000 (SNI)
                if data[i : i + 2] != TLSConstants.SNI_EXTENSION_TYPE:
                    continue
                if i + 9 > len(data):
                    continue

                # Structure:
                # i+0..1  extension_type (0x0000)
                # i+2..3  extension_length
                # i+4..5  list_length
                # i+6     name_type (0=host_name)
                # i+7..8  name_length
                # i+9..   hostname
                name_type = data[i + 6]
                if name_type != 0:
                    continue

                name_len = int.from_bytes(data[i + 7 : i + 9], "big")
                host_start = i + 9
                host_end = host_start + name_len

                if name_len <= 0 or host_end > len(data):
                    continue

                host_bytes = data[host_start:host_end]
                try:
                    hostname = host_bytes.decode("ascii")
                except UnicodeDecodeError:
                    hostname = host_bytes.decode("ascii", "ignore")

                if not hostname:
                    continue

                # Additional hostname validation to reduce false matches
                if not self._is_valid_hostname(hostname):
                    logger.debug(f"Invalid hostname format: {hostname}")
                    continue

                logger.warning(f"Legacy parser extracted hostname: {hostname}")
                return host_start, hostname

        except Exception as e:
            logger.debug(f"Failed to parse SNI extension with legacy parser: {e}")

        return None

    def _is_valid_hostname(self, hostname: str) -> bool:
        """
        Validate hostname to reduce false matches.

        Args:
            hostname: Hostname to validate

        Returns:
            True if hostname is valid, False otherwise

        Requirements: 3.5
        """
        if not hostname or len(hostname) > 253:
            return False

        # Basic character validation
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(c in allowed_chars for c in hostname):
            return False

        # Structural validation
        if hostname.startswith(".") or hostname.endswith(".") or ".." in hostname:
            return False

        if hostname.startswith("-") or hostname.endswith("-"):
            return False

        # Must have at least one dot (TLD)
        if "." not in hostname:
            return False

        return True
