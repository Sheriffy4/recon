"""
ClientHelloParser - TLS ClientHello parsing with full field extraction.

This module implements ClientHello parsing with:
- Extracting record_len, hs_len, versions
- SNI extraction with offset calculation
- Full extensions list extraction
- JA3 fingerprinting

Requirements: 8.1, 8.2, 8.3
"""

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ClientHelloInfo:
    """Information extracted from TLS ClientHello."""

    record_len: int
    hs_len: int
    record_version: str
    client_version: str
    sni: Optional[str]
    sni_offset: Optional[int]
    extensions: List[int]
    ja3: str
    error: Optional[str] = None
    cipher_suites: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)


class ClientHelloParser:
    """
    Parser for TLS ClientHello messages.

    Extracts all TLS fields including:
    - Record and handshake lengths
    - TLS versions
    - SNI with offset
    - Extensions list
    - Cipher suites
    - Supported groups (curves)
    - EC point formats
    - JA3 fingerprint

    Requirements: 8.1, 8.2, 8.3
    """

    def __init__(self):
        """Initialize ClientHello parser."""
        pass

    def parse(self, data: bytes) -> ClientHelloInfo:
        """
        Parse ClientHello and extract all TLS fields.

        Args:
            data: ClientHello bytes (TLS record)

        Returns:
            ClientHelloInfo with extracted fields
        """
        try:
            return self._parse_impl(data)
        except Exception as e:
            logger.error(f"Failed to parse ClientHello: {e}")
            return ClientHelloInfo(
                record_len=0,
                hs_len=0,
                record_version="unknown",
                client_version="unknown",
                sni=None,
                sni_offset=None,
                extensions=[],
                ja3="",
                error=str(e),
            )

    def _parse_impl(self, data: bytes) -> ClientHelloInfo:
        """Internal ClientHello parsing implementation."""
        if len(data) < 43:
            raise ValueError("Data too short for ClientHello")

        # TLS Record header
        content_type = data[0]
        if content_type != 0x16:
            raise ValueError(f"Not a handshake record: {content_type}")

        record_version = f"{data[1]}.{data[2]}"
        record_len = struct.unpack(">H", data[3:5])[0]

        # Handshake header
        hs_type = data[5]
        if hs_type != 0x01:
            raise ValueError(f"Not ClientHello: {hs_type}")

        hs_len = struct.unpack(">I", b"\x00" + data[6:9])[0]
        client_version = f"{data[9]}.{data[10]}"

        # Skip random (32 bytes)
        offset = 43

        # Session ID
        if offset >= len(data):
            raise ValueError("Truncated at session ID")
        session_id_len = data[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(data):
            raise ValueError("Truncated at cipher suites")
        cipher_suites_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 <= len(data):
                cs = struct.unpack(">H", data[offset + i : offset + i + 2])[0]
                cipher_suites.append(cs)
        offset += cipher_suites_len

        # Compression methods
        if offset >= len(data):
            raise ValueError("Truncated at compression")
        comp_len = data[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        sni = None
        sni_offset = None
        supported_groups = []
        ec_point_formats = []

        if offset + 2 <= len(data):
            ext_len = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
            ext_end = offset + ext_len

            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack(">H", data[offset : offset + 2])[0]
                ext_data_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                extensions.append(ext_type)

                ext_data_start = offset + 4
                ext_data_end = ext_data_start + ext_data_len

                if ext_type == 0x0000 and ext_data_end <= len(data):
                    sni, sni_offset = self.extract_sni(
                        data[ext_data_start:ext_data_end], ext_data_start
                    )
                elif ext_type == 0x000A and ext_data_end <= len(data):
                    supported_groups = self._parse_supported_groups(
                        data[ext_data_start:ext_data_end]
                    )
                elif ext_type == 0x000B and ext_data_end <= len(data):
                    ec_point_formats = self._parse_ec_point_formats(
                        data[ext_data_start:ext_data_end]
                    )

                offset += 4 + ext_data_len

        ja3 = self.calculate_ja3(
            client_version, cipher_suites, extensions, supported_groups, ec_point_formats
        )

        return ClientHelloInfo(
            record_len=record_len,
            hs_len=hs_len,
            record_version=record_version,
            client_version=client_version,
            sni=sni,
            sni_offset=sni_offset,
            extensions=extensions,
            ja3=ja3,
            cipher_suites=cipher_suites,
            supported_groups=supported_groups,
            ec_point_formats=ec_point_formats,
        )

    def extract_sni(self, data: bytes, base_offset: int) -> Tuple[Optional[str], Optional[int]]:
        """
        Extract SNI from SNI extension with offset calculation.

        Args:
            data: SNI extension data
            base_offset: Base offset in full ClientHello

        Returns:
            Tuple of (sni, offset) or (None, None) if not found
        """
        if len(data) < 5:
            return None, None

        sni_list_len = struct.unpack(">H", data[0:2])[0]
        if len(data) < 2 + sni_list_len:
            return None, None

        offset = 2
        while offset + 3 <= len(data):
            name_type = data[offset]
            name_len = struct.unpack(">H", data[offset + 1 : offset + 3])[0]

            if name_type == 0x00:  # host_name
                if offset + 3 + name_len <= len(data):
                    sni = data[offset + 3 : offset + 3 + name_len].decode("ascii", errors="ignore")
                    sni_offset_in_data = base_offset + offset + 3
                    return sni, sni_offset_in_data

            offset += 3 + name_len

        return None, None

    def extract_extensions(self, data: bytes, offset: int) -> List[int]:
        """
        Extract full extensions list from ClientHello.

        Args:
            data: ClientHello data
            offset: Offset to extensions section

        Returns:
            List of extension type IDs
        """
        extensions = []

        if offset + 2 > len(data):
            return extensions

        ext_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack(">H", data[offset : offset + 2])[0]
            ext_data_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
            extensions.append(ext_type)
            offset += 4 + ext_data_len

        return extensions

    def calculate_ja3(
        self,
        version: str,
        cipher_suites: List[int],
        extensions: List[int],
        groups: List[int],
        formats: List[int],
    ) -> str:
        """
        Calculate JA3 fingerprint.

        JA3 is an MD5 hash of:
        TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

        Args:
            version: TLS version string (e.g., "3.3")
            cipher_suites: List of cipher suite IDs
            extensions: List of extension type IDs
            groups: List of supported group IDs
            formats: List of EC point format IDs

        Returns:
            JA3 fingerprint as 32-character hex string
        """
        # Convert version to TLS version number
        version_map = {"3.1": "769", "3.3": "771", "3.4": "772"}
        tls_version = version_map.get(version, "771")

        # Filter GREASE values (RFC 8701)
        def filter_grease(values: List[int]) -> List[int]:
            grease = {
                0x0A0A,
                0x1A1A,
                0x2A2A,
                0x3A3A,
                0x4A4A,
                0x5A5A,
                0x6A6A,
                0x7A7A,
                0x8A8A,
                0x9A9A,
                0xAAAA,
                0xBABA,
                0xCACA,
                0xDADA,
                0xEAEA,
                0xFAFA,
            }
            return [v for v in values if v not in grease]

        filtered_ciphers = filter_grease(cipher_suites)
        filtered_extensions = filter_grease(extensions)
        filtered_groups = filter_grease(groups)

        # Build JA3 string
        ja3_string = ",".join(
            [
                tls_version,
                "-".join(str(c) for c in filtered_ciphers),
                "-".join(str(e) for e in filtered_extensions),
                "-".join(str(g) for g in filtered_groups),
                "-".join(str(f) for f in formats),
            ]
        )

        # Calculate MD5 hash
        return hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest()

    def _parse_supported_groups(self, data: bytes) -> List[int]:
        """Parse supported_groups extension."""
        if len(data) < 2:
            return []

        groups_len = struct.unpack(">H", data[0:2])[0]
        groups = []
        for i in range(2, min(2 + groups_len, len(data)), 2):
            if i + 2 <= len(data):
                groups.append(struct.unpack(">H", data[i : i + 2])[0])
        return groups

    def _parse_ec_point_formats(self, data: bytes) -> List[int]:
        """Parse ec_point_formats extension."""
        if len(data) < 1:
            return []

        formats_len = data[0]
        return list(data[1 : 1 + formats_len])
