"""
SNI Detector component for DPI strategy implementation.

This module provides functionality to detect and extract SNI (Server Name Indication)
information from TLS Client Hello packets for DPI bypass strategies.
"""

import struct
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class SNIDetector:
    """
    Detects and extracts SNI information from TLS packets.

    This class provides methods to:
    - Identify TLS Client Hello packets
    - Parse TLS extensions to find SNI
    - Extract SNI values for logging and debugging
    """

    # TLS constants
    TLS_HANDSHAKE_TYPE = 0x16
    TLS_CLIENT_HELLO = 0x01
    SNI_EXTENSION_TYPE = 0x0000

    # TLS version constants
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

    SUPPORTED_TLS_VERSIONS = {TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3}

    def __init__(self):
        """Initialize SNI Detector."""
        self.logger = logger

    def is_client_hello(self, packet: bytes) -> bool:
        """
        Check if packet is a TLS Client Hello packet.

        Args:
            packet: Raw packet bytes

        Returns:
            True if packet is TLS Client Hello, False otherwise

        Requirements: 3.1, 3.3
        """
        try:
            if len(packet) < 6:  # Minimum TLS record header size
                return False

            # Parse TLS record header
            # Format: [content_type(1)] [version(2)] [length(2)] [handshake_type(1)]
            content_type = packet[0]
            version = struct.unpack("!H", packet[1:3])[0]
            record_length = struct.unpack("!H", packet[3:5])[0]

            # Check if it's a handshake record
            if content_type != self.TLS_HANDSHAKE_TYPE:
                return False

            # Check TLS version
            if version not in self.SUPPORTED_TLS_VERSIONS:
                self.logger.debug(f"Unsupported TLS version: 0x{version:04x}")
                return False

            # Check if packet is long enough for handshake header
            if len(packet) < 9:  # TLS record header (5) + handshake header (4)
                return False

            # Check record length consistency
            if record_length > len(packet) - 5:
                self.logger.debug(
                    f"TLS record length mismatch: {record_length} > {len(packet) - 5}"
                )
                return False

            # Parse handshake header
            handshake_type = packet[5]

            # Check if it's Client Hello
            if handshake_type != self.TLS_CLIENT_HELLO:
                return False

            self.logger.debug(
                f"Detected TLS Client Hello, version: 0x{version:04x}, length: {record_length}"
            )
            return True

        except (struct.error, IndexError) as e:
            self.logger.debug(f"Error parsing TLS packet: {e}")
            return False

    def find_sni_position(self, tls_packet: bytes) -> Optional[int]:
        """
        Find the position of SNI extension in TLS Client Hello packet.

        Args:
            tls_packet: Raw TLS packet bytes

        Returns:
            Position of SNI extension start, or None if not found

        Requirements: 3.2, 3.4, 3.7
        """
        try:
            if not self.is_client_hello(tls_packet):
                self.logger.debug("Packet is not TLS Client Hello")
                return None

            # Parse extensions and find SNI
            extensions = self.parse_tls_extensions(tls_packet)

            if self.SNI_EXTENSION_TYPE in extensions:
                sni_position = extensions[self.SNI_EXTENSION_TYPE]
                self.logger.debug(f"Found SNI extension at position: {sni_position}")
                return sni_position

            self.logger.debug("SNI extension not found in packet")
            return None

        except Exception as e:
            self.logger.error(f"Error finding SNI position: {e}")
            return None

    def parse_tls_extensions(self, packet: bytes) -> Dict[int, int]:
        """
        Parse TLS extensions and return their positions.

        Args:
            packet: Raw TLS packet bytes

        Returns:
            Dictionary mapping extension type to position

        Requirements: 3.2, 3.4, 3.7
        """
        extensions = {}

        try:
            # Basic validation
            if not self.is_client_hello(packet):
                return extensions

            # Skip to Client Hello payload
            # TLS record header (5) + handshake header (4) = 9 bytes
            offset = 9

            # Skip Client Hello fixed fields (version + random = 34 bytes)
            offset += 34

            # Skip session ID
            if len(packet) < offset + 1:
                return extensions
            session_id_length = packet[offset]
            offset += 1 + session_id_length

            # Skip cipher suites
            if len(packet) < offset + 2:
                return extensions
            cipher_suites_length = struct.unpack("!H", packet[offset : offset + 2])[0]
            offset += 2 + cipher_suites_length

            # Skip compression methods
            if len(packet) < offset + 1:
                return extensions
            compression_methods_length = packet[offset]
            offset += 1 + compression_methods_length

            # Parse extensions
            if len(packet) < offset + 2:
                return extensions

            extensions_length = struct.unpack("!H", packet[offset : offset + 2])[0]
            offset += 2

            extensions_end = offset + extensions_length

            # Parse individual extensions
            while offset < extensions_end and offset + 4 <= len(packet):
                ext_type = struct.unpack("!H", packet[offset : offset + 2])[0]
                ext_length = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]

                # Store extension position
                extensions[ext_type] = offset

                self.logger.debug(
                    f"Found extension type 0x{ext_type:04x} at position {offset}, length: {ext_length}"
                )

                # Move to next extension
                offset += 4 + ext_length

            return extensions

        except Exception as e:
            self.logger.error(f"Error parsing TLS extensions: {e}")
            return {}

    def extract_sni_value(self, packet: bytes, position: int = None) -> Optional[str]:
        """
        Extract SNI value from TLS packet for logging and debugging.

        Args:
            packet: Raw TLS packet bytes
            position: Optional position of SNI extension (will be found if not provided)

        Returns:
            SNI server name string, or None if not found/invalid

        Requirements: 3.4, 3.6
        """
        try:
            if position is None:
                position = self.find_sni_position(packet)
                if position is None:
                    return None

            # Parse SNI extension structure
            sni_value = self._parse_sni_extension(packet, position)

            if sni_value:
                self.logger.debug(f"Extracted SNI value: {sni_value}")
                return sni_value

            return None

        except Exception as e:
            self.logger.error(f"Error extracting SNI value: {e}")
            return None

    def _parse_sni_extension(self, packet: bytes, position: int) -> Optional[str]:
        """
        Parse SNI extension structure to extract server name.

        Args:
            packet: Raw packet bytes
            position: Position of SNI extension

        Returns:
            Server name string or None if invalid
        """
        try:
            # SNI extension structure:
            # Extension Type (2) + Extension Length (2) + SNI List Length (2) + SNI Entry
            # SNI Entry: Name Type (1) + Name Length (2) + Name (variable)

            if len(packet) < position + 9:  # Minimum SNI extension size
                return None

            # Verify extension type
            ext_type = struct.unpack("!H", packet[position : position + 2])[0]
            if ext_type != self.SNI_EXTENSION_TYPE:
                return None

            # Read extension length
            ext_length = struct.unpack("!H", packet[position + 2 : position + 4])[0]

            if len(packet) < position + 4 + ext_length:
                return None

            # Parse SNI list
            offset = position + 4

            # Read SNI list length
            sni_list_length = struct.unpack("!H", packet[offset : offset + 2])[0]
            offset += 2

            if len(packet) < offset + sni_list_length or sni_list_length < 3:
                return None

            # Read name type (should be 0x00 for hostname)
            name_type = packet[offset]
            offset += 1

            if name_type != 0x00:
                return None

            # Read name length
            name_length = struct.unpack("!H", packet[offset : offset + 2])[0]
            offset += 2

            if len(packet) < offset + name_length:
                return None

            # Extract server name
            server_name_bytes = packet[offset : offset + name_length]

            # Decode server name
            try:
                server_name = server_name_bytes.decode("utf-8")
                if self._is_valid_hostname(server_name):
                    return server_name
            except UnicodeDecodeError:
                pass

            return None

        except Exception as e:
            self.logger.error(f"Error parsing SNI extension: {e}")
            return None

    def _is_valid_hostname(self, hostname: str) -> bool:
        """
        Basic hostname validation for SNI.

        Args:
            hostname: Hostname string to validate

        Returns:
            True if hostname appears valid, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False

        # Check for valid characters (basic check)
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(c in allowed_chars for c in hostname):
            return False

        # Check for valid structure (no consecutive dots, etc.)
        if ".." in hostname or hostname.startswith(".") or hostname.endswith("."):
            return False

        return True

    def get_sni_info(self, packet: bytes) -> Dict[str, any]:
        """
        Get comprehensive SNI information from packet.

        Args:
            packet: Raw TLS packet bytes

        Returns:
            Dictionary with SNI information
        """
        info = {
            "is_client_hello": False,
            "has_sni": False,
            "sni_position": None,
            "sni_value": None,
            "packet_size": len(packet),
        }

        try:
            info["is_client_hello"] = self.is_client_hello(packet)

            if info["is_client_hello"]:
                info["sni_position"] = self.find_sni_position(packet)

                if info["sni_position"] is not None:
                    info["has_sni"] = True
                    info["sni_value"] = self.extract_sni_value(packet, info["sni_position"])

        except Exception as e:
            self.logger.error(f"Error getting SNI info: {e}")

        return info

    def _create_client_hello_with_sni(self, hostname: str) -> bytes:
        """
        Create a TLS Client Hello packet with SNI extension for testing.

        Args:
            hostname: The hostname to include in SNI extension

        Returns:
            Complete TLS Client Hello packet bytes
        """
        # TLS Record Header (5 bytes)
        record = bytearray()
        record.extend(b"\x16")  # Content Type: Handshake (22)
        record.extend(b"\x03\x03")  # Version: TLS 1.2

        # We'll set the record length later
        record_length_pos = len(record)
        record.extend(b"\x00\x00")  # Placeholder for record length

        # Handshake Header (4 bytes)
        handshake_start = len(record)
        record.extend(b"\x01")  # Handshake Type: Client Hello (1)

        # We'll set the handshake length later
        handshake_length_pos = len(record)
        record.extend(b"\x00\x00\x00")  # Placeholder for handshake length (3 bytes)

        # Client Hello Message
        client_hello_start = len(record)
        record.extend(b"\x03\x03")  # Client Version: TLS 1.2
        record.extend(b"\x00" * 32)  # Random (32 bytes)
        record.extend(b"\x00")  # Session ID Length (0)

        # Cipher Suites
        record.extend(b"\x00\x02")  # Cipher Suites Length (2 bytes)
        record.extend(b"\x00\x35")  # TLS_RSA_WITH_AES_256_CBC_SHA

        # Compression Methods
        record.extend(b"\x01")  # Compression Methods Length (1 byte)
        record.extend(b"\x00")  # Compression Method: null

        # Extensions
        extensions_length_pos = len(record)
        record.extend(b"\x00\x00")  # Extensions length placeholder

        # SNI Extension
        sni_extension_start = len(record)

        record.extend(struct.pack(">H", 0x0000))  # Extension Type: SNI (0)

        # SNI Extension Data
        hostname_bytes = hostname.encode("utf-8")
        sni_list_length = 1 + 2 + len(hostname_bytes)  # name_type(1) + name_length(2) + name
        sni_extension_length = 2 + sni_list_length  # list_length(2) + sni_list

        record.extend(struct.pack(">H", sni_extension_length))  # Extension Length
        record.extend(struct.pack(">H", sni_list_length))  # Server Name List Length
        record.extend(b"\x00")  # Server Name Type: host_name (0)
        record.extend(struct.pack(">H", len(hostname_bytes)))  # Server Name Length
        record.extend(hostname_bytes)  # Server Name

        # Calculate and set lengths
        total_extensions_length = len(record) - extensions_length_pos - 2
        struct.pack_into(">H", record, extensions_length_pos, total_extensions_length)

        handshake_length = len(record) - handshake_start - 4
        struct.pack_into(">I", record, handshake_length_pos, handshake_length)
        record[handshake_length_pos] = 0  # Clear the first byte (should be 0 for 3-byte length)

        record_length = len(record) - 5  # Exclude TLS record header
        struct.pack_into(">H", record, record_length_pos, record_length)

        return bytes(record)

    def parse_tls_extensions(self, packet: bytes) -> Dict[int, int]:
        """
        Parse all TLS extensions and return their positions.

        Args:
            packet: Raw TLS Client Hello packet bytes

        Returns:
            Dictionary mapping extension type to position in packet
        """
        extensions = {}

        try:
            if not self.is_client_hello(packet):
                return extensions

            # Skip to extensions section
            offset = 5  # TLS record header
            offset += 4  # Handshake header
            offset += 2  # Client Hello version
            offset += 32  # Random

            if len(packet) <= offset:
                return extensions

            # Session ID
            session_id_length = packet[offset]
            offset += 1 + session_id_length

            if len(packet) <= offset + 2:
                return extensions

            # Cipher suites
            cipher_suites_length = struct.unpack(">H", packet[offset : offset + 2])[0]
            offset += 2 + cipher_suites_length

            if len(packet) <= offset + 1:
                return extensions

            # Compression methods
            compression_methods_length = packet[offset]
            offset += 1 + compression_methods_length

            if len(packet) <= offset + 2:
                return extensions

            # Extensions length
            extensions_length = struct.unpack(">H", packet[offset : offset + 2])[0]
            offset += 2

            # Parse individual extensions
            extensions_end = offset + extensions_length

            while offset < extensions_end and offset + 4 <= len(packet):
                extension_type = struct.unpack(">H", packet[offset : offset + 2])[0]
                extension_length = struct.unpack(">H", packet[offset + 2 : offset + 4])[0]

                # Store extension position
                extensions[extension_type] = offset

                # Move to next extension
                offset += 4 + extension_length

        except (struct.error, IndexError) as e:
            self.logger.debug(f"Error parsing TLS extensions: {e}")

        return extensions
