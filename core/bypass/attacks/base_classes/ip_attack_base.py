"""
Base class for IP-layer attacks.

Provides common functionality for attacks that manipulate IP protocol:
- IP packet parsing and construction
- MTU detection and fragmentation logic
- Checksum calculation utilities
- IP options manipulation
"""

import logging
import struct
import socket
from abc import abstractmethod
from typing import Dict, Any, List, Optional
from ..base import BaseAttack, AttackContext

logger = logging.getLogger(__name__)


class IPPacket:
    """Represents a parsed IP packet."""

    def __init__(self, data: bytes):
        """Parse IP packet from raw bytes."""
        self.raw_data = data
        self.version = (data[0] >> 4) & 0xF
        self.ihl = data[0] & 0xF
        self.header_length = self.ihl * 4
        self.tos = data[1]
        self.total_length = struct.unpack("!H", data[2:4])[0]
        self.identification = struct.unpack("!H", data[4:6])[0]
        self.flags_fragment = struct.unpack("!H", data[6:8])[0]
        self.flags = (self.flags_fragment >> 13) & 0x7
        self.fragment_offset = self.flags_fragment & 0x1FFF
        self.ttl = data[8]
        self.protocol = data[9]
        self.checksum = struct.unpack("!H", data[10:12])[0]
        self.src_ip = socket.inet_ntoa(data[12:16])
        self.dst_ip = socket.inet_ntoa(data[16:20])

        # Parse options if present
        self.options = b""
        if self.ihl > 5:
            self.options = data[20 : self.header_length]

        # Payload
        self.payload = data[self.header_length : self.total_length]

    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        return {
            "version": self.version,
            "ihl": self.ihl,
            "tos": self.tos,
            "total_length": self.total_length,
            "identification": self.identification,
            "flags": self.flags,
            "fragment_offset": self.fragment_offset,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "checksum": self.checksum,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "options_length": len(self.options),
            "payload_length": len(self.payload),
        }


class IPAttackBase(BaseAttack):
    """Base class for IP-layer attacks."""

    # Default MTU values
    DEFAULT_MTU = 1500
    MIN_MTU = 576  # Minimum MTU for IPv4
    MAX_MTU = 65535

    # IP header constants
    IP_HEADER_MIN_LENGTH = 20
    IP_HEADER_MAX_LENGTH = 60
    IP_VERSION = 4

    # IP flags
    IP_FLAG_RESERVED = 0x4
    IP_FLAG_DF = 0x2  # Don't Fragment
    IP_FLAG_MF = 0x1  # More Fragments

    def __init__(self):
        """Initialize IP attack base."""
        super().__init__()
        self._mtu_cache: Dict[str, int] = {}
        self._detected_mtu: Optional[int] = None

    @abstractmethod
    def modify_ip_packet(self, packet: IPPacket, context: AttackContext) -> Optional[bytes]:
        """
        Modify IP packet according to attack strategy.

        Args:
            packet: Parsed IP packet
            context: Attack context

        Returns:
            Modified packet bytes or None if no modification
        """
        pass

    @abstractmethod
    def should_fragment(self, packet: IPPacket, context: AttackContext) -> bool:
        """
        Determine if packet should be fragmented.

        Args:
            packet: Parsed IP packet
            context: Attack context

        Returns:
            True if packet should be fragmented
        """
        pass

    # IP Packet Parsing Helpers

    def parse_ip_packet(self, data: bytes) -> Optional[IPPacket]:
        """
        Parse IP packet from raw bytes.

        Args:
            data: Raw packet bytes

        Returns:
            Parsed IPPacket or None if parsing fails
        """
        try:
            if len(data) < self.IP_HEADER_MIN_LENGTH:
                logger.warning(f"Packet too short: {len(data)} bytes")
                return None

            packet = IPPacket(data)

            # Validate packet
            if packet.version != self.IP_VERSION:
                logger.warning(f"Invalid IP version: {packet.version}")
                return None

            if packet.ihl < 5 or packet.ihl > 15:
                logger.warning(f"Invalid IHL: {packet.ihl}")
                return None

            return packet

        except Exception as e:
            logger.error(f"Failed to parse IP packet: {e}")
            return None

    def validate_ip_checksum(self, packet: IPPacket) -> bool:
        """
        Validate IP header checksum.

        Args:
            packet: Parsed IP packet

        Returns:
            True if checksum is valid
        """
        # Reconstruct header without checksum
        header = self._build_ip_header(
            packet.version,
            packet.ihl,
            packet.tos,
            packet.total_length,
            packet.identification,
            packet.flags,
            packet.fragment_offset,
            packet.ttl,
            packet.protocol,
            0,  # checksum = 0 for calculation
            packet.src_ip,
            packet.dst_ip,
            packet.options,
        )

        calculated = self.calculate_ip_checksum(header)
        return calculated == packet.checksum

    # IP Packet Construction Helpers

    def build_ip_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        payload: bytes,
        ttl: int = 64,
        tos: int = 0,
        identification: int = 0,
        flags: int = 0,
        fragment_offset: int = 0,
        options: bytes = b"",
    ) -> bytes:
        """
        Build IP packet from components.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            protocol: IP protocol number
            payload: Packet payload
            ttl: Time to live
            tos: Type of service
            identification: Packet identification
            flags: IP flags
            fragment_offset: Fragment offset
            options: IP options

        Returns:
            Complete IP packet bytes
        """
        ihl = 5 + (len(options) + 3) // 4  # Round up to 4-byte boundary
        total_length = ihl * 4 + len(payload)

        # Pad options to 4-byte boundary
        if len(options) % 4 != 0:
            options += b"\x00" * (4 - len(options) % 4)

        header = self._build_ip_header(
            self.IP_VERSION,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            0,  # checksum calculated later
            src_ip,
            dst_ip,
            options,
        )

        # Calculate and insert checksum
        checksum = self.calculate_ip_checksum(header)
        header = header[:10] + struct.pack("!H", checksum) + header[12:]

        return header + payload

    def _build_ip_header(
        self,
        version: int,
        ihl: int,
        tos: int,
        total_length: int,
        identification: int,
        flags: int,
        fragment_offset: int,
        ttl: int,
        protocol: int,
        checksum: int,
        src_ip: str,
        dst_ip: str,
        options: bytes,
    ) -> bytes:
        """Build IP header bytes."""
        header = struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) | ihl,
            tos,
            total_length,
            identification,
            (flags << 13) | fragment_offset,
            ttl,
            protocol,
            checksum,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        return header + options

    # Checksum Calculation

    def calculate_ip_checksum(self, header: bytes) -> int:
        """
        Calculate IP header checksum.

        Args:
            header: IP header bytes (with checksum field set to 0)

        Returns:
            Calculated checksum
        """
        # Ensure even length
        if len(header) % 2 == 1:
            header += b"\x00"

        # Sum all 16-bit words
        checksum = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + header[i + 1]
            checksum += word

        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement
        return ~checksum & 0xFFFF

    def verify_checksum(self, data: bytes, checksum: int) -> bool:
        """
        Verify checksum against data.

        Args:
            data: Data to verify
            checksum: Expected checksum

        Returns:
            True if checksum matches
        """
        calculated = self.calculate_ip_checksum(data)
        return calculated == checksum

    # MTU Detection and Fragmentation

    def detect_mtu(self, target_ip: str, context: AttackContext) -> int:
        """
        Detect MTU for target IP.

        Args:
            target_ip: Target IP address
            context: Attack context

        Returns:
            Detected MTU value
        """
        # Check cache first
        if target_ip in self._mtu_cache:
            return self._mtu_cache[target_ip]

        # Try to detect MTU using path MTU discovery
        mtu = self._perform_mtu_discovery(target_ip, context)

        # Cache result
        self._mtu_cache[target_ip] = mtu
        self._detected_mtu = mtu

        logger.info(f"Detected MTU for {target_ip}: {mtu}")
        return mtu

    def _perform_mtu_discovery(self, target_ip: str, context: AttackContext) -> int:
        """
        Perform path MTU discovery.

        Args:
            target_ip: Target IP address
            context: Attack context

        Returns:
            Discovered MTU
        """
        # In a real implementation, this would send ICMP packets with DF flag
        # and binary search for the MTU. For now, return default.

        # Check if context provides MTU hint
        if hasattr(context, "mtu") and context.mtu:
            return context.mtu

        # Use default MTU
        return self.DEFAULT_MTU

    def fragment_packet(self, packet: IPPacket, mtu: int, context: AttackContext) -> List[bytes]:
        """
        Fragment IP packet according to MTU.

        Args:
            packet: Packet to fragment
            mtu: Maximum transmission unit
            context: Attack context

        Returns:
            List of fragmented packet bytes
        """
        # Check if fragmentation is needed
        if packet.total_length <= mtu:
            return [packet.raw_data]

        # Check if DF flag is set
        if packet.flags & self.IP_FLAG_DF:
            logger.warning("Cannot fragment packet with DF flag set")
            return [packet.raw_data]

        fragments = []
        payload = packet.payload
        header_length = packet.header_length

        # Calculate fragment size (must be multiple of 8)
        fragment_size = ((mtu - header_length) // 8) * 8

        if fragment_size <= 0:
            logger.error(f"MTU {mtu} too small for fragmentation")
            return [packet.raw_data]

        offset = 0
        identification = packet.identification

        while offset < len(payload):
            # Determine fragment payload
            end = min(offset + fragment_size, len(payload))
            fragment_payload = payload[offset:end]

            # Set flags
            flags = packet.flags
            if end < len(payload):
                flags |= self.IP_FLAG_MF  # More fragments

            # Calculate fragment offset (in 8-byte units)
            frag_offset = (packet.fragment_offset * 8 + offset) // 8

            # Build fragment
            fragment = self.build_ip_packet(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol=packet.protocol,
                payload=fragment_payload,
                ttl=packet.ttl,
                tos=packet.tos,
                identification=identification,
                flags=flags,
                fragment_offset=frag_offset,
                options=packet.options if offset == 0 else b"",
            )

            fragments.append(fragment)
            offset = end

        logger.info(f"Fragmented packet into {len(fragments)} fragments")
        return fragments

    def calculate_fragment_count(self, packet_size: int, mtu: int) -> int:
        """
        Calculate number of fragments needed.

        Args:
            packet_size: Total packet size
            mtu: Maximum transmission unit

        Returns:
            Number of fragments needed
        """
        if packet_size <= mtu:
            return 1

        header_length = self.IP_HEADER_MIN_LENGTH
        fragment_size = ((mtu - header_length) // 8) * 8

        if fragment_size <= 0:
            return 1

        payload_size = packet_size - header_length
        return (payload_size + fragment_size - 1) // fragment_size

    # IP Options Manipulation

    def add_ip_option(self, options: bytes, option_type: int, option_data: bytes) -> bytes:
        """
        Add IP option to options field.

        Args:
            options: Existing options
            option_type: Option type byte
            option_data: Option data

        Returns:
            Updated options bytes
        """
        # Option format: type (1 byte) + length (1 byte) + data
        option_length = 2 + len(option_data)
        new_option = struct.pack("!BB", option_type, option_length) + option_data

        result = options + new_option

        # Ensure total options don't exceed maximum
        if len(result) > self.IP_HEADER_MAX_LENGTH - self.IP_HEADER_MIN_LENGTH:
            logger.warning("IP options exceed maximum length")
            return options

        return result

    def remove_ip_option(self, options: bytes, option_type: int) -> bytes:
        """
        Remove IP option from options field.

        Args:
            options: Existing options
            option_type: Option type to remove

        Returns:
            Updated options bytes
        """
        result = b""
        i = 0

        while i < len(options):
            opt_type = options[i]

            # Handle single-byte options (NOP, EOL)
            if opt_type in (0, 1):
                if opt_type != option_type:
                    result += bytes([opt_type])
                i += 1
                continue

            # Multi-byte option
            if i + 1 >= len(options):
                break

            opt_length = options[i + 1]

            if opt_type != option_type:
                result += options[i : i + opt_length]

            i += opt_length

        return result

    def parse_ip_options(self, options: bytes) -> List[Dict[str, Any]]:
        """
        Parse IP options into list of option dictionaries.

        Args:
            options: Options bytes

        Returns:
            List of parsed options
        """
        parsed = []
        i = 0

        while i < len(options):
            opt_type = options[i]

            # Handle single-byte options
            if opt_type in (0, 1):  # EOL, NOP
                parsed.append(
                    {
                        "type": opt_type,
                        "name": "EOL" if opt_type == 0 else "NOP",
                        "length": 1,
                        "data": b"",
                    }
                )
                i += 1
                continue

            # Multi-byte option
            if i + 1 >= len(options):
                break

            opt_length = options[i + 1]
            opt_data = options[i + 2 : i + opt_length] if opt_length > 2 else b""

            parsed.append({"type": opt_type, "length": opt_length, "data": opt_data})

            i += opt_length

        return parsed

    def build_ip_options(self, options_list: List[Dict[str, Any]]) -> bytes:
        """
        Build IP options bytes from list of option dictionaries.

        Args:
            options_list: List of option dictionaries

        Returns:
            Options bytes
        """
        result = b""

        for opt in options_list:
            opt_type = opt["type"]

            # Single-byte options
            if opt_type in (0, 1):
                result += bytes([opt_type])
                continue

            # Multi-byte option
            opt_data = opt.get("data", b"")
            opt_length = 2 + len(opt_data)
            result += struct.pack("!BB", opt_type, opt_length) + opt_data

        return result

    # Helper Methods

    def get_mtu(self, context: AttackContext) -> int:
        """
        Get MTU for current context.

        Args:
            context: Attack context

        Returns:
            MTU value
        """
        if hasattr(context, "mtu") and context.mtu:
            return context.mtu

        if self._detected_mtu:
            return self._detected_mtu

        return self.DEFAULT_MTU

    def clear_mtu_cache(self):
        """Clear MTU cache."""
        self._mtu_cache.clear()
        self._detected_mtu = None
