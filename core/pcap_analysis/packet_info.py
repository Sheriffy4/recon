"""
PacketInfo data model for PCAP analysis.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import struct
import socket


@dataclass
class TLSInfo:
    """TLS packet information."""

    version: str = ""
    cipher_suites: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    sni: Optional[str] = None
    client_hello_length: int = 0
    handshake_type: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: bytes) -> Optional["TLSInfo"]:
        """Extract TLS info from packet payload."""
        if len(payload) < 6:
            return None

        # Check if this is a TLS record
        if payload[0] != 0x16:  # TLS Handshake
            return None

        try:
            # TLS version
            version_major = payload[1]
            version_minor = payload[2]
            version = f"{version_major}.{version_minor}"

            # Record length
            record_length = struct.unpack(">H", payload[3:5])[0]

            if len(payload) < 5 + record_length:
                return None

            # Handshake type
            handshake_type_map = {
                0x01: "ClientHello",
                0x02: "ServerHello",
                0x0B: "Certificate",
                0x0C: "ServerKeyExchange",
                0x0E: "ServerHelloDone",
                0x10: "ClientKeyExchange",
                0x14: "Finished",
            }

            handshake_type = handshake_type_map.get(
                payload[5], f"Unknown({payload[5]})"
            )

            tls_info = cls(
                version=version,
                handshake_type=handshake_type,
                client_hello_length=record_length,
            )

            # Parse ClientHello details if available
            if payload[5] == 0x01 and len(payload) > 43:  # ClientHello
                tls_info = cls._parse_client_hello(payload[5:], tls_info)

            return tls_info

        except Exception:
            return None

    @classmethod
    def _parse_client_hello(
        cls, handshake_data: bytes, tls_info: "TLSInfo"
    ) -> "TLSInfo":
        """Parse ClientHello handshake data."""
        try:
            if len(handshake_data) < 38:
                return tls_info

            # Skip handshake header (4 bytes) and random (32 bytes)
            offset = 38

            if offset >= len(handshake_data):
                return tls_info

            # Session ID length
            session_id_len = handshake_data[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(handshake_data):
                return tls_info

            # Cipher suites length
            cipher_suites_len = struct.unpack(
                ">H", handshake_data[offset : offset + 2]
            )[0]
            offset += 2

            # Parse cipher suites
            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                if offset + i + 2 <= len(handshake_data):
                    cipher_suite = struct.unpack(
                        ">H", handshake_data[offset + i : offset + i + 2]
                    )[0]
                    cipher_suites.append(f"0x{cipher_suite:04x}")

            tls_info.cipher_suites = cipher_suites[:10]  # Limit to first 10

            # Skip compression methods and parse extensions for SNI
            offset += cipher_suites_len
            if offset + 1 < len(handshake_data):
                compression_len = handshake_data[offset]
                offset += 1 + compression_len

                # Parse extensions for SNI
                if offset + 2 < len(handshake_data):
                    extensions_len = struct.unpack(
                        ">H", handshake_data[offset : offset + 2]
                    )[0]
                    offset += 2

                    sni = cls._extract_sni(
                        handshake_data[offset : offset + extensions_len]
                    )
                    if sni:
                        tls_info.sni = sni

            return tls_info

        except Exception:
            return tls_info

    @classmethod
    def _extract_sni(cls, extensions_data: bytes) -> Optional[str]:
        """Extract SNI from TLS extensions."""
        try:
            offset = 0
            while offset + 4 < len(extensions_data):
                ext_type = struct.unpack(">H", extensions_data[offset : offset + 2])[0]
                ext_len = struct.unpack(">H", extensions_data[offset + 2 : offset + 4])[
                    0
                ]

                if ext_type == 0x0000:  # Server Name extension
                    if offset + 4 + ext_len <= len(extensions_data):
                        sni_data = extensions_data[offset + 4 : offset + 4 + ext_len]
                        if len(sni_data) > 5:
                            # Skip server name list length (2 bytes)
                            # Skip name type (1 byte) and name length (2 bytes)
                            name_len = struct.unpack(">H", sni_data[3:5])[0]
                            if len(sni_data) >= 5 + name_len:
                                return sni_data[5 : 5 + name_len].decode(
                                    "utf-8", errors="ignore"
                                )

                offset += 4 + ext_len

        except Exception:
            pass

        return None


@dataclass
class PacketInfo:
    """Comprehensive packet information for PCAP analysis."""

    # Basic packet info
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    # TCP specific
    sequence_num: int
    ack_num: int
    ttl: int
    flags: List[str]
    window_size: int = 0

    # Payload info
    payload_length: int = 0
    payload_hex: str = ""
    payload: bytes = b""

    # Checksum info
    checksum: int = 0
    checksum_valid: bool = True

    # Protocol info
    protocol: str = "TCP"
    is_client_hello: bool = False
    tls_info: Optional[TLSInfo] = None

    # Additional metadata
    packet_size: int = 0
    direction: str = "outbound"  # outbound/inbound
    raw_data: bytes = b""

    def __post_init__(self):
        """Post-initialization processing."""
        # Convert payload to hex if not already done
        if self.payload and not self.payload_hex:
            self.payload_hex = self.payload.hex()
        elif self.payload_hex and not self.payload:
            try:
                self.payload = bytes.fromhex(self.payload_hex)
            except ValueError:
                self.payload = b""

        # Set payload length
        if self.payload:
            self.payload_length = len(self.payload)

        # Detect TLS and ClientHello
        if self.payload and len(self.payload) > 5:
            if self.payload[0] == 0x16:  # TLS Handshake
                self.tls_info = TLSInfo.from_payload(self.payload)
                if self.tls_info and self.tls_info.handshake_type == "ClientHello":
                    self.is_client_hello = True

    @classmethod
    def from_raw_packet(
        cls, raw_data: bytes, timestamp: float
    ) -> Optional["PacketInfo"]:
        """Create PacketInfo from raw packet data."""
        try:
            if len(raw_data) < 34:  # Minimum Ethernet + IP + TCP
                return None

            # Skip Ethernet header (14 bytes)
            ip_data = raw_data[14:]

            if len(ip_data) < 20:
                return None

            # Parse IP header
            version_ihl = ip_data[0]
            version = (version_ihl >> 4) & 0xF

            if version != 4:  # Only IPv4 supported
                return None

            ihl = (version_ihl & 0xF) * 4
            ttl = ip_data[8]
            protocol = ip_data[9]
            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])

            if protocol != 6:  # Only TCP
                return None

            # Parse TCP header
            tcp_data = ip_data[ihl:]
            if len(tcp_data) < 20:
                return None

            src_port = struct.unpack(">H", tcp_data[0:2])[0]
            dst_port = struct.unpack(">H", tcp_data[2:4])[0]
            seq_num = struct.unpack(">I", tcp_data[4:8])[0]
            ack_num = struct.unpack(">I", tcp_data[8:12])[0]

            # TCP flags
            flags_byte = tcp_data[13]
            flags = []
            flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
            for i, flag_name in enumerate(flag_names):
                if flags_byte & (1 << i):
                    flags.append(flag_name)

            # Window size
            window_size = struct.unpack(">H", tcp_data[14:16])[0]

            # Checksum
            checksum = struct.unpack(">H", tcp_data[16:18])[0]

            # TCP header length
            tcp_header_len = ((tcp_data[12] >> 4) & 0xF) * 4

            # Payload
            payload = (
                tcp_data[tcp_header_len:] if tcp_header_len < len(tcp_data) else b""
            )

            return cls(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                sequence_num=seq_num,
                ack_num=ack_num,
                ttl=ttl,
                flags=flags,
                window_size=window_size,
                payload_length=len(payload),
                payload=payload,
                checksum=checksum,
                checksum_valid=True,  # TODO: Implement checksum validation
                packet_size=len(raw_data),
                raw_data=raw_data,
            )

        except Exception:
            return None

    def is_fake_packet(self) -> bool:
        """Detect if this is likely a fake packet used for DPI bypass."""
        # Common indicators of fake packets
        fake_indicators = [
            self.ttl <= 3,  # Low TTL
            not self.checksum_valid,  # Bad checksum
            self.payload_length == 0 and "PSH" in self.flags,  # Empty PSH packet
            self.sequence_num == 0,  # Zero sequence number
        ]

        return sum(fake_indicators) >= 2

    def get_connection_key(self) -> str:
        """Get unique connection identifier."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"

    def get_reverse_connection_key(self) -> str:
        """Get reverse connection identifier."""
        return f"{self.dst_ip}:{self.dst_port}->{self.src_ip}:{self.src_port}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "sequence_num": self.sequence_num,
            "ack_num": self.ack_num,
            "ttl": self.ttl,
            "flags": self.flags,
            "window_size": self.window_size,
            "payload_length": self.payload_length,
            "payload_hex": self.payload_hex,
            "checksum": self.checksum,
            "checksum_valid": self.checksum_valid,
            "protocol": self.protocol,
            "is_client_hello": self.is_client_hello,
            "packet_size": self.packet_size,
            "direction": self.direction,
            "is_fake": self.is_fake_packet(),
        }

        if self.tls_info:
            result["tls_info"] = {
                "version": self.tls_info.version,
                "handshake_type": self.tls_info.handshake_type,
                "cipher_suites": self.tls_info.cipher_suites,
                "sni": self.tls_info.sni,
                "client_hello_length": self.tls_info.client_hello_length,
            }

        return result

    def matches_filter(self, **filters) -> bool:
        """Check if packet matches given filters."""
        for key, value in filters.items():
            if hasattr(self, key):
                packet_value = getattr(self, key)
                if isinstance(value, list):
                    if packet_value not in value:
                        return False
                elif packet_value != value:
                    return False
            elif key == "has_payload":
                if value and self.payload_length == 0:
                    return False
                elif not value and self.payload_length > 0:
                    return False
            elif key == "is_fake":
                if value != self.is_fake_packet():
                    return False

        return True
