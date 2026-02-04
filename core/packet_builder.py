"""
Unified PacketBuilder for all packet manipulation techniques.
Combines functionality from EnhancedPacketBuilder and PacketFactory.
"""

import struct
import socket
import random
import logging
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass

try:
    from scapy.all import IP, IPv6, TCP, UDP, Raw, Packet
    from scapy.layers.inet import ICMP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = IPv6 = TCP = UDP = Raw = Packet = ICMP = None
from core.interfaces import IPacketBuilder
from core.packet_utils.checksum import ChecksumCache
from core.packet_utils.ip_builder import IPHeaderBuilder
from core.packet_utils.tcp_builder import TCPHeaderBuilder
from core.packet_utils.udp_builder import UDPHeaderBuilder
from core.packet_utils.packet_assembler import PacketAssembler
from core.packet_utils.fragmenter import PacketFragmenter
from core.packet_utils.scapy_builder import ScapyPacketBuilder
from core.packet_utils.performance import PerformanceMonitor


@dataclass
class PacketParams:
    """Parameters for packet creation."""

    dst_ip: str
    dst_port: int
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    seq: Optional[int] = None
    ack: Optional[int] = None
    flags: str = "PA"
    window: int = 65535
    ttl: Optional[int] = None
    payload: bytes = b""
    options: Optional[List[Any]] = None


class PacketBuilder(IPacketBuilder):
    """
    Unified high-performance packet builder with global checksum caching.
    Combines functionality from EnhancedPacketBuilder and PacketFactory.
    Implements IPacketBuilder interface for DI compatibility.
    """

    def __init__(self, use_scapy: bool = True):
        """
        Initialize packet builder.

        Args:
            use_scapy: Use Scapy for packet creation when available
        """
        self.use_scapy = use_scapy and SCAPY_AVAILABLE
        self.logger = logging.getLogger(__name__)
        if not self.use_scapy:
            self.logger.info("Scapy not available, using byte-level packet creation")

    @classmethod
    def calculate_checksum(cls, data: bytes) -> int:
        """Calculate standard IP checksum (RFC 1071) with caching."""
        return ChecksumCache.calculate_checksum(data)

    @classmethod
    def build_tcp_checksum(
        cls, src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes
    ) -> int:
        """Build TCP checksum including pseudo-header with caching."""
        return ChecksumCache.build_tcp_checksum(src_ip, dst_ip, tcp_header, payload)

    @classmethod
    def clear_cache(cls) -> Dict[str, int]:
        """Clear checksum cache and return statistics."""
        return ChecksumCache.clear_cache()

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """Get cache performance statistics."""
        return ChecksumCache.get_cache_stats()

    def create_tcp_packet(self, **kwargs) -> Optional[Union[Packet, bytes]]:
        """
        Create TCP packet using either Scapy or byte-level construction.

        Args:
            **kwargs: Packet parameters

        Returns:
            Scapy Packet or bytes
        """
        import time

        start_time = time.time()
        params = self._parse_params(**kwargs)
        if self.use_scapy:
            result = self._create_tcp_packet_scapy(params)
        else:
            result = self._create_tcp_packet_bytes(params)
        if result is not None:
            PerformanceMonitor.record_packet_build((time.time() - start_time) * 1000)
        return result

    def create_udp_packet(self, **kwargs) -> Optional[Union[Packet, bytes]]:
        """
        Create UDP packet using either Scapy or byte-level construction.

        Args:
            **kwargs: Packet parameters

        Returns:
            Scapy Packet or bytes
        """
        params = self._parse_params(**kwargs)
        if self.use_scapy:
            return self._create_udp_packet_scapy(params)
        else:
            return self._create_udp_packet_bytes(params)

    def create_syn_packet(
        self, dst_ip: str, dst_port: int, src_port: Optional[int] = None
    ) -> Optional[Union[Packet, bytes]]:
        """
        Create SYN packet for connection establishment.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port (optional)

        Returns:
            SYN packet
        """
        if not src_port:
            src_port = random.randint(49152, 65535)
        seq = random.randint(0, 2**32 - 1)
        tcp_options = [
            ("MSS", 1460),
            ("WScale", 8),
            ("SAckOK", b""),
            ("Timestamp", (random.randint(10000, 50000), 0)),
        ]
        return self.create_tcp_packet(
            dst_ip=dst_ip,
            dst_port=dst_port,
            src_port=src_port,
            seq=seq,
            ack=0,
            flags="S",
            options=tcp_options,
        )

    def fragment_packet(
        self, packet: Union[Packet, bytes], frag_size: int = 8
    ) -> List[Union[Packet, bytes]]:
        """
        Fragment packet into smaller pieces.

        Args:
            packet: Packet to fragment
            frag_size: Fragment size

        Returns:
            List of packet fragments
        """
        if self.use_scapy and isinstance(packet, Packet):
            return PacketFragmenter.fragment_packet_scapy(packet, frag_size)
        else:
            return PacketFragmenter.fragment_packet_bytes(packet, frag_size)

    @classmethod
    def assemble_tcp_packet(
        cls,
        original_raw: bytes,
        new_payload: bytes = b"",
        new_seq: Optional[int] = None,
        new_flags: Optional[str] = None,
        new_ttl: Optional[int] = None,
        new_window: Optional[int] = None,
        new_options: bytes = b"",
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
    ) -> bytes:
        """
        Assemble TCP packet with modifications (legacy method for compatibility).
        Delegates to PacketAssembler utility.
        """
        # If original packet is missing, keep previous behavior: attempt to build a fresh packet.
        if not original_raw or len(original_raw) < 20:
            if src_ip and dst_ip:
                params = PacketParams(
                    dst_ip=dst_ip,
                    dst_port=dst_port or 80,
                    src_ip=src_ip,
                    src_port=src_port or random.randint(49152, 65535),
                    seq=new_seq or random.randint(0, 2**32 - 1),
                    ack=0,
                    flags=new_flags or "PA",
                    window=new_window or 65535,
                    ttl=new_ttl,
                    payload=new_payload,
                )
                builder = cls()  # default: prefer scapy if available
                packet = builder.create_tcp_packet(**params.__dict__)
                if packet is not None:
                    return (
                        bytes(packet)
                        if not isinstance(packet, (bytes, bytearray))
                        else bytes(packet)
                    )

            return PacketAssembler.create_minimal_tcp_packet(
                src_ip or "127.0.0.1",
                dst_ip or "127.0.0.1",
                src_port or 12345,
                dst_port or 80,
                new_payload,
                new_seq,
                new_flags,
            )

        return PacketAssembler.assemble_tcp_packet(
            original_raw,
            new_payload,
            new_seq,
            new_flags,
            new_ttl,
            new_window,
            new_options,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        )

    @staticmethod
    def _create_minimal_tcp_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
        seq: Optional[int] = None,
        flags: Optional[str] = None,
    ) -> bytes:
        """Create a minimal TCP packet when no original raw data is available."""
        return PacketAssembler.create_minimal_tcp_packet(
            src_ip, dst_ip, src_port, dst_port, payload, seq, flags
        )

    @staticmethod
    def _flags_to_byte(flags: str) -> int:
        """Convert TCP flags string to byte value."""
        return TCPHeaderBuilder.flags_to_byte(flags)

    def _parse_params(self, **kwargs) -> PacketParams:
        """Parse and validate packet parameters."""
        params = PacketParams(
            dst_ip=kwargs.get("dst_ip", ""),
            dst_port=kwargs.get("dst_port", 0),
            src_ip=kwargs.get("src_ip"),
            src_port=kwargs.get("src_port", random.randint(49152, 65535)),
            seq=kwargs.get("seq", random.randint(0, 2**32 - 1)),
            ack=kwargs.get("ack", 0),
            flags=kwargs.get("flags", "PA"),
            window=kwargs.get("window", 65535),
            ttl=kwargs.get("ttl"),
            payload=kwargs.get("payload", b""),
            options=kwargs.get("options"),
        )
        if not params.dst_ip:
            raise ValueError("Destination IP is required")
        if params.dst_port <= 0 or params.dst_port > 65535:
            raise ValueError(f"Invalid destination port: {params.dst_port}")
        return params

    def _create_tcp_packet_scapy(self, params: PacketParams) -> Optional[Packet]:
        """Create TCP packet using Scapy."""
        return ScapyPacketBuilder.create_tcp_packet(params)

    def _create_tcp_packet_bytes(self, params: PacketParams) -> Optional[bytes]:
        """Create TCP packet at byte level."""
        try:
            is_ipv6 = IPHeaderBuilder.is_ipv6(params.dst_ip)
            tcp_header = TCPHeaderBuilder.build_tcp_header(params, is_ipv6)
            payload_length = len(tcp_header) + len(params.payload)

            if is_ipv6:
                ip_header = IPHeaderBuilder.build_ipv6_header(params, payload_length)
            else:
                ip_header = IPHeaderBuilder.build_ipv4_header(params, payload_length)

            packet = ip_header + tcp_header + params.payload
            return packet
        except Exception as e:
            self.logger.error(f"Failed to create TCP packet bytes: {e}")
            return None

    def _create_udp_packet_scapy(self, params: PacketParams) -> Optional[Packet]:
        """Create UDP packet using Scapy."""
        return ScapyPacketBuilder.create_udp_packet(params)

    def _create_udp_packet_bytes(self, params: PacketParams) -> Optional[bytes]:
        """Create UDP packet at byte level."""
        try:
            is_ipv6 = IPHeaderBuilder.is_ipv6(params.dst_ip)
            udp_header = UDPHeaderBuilder.build_udp_header(params, is_ipv6)
            payload_length = len(udp_header) + len(params.payload)

            if is_ipv6:
                ip_header = IPHeaderBuilder.build_ipv6_header(
                    params, payload_length, next_header=17
                )
            else:
                ip_header = IPHeaderBuilder.build_ipv4_header(params, payload_length, protocol=17)

            packet = ip_header + udp_header + params.payload
            return packet
        except Exception as e:
            self.logger.error(f"Failed to create UDP packet bytes: {e}")
            return None

    def build_tls_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        tls_data: bytes,
        **kwargs,
    ) -> bytes:
        """Build TLS packet by wrapping TLS data in TCP packet."""
        packet = self.create_tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq=kwargs.get("seq", 0),
            ack=kwargs.get("ack", 0),
            flags=kwargs.get("flags", "PA"),
            payload=tls_data,
            ttl=kwargs.get("ttl", 64),
            window=kwargs.get("window", 65535),
            options=kwargs.get("tcp_options"),
        )
        if packet is None:
            return b""
        if isinstance(packet, (bytes, bytearray)):
            return bytes(packet)
        try:
            return bytes(packet)
        except Exception:
            return b""

    @classmethod
    def get_performance_stats(cls) -> Dict[str, Any]:
        """
        Get performance statistics for PacketBuilder.

        Returns:
            Dictionary with performance metrics
        """
        return PerformanceMonitor.get_performance_stats()

    @classmethod
    def reset_performance_stats(cls):
        """Reset performance statistics."""
        PerformanceMonitor.reset_performance_stats()


EnhancedPacketBuilder = PacketBuilder
PacketFactory = PacketBuilder
