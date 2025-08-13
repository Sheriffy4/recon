# recon/core/packet_builder.py
"""
Unified PacketBuilder for all packet manipulation techniques.
Combines functionality from EnhancedPacketBuilder and PacketFactory.
"""
import struct
import socket
import random
import logging
from typing import Dict, List, Any, Optional, Tuple, Set, TYPE_CHECKING, Union
from functools import lru_cache
from dataclasses import dataclass

try:
    from scapy.all import IP, IPv6, TCP, UDP, Raw, Packet
    from scapy.layers.inet import ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = IPv6 = TCP = UDP = Raw = Packet = ICMP = None

# >>> НАЧАЛО ИСПРАВЛЕНИЯ <<<
from .interfaces import IPacketBuilder
# >>> КОНЕЦ ИСПРАВЛЕНИЯ <<<

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

    # Global checksum cache for performance optimization
    _checksum_cache: Dict[int, int] = {}
    _cache_stats = {"hits": 0, "misses": 0}
    _max_cache_size = 10000
    _packets_built = 0
    _total_build_time_ms = 0.0

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
        """
        Вычисляет стандартную контрольную сумму IP (RFC 1071) с кэшированием.
        """
        # Check cache first for performance
        data_hash = hash(data)
        if data_hash in cls._checksum_cache:
            cls._cache_stats["hits"] += 1
            return cls._checksum_cache[data_hash]

        cls._cache_stats["misses"] += 1

        # Pad data if necessary
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        length = len(data)

        # Process 16-bit words efficiently
        for i in range(0, length - 1, 2):
            checksum += (data[i] << 8) | data[i + 1]

        # Add left-over byte if present
        if length % 2:
            checksum += data[length - 1] << 8

        # Fold 32-bit sum to 16 bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement
        checksum = ~checksum & 0xFFFF

        # Cache result (with size limit)
        if len(cls._checksum_cache) < cls._max_cache_size:
            cls._checksum_cache[data_hash] = checksum

        return checksum

    @classmethod
    def build_tcp_checksum(
        cls, src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes
    ) -> int:
        """Build TCP checksum including pseudo-header with caching."""
        # Build pseudo-header
        pseudo_header = (
            src_ip
            + dst_ip
            + b"\x00\x06"  # Protocol (TCP)
            + struct.pack("!H", len(tcp_header) + len(payload))
        )

        # Combine all data
        data = pseudo_header + tcp_header + payload

        # Pad if necessary
        if len(data) % 2:
            data += b"\x00"

        return cls.calculate_checksum(data)

    @classmethod
    def clear_cache(cls) -> Dict[str, int]:
        """Clear checksum cache and return statistics."""
        stats = cls._cache_stats.copy()
        cls._checksum_cache.clear()
        cls._cache_stats = {"hits": 0, "misses": 0}
        return stats

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """Get cache performance statistics."""
        total = cls._cache_stats["hits"] + cls._cache_stats["misses"]
        hit_rate = cls._cache_stats["hits"] / total if total > 0 else 0.0

        return {
            "cache_size": len(cls._checksum_cache),
            "hits": cls._cache_stats["hits"],
            "misses": cls._cache_stats["misses"],
            "hit_rate": hit_rate,
            "max_size": cls._max_cache_size,
        }

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
        
        # Track performance
        if result is not None:
            PacketBuilder._packets_built += 1
            PacketBuilder._total_build_time_ms += (time.time() - start_time) * 1000
        
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
            return self._fragment_packet_scapy(packet, frag_size)
        else:
            return self._fragment_packet_bytes(packet, frag_size)

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
        If original_raw is empty, create a new packet from scratch.
        """
        try:
            # If original_raw is empty, create a minimal packet structure
            if not original_raw or len(original_raw) < 20:
                # Create minimal IP + TCP headers
                if src_ip and dst_ip:
                    # Build from scratch
                    params = PacketParams(
                        dst_ip=dst_ip,
                        dst_port=dst_port or 80,
                        src_ip=src_ip,
                        src_port=src_port or random.randint(49152, 65535),
                        seq=new_seq or random.randint(0, 2**32 - 1),
                        ack=0,
                        flags=new_flags or "PA",
                        window=new_window or 65535,
                        payload=new_payload,
                    )
                    
                    # Try to create packet using existing methods
                    builder = cls()
                    packet = builder.create_tcp_packet(**params.__dict__)
                    if packet is not None:
                        if isinstance(packet, bytes):
                            return packet
                        else:
                            # Scapy packet
                            return bytes(packet)
                
                # Fallback to minimal packet
                return cls._create_minimal_tcp_packet(
                    src_ip or "127.0.0.1",
                    dst_ip or "127.0.0.1", 
                    src_port or 12345,
                    dst_port or 80,
                    new_payload,
                    new_seq,
                    new_flags
                )

            # Extract IP header length
            ip_header_len = (original_raw[0] & 0x0F) * 4

            # Extract TCP header length
            tcp_header_start = ip_header_len
            tcp_header_len = ((original_raw[tcp_header_start + 12] >> 4) & 0x0F) * 4

            # Build new packet
            ip_header = bytearray(original_raw[:ip_header_len])
            tcp_header = bytearray(
                original_raw[tcp_header_start : tcp_header_start + tcp_header_len]
            )

            # Modify TCP header if needed
            if new_seq is not None:
                struct.pack_into("!I", tcp_header, 4, new_seq)

            if new_flags is not None:
                flags_byte = cls._flags_to_byte(new_flags)
                tcp_header[13] = flags_byte

            if new_window is not None:
                struct.pack_into("!H", tcp_header, 14, new_window)

            # Update lengths
            new_total_length = ip_header_len + tcp_header_len + len(new_payload)
            struct.pack_into("!H", ip_header, 2, new_total_length)

            # Update TTL if specified
            if new_ttl is not None:
                ip_header[8] = new_ttl

            # Recalculate IP checksum
            ip_header[10:12] = b"\x00\x00"  # Clear checksum
            ip_checksum = cls.calculate_checksum(bytes(ip_header))
            struct.pack_into("!H", ip_header, 10, ip_checksum)

            # Recalculate TCP checksum
            tcp_header[16:18] = b"\x00\x00"  # Clear checksum

            # Build pseudo header for TCP checksum
            src_ip = ip_header[12:16]
            dst_ip = ip_header[16:20]
            tcp_length = tcp_header_len + len(new_payload)
            pseudo_header = (
                src_ip + dst_ip + b"\x00\x06" + struct.pack("!H", tcp_length)
            )

            tcp_checksum = cls.calculate_checksum(
                pseudo_header + bytes(tcp_header) + new_payload
            )
            struct.pack_into("!H", tcp_header, 16, tcp_checksum)

            return bytes(ip_header) + bytes(tcp_header) + new_payload

        except Exception as e:
            cls.logger.error(f"Failed to assemble TCP packet: {e}")
            # Fallback to concatenating original with payload
            return original_raw + new_payload if original_raw else new_payload

    @staticmethod
    def _create_minimal_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                                  payload: bytes, seq: Optional[int] = None, flags: Optional[str] = None) -> bytes:
        """Create a minimal TCP packet when no original raw data is available."""
        try:
            import socket
            import struct
            import random
            
            # Convert IPs to bytes
            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)
            
            # IP Header (20 bytes)
            version_ihl = (4 << 4) | 5  # IPv4, 20-byte header
            tos = 0
            total_length = 20 + 20 + len(payload)  # IP + TCP + payload
            identification = random.randint(0, 65535)
            flags_offset = 0
            ttl = 64
            protocol = 6  # TCP
            checksum = 0  # Will calculate
            
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                version_ihl, tos, total_length, identification,
                flags_offset, ttl, protocol, checksum,
                src_ip_bytes, dst_ip_bytes
            )
            
            # Calculate IP checksum
            checksum = 0
            header_words = struct.unpack("!10H", ip_header[:20])
            for word in header_words:
                checksum += word
            while checksum >> 16:
                checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum = ~checksum & 0xFFFF
            
            # Rebuild with correct checksum
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                version_ihl, tos, total_length, identification,
                flags_offset, ttl, protocol, checksum,
                src_ip_bytes, dst_ip_bytes
            )
            
            # TCP Header (20 bytes)
            seq_num = seq or random.randint(0, 2**32 - 1)
            ack_num = 0
            data_offset = 5 << 4  # 5 words = 20 bytes
            flags_byte = 0x18 if flags is None else 0  # PA by default
            if flags:
                if "F" in flags: flags_byte |= 0x01
                if "S" in flags: flags_byte |= 0x02
                if "R" in flags: flags_byte |= 0x04
                if "P" in flags: flags_byte |= 0x08
                if "A" in flags: flags_byte |= 0x10
                if "U" in flags: flags_byte |= 0x20
            window = 65535
            tcp_checksum = 0  # Will calculate
            urgent_ptr = 0
            
            tcp_header = struct.pack(
                "!HHIIBBHHH",
                src_port, dst_port, seq_num, ack_num,
                data_offset, flags_byte, window, tcp_checksum, urgent_ptr
            )
            
            # Calculate TCP checksum
            pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack("!BBH", 0, 6, 20 + len(payload))
            checksum_data = pseudo_header + tcp_header + payload
            # Pad if odd length
            if len(checksum_data) % 2:
                checksum_data += b'\x00'
            
            checksum = 0
            for i in range(0, len(checksum_data), 2):
                checksum += (checksum_data[i] << 8) + checksum_data[i+1]
            while checksum >> 16:
                checksum = (checksum & 0xFFFF) + (checksum >> 16)
            tcp_checksum = ~checksum & 0xFFFF
            
            # Rebuild TCP header with correct checksum
            tcp_header = struct.pack(
                "!HHIIBBHHH",
                src_port, dst_port, seq_num, ack_num,
                data_offset, flags_byte, window, tcp_checksum, urgent_ptr
            )
            
            return ip_header + tcp_header + payload
            
        except Exception:
            # Ultimate fallback
            return payload if payload else b""

    @staticmethod
    def _flags_to_byte(flags: str) -> int:
        """Convert TCP flags string to byte value."""
        flags_byte = 0
        if "F" in flags:
            flags_byte |= 0x01  # FIN
        if "S" in flags:
            flags_byte |= 0x02  # SYN
        if "R" in flags:
            flags_byte |= 0x04  # RST
        if "P" in flags:
            flags_byte |= 0x08  # PSH
        if "A" in flags:
            flags_byte |= 0x10  # ACK
        if "U" in flags:
            flags_byte |= 0x20  # URG
        return flags_byte

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

        # Validation
        if not params.dst_ip:
            raise ValueError("Destination IP is required")

        if params.dst_port <= 0 or params.dst_port > 65535:
            raise ValueError(f"Invalid destination port: {params.dst_port}")

        return params

    def _create_tcp_packet_scapy(self, params: PacketParams) -> Optional[Packet]:
        """Create TCP packet using Scapy."""
        try:
            # Determine IP layer
            if ":" in params.dst_ip:
                ip_layer = IPv6(dst=params.dst_ip)
            else:
                ip_layer = IP(dst=params.dst_ip)

            if params.src_ip:
                ip_layer.src = params.src_ip

            if params.ttl:
                if hasattr(ip_layer, "ttl"):
                    ip_layer.ttl = params.ttl
                else:
                    ip_layer.hlim = params.ttl  # IPv6

            # TCP layer
            tcp_layer = TCP(
                sport=params.src_port,
                dport=params.dst_port,
                seq=params.seq,
                ack=params.ack,
                flags=params.flags,
                window=params.window,
            )

            if params.options:
                tcp_layer.options = params.options

            # Assemble packet
            packet = ip_layer / tcp_layer

            if params.payload:
                packet = packet / Raw(load=params.payload)

            return packet

        except Exception as e:
            self.logger.error(f"Failed to create TCP packet with Scapy: {e}")
            return None

    def _create_tcp_packet_bytes(self, params: PacketParams) -> Optional[bytes]:
        """Create TCP packet at byte level."""
        try:
            # Check IPv4/IPv6
            is_ipv6 = ":" in params.dst_ip

            if is_ipv6:
                ip_header = self._build_ipv6_header(params)
            else:
                ip_header = self._build_ipv4_header(params)

            # TCP header
            tcp_header = self._build_tcp_header(params, is_ipv6)

            # Combine
            packet = ip_header + tcp_header + params.payload

            return packet

        except Exception as e:
            self.logger.error(f"Failed to create TCP packet bytes: {e}")
            return None

    def _create_udp_packet_scapy(self, params: PacketParams) -> Optional[Packet]:
        """Create UDP packet using Scapy."""
        try:
            # IP layer
            if ":" in params.dst_ip:
                ip_layer = IPv6(dst=params.dst_ip)
            else:
                ip_layer = IP(dst=params.dst_ip)

            if params.src_ip:
                ip_layer.src = params.src_ip

            if params.ttl:
                if hasattr(ip_layer, "ttl"):
                    ip_layer.ttl = params.ttl
                else:
                    ip_layer.hlim = params.ttl

            # UDP layer
            udp_layer = UDP(sport=params.src_port, dport=params.dst_port)

            # Assemble packet
            packet = ip_layer / udp_layer

            if params.payload:
                packet = packet / Raw(load=params.payload)

            return packet

        except Exception as e:
            self.logger.error(f"Failed to create UDP packet with Scapy: {e}")
            return None

    def _create_udp_packet_bytes(self, params: PacketParams) -> Optional[bytes]:
        """Create UDP packet at byte level."""
        try:
            # IP header
            is_ipv6 = ":" in params.dst_ip
            if is_ipv6:
                ip_header = self._build_ipv6_header(params)
            else:
                ip_header = self._build_ipv4_header(params)

            # UDP header (8 bytes)
            udp_length = 8 + len(params.payload)
            checksum = 0  # Can be 0 for UDP

            udp_header = struct.pack(
                "!HHHH", params.src_port, params.dst_port, udp_length, checksum
            )

            # Combine
            packet = ip_header + udp_header + params.payload

            return packet

        except Exception as e:
            self.logger.error(f"Failed to create UDP packet bytes: {e}")
            return None

    def _fragment_packet_scapy(self, packet: Packet, frag_size: int) -> List[Packet]:
        """Fragment packet using Scapy."""
        try:
            from scapy.all import fragment

            return fragment(packet, fragsize=frag_size)
        except Exception as e:
            self.logger.error(f"Failed to fragment packet with Scapy: {e}")
            return [packet]

    def _fragment_packet_bytes(self, packet: bytes, frag_size: int) -> List[bytes]:
        """Fragment packet at byte level."""
        fragments = []

        try:
            # Determine IP version
            if len(packet) > 0:
                version = (packet[0] >> 4) & 0x0F

                if version == 4:
                    # IPv4 fragmentation
                    ip_header_len = (packet[0] & 0x0F) * 4
                    total_length = struct.unpack("!H", packet[2:4])[0]

                    # Data to fragment
                    data_start = ip_header_len
                    data = packet[data_start:]

                    # Create fragments
                    offset = 0
                    frag_id = struct.unpack("!H", packet[4:6])[0]

                    while offset < len(data):
                        # Fragment size (aligned to 8 bytes)
                        chunk_size = min(frag_size, len(data) - offset)
                        chunk_size = (chunk_size // 8) * 8

                        if chunk_size == 0 and offset < len(data):
                            chunk_size = len(data) - offset

                        # Flags and offset
                        more_fragments = 1 if offset + chunk_size < len(data) else 0
                        flags_offset = (more_fragments << 13) | (offset // 8)

                        # New IP header
                        new_header = bytearray(packet[:ip_header_len])
                        new_total_length = ip_header_len + chunk_size
                        struct.pack_into("!H", new_header, 2, new_total_length)
                        struct.pack_into("!H", new_header, 6, flags_offset)

                        # Recalculate IP checksum
                        struct.pack_into("!H", new_header, 10, 0)
                        checksum = self.calculate_checksum(bytes(new_header))
                        struct.pack_into("!H", new_header, 10, checksum)

                        # Fragment
                        fragment = (
                            bytes(new_header) + data[offset : offset + chunk_size]
                        )
                        fragments.append(fragment)

                        offset += chunk_size

                else:
                    # IPv6 or unknown protocol - return as is
                    fragments = [packet]
            else:
                fragments = [packet]

        except Exception as e:
            self.logger.error(f"Failed to fragment packet bytes: {e}")
            fragments = [packet]

        return fragments

    def _build_ipv4_header(self, params: PacketParams) -> bytes:
        """Build IPv4 header."""
        # Convert IP addresses
        src_ip = params.src_ip or socket.gethostbyname(socket.gethostname())
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(params.dst_ip)

        # Header parameters
        version_ihl = (4 << 4) | 5  # Version 4, Header length 5 (20 bytes)
        tos = 0
        total_length = 20 + 20 + len(params.payload)  # IP + TCP + payload
        identification = random.randint(0, 65535)
        flags_offset = 0
        ttl = params.ttl or 64
        protocol = 6  # TCP
        checksum = 0  # Temporarily 0

        # Assemble header
        header = (
            struct.pack(
                "!BBHHHBBH",
                version_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                checksum,
            )
            + src_ip_bytes
            + dst_ip_bytes
        )

        # Calculate checksum
        checksum = self.calculate_checksum(header)

        # Reassemble with correct checksum
        header = header[:10] + struct.pack("!H", checksum) + header[12:]

        return header

    def _build_ipv6_header(self, params: PacketParams) -> bytes:
        """Build IPv6 header."""
        # Convert IP addresses
        src_ip = params.src_ip or "::"
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)

        # Header parameters
        version_class_flow = 6 << 28  # Version 6
        payload_length = 20 + len(params.payload)  # TCP + payload
        next_header = 6  # TCP
        hop_limit = params.ttl or 64

        # Assemble header
        header = (
            struct.pack(
                "!IHBB", version_class_flow, payload_length, next_header, hop_limit
            )
            + src_ip_bytes
            + dst_ip_bytes
        )

        return header

    def _build_tcp_header(self, params: PacketParams, is_ipv6: bool) -> bytes:
        """Build TCP header."""
        # Convert flags
        flags_byte = self._flags_to_byte(params.flags)

        # Header parameters
        data_offset = 5  # 20 bytes (without options)
        reserved_flags = (data_offset << 4) | 0
        checksum = 0  # Temporarily 0
        urgent_pointer = 0

        # Basic header (without options)
        header = struct.pack(
            "!HHIIBBHHH",
            params.src_port,
            params.dst_port,
            params.seq,
            params.ack,
            reserved_flags,
            flags_byte,
            params.window,
            checksum,
            urgent_pointer,
        )

        # Add options if present
        if params.options:
            options_bytes = self._build_tcp_options(params.options)
            header += options_bytes
            # Update data_offset
            data_offset = (20 + len(options_bytes)) // 4
            header = header[:12] + struct.pack("!B", data_offset << 4) + header[13:]

        # Calculate checksum
        if is_ipv6:
            pseudo_header = self._build_ipv6_pseudo_header(
                params, len(header) + len(params.payload)
            )
        else:
            pseudo_header = self._build_ipv4_pseudo_header(
                params, len(header) + len(params.payload)
            )

        checksum = self.calculate_checksum(pseudo_header + header + params.payload)

        # Insert checksum
        header = header[:16] + struct.pack("!H", checksum) + header[18:]

        return header

    def _build_tcp_options(self, options: List[Any]) -> bytes:
        """Build TCP options."""
        options_bytes = b""

        for option in options:
            if isinstance(option, tuple):
                opt_name, opt_value = option

                if opt_name == "MSS":
                    # Maximum Segment Size (kind=2, length=4)
                    options_bytes += struct.pack("!BBH", 2, 4, opt_value)
                elif opt_name == "WScale":
                    # Window Scale (kind=3, length=3)
                    options_bytes += struct.pack("!BBB", 3, 3, opt_value)
                elif opt_name == "SAckOK":
                    # SACK Permitted (kind=4, length=2)
                    options_bytes += struct.pack("!BB", 4, 2)
                elif opt_name == "Timestamp":
                    # Timestamp (kind=8, length=10)
                    ts_val, ts_ecr = opt_value
                    options_bytes += struct.pack("!BBII", 8, 10, ts_val, ts_ecr)
                elif opt_name == "NOP":
                    # No Operation (kind=1, length=1)
                    options_bytes += b"\x01"

        # Padding to 4-byte boundary
        while len(options_bytes) % 4 != 0:
            options_bytes += b"\x00"  # EOL

        return options_bytes

    def _build_ipv4_pseudo_header(self, params: PacketParams, tcp_length: int) -> bytes:
        """Build pseudo-header for TCP checksum calculation over IPv4."""
        src_ip = params.src_ip or socket.gethostbyname(socket.gethostname())
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(params.dst_ip)

        return src_ip_bytes + dst_ip_bytes + struct.pack("!BBH", 0, 6, tcp_length)

    def _build_ipv6_pseudo_header(self, params: PacketParams, tcp_length: int) -> bytes:
        """Build pseudo-header for TCP checksum calculation over IPv6."""
        src_ip = params.src_ip or "::"
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)

        return src_ip_bytes + dst_ip_bytes + struct.pack("!IH", tcp_length, 6)

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
        # Build via unified TCP packet creation API
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
        return {
            "checksum_cache_size": len(cls._checksum_cache),
            "checksum_cache_hits": cls._cache_stats["hits"],
            "checksum_cache_misses": cls._cache_stats["misses"],
            "packets_built": getattr(cls, '_packets_built', 0),
            "total_build_time_ms": getattr(cls, '_total_build_time_ms', 0.0),
        }

    @classmethod
    def reset_performance_stats(cls):
        """Reset performance statistics."""
        cls._cache_stats = {"hits": 0, "misses": 0}
        cls._packets_built = 0
        cls._total_build_time_ms = 0.0


# Legacy aliases for backward compatibility
EnhancedPacketBuilder = PacketBuilder
PacketFactory = PacketBuilder
