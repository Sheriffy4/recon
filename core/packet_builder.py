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

@dataclass
class PacketParams:
    """Parameters for packet creation."""
    dst_ip: str
    dst_port: int
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    seq: Optional[int] = None
    ack: Optional[int] = None
    flags: str = 'PA'
    window: int = 65535
    ttl: Optional[int] = None
    payload: bytes = b''
    options: Optional[List[Any]] = None

class PacketBuilder(IPacketBuilder):
    """
    Unified high-performance packet builder with global checksum caching.
    Combines functionality from EnhancedPacketBuilder and PacketFactory.
    Implements IPacketBuilder interface for DI compatibility.
    """
    _checksum_cache: Dict[int, int] = {}
    _cache_stats = {'hits': 0, 'misses': 0}
    _max_cache_size = 10000
    _packets_built = 0
    _total_build_time_ms = 0.0

    def __init__(self, use_scapy: bool=True):
        """
        Initialize packet builder.

        Args:
            use_scapy: Use Scapy for packet creation when available
        """
        self.use_scapy = use_scapy and SCAPY_AVAILABLE
        self.logger = logging.getLogger(__name__)
        if not self.use_scapy:
            self.logger.info('Scapy not available, using byte-level packet creation')

    @classmethod
    def calculate_checksum(cls, data: bytes) -> int:
        """
        Вычисляет стандартную контрольную сумму IP (RFC 1071) с кэшированием.
        """
        data_hash = hash(data)
        if data_hash in cls._checksum_cache:
            cls._cache_stats['hits'] += 1
            return cls._checksum_cache[data_hash]
        cls._cache_stats['misses'] += 1
        if len(data) % 2:
            data += b'\x00'
        checksum = 0
        length = len(data)
        for i in range(0, length - 1, 2):
            checksum += data[i] << 8 | data[i + 1]
        if length % 2:
            checksum += data[length - 1] << 8
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        checksum = ~checksum & 65535
        if len(cls._checksum_cache) < cls._max_cache_size:
            cls._checksum_cache[data_hash] = checksum
        return checksum

    @classmethod
    def build_tcp_checksum(cls, src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes) -> int:
        """Build TCP checksum including pseudo-header with caching."""
        pseudo_header = src_ip + dst_ip + b'\x00\x06' + struct.pack('!H', len(tcp_header) + len(payload))
        data = pseudo_header + tcp_header + payload
        if len(data) % 2:
            data += b'\x00'
        return cls.calculate_checksum(data)

    @classmethod
    def clear_cache(cls) -> Dict[str, int]:
        """Clear checksum cache and return statistics."""
        stats = cls._cache_stats.copy()
        cls._checksum_cache.clear()
        cls._cache_stats = {'hits': 0, 'misses': 0}
        return stats

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """Get cache performance statistics."""
        total = cls._cache_stats['hits'] + cls._cache_stats['misses']
        hit_rate = cls._cache_stats['hits'] / total if total > 0 else 0.0
        return {'cache_size': len(cls._checksum_cache), 'hits': cls._cache_stats['hits'], 'misses': cls._cache_stats['misses'], 'hit_rate': hit_rate, 'max_size': cls._max_cache_size}

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

    def create_syn_packet(self, dst_ip: str, dst_port: int, src_port: Optional[int]=None) -> Optional[Union[Packet, bytes]]:
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
        seq = random.randint(0, 2 ** 32 - 1)
        tcp_options = [('MSS', 1460), ('WScale', 8), ('SAckOK', b''), ('Timestamp', (random.randint(10000, 50000), 0))]
        return self.create_tcp_packet(dst_ip=dst_ip, dst_port=dst_port, src_port=src_port, seq=seq, ack=0, flags='S', options=tcp_options)

    def fragment_packet(self, packet: Union[Packet, bytes], frag_size: int=8) -> List[Union[Packet, bytes]]:
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
    def assemble_tcp_packet(cls, original_raw: bytes, new_payload: bytes=b'', new_seq: Optional[int]=None, new_flags: Optional[str]=None, new_ttl: Optional[int]=None, new_window: Optional[int]=None, new_options: bytes=b'', src_ip: Optional[str]=None, dst_ip: Optional[str]=None, src_port: Optional[int]=None, dst_port: Optional[int]=None) -> bytes:
        """
        Assemble TCP packet with modifications (legacy method for compatibility).
        If original_raw is empty, create a new packet from scratch.
        """
        try:
            if not original_raw or len(original_raw) < 20:
                if src_ip and dst_ip:
                    params = PacketParams(dst_ip=dst_ip, dst_port=dst_port or 80, src_ip=src_ip, src_port=src_port or random.randint(49152, 65535), seq=new_seq or random.randint(0, 2 ** 32 - 1), ack=0, flags=new_flags or 'PA', window=new_window or 65535, payload=new_payload)
                    builder = cls()
                    packet = builder.create_tcp_packet(**params.__dict__)
                    if packet is not None:
                        if isinstance(packet, bytes):
                            return packet
                        else:
                            return bytes(packet)
                return cls._create_minimal_tcp_packet(src_ip or '127.0.0.1', dst_ip or '127.0.0.1', src_port or 12345, dst_port or 80, new_payload, new_seq, new_flags)
            ip_header_len = (original_raw[0] & 15) * 4
            tcp_header_start = ip_header_len
            tcp_header_len = (original_raw[tcp_header_start + 12] >> 4 & 15) * 4
            ip_header = bytearray(original_raw[:ip_header_len])
            tcp_header = bytearray(original_raw[tcp_header_start:tcp_header_start + tcp_header_len])
            if new_seq is not None:
                struct.pack_into('!I', tcp_header, 4, new_seq)
            if new_flags is not None:
                flags_byte = cls._flags_to_byte(new_flags)
                tcp_header[13] = flags_byte
            if new_window is not None:
                struct.pack_into('!H', tcp_header, 14, new_window)
            new_total_length = ip_header_len + tcp_header_len + len(new_payload)
            struct.pack_into('!H', ip_header, 2, new_total_length)
            if new_ttl is not None:
                ip_header[8] = new_ttl
            ip_header[10:12] = b'\x00\x00'
            ip_checksum = cls.calculate_checksum(bytes(ip_header))
            struct.pack_into('!H', ip_header, 10, ip_checksum)
            tcp_header[16:18] = b'\x00\x00'
            src_ip = ip_header[12:16]
            dst_ip = ip_header[16:20]
            tcp_length = tcp_header_len + len(new_payload)
            pseudo_header = src_ip + dst_ip + b'\x00\x06' + struct.pack('!H', tcp_length)
            tcp_checksum = cls.calculate_checksum(pseudo_header + bytes(tcp_header) + new_payload)
            struct.pack_into('!H', tcp_header, 16, tcp_checksum)
            return bytes(ip_header) + bytes(tcp_header) + new_payload
        except Exception as e:
            cls.logger.error(f'Failed to assemble TCP packet: {e}')
            return original_raw + new_payload if original_raw else new_payload

    @staticmethod
    def _create_minimal_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, seq: Optional[int]=None, flags: Optional[str]=None) -> bytes:
        """Create a minimal TCP packet when no original raw data is available."""
        try:
            import socket
            import struct
            import random
            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)
            version_ihl = 4 << 4 | 5
            tos = 0
            total_length = 20 + 20 + len(payload)
            identification = random.randint(0, 65535)
            flags_offset = 0
            ttl = 64
            protocol = 6
            checksum = 0
            ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src_ip_bytes, dst_ip_bytes)
            checksum = 0
            header_words = struct.unpack('!10H', ip_header[:20])
            for word in header_words:
                checksum += word
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            checksum = ~checksum & 65535
            ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src_ip_bytes, dst_ip_bytes)
            seq_num = seq or random.randint(0, 2 ** 32 - 1)
            ack_num = 0
            data_offset = 5 << 4
            flags_byte = 24 if flags is None else 0
            if flags:
                if 'F' in flags:
                    flags_byte |= 1
                if 'S' in flags:
                    flags_byte |= 2
                if 'R' in flags:
                    flags_byte |= 4
                if 'P' in flags:
                    flags_byte |= 8
                if 'A' in flags:
                    flags_byte |= 16
                if 'U' in flags:
                    flags_byte |= 32
            window = 65535
            tcp_checksum = 0
            urgent_ptr = 0
            tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num, data_offset, flags_byte, window, tcp_checksum, urgent_ptr)
            pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, 6, 20 + len(payload))
            checksum_data = pseudo_header + tcp_header + payload
            if len(checksum_data) % 2:
                checksum_data += b'\x00'
            checksum = 0
            for i in range(0, len(checksum_data), 2):
                checksum += (checksum_data[i] << 8) + checksum_data[i + 1]
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            tcp_checksum = ~checksum & 65535
            tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num, data_offset, flags_byte, window, tcp_checksum, urgent_ptr)
            return ip_header + tcp_header + payload
        except Exception:
            return payload if payload else b''

    @staticmethod
    def _flags_to_byte(flags: str) -> int:
        """Convert TCP flags string to byte value."""
        flags_byte = 0
        if 'F' in flags:
            flags_byte |= 1
        if 'S' in flags:
            flags_byte |= 2
        if 'R' in flags:
            flags_byte |= 4
        if 'P' in flags:
            flags_byte |= 8
        if 'A' in flags:
            flags_byte |= 16
        if 'U' in flags:
            flags_byte |= 32
        return flags_byte

    def _parse_params(self, **kwargs) -> PacketParams:
        """Parse and validate packet parameters."""
        params = PacketParams(dst_ip=kwargs.get('dst_ip', ''), dst_port=kwargs.get('dst_port', 0), src_ip=kwargs.get('src_ip'), src_port=kwargs.get('src_port', random.randint(49152, 65535)), seq=kwargs.get('seq', random.randint(0, 2 ** 32 - 1)), ack=kwargs.get('ack', 0), flags=kwargs.get('flags', 'PA'), window=kwargs.get('window', 65535), ttl=kwargs.get('ttl'), payload=kwargs.get('payload', b''), options=kwargs.get('options'))
        if not params.dst_ip:
            raise ValueError('Destination IP is required')
        if params.dst_port <= 0 or params.dst_port > 65535:
            raise ValueError(f'Invalid destination port: {params.dst_port}')
        return params

    def _create_tcp_packet_scapy(self, params: PacketParams) -> Optional[Packet]:
        """Create TCP packet using Scapy."""
        try:
            if ':' in params.dst_ip:
                ip_layer = IPv6(dst=params.dst_ip)
            else:
                ip_layer = IP(dst=params.dst_ip)
            if params.src_ip:
                ip_layer.src = params.src_ip
            if params.ttl:
                if hasattr(ip_layer, 'ttl'):
                    ip_layer.ttl = params.ttl
                else:
                    ip_layer.hlim = params.ttl
            tcp_layer = TCP(sport=params.src_port, dport=params.dst_port, seq=params.seq, ack=params.ack, flags=params.flags, window=params.window)
            if params.options:
                tcp_layer.options = params.options
            packet = ip_layer / tcp_layer
            if params.payload:
                packet = packet / Raw(load=params.payload)
            return packet
        except Exception as e:
            self.logger.error(f'Failed to create TCP packet with Scapy: {e}')
            return None

    def _create_tcp_packet_bytes(self, params: PacketParams) -> Optional[bytes]:
        """Create TCP packet at byte level."""
        try:
            is_ipv6 = ':' in params.dst_ip
            if is_ipv6:
                ip_header = self._build_ipv6_header(params)
            else:
                ip_header = self._build_ipv4_header(params)
            tcp_header = self._build_tcp_header(params, is_ipv6)
            packet = ip_header + tcp_header + params.payload
            return packet
        except Exception as e:
            self.logger.error(f'Failed to create TCP packet bytes: {e}')
            return None

    def _create_udp_packet_scapy(self, params: PacketParams) -> Optional[Packet]:
        """Create UDP packet using Scapy."""
        try:
            if ':' in params.dst_ip:
                ip_layer = IPv6(dst=params.dst_ip)
            else:
                ip_layer = IP(dst=params.dst_ip)
            if params.src_ip:
                ip_layer.src = params.src_ip
            if params.ttl:
                if hasattr(ip_layer, 'ttl'):
                    ip_layer.ttl = params.ttl
                else:
                    ip_layer.hlim = params.ttl
            udp_layer = UDP(sport=params.src_port, dport=params.dst_port)
            packet = ip_layer / udp_layer
            if params.payload:
                packet = packet / Raw(load=params.payload)
            return packet
        except Exception as e:
            self.logger.error(f'Failed to create UDP packet with Scapy: {e}')
            return None

    def _create_udp_packet_bytes(self, params: PacketParams) -> Optional[bytes]:
        """Create UDP packet at byte level."""
        try:
            is_ipv6 = ':' in params.dst_ip
            if is_ipv6:
                ip_header = self._build_ipv6_header(params)
            else:
                ip_header = self._build_ipv4_header(params)
            udp_length = 8 + len(params.payload)
            checksum = 0
            udp_header = struct.pack('!HHHH', params.src_port, params.dst_port, udp_length, checksum)
            packet = ip_header + udp_header + params.payload
            return packet
        except Exception as e:
            self.logger.error(f'Failed to create UDP packet bytes: {e}')
            return None

    def _fragment_packet_scapy(self, packet: Packet, frag_size: int) -> List[Packet]:
        """Fragment packet using Scapy."""
        try:
            from scapy.all import fragment
            return fragment(packet, fragsize=frag_size)
        except Exception as e:
            self.logger.error(f'Failed to fragment packet with Scapy: {e}')
            return [packet]

    def _fragment_packet_bytes(self, packet: bytes, frag_size: int) -> List[bytes]:
        """Fragment packet at byte level."""
        fragments = []
        try:
            if len(packet) > 0:
                version = packet[0] >> 4 & 15
                if version == 4:
                    ip_header_len = (packet[0] & 15) * 4
                    total_length = struct.unpack('!H', packet[2:4])[0]
                    data_start = ip_header_len
                    data = packet[data_start:]
                    offset = 0
                    frag_id = struct.unpack('!H', packet[4:6])[0]
                    while offset < len(data):
                        chunk_size = min(frag_size, len(data) - offset)
                        chunk_size = chunk_size // 8 * 8
                        if chunk_size == 0 and offset < len(data):
                            chunk_size = len(data) - offset
                        more_fragments = 1 if offset + chunk_size < len(data) else 0
                        flags_offset = more_fragments << 13 | offset // 8
                        new_header = bytearray(packet[:ip_header_len])
                        new_total_length = ip_header_len + chunk_size
                        struct.pack_into('!H', new_header, 2, new_total_length)
                        struct.pack_into('!H', new_header, 6, flags_offset)
                        struct.pack_into('!H', new_header, 10, 0)
                        checksum = self.calculate_checksum(bytes(new_header))
                        struct.pack_into('!H', new_header, 10, checksum)
                        fragment = bytes(new_header) + data[offset:offset + chunk_size]
                        fragments.append(fragment)
                        offset += chunk_size
                else:
                    fragments = [packet]
            else:
                fragments = [packet]
        except Exception as e:
            self.logger.error(f'Failed to fragment packet bytes: {e}')
            fragments = [packet]
        return fragments

    def _build_ipv4_header(self, params: PacketParams) -> bytes:
        """Build IPv4 header."""
        src_ip = params.src_ip or socket.gethostbyname(socket.gethostname())
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(params.dst_ip)
        version_ihl = 4 << 4 | 5
        tos = 0
        total_length = 20 + 20 + len(params.payload)
        identification = random.randint(0, 65535)
        flags_offset = 0
        ttl = params.ttl or 64
        protocol = 6
        checksum = 0
        header = struct.pack('!BBHHHBBH', version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum) + src_ip_bytes + dst_ip_bytes
        checksum = self.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        return header

    def _build_ipv6_header(self, params: PacketParams) -> bytes:
        """Build IPv6 header."""
        src_ip = params.src_ip or '::'
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)
        version_class_flow = 6 << 28
        payload_length = 20 + len(params.payload)
        next_header = 6
        hop_limit = params.ttl or 64
        header = struct.pack('!IHBB', version_class_flow, payload_length, next_header, hop_limit) + src_ip_bytes + dst_ip_bytes
        return header

    def _build_tcp_header(self, params: PacketParams, is_ipv6: bool) -> bytes:
        """Build TCP header."""
        flags_byte = self._flags_to_byte(params.flags)
        data_offset = 5
        reserved_flags = data_offset << 4 | 0
        checksum = 0
        urgent_pointer = 0
        header = struct.pack('!HHIIBBHHH', params.src_port, params.dst_port, params.seq, params.ack, reserved_flags, flags_byte, params.window, checksum, urgent_pointer)
        if params.options:
            options_bytes = self._build_tcp_options(params.options)
            header += options_bytes
            data_offset = (20 + len(options_bytes)) // 4
            header = header[:12] + struct.pack('!B', data_offset << 4) + header[13:]
        if is_ipv6:
            pseudo_header = self._build_ipv6_pseudo_header(params, len(header) + len(params.payload))
        else:
            pseudo_header = self._build_ipv4_pseudo_header(params, len(header) + len(params.payload))
        checksum = self.calculate_checksum(pseudo_header + header + params.payload)
        header = header[:16] + struct.pack('!H', checksum) + header[18:]
        return header

    def _build_tcp_options(self, options: List[Any]) -> bytes:
        """Build TCP options."""
        options_bytes = b''
        for option in options:
            if isinstance(option, tuple):
                opt_name, opt_value = option
                if opt_name == 'MSS':
                    options_bytes += struct.pack('!BBH', 2, 4, opt_value)
                elif opt_name == 'WScale':
                    options_bytes += struct.pack('!BBB', 3, 3, opt_value)
                elif opt_name == 'SAckOK':
                    options_bytes += struct.pack('!BB', 4, 2)
                elif opt_name == 'Timestamp':
                    ts_val, ts_ecr = opt_value
                    options_bytes += struct.pack('!BBII', 8, 10, ts_val, ts_ecr)
                elif opt_name == 'NOP':
                    options_bytes += b'\x01'
        while len(options_bytes) % 4 != 0:
            options_bytes += b'\x00'
        return options_bytes

    def _build_ipv4_pseudo_header(self, params: PacketParams, tcp_length: int) -> bytes:
        """Build pseudo-header for TCP checksum calculation over IPv4."""
        src_ip = params.src_ip or socket.gethostbyname(socket.gethostname())
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(params.dst_ip)
        return src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, 6, tcp_length)

    def _build_ipv6_pseudo_header(self, params: PacketParams, tcp_length: int) -> bytes:
        """Build pseudo-header for TCP checksum calculation over IPv6."""
        src_ip = params.src_ip or '::'
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)
        return src_ip_bytes + dst_ip_bytes + struct.pack('!IH', tcp_length, 6)

    def build_tls_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, tls_data: bytes, **kwargs) -> bytes:
        """Build TLS packet by wrapping TLS data in TCP packet."""
        packet = self.create_tcp_packet(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, seq=kwargs.get('seq', 0), ack=kwargs.get('ack', 0), flags=kwargs.get('flags', 'PA'), payload=tls_data, ttl=kwargs.get('ttl', 64), window=kwargs.get('window', 65535), options=kwargs.get('tcp_options'))
        if packet is None:
            return b''
        if isinstance(packet, (bytes, bytearray)):
            return bytes(packet)
        try:
            return bytes(packet)
        except Exception:
            return b''

    @classmethod
    def get_performance_stats(cls) -> Dict[str, Any]:
        """
        Get performance statistics for PacketBuilder.

        Returns:
            Dictionary with performance metrics
        """
        return {'checksum_cache_size': len(cls._checksum_cache), 'checksum_cache_hits': cls._cache_stats['hits'], 'checksum_cache_misses': cls._cache_stats['misses'], 'packets_built': getattr(cls, '_packets_built', 0), 'total_build_time_ms': getattr(cls, '_total_build_time_ms', 0.0)}

    @classmethod
    def reset_performance_stats(cls):
        """Reset performance statistics."""
        cls._cache_stats = {'hits': 0, 'misses': 0}
        cls._packets_built = 0
        cls._total_build_time_ms = 0.0
EnhancedPacketBuilder = PacketBuilder
PacketFactory = PacketBuilder