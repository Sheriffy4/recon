"""Enhanced packet builder with performance optimizations."""
import struct
import socket
import random
from typing import List, Optional, Dict, Any, Union
import logging
from recon.core.bypass.exceptions import InvalidPacketError

class PacketBuilder:
    """High-performance packet builder without Scapy dependency."""
    _checksum_cache: Dict[bytes, int] = {}
    _cache_stats = {'hits': 0, 'misses': 0}
    logger = logging.getLogger(__name__)

    @classmethod
    def calculate_checksum(cls, data: bytes) -> int:
        """Calculate IP/TCP checksum with caching."""
        data_hash = hash(data)
        if data_hash in cls._checksum_cache:
            cls._cache_stats['hits'] += 1
            return cls._checksum_cache[data_hash]
        cls._cache_stats['misses'] += 1
        checksum = 0
        length = len(data)
        for i in range(0, length - 1, 2):
            checksum += data[i] << 8 | data[i + 1]
        if length % 2:
            checksum += data[length - 1] << 8
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        checksum = ~checksum & 65535
        if len(cls._checksum_cache) < 10000:
            cls._checksum_cache[data_hash] = checksum
        return checksum

    @classmethod
    def build_tcp_checksum(cls, src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes) -> int:
        """Build TCP checksum including pseudo-header."""
        pseudo_header = src_ip + dst_ip + b'\x00\x06' + struct.pack('!H', len(tcp_header) + len(payload))
        data = pseudo_header + tcp_header + payload
        if len(data) % 2:
            data += b'\x00'
        return cls.calculate_checksum(data)

    @classmethod
    def build_ip_header(cls, src_ip: str, dst_ip: str, protocol: int=6, ttl: int=64, identification: Optional[int]=None, flags: int=0, fragment_offset: int=0, options: bytes=b'', total_length: Optional[int]=None) -> bytes:
        """Build IP header with options support."""
        try:
            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)
        except socket.error as e:
            raise InvalidPacketError(f'Invalid IP address: {e}')
        header_length = 20 + len(options)
        if header_length % 4:
            padding_needed = 4 - header_length % 4
            options += b'\x00' * padding_needed
            header_length += padding_needed
        ihl = header_length // 4
        header = struct.pack('!BBHHHBBH', 4 << 4 | ihl, 0, total_length or header_length, identification or random.randint(0, 65535), flags << 13 | fragment_offset, ttl, protocol, 0) + src_ip_bytes + dst_ip_bytes + options
        checksum = cls.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        return header

    @classmethod
    def build_tcp_header(cls, src_port: int, dst_port: int, seq: int, ack: int, flags: Union[int, str], window: int=65535, urgent: int=0, options: bytes=b'') -> bytes:
        """Build TCP header with options support."""
        if isinstance(flags, str):
            flag_byte = 0
            if 'F' in flags:
                flag_byte |= 1
            if 'S' in flags:
                flag_byte |= 2
            if 'R' in flags:
                flag_byte |= 4
            if 'P' in flags:
                flag_byte |= 8
            if 'A' in flags:
                flag_byte |= 16
            if 'U' in flags:
                flag_byte |= 32
        else:
            flag_byte = flags
        header_length = 20 + len(options)
        if header_length % 4:
            padding_needed = 4 - header_length % 4
            options += b'\x00' * padding_needed
        data_offset = header_length // 4 << 4
        header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flag_byte, window, 0, urgent) + options
        return header

    @classmethod
    def assemble_packet(cls, src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: Union[int, str], payload: bytes=b'', ttl: int=64, window: int=65535, urgent: int=0, ip_options: bytes=b'', tcp_options: bytes=b'', **kwargs) -> bytes:
        """Assemble complete TCP/IP packet."""
        tcp_header = cls.build_tcp_header(src_port, dst_port, seq, ack, flags, window, urgent, tcp_options)
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        tcp_checksum = cls.build_tcp_checksum(src_ip_bytes, dst_ip_bytes, tcp_header, payload)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
        total_length = 20 + len(ip_options) + len(tcp_header) + len(payload)
        ip_header = cls.build_ip_header(src_ip, dst_ip, 6, ttl, options=ip_options, total_length=total_length, **kwargs)
        return ip_header + tcp_header + payload

    @classmethod
    def modify_packet(cls, packet_data: bytes, new_payload: Optional[bytes]=None, new_seq: Optional[int]=None, new_ack: Optional[int]=None, new_flags: Optional[Union[int, str]]=None, new_window: Optional[int]=None, new_ttl: Optional[int]=None, **kwargs) -> bytes:
        """Modify existing packet with new values."""
        if len(packet_data) < 40:
            raise InvalidPacketError('Packet too small for TCP/IP')
        ip_hlen = (packet_data[0] & 15) * 4
        tcp_start = ip_hlen
        tcp_hlen = (packet_data[tcp_start + 12] >> 4 & 15) * 4
        src_ip = socket.inet_ntoa(packet_data[12:16])
        dst_ip = socket.inet_ntoa(packet_data[16:20])
        src_port = struct.unpack('!H', packet_data[tcp_start:tcp_start + 2])[0]
        dst_port = struct.unpack('!H', packet_data[tcp_start + 2:tcp_start + 4])[0]
        seq = new_seq if new_seq is not None else struct.unpack('!I', packet_data[tcp_start + 4:tcp_start + 8])[0]
        ack = new_ack if new_ack is not None else struct.unpack('!I', packet_data[tcp_start + 8:tcp_start + 12])[0]
        if new_flags is None:
            flags = packet_data[tcp_start + 13]
        else:
            flags = new_flags
        window = new_window if new_window is not None else struct.unpack('!H', packet_data[tcp_start + 14:tcp_start + 16])[0]
        urgent = struct.unpack('!H', packet_data[tcp_start + 18:tcp_start + 20])[0]
        tcp_options = packet_data[tcp_start + 20:tcp_start + tcp_hlen] if tcp_hlen > 20 else b''
        ip_options = packet_data[20:ip_hlen] if ip_hlen > 20 else b''
        payload = new_payload if new_payload is not None else packet_data[ip_hlen + tcp_hlen:]
        return cls.assemble_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, ttl=new_ttl or packet_data[8], window=window, urgent=urgent, ip_options=ip_options, tcp_options=tcp_options, **kwargs)

    @classmethod
    def fragment_packet(cls, packet_data: bytes, fragment_size: int, overlap_bytes: int=0) -> List[bytes]:
        """Fragment IP packet with optional overlap."""
        if len(packet_data) < 20:
            raise InvalidPacketError('Packet too small for IP')
        ip_hlen = (packet_data[0] & 15) * 4
        total_length = struct.unpack('!H', packet_data[2:4])[0]
        identification = struct.unpack('!H', packet_data[4:6])[0]
        ttl = packet_data[8]
        protocol = packet_data[9]
        src_ip = packet_data[12:16]
        dst_ip = packet_data[16:20]
        payload = packet_data[ip_hlen:]
        fragments = []
        offset = 0
        while offset < len(payload):
            current_frag_size = min(fragment_size, len(payload) - offset)
            frag_start = max(0, offset - overlap_bytes) if offset > 0 else 0
            frag_data = payload[frag_start:offset + current_frag_size]
            frag_offset = frag_start // 8
            more_fragments = 1 if offset + current_frag_size < len(payload) else 0
            flags_offset = more_fragments << 13 | frag_offset
            frag_header = struct.pack('!BBHHHBBH', 69, 0, 20 + len(frag_data), identification, flags_offset, ttl, protocol, 0) + src_ip + dst_ip
            checksum = cls.calculate_checksum(frag_header)
            frag_header = frag_header[:10] + struct.pack('!H', checksum) + frag_header[12:]
            fragments.append(frag_header + frag_data)
            offset += current_frag_size
        return fragments

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
        return {'cache_size': len(cls._checksum_cache), 'hits': cls._cache_stats['hits'], 'misses': cls._cache_stats['misses'], 'hit_rate': hit_rate, 'total_requests': total}