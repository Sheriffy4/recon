"""Checksum calculation utilities with caching."""

import struct
from typing import Dict, Any


class ChecksumCache:
    """Global checksum cache for high-performance packet building."""

    # Keyed by (padded) bytes to avoid collisions.
    # To prevent memory blow-ups, we do not cache very large buffers.
    _checksum_cache: Dict[bytes, int] = {}
    _cache_stats = {"hits": 0, "misses": 0}
    _max_cache_size = 10000
    _max_cache_key_len = 2048  # do not cache huge payload-derived buffers

    @classmethod
    def calculate_checksum(cls, data: bytes) -> int:
        """
        Calculate standard IP checksum (RFC 1071) with caching.

        Args:
            data: Data to calculate checksum for

        Returns:
            Checksum value
        """
        # RFC1071: pad odd length with a trailing zero byte
        padded = data if (len(data) % 2 == 0) else (data + b"\x00")
        cacheable = len(padded) <= cls._max_cache_key_len

        if cacheable and padded in cls._checksum_cache:
            cls._cache_stats["hits"] += 1
            return cls._checksum_cache[padded]

        cls._cache_stats["misses"] += 1

        checksum = 0
        length = len(padded)
        for i in range(0, length, 2):
            checksum += (padded[i] << 8) | padded[i + 1]

        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)

        checksum = ~checksum & 65535

        if cacheable and len(cls._checksum_cache) < cls._max_cache_size:
            cls._checksum_cache[padded] = checksum

        return checksum

    @classmethod
    def build_tcp_checksum(
        cls, src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes
    ) -> int:
        """
        Build TCP checksum including pseudo-header with caching.

        Args:
            src_ip: Source IP address bytes
            dst_ip: Destination IP address bytes
            tcp_header: TCP header bytes
            payload: Payload bytes

        Returns:
            TCP checksum value
        """
        tcp_len = len(tcp_header) + len(payload)
        if len(src_ip) == 16 and len(dst_ip) == 16:
            # IPv6 pseudo-header: src(16) + dst(16) + len(4) + zeros(3) + next_header(1)
            pseudo_header = src_ip + dst_ip + struct.pack("!I3xB", tcp_len, 6)
        else:
            # IPv4 pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + len(2)
            pseudo_header = src_ip + dst_ip + struct.pack("!BBH", 0, 6, tcp_len)
        return cls.calculate_checksum(pseudo_header + tcp_header + payload)

    @classmethod
    def build_udp_checksum(
        cls, src_ip: bytes, dst_ip: bytes, udp_header: bytes, payload: bytes
    ) -> int:
        """
        Build UDP checksum including pseudo-header.
        Note: for IPv6 checksum is mandatory; caller should not transmit 0x0000.

        Args:
            src_ip: Source IP address bytes
            dst_ip: Destination IP address bytes
            udp_header: UDP header bytes
            payload: Payload bytes

        Returns:
            UDP checksum value
        """
        udp_len = len(udp_header) + len(payload)
        if len(src_ip) == 16 and len(dst_ip) == 16:
            pseudo_header = src_ip + dst_ip + struct.pack("!I3xB", udp_len, 17)
        else:
            pseudo_header = src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_len)
        return cls.calculate_checksum(pseudo_header + udp_header + payload)

    @classmethod
    def clear_cache(cls) -> Dict[str, int]:
        """
        Clear checksum cache and return statistics.

        Returns:
            Dictionary with cache statistics before clearing
        """
        stats = cls._cache_stats.copy()
        cls._checksum_cache.clear()
        cls._cache_stats = {"hits": 0, "misses": 0}
        return stats

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """
        Get cache performance statistics.

        Returns:
            Dictionary with cache metrics
        """
        total = cls._cache_stats["hits"] + cls._cache_stats["misses"]
        hit_rate = cls._cache_stats["hits"] / total if total > 0 else 0.0
        return {
            "cache_size": len(cls._checksum_cache),
            "hits": cls._cache_stats["hits"],
            "misses": cls._cache_stats["misses"],
            "hit_rate": hit_rate,
            "max_size": cls._max_cache_size,
            "max_cache_key_len": cls._max_cache_key_len,
        }
