"""
Path MTU Discovery Support

Provides enhanced MTU detection and caching mechanisms for IP fragmentation attacks.
Implements RFC 1191 Path MTU Discovery concepts.
"""

import logging
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class MTUCacheEntry:
    """Cache entry for discovered MTU values."""

    mtu: int
    timestamp: datetime
    discovery_method: str  # "manual", "auto", "default"
    confidence: float  # 0.0 to 1.0
    attempts: int = 0

    def is_expired(self, ttl_seconds: int = 600) -> bool:
        """Check if cache entry has expired."""
        return (datetime.now() - self.timestamp).total_seconds() > ttl_seconds


class MTUDiscovery:
    """
    Path MTU Discovery implementation.

    Provides MTU detection, caching, and automatic adjustment for IP fragmentation.
    Implements a simplified version of RFC 1191 Path MTU Discovery.

    Requirements: 7.4
    """

    # Common MTU values for different network types
    COMMON_MTUS = {
        "ethernet": 1500,
        "pppoe": 1492,
        "vpn": 1400,
        "mobile": 1280,
        "tunnel": 1400,
        "jumbo": 9000,
    }

    DEFAULT_MTU = 1500
    MIN_MTU = 576  # RFC 791 minimum for IPv4
    MAX_MTU = 65535

    def __init__(self, cache_ttl: int = 600):
        """
        Initialize MTU discovery.

        Args:
            cache_ttl: Cache time-to-live in seconds (default: 600)
        """
        self._cache: Dict[str, MTUCacheEntry] = {}
        self._cache_ttl = cache_ttl
        self._global_mtu: Optional[int] = None

    def detect_mtu(self, target_ip: str, method: str = "auto", force_refresh: bool = False) -> int:
        """
        Detect MTU for target IP address.

        Args:
            target_ip: Target IP address
            method: Detection method (auto/manual/default)
            force_refresh: Force new detection, ignore cache

        Returns:
            Detected MTU value
        """
        # Check cache first
        if not force_refresh and target_ip in self._cache:
            entry = self._cache[target_ip]
            if not entry.is_expired(self._cache_ttl):
                logger.debug(f"Using cached MTU for {target_ip}: {entry.mtu}")
                return entry.mtu

        # Perform detection based on method
        if method == "auto":
            mtu = self._auto_detect_mtu(target_ip)
        elif method == "manual":
            mtu = self._global_mtu or self.DEFAULT_MTU
        else:
            mtu = self.DEFAULT_MTU

        # Cache the result
        self._cache[target_ip] = MTUCacheEntry(
            mtu=mtu,
            timestamp=datetime.now(),
            discovery_method=method,
            confidence=0.8 if method == "auto" else 0.5,
            attempts=1,
        )

        logger.info(f"Detected MTU for {target_ip}: {mtu} (method: {method})")
        return mtu

    def _auto_detect_mtu(self, target_ip: str) -> int:
        """
        Automatically detect MTU using heuristics.

        In a real implementation, this would:
        1. Send ICMP packets with DF flag set
        2. Binary search for maximum packet size
        3. Handle ICMP "Fragmentation Needed" responses

        For now, we use heuristics based on network type.

        Args:
            target_ip: Target IP address

        Returns:
            Estimated MTU
        """
        # Simple heuristic: use default MTU
        # In production, this would perform actual PMTU discovery

        # Check if it's a private network (might have different MTU)
        if self._is_private_ip(target_ip):
            # Private networks often use standard Ethernet MTU
            return self.COMMON_MTUS["ethernet"]

        # For public IPs, assume standard Internet MTU
        # Account for possible PPPoE or VPN overhead
        return self.COMMON_MTUS["pppoe"]

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return False

            # 10.0.0.0/8
            if parts[0] == 10:
                return True

            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True

            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True

            return False
        except (ValueError, IndexError):
            return False

    def set_global_mtu(self, mtu: int) -> None:
        """
        Set global MTU for all connections.

        Args:
            mtu: MTU value to use globally
        """
        if not self.MIN_MTU <= mtu <= self.MAX_MTU:
            raise ValueError(f"MTU must be between {self.MIN_MTU} and {self.MAX_MTU}")

        self._global_mtu = mtu
        logger.info(f"Set global MTU to {mtu}")

    def get_cached_mtu(self, target_ip: str) -> Optional[int]:
        """
        Get cached MTU for target IP.

        Args:
            target_ip: Target IP address

        Returns:
            Cached MTU or None if not cached or expired
        """
        if target_ip in self._cache:
            entry = self._cache[target_ip]
            if not entry.is_expired(self._cache_ttl):
                return entry.mtu
        return None

    def clear_cache(self, target_ip: Optional[str] = None) -> None:
        """
        Clear MTU cache.

        Args:
            target_ip: Specific IP to clear, or None to clear all
        """
        if target_ip:
            if target_ip in self._cache:
                del self._cache[target_ip]
                logger.debug(f"Cleared MTU cache for {target_ip}")
        else:
            self._cache.clear()
            logger.debug("Cleared all MTU cache entries")

    def get_fragment_size(self, target_ip: str, overhead: int = 20, alignment: int = 8) -> int:
        """
        Calculate optimal fragment size for target.

        Args:
            target_ip: Target IP address
            overhead: IP header overhead (default: 20)
            alignment: Fragment alignment requirement (default: 8)

        Returns:
            Optimal fragment size in bytes
        """
        mtu = self.detect_mtu(target_ip)

        # Calculate available payload space
        available = mtu - overhead

        # Align to required boundary
        fragment_size = (available // alignment) * alignment

        # Ensure minimum size
        if fragment_size < alignment:
            fragment_size = alignment

        return fragment_size

    def adjust_fragment_size(self, target_ip: str, current_size: int, failed: bool = False) -> int:
        """
        Adjust fragment size based on feedback.

        Args:
            target_ip: Target IP address
            current_size: Current fragment size
            failed: Whether current size failed

        Returns:
            Adjusted fragment size
        """
        if failed:
            # Reduce size by 10%
            new_size = int(current_size * 0.9)
            new_size = (new_size // 8) * 8  # Align to 8 bytes

            if new_size < 8:
                new_size = 8

            logger.info(f"Reducing fragment size for {target_ip}: {current_size} -> {new_size}")

            # Update cache with lower MTU
            if target_ip in self._cache:
                entry = self._cache[target_ip]
                entry.mtu = new_size + 20  # Add IP header overhead
                entry.confidence *= 0.8
                entry.attempts += 1

            return new_size
        else:
            # Success - keep current size
            return current_size

    def get_cache_stats(self) -> Dict[str, any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        total = len(self._cache)
        expired = sum(1 for entry in self._cache.values() if entry.is_expired(self._cache_ttl))
        valid = total - expired

        avg_confidence = 0.0
        if valid > 0:
            avg_confidence = (
                sum(
                    entry.confidence
                    for entry in self._cache.values()
                    if not entry.is_expired(self._cache_ttl)
                )
                / valid
            )

        return {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": expired,
            "average_confidence": avg_confidence,
            "cache_ttl": self._cache_ttl,
            "global_mtu": self._global_mtu,
        }


# Global MTU discovery instance
_mtu_discovery = None


def get_mtu_discovery() -> MTUDiscovery:
    """Get global MTU discovery instance."""
    global _mtu_discovery
    if _mtu_discovery is None:
        _mtu_discovery = MTUDiscovery()
    return _mtu_discovery
