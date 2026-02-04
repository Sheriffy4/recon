"""
Runtime Packet Filter for domain-based filtering.

This module provides the main RuntimePacketFilter class that integrates
domain extraction and matching for real-time packet filtering.
"""

import logging
from typing import Optional, Set, Dict, Any
from functools import lru_cache

try:
    import pydivert
except ImportError:
    # Handle case where pydivert is not available (testing environments)
    pydivert = None

from .sni_extractor import SNIExtractor
from .host_extractor import HostHeaderExtractor
from .domain_matcher import DomainMatcher
from .cache import CacheManager
from .config import FilterConfig, FilterConfigManager, FilterMode
from .performance_monitor import PerformanceMonitor, get_global_monitor
from .resource_manager import ResourceManager, get_global_resource_manager


logger = logging.getLogger(__name__)


class RuntimePacketFilter:
    """
    Main runtime packet filter that determines if bypass should be applied.

    This class integrates domain extraction from SNI and Host headers with
    domain matching logic to provide real-time packet filtering decisions.
    """

    def __init__(
        self,
        config: Optional[FilterConfig] = None,
        performance_monitor: Optional[PerformanceMonitor] = None,
        resource_manager: Optional[ResourceManager] = None,
    ):
        """
        Initialize Runtime Packet Filter.

        Args:
            config: Filter configuration (defaults to empty config)
            performance_monitor: Performance monitor instance (defaults to global monitor)
            resource_manager: Resource manager instance (defaults to global manager)

        Requirements: 2.1, 2.2, 5.1, 5.2, 5.3
        """
        self.config = config or FilterConfig()
        self.mode = self.config.mode
        self.domain_list = self.config.domains

        # Initialize performance monitoring
        self.performance_monitor = performance_monitor or get_global_monitor()

        # Initialize resource management
        self.resource_manager = resource_manager or get_global_resource_manager()

        # Initialize extractors
        self.sni_extractor = SNIExtractor()
        self.host_extractor = HostHeaderExtractor()

        # Initialize domain matcher
        self.domain_matcher = DomainMatcher(self.mode, self.domain_list)

        # Performance caching with config settings
        self.cache_manager = CacheManager()
        self.cache_manager.domain_cache.max_size = self.config.cache_size
        self.cache_manager.domain_cache.ttl_seconds = self.config.cache_ttl
        self.cache_manager._cleanup_interval = self.config.cleanup_interval

        # Register cleanup callbacks with resource manager
        self.resource_manager.add_cleanup_callback(self._handle_resource_cleanup)

        logger.info(
            f"RuntimePacketFilter initialized with mode={self.mode.value}, domains={len(self.domain_list)}"
        )

    def should_apply_bypass(self, packet) -> bool:
        """
        Determine if bypass should be applied to this packet.

        Args:
            packet: pydivert.Packet or packet-like object

        Returns:
            True if bypass should be applied, False otherwise

        Requirements: 2.1, 2.2, 5.1, 5.2, 5.3
        """
        # Check if processing should be throttled due to resource pressure
        if self.resource_manager.should_throttle_processing():
            import time

            delay = self.resource_manager.get_throttle_delay()
            if delay > 0:
                time.sleep(delay)

        with self.performance_monitor.start_packet_processing():
            try:
                self.performance_monitor.record_packet_processed()

                # Extract domain from packet
                domain = self.extract_domain(packet)

                if not domain:
                    # No domain found - apply default behavior based on mode
                    if self.mode == FilterMode.NONE:
                        return True  # Apply to all traffic when no filtering
                    else:
                        # In blacklist/whitelist mode, if we can't extract domain, don't apply bypass
                        # This prevents unknown IPs from getting bypass strategies
                        logger.debug(
                            f"No domain extracted from packet, skipping bypass (mode={self.mode.value})"
                        )
                        return False

                # Check if domain matches filtering rules
                with self.performance_monitor.start_pattern_matching():
                    result = self.domain_matcher.matches(domain)

                return result

            except Exception as e:
                logger.warning(f"Error in should_apply_bypass: {e}")
                # Default to safe behavior - don't apply bypass on errors
                return False

    def extract_domain(self, packet) -> Optional[str]:
        """
        Extract domain from packet payload with fallback between SNI and Host.

        Args:
            packet: pydivert.Packet or packet-like object

        Returns:
            Extracted domain name or None if not found

        Requirements: 2.1, 2.2, 5.1, 5.2, 5.3
        """
        if not packet:
            return None

        with self.performance_monitor.start_domain_extraction():
            try:
                # Get packet payload
                payload = self._get_packet_payload(packet)
                if not payload:
                    self.performance_monitor.record_domain_extracted(success=False)
                    return None

                # Create cache key based on payload hash (for performance)
                cache_key = hash(
                    payload[: min(200, len(payload))]
                )  # Use first 200 bytes for cache key

                # Check cache first
                cached_domain = self.cache_manager.domain_cache.get(cache_key)
                if cached_domain is not None:
                    self.performance_monitor.record_cache_hit()
                    self.performance_monitor.record_domain_extracted(success=True)
                    return cached_domain

                self.performance_monitor.record_cache_miss()
                domain = None

                # Try SNI extraction first (for HTTPS traffic)
                if self._is_likely_https_port(packet):
                    domain = self.sni_extractor.extract_sni(payload)
                    self.performance_monitor.record_sni_extraction(success=bool(domain))
                    if domain:
                        logger.debug(f"Extracted domain from SNI: {domain}")

                # Fallback to Host header extraction (for HTTP traffic)
                if not domain and self._is_likely_http_port(packet):
                    domain = self.host_extractor.extract_host(payload)
                    self.performance_monitor.record_host_extraction(success=bool(domain))
                    if domain:
                        logger.debug(f"Extracted domain from Host header: {domain}")

                # Cache the result
                self.cache_manager.domain_cache.put(cache_key, domain)

                # Perform periodic cleanup
                self.cache_manager.maybe_cleanup()

                # Record extraction result
                self.performance_monitor.record_domain_extracted(success=bool(domain))

                return domain

            except Exception as e:
                logger.warning(f"Error extracting domain from packet: {e}")
                self.performance_monitor.record_domain_extracted(success=False)
                return None

    def _get_packet_payload(self, packet) -> Optional[bytes]:
        """
        Extract payload from packet object.

        Args:
            packet: Packet object (pydivert.Packet or similar)

        Returns:
            Packet payload bytes or None
        """
        try:
            # Handle pydivert.Packet
            if hasattr(packet, "payload"):
                return packet.payload

            # Handle raw bytes
            if isinstance(packet, bytes):
                return packet

            # Handle dict-like objects (for testing)
            if isinstance(packet, dict) and "payload" in packet:
                return packet["payload"]

            logger.warning(f"Unknown packet type: {type(packet)}")
            return None

        except Exception as e:
            logger.warning(f"Error getting packet payload: {e}")
            return None

    def _is_likely_https_port(self, packet) -> bool:
        """
        Check if packet is likely HTTPS traffic based on port.

        Args:
            packet: Packet object

        Returns:
            True if likely HTTPS traffic
        """
        try:
            # Common HTTPS ports
            https_ports = {443, 8443, 9443}

            # Try to get destination port
            dst_port = self._get_packet_dst_port(packet)
            if dst_port and dst_port in https_ports:
                return True

            # Try to get source port (for response packets)
            src_port = self._get_packet_src_port(packet)
            if src_port and src_port in https_ports:
                return True

            return False

        except Exception:
            # Default to trying SNI extraction anyway
            return True

    def _is_likely_http_port(self, packet) -> bool:
        """
        Check if packet is likely HTTP traffic based on port.

        Args:
            packet: Packet object

        Returns:
            True if likely HTTP traffic
        """
        try:
            # Common HTTP ports
            http_ports = {80, 8080, 8000, 3000, 5000}

            # Try to get destination port
            dst_port = self._get_packet_dst_port(packet)
            if dst_port and dst_port in http_ports:
                return True

            # Try to get source port (for response packets)
            src_port = self._get_packet_src_port(packet)
            if src_port and src_port in http_ports:
                return True

            return False

        except Exception:
            # Default to trying Host extraction anyway
            return True

    def _get_packet_dst_port(self, packet) -> Optional[int]:
        """Get destination port from packet."""
        try:
            if hasattr(packet, "dst_port"):
                return packet.dst_port
            if hasattr(packet, "dstport"):
                return packet.dstport
            if isinstance(packet, dict) and "dst_port" in packet:
                return packet["dst_port"]
            return None
        except Exception:
            return None

    def _get_packet_src_port(self, packet) -> Optional[int]:
        """Get source port from packet."""
        try:
            if hasattr(packet, "src_port"):
                return packet.src_port
            if hasattr(packet, "srcport"):
                return packet.srcport
            if isinstance(packet, dict) and "src_port" in packet:
                return packet["src_port"]
            return None
        except Exception:
            return None

    def update_configuration(self, config: FilterConfig) -> None:
        """
        Update filter configuration at runtime.

        Args:
            config: New filter configuration

        Requirements: 5.1, 5.2, 5.3
        """
        self.config = config
        self.mode = config.mode
        self.domain_list = config.domains

        # Update domain matcher
        self.domain_matcher = DomainMatcher(self.mode, self.domain_list)

        # Update cache settings
        self.cache_manager.domain_cache.max_size = config.cache_size
        self.cache_manager.domain_cache.ttl_seconds = config.cache_ttl
        self.cache_manager._cleanup_interval = config.cleanup_interval

        # Clear caches to ensure consistency
        self.clear_caches()

        logger.info(
            f"Configuration updated: mode={self.mode.value}, domains={len(self.domain_list)}"
        )

    def clear_caches(self) -> None:
        """
        Clear all internal caches.

        Requirements: 6.3, 6.4
        """
        self.cache_manager.clear_all()
        self.domain_matcher.clear_cache()

        # Clear extractor caches
        if hasattr(self.sni_extractor, "clear_cache"):
            self.sni_extractor.clear_cache()
        if hasattr(self.host_extractor, "clear_cache"):
            self.host_extractor.clear_cache()

        logger.debug("All caches cleared")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get filter statistics for monitoring.

        Returns:
            Dictionary with filter statistics

        Requirements: 6.3, 6.4
        """
        stats = {
            "mode": self.mode.value,
            "domain_count": len(self.domain_list),
            "config": self.config.to_dict(),
        }

        # Add cache manager statistics
        cache_stats = self.cache_manager.get_all_statistics()
        stats.update({f"cache_{k}": v for k, v in cache_stats.items()})

        # Add domain matcher statistics
        matcher_stats = self.domain_matcher.get_cache_stats()
        stats.update({f"matcher_{k}": v for k, v in matcher_stats.items()})

        # Add performance monitoring statistics
        perf_stats = self.performance_monitor.get_statistics()
        stats.update({f"performance_{k}": v for k, v in perf_stats.items()})

        # Sample current memory usage
        current_memory = self.performance_monitor.sample_memory_usage()
        stats["current_memory_mb"] = current_memory

        return stats

    def get_performance_dashboard(self) -> Dict[str, Any]:
        """
        Get performance dashboard data.

        Returns:
            Dictionary with dashboard-ready performance data

        Requirements: 6.3, 6.4
        """
        return self.performance_monitor.get_dashboard_data()

    def _handle_resource_cleanup(self) -> None:
        """
        Handle resource cleanup requests from resource manager.

        Requirements: 6.4
        """
        logger.debug("Handling resource cleanup request")

        # Get recommended cache size based on resource state
        recommended_cache_size = self.resource_manager.get_cache_size_limit()

        # Adjust cache sizes if needed
        current_cache_size = len(self.cache_manager.domain_cache._cache)
        if current_cache_size > recommended_cache_size:
            # Clear excess cache entries
            excess_entries = current_cache_size - recommended_cache_size
            logger.info(f"Reducing cache size by {excess_entries} entries due to resource pressure")

            # Clear oldest entries from domain cache
            with self.cache_manager.domain_cache._lock:
                for _ in range(excess_entries):
                    if self.cache_manager.domain_cache._cache:
                        self.cache_manager.domain_cache._cache.popitem(last=False)

        # Update cache size limits
        self.cache_manager.domain_cache.max_size = recommended_cache_size

        # Clear extractor caches if under severe pressure
        resource_stats = self.resource_manager.get_statistics()
        if resource_stats["current_state"] in ["critical", "emergency"]:
            logger.info("Clearing extractor caches due to severe resource pressure")
            if hasattr(self.sni_extractor, "clear_cache"):
                self.sni_extractor.clear_cache()
            if hasattr(self.host_extractor, "clear_cache"):
                self.host_extractor.clear_cache()

        # Perform cache cleanup
        self.cache_manager.cleanup()

    def start_resource_monitoring(self) -> None:
        """
        Start resource monitoring.

        Requirements: 6.4
        """
        self.resource_manager.start_monitoring()
        logger.info("Resource monitoring started for RuntimePacketFilter")

    def stop_resource_monitoring(self) -> None:
        """
        Stop resource monitoring.

        Requirements: 6.4
        """
        self.resource_manager.stop_monitoring()
        logger.info("Resource monitoring stopped for RuntimePacketFilter")
