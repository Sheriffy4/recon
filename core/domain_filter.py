"""
Domain Filter for Auto Strategy Discovery System

This module implements domain-based filtering for the auto strategy discovery system,
ensuring that only traffic for the target domain is processed during discovery sessions.

Requirements: 1.1, 1.2, 1.4 from auto-strategy-discovery spec
"""

import logging
from typing import Optional, Set, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import time

from core.bypass.engine.sni_domain_extractor import SNIDomainExtractor, DomainExtractionResult
from core.bypass.filtering.sni_extractor import SNIExtractor

LOG = logging.getLogger(__name__)

# Import discovery logging (with fallback if not available)
try:
    from core.discovery_logging import get_discovery_logger, get_metrics_collector

    DISCOVERY_LOGGING_AVAILABLE = True
except ImportError:
    DISCOVERY_LOGGING_AVAILABLE = False


class FilterMode(Enum):
    """Domain filtering modes"""

    DISCOVERY = "discovery"  # Filter for discovery mode - only target domain
    NORMAL = "normal"  # Normal operation - no filtering
    DISABLED = "disabled"  # Filtering disabled


@dataclass
class FilterRule:
    """Represents a domain filtering rule"""

    target_domain: str
    mode: FilterMode
    created_at: float = field(default_factory=time.time)
    processed_packets: int = 0
    filtered_packets: int = 0


@dataclass
class FilterStats:
    """Statistics for domain filtering operations"""

    total_packets: int = 0
    processed_packets: int = 0
    filtered_packets: int = 0
    target_domain_packets: int = 0
    background_packets: int = 0
    extraction_errors: int = 0

    @property
    def filter_rate(self) -> float:
        """Calculate the filtering rate (filtered/total)"""
        return self.filtered_packets / self.total_packets if self.total_packets > 0 else 0.0

    @property
    def target_rate(self) -> float:
        """Calculate the target domain rate (target/processed)"""
        return (
            self.target_domain_packets / self.processed_packets
            if self.processed_packets > 0
            else 0.0
        )


class DomainFilter:
    """
    Domain-based packet filter for auto strategy discovery.

    Provides SNI-based filtering to ensure only target domain traffic
    is processed during discovery sessions, filtering out unrelated domains.

    Key features:
    - SNI-based filtering using existing TLS parsing infrastructure
    - Configurable filtering rules per target domain
    - Statistics collection for monitoring effectiveness
    - Integration with existing domain extraction components
    """

    def __init__(self, session_id: Optional[str] = None):
        """Initialize the domain filter with default configuration."""
        self._rules: Dict[str, FilterRule] = {}
        self._stats = FilterStats()
        self._current_target: Optional[str] = None
        self._mode = FilterMode.NORMAL
        self._session_id = session_id

        # Initialize domain extraction components
        self._sni_extractor = SNIExtractor()
        self._domain_extractor = SNIDomainExtractor(enable_fast_sni=True)

        # Initialize discovery logging if available
        self._discovery_logger = None
        self._metrics_collector = None
        if DISCOVERY_LOGGING_AVAILABLE:
            try:
                self._discovery_logger = get_discovery_logger()
                self._metrics_collector = get_metrics_collector()
            except Exception as e:
                LOG.warning(f"Failed to initialize discovery logging: {e}")

        LOG.info("DomainFilter initialized")

    def configure_filter(self, target_domain: str, mode: FilterMode = FilterMode.DISCOVERY) -> None:
        """
        Configure domain filtering for a specific target domain.

        Args:
            target_domain: The domain to filter for (e.g., "mail.ru")
            mode: Filtering mode to use

        Requirements: 1.1, 1.2
        """
        if not target_domain:
            raise ValueError("Target domain cannot be empty")

        # Normalize domain (lowercase, strip)
        target_domain = target_domain.strip().lower().rstrip(".")

        # Create or update filter rule
        if target_domain in self._rules:
            self._rules[target_domain].mode = mode
            LOG.info(f"Updated filter rule for domain '{target_domain}' to mode {mode.value}")
        else:
            rule = FilterRule(target_domain=target_domain, mode=mode)
            self._rules[target_domain] = rule
            LOG.info(f"Created new filter rule for domain '{target_domain}' with mode {mode.value}")

        # Set as current target if in discovery mode
        if mode == FilterMode.DISCOVERY:
            self._current_target = target_domain
            self._mode = mode
            LOG.info(f"Set current discovery target to '{target_domain}'")

        # Reset stats for new configuration
        self._reset_stats()

    def should_process_packet(self, packet_data: bytes) -> bool:
        """
        Determine if a packet should be processed based on domain filtering rules.

        Args:
            packet_data: Raw packet payload bytes

        Returns:
            True if packet should be processed, False if it should be filtered out

        Requirements: 1.1, 1.2, 1.4
        """
        self._stats.total_packets += 1

        # If filtering is disabled or in normal mode, process all packets
        if self._mode in (FilterMode.DISABLED, FilterMode.NORMAL):
            self._stats.processed_packets += 1
            return True

        # If no current target is set, process all packets
        if not self._current_target:
            self._stats.processed_packets += 1
            return True

        try:
            # Extract domain from packet using SNI-based filtering
            domain = self._extract_domain_from_packet(packet_data)

            if domain is None:
                # No domain found - could be non-TLS traffic or malformed packet
                # In discovery mode, we filter out packets without identifiable domains
                self._stats.background_packets += 1
                self._stats.filtered_packets += 1
                LOG.debug("Filtered packet: no domain extracted")
                return False

            # Check if domain matches current target
            if self._matches_target_domain(domain, self._current_target):
                # Domain matches target - process the packet
                self._stats.target_domain_packets += 1
                self._stats.processed_packets += 1

                # Update rule statistics
                if self._current_target in self._rules:
                    self._rules[self._current_target].processed_packets += 1

                # Log packet processing if discovery logging is available
                if self._discovery_logger and self._session_id and self._current_target:
                    self._discovery_logger.log_packet_processed(
                        self._session_id, self._current_target, domain, True, "Target domain match"
                    )

                LOG.debug(f"Processing packet for target domain: {domain}")
                return True
            else:
                # Domain doesn't match target - filter out
                self._stats.background_packets += 1
                self._stats.filtered_packets += 1

                # Update rule statistics
                if self._current_target in self._rules:
                    self._rules[self._current_target].filtered_packets += 1

                # Log domain filtering if discovery logging is available
                if self._discovery_logger and self._session_id and self._current_target:
                    self._discovery_logger.log_domain_filtering(
                        self._session_id,
                        self._current_target,
                        domain,
                        "packet",
                        "Non-target domain",
                    )

                LOG.debug(f"Filtered packet for non-target domain: {domain}")
                return False

        except Exception as e:
            # Error during domain extraction - log and filter out to be safe
            self._stats.extraction_errors += 1
            self._stats.filtered_packets += 1

            # Log error if discovery logging is available
            if self._discovery_logger and self._session_id and self._current_target:
                self._discovery_logger.log_error(
                    self._session_id,
                    self._current_target,
                    f"Domain extraction error: {e}",
                    "domain_filter",
                    e,
                )

            LOG.warning(f"Error extracting domain from packet: {e}")
            return False

    def _extract_domain_from_packet(self, packet_data: bytes) -> Optional[str]:
        """
        Extract domain name from packet data using SNI-based extraction.

        Args:
            packet_data: Raw packet payload bytes

        Returns:
            Extracted domain name or None if not found
        """
        try:
            # First try fast SNI extraction
            domain = self._sni_extractor.extract_sni(packet_data)
            if domain:
                return self._normalize_domain(domain)

            # Fallback to comprehensive domain extraction
            result = self._domain_extractor.extract_from_payload(packet_data)
            if result.domain:
                return self._normalize_domain(result.domain)

            return None

        except Exception as e:
            LOG.debug(f"Domain extraction error: {e}")
            return None

    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain name for consistent matching.

        Args:
            domain: Raw domain name

        Returns:
            Normalized domain name
        """
        if not domain:
            return domain

        # Basic normalization: lowercase, strip, remove trailing dot
        return domain.strip().lower().rstrip(".")

    def _matches_target_domain(self, extracted_domain: str, target_domain: str) -> bool:
        """
        Check if extracted domain matches the target domain.

        Supports exact matching and bidirectional subdomain matching.

        Args:
            extracted_domain: Domain extracted from packet
            target_domain: Target domain to match against

        Returns:
            True if domains match

        Requirements: 1.4 (SNI-based filtering priority)
        """
        if not extracted_domain or not target_domain:
            return False

        # Normalize both domains
        extracted = self._normalize_domain(extracted_domain)
        target = self._normalize_domain(target_domain)

        # Exact match
        if extracted == target:
            return True

        # Subdomain match (e.g., "www.mail.ru" matches "mail.ru")
        if extracted.endswith(f".{target}"):
            return True

        # Reverse subdomain match (e.g., "youtube.com" matches "www.youtube.com")
        # This handles cases where the packet contains the parent domain
        # but we're targeting a specific subdomain
        if target.endswith(f".{extracted}"):
            return True

        return False

    def filter_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter results to include only those related to the target domain.

        Args:
            results: List of result dictionaries

        Returns:
            Filtered results containing only target domain data

        Requirements: 1.5, 3.5 (target domain statistics isolation)
        """
        if self._mode != FilterMode.DISCOVERY or not self._current_target:
            # No filtering in non-discovery modes
            return results

        filtered_results = []

        for result in results:
            # Check if result is related to target domain
            if self._is_result_for_target_domain(result):
                filtered_results.append(result)
            else:
                LOG.debug(
                    f"Filtered out result for non-target domain: {result.get('domain', 'unknown')}"
                )

        LOG.info(
            f"Filtered results: {len(filtered_results)}/{len(results)} kept for target '{self._current_target}'"
        )
        return filtered_results

    def _is_result_for_target_domain(self, result: Dict[str, Any]) -> bool:
        """
        Check if a result is related to the target domain.

        Args:
            result: Result dictionary to check

        Returns:
            True if result is for target domain
        """
        if not self._current_target:
            return True

        # Check various possible domain fields in result
        domain_fields = ["domain", "target_domain", "host", "hostname", "sni"]

        found_domain_field = False
        for field in domain_fields:
            if field in result:
                found_domain_field = True
                domain = result[field]
                if isinstance(domain, str) and self._matches_target_domain(
                    domain, self._current_target
                ):
                    return True

        # If no domain field found, include by default (could be aggregate data)
        # If domain field was found but didn't match, exclude it
        return not found_domain_field

    def get_stats(self) -> FilterStats:
        """
        Get current filtering statistics.

        Returns:
            Current FilterStats object
        """
        return self._stats

    def get_rule_stats(self, domain: str) -> Optional[FilterRule]:
        """
        Get statistics for a specific domain rule.

        Args:
            domain: Domain to get stats for

        Returns:
            FilterRule object or None if not found
        """
        return self._rules.get(self._normalize_domain(domain))

    def clear_rules(self) -> None:
        """Clear all filtering rules and reset to normal mode."""
        self._rules.clear()
        self._current_target = None
        self._mode = FilterMode.NORMAL
        self._reset_stats()
        LOG.info("Cleared all domain filtering rules")

    def disable_filtering(self) -> None:
        """Disable domain filtering while keeping rules."""
        self._mode = FilterMode.DISABLED
        LOG.info("Domain filtering disabled")

    def enable_filtering(self) -> None:
        """Re-enable domain filtering with existing rules."""
        if self._current_target:
            self._mode = FilterMode.DISCOVERY
        else:
            self._mode = FilterMode.NORMAL
        LOG.info(f"Domain filtering enabled in {self._mode.value} mode")

    def _reset_stats(self) -> None:
        """Reset filtering statistics."""
        self._stats = FilterStats()

    def get_current_target(self) -> Optional[str]:
        """Get the current target domain."""
        return self._current_target

    def get_mode(self) -> FilterMode:
        """Get the current filtering mode."""
        return self._mode

    def is_discovery_mode(self) -> bool:
        """Check if currently in discovery mode."""
        return self._mode == FilterMode.DISCOVERY

    def set_session_id(self, session_id: str) -> None:
        """Set the session ID for discovery logging integration."""
        self._session_id = session_id

    def log_filtering_summary(self) -> None:
        """Log a summary of filtering statistics."""
        stats = self._stats
        LOG.info(f"Domain Filtering Summary:")
        LOG.info(f"  Total packets: {stats.total_packets}")
        LOG.info(f"  Processed: {stats.processed_packets}")
        LOG.info(f"  Filtered: {stats.filtered_packets}")
        LOG.info(f"  Target domain: {stats.target_domain_packets}")
        LOG.info(f"  Background: {stats.background_packets}")
        LOG.info(f"  Errors: {stats.extraction_errors}")
        LOG.info(f"  Filter rate: {stats.filter_rate:.2%}")
        LOG.info(f"  Target rate: {stats.target_rate:.2%}")

        if self._current_target:
            LOG.info(f"  Current target: {self._current_target}")

        # Record filtering metrics if discovery logging is available
        if self._metrics_collector and self._session_id:
            self._metrics_collector.record_filtering_metrics(
                self._session_id,
                stats.total_packets,
                stats.filtered_packets,
                stats.target_domain_packets,
                stats.background_packets,
            )
