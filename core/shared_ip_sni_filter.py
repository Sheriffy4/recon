"""
Shared IP SNI-based Filtering for CLI Auto Mode

This module implements SNI-based filtering specifically for scenarios where
multiple domains resolve to the same IP address. It ensures that only packets
with SNI matching the target domain are processed during auto discovery.

Requirements: 2.5 from cli-auto-mode-fixes spec
"""

import logging
from typing import Optional, Set, Dict, Any, List, Tuple
from dataclasses import dataclass, field
import time

from core.domain_filter import DomainFilter, FilterMode, FilterStats
from core.bypass.filtering.sni_extractor import SNIExtractor

LOG = logging.getLogger(__name__)


@dataclass
class SharedIPScenario:
    """Represents a shared IP scenario with multiple domains"""

    ip_address: str
    domains: Set[str]
    target_domain: str
    packets_processed: int = 0
    packets_filtered: int = 0
    sni_extractions: int = 0
    sni_failures: int = 0


@dataclass
class SharedIPFilterStats:
    """Statistics for shared IP filtering operations"""

    total_shared_ip_scenarios: int = 0
    active_shared_ip_scenarios: int = 0
    packets_processed_via_sni: int = 0
    packets_filtered_via_sni: int = 0
    sni_extraction_success_rate: float = 0.0

    @property
    def sni_filter_rate(self) -> float:
        """Calculate the SNI-based filtering rate"""
        total = self.packets_processed_via_sni + self.packets_filtered_via_sni
        return self.packets_filtered_via_sni / total if total > 0 else 0.0


class SharedIPSNIFilter:
    """
    SNI-based filter specifically designed for shared IP scenarios.

    This filter ensures that when multiple domains resolve to the same IP address,
    only packets with SNI matching the target domain are processed during discovery.

    Key features:
    - Detects shared IP scenarios automatically
    - Uses SNI extraction to distinguish between domains on same IP
    - Maintains statistics for shared IP filtering effectiveness
    - Integrates with existing domain filter infrastructure
    """

    def __init__(self, session_id: Optional[str] = None):
        """Initialize the shared IP SNI filter."""
        self._session_id = session_id
        self._shared_ip_scenarios: Dict[str, SharedIPScenario] = {}
        self._stats = SharedIPFilterStats()
        self._sni_extractor = SNIExtractor()
        self._domain_filter: Optional[DomainFilter] = None

        LOG.info("SharedIPSNIFilter initialized")

    def set_domain_filter(self, domain_filter: DomainFilter) -> None:
        """Set the underlying domain filter for integration."""
        self._domain_filter = domain_filter
        LOG.info("Domain filter integrated with SharedIPSNIFilter")

    def register_shared_ip_scenario(
        self, ip_address: str, domains: Set[str], target_domain: str
    ) -> None:
        """
        Register a shared IP scenario for monitoring.

        Args:
            ip_address: The shared IP address
            domains: Set of domains that resolve to this IP
            target_domain: The target domain we want to process
        """
        if target_domain not in domains:
            raise ValueError(f"Target domain '{target_domain}' not in domains set: {domains}")

        scenario = SharedIPScenario(
            ip_address=ip_address, domains=domains, target_domain=target_domain
        )

        self._shared_ip_scenarios[ip_address] = scenario
        self._stats.total_shared_ip_scenarios += 1
        self._stats.active_shared_ip_scenarios += 1

        LOG.info(
            f"Registered shared IP scenario: {ip_address} -> {domains} (target: {target_domain})"
        )

    def should_process_packet_for_shared_ip(self, packet_data: bytes, ip_address: str) -> bool:
        """
        Determine if a packet should be processed in a shared IP scenario.

        This method specifically handles the case where multiple domains resolve
        to the same IP address and uses SNI to distinguish between them.

        Args:
            packet_data: Raw packet payload bytes
            ip_address: The IP address the packet is destined for

        Returns:
            True if packet should be processed (SNI matches target domain)
            False if packet should be filtered out (SNI doesn't match target domain)
        """
        # Check if this is a known shared IP scenario
        scenario = self._shared_ip_scenarios.get(ip_address)
        if not scenario:
            # Not a shared IP scenario - delegate to regular domain filter
            if self._domain_filter:
                return self._domain_filter.should_process_packet(packet_data)
            return True

        try:
            # Extract SNI from packet
            sni_domain = self._sni_extractor.extract_sni(packet_data)
            scenario.sni_extractions += 1

            if sni_domain is None:
                # No SNI found - filter out in shared IP scenarios to be safe
                scenario.sni_failures += 1
                scenario.packets_filtered += 1
                self._stats.packets_filtered_via_sni += 1

                LOG.debug(f"Filtered packet for shared IP {ip_address}: no SNI found")
                return False

            # Normalize domain for comparison
            sni_domain = self._normalize_domain(sni_domain)
            target_domain = self._normalize_domain(scenario.target_domain)

            # Check if SNI matches target domain
            if self._matches_target_domain(sni_domain, target_domain):
                # SNI matches target domain - process packet
                scenario.packets_processed += 1
                self._stats.packets_processed_via_sni += 1

                LOG.debug(
                    f"Processing packet for shared IP {ip_address}: SNI {sni_domain} matches target {target_domain}"
                )
                return True
            else:
                # SNI doesn't match target domain - filter out
                scenario.packets_filtered += 1
                self._stats.packets_filtered_via_sni += 1

                LOG.debug(
                    f"Filtered packet for shared IP {ip_address}: SNI {sni_domain} doesn't match target {target_domain}"
                )
                return False

        except Exception as e:
            # Error during SNI extraction - filter out to be safe
            scenario.sni_failures += 1
            scenario.packets_filtered += 1
            self._stats.packets_filtered_via_sni += 1

            LOG.warning(f"Error processing packet for shared IP {ip_address}: {e}")
            return False

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name for consistent matching."""
        if not domain:
            return domain
        return domain.strip().lower().rstrip(".")

    def _matches_target_domain(self, extracted_domain: str, target_domain: str) -> bool:
        """
        Check if extracted domain matches the target domain.

        Supports exact matching and subdomain matching.
        """
        if not extracted_domain or not target_domain:
            return False

        # Exact match
        if extracted_domain == target_domain:
            return True

        # Subdomain match (e.g., "www.mail.ru" matches "mail.ru")
        if extracted_domain.endswith(f".{target_domain}"):
            return True

        return False

    def get_shared_ip_stats(self) -> SharedIPFilterStats:
        """Get shared IP filtering statistics."""
        # Update success rate
        total_extractions = sum(
            scenario.sni_extractions for scenario in self._shared_ip_scenarios.values()
        )
        total_failures = sum(
            scenario.sni_failures for scenario in self._shared_ip_scenarios.values()
        )

        if total_extractions > 0:
            self._stats.sni_extraction_success_rate = (
                total_extractions - total_failures
            ) / total_extractions

        return self._stats

    def get_scenario_stats(self, ip_address: str) -> Optional[SharedIPScenario]:
        """Get statistics for a specific shared IP scenario."""
        return self._shared_ip_scenarios.get(ip_address)

    def list_active_scenarios(self) -> List[SharedIPScenario]:
        """List all active shared IP scenarios."""
        return list(self._shared_ip_scenarios.values())

    def clear_scenarios(self) -> None:
        """Clear all registered shared IP scenarios."""
        self._shared_ip_scenarios.clear()
        self._stats = SharedIPFilterStats()
        LOG.info("Cleared all shared IP scenarios")

    def log_filtering_summary(self) -> None:
        """Log a summary of shared IP filtering statistics."""
        stats = self._stats
        LOG.info("Shared IP SNI Filtering Summary:")
        LOG.info(f"  Total scenarios: {stats.total_shared_ip_scenarios}")
        LOG.info(f"  Active scenarios: {stats.active_shared_ip_scenarios}")
        LOG.info(f"  Packets processed via SNI: {stats.packets_processed_via_sni}")
        LOG.info(f"  Packets filtered via SNI: {stats.packets_filtered_via_sni}")
        LOG.info(f"  SNI extraction success rate: {stats.sni_extraction_success_rate:.2%}")
        LOG.info(f"  SNI filter rate: {stats.sni_filter_rate:.2%}")

        for ip, scenario in self._shared_ip_scenarios.items():
            LOG.info(
                f"  Scenario {ip}: {scenario.packets_processed} processed, {scenario.packets_filtered} filtered"
            )


def create_shared_ip_sni_filter(session_id: Optional[str] = None) -> SharedIPSNIFilter:
    """Factory function to create a shared IP SNI filter."""
    return SharedIPSNIFilter(session_id=session_id)
