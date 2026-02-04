"""
Strategy auto-discovery and testing.

Automatically discovers and tests new bypass strategies for failing domains.
"""

import logging
import time
from datetime import datetime
from typing import List, Optional

from .models import Strategy
from .metrics_calculator import estimate_technique_latency


class StrategyDiscovery:
    """Discovers and tests new bypass strategies."""

    def __init__(
        self,
        fast_bypass_engine=None,
        advanced_fingerprint_engine=None,
        debug: bool = False,
    ):
        """
        Initialize strategy discovery.

        Args:
            fast_bypass_engine: FastBypassEngine for testing
            advanced_fingerprint_engine: Engine for fingerprint analysis
            debug: Enable debug logging
        """
        self.fast_bypass_engine = fast_bypass_engine
        self.advanced_fingerprint_engine = advanced_fingerprint_engine
        self.logger = logging.getLogger("StrategyDiscovery")

        if debug:
            self.logger.setLevel(logging.DEBUG)

        self.discovered_strategies = {}
        self.stats = {"strategies_discovered": 0}

    def auto_discover_strategies(self, failed_domains: List[str]) -> List[Strategy]:
        """
        Auto-discover new working strategies using BypassTechniques.

        Args:
            failed_domains: List of domains where current strategies failed

        Returns:
            List of newly discovered strategies
        """
        try:
            self.logger.info(
                f"Auto-discovering strategies for {len(failed_domains)} failed domains"
            )

            discovered_strategies = []

            if not self.fast_bypass_engine:
                self.logger.warning("FastBypassEngine not available for strategy discovery")
                return discovered_strategies

            # Get available techniques from BypassTechniques
            available_techniques = self._get_available_techniques()

            for domain in failed_domains:
                self.logger.debug(f"Discovering strategies for {domain}")

                # Get domain fingerprint for targeted discovery
                domain_fingerprint = None
                if self.advanced_fingerprint_engine:
                    domain_fingerprint = (
                        self.advanced_fingerprint_engine.create_comprehensive_fingerprint(domain)
                    )

                # Test techniques based on fingerprint analysis
                promising_techniques = self._select_promising_techniques(
                    domain_fingerprint, available_techniques
                )

                for technique in promising_techniques:
                    strategy = self._test_technique_for_domain(
                        domain, technique, domain_fingerprint
                    )
                    if strategy and strategy.success_rate > 0.5:  # 50% success threshold
                        discovered_strategies.append(strategy)
                        self.discovered_strategies[strategy.strategy_id] = strategy
                        self.stats["strategies_discovered"] += 1

                        self.logger.info(
                            f"Discovered working strategy: {strategy.strategy_id} for {domain}"
                        )

            return discovered_strategies

        except Exception as e:
            self.logger.error(f"Error in auto-discovery: {e}")
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.exception("Detailed auto-discovery error:")
            return []

    def _get_available_techniques(self) -> List[str]:
        """
        Get list of available techniques from BypassTechniques.

        Returns:
            List of technique names
        """
        return [
            "fakeddisorder",
            "multisplit",
            "multidisorder",
            "seqovl",
            "tlsrec_split",
            "wssize_limit",
            "badsum_fooling",
            "md5sig_fooling",
            "tcp_window_scaling",
            "urgent_pointer_manipulation",
            "tcp_options_padding",
            "ip_fragmentation_advanced",
            "timing_based_evasion",
            "payload_encryption",
            "protocol_tunneling",
            "decoy_packets",
            "noise_injection",
        ]

    def _select_promising_techniques(
        self, fingerprint, available_techniques: List[str]
    ) -> List[str]:
        """
        Select most promising techniques based on fingerprint analysis.

        Args:
            fingerprint: Domain fingerprint object
            available_techniques: List of all available techniques

        Returns:
            List of promising technique names
        """
        if not fingerprint:
            return available_techniques[:5]  # Return first 5 if no fingerprint

        promising = []

        # Analyze fingerprint characteristics
        if hasattr(fingerprint, "supports_fragmentation") and fingerprint.supports_fragmentation:
            promising.extend(["multisplit", "ip_fragmentation_advanced"])

        if hasattr(fingerprint, "checksum_validation") and not fingerprint.checksum_validation:
            promising.extend(["badsum_fooling", "md5sig_fooling"])

        if hasattr(fingerprint, "timing_sensitivity"):
            timing_sens = fingerprint.timing_sensitivity
            if isinstance(timing_sens, dict) and timing_sens.get("delay_sensitivity", 0) > 0.5:
                promising.append("timing_based_evasion")

        # Add techniques based on success rates
        if hasattr(fingerprint, "technique_success_rates"):
            for technique, success_rate in fingerprint.technique_success_rates.items():
                if success_rate > 0.6 and technique in available_techniques:
                    promising.append(technique)

        # Ensure we have at least some techniques to test
        if not promising:
            promising = ["fakeddisorder", "multisplit", "seqovl"]

        return list(set(promising))  # Remove duplicates

    def _test_technique_for_domain(
        self, domain: str, technique: str, fingerprint
    ) -> Optional[Strategy]:
        """
        Test a specific technique for a domain and create strategy if successful.

        Args:
            domain: Domain to test
            technique: Technique name to test
            fingerprint: Domain fingerprint object

        Returns:
            Strategy object if successful, None otherwise
        """
        try:
            self.logger.debug(f"Testing technique {technique} for {domain}")

            # Get technique effectiveness from fingerprint or engine
            effectiveness = 0.0
            if fingerprint and hasattr(fingerprint, "technique_success_rates"):
                if technique in fingerprint.technique_success_rates:
                    effectiveness = fingerprint.technique_success_rates[technique]
            elif self.advanced_fingerprint_engine:
                if hasattr(self.advanced_fingerprint_engine, "analyze_technique_effectiveness"):
                    effectiveness = (
                        self.advanced_fingerprint_engine.analyze_technique_effectiveness(
                            domain, technique
                        )
                    )

            # Simulate strategy testing (in real implementation, this would involve actual testing)
            if effectiveness > 0.5:
                # Create strategy
                strategy_string = self._technique_to_zapret_string(technique)
                strategy_id = f"{technique}_{domain}_{int(time.time())}"

                strategy = Strategy(
                    strategy_id=strategy_id,
                    strategy_string=strategy_string,
                    technique_type=technique,
                    success_rate=effectiveness,
                    avg_latency_ms=estimate_technique_latency(technique),
                    domains=[domain],
                    fingerprint_hash=(
                        fingerprint.get_fingerprint_hash()
                        if fingerprint and hasattr(fingerprint, "get_fingerprint_hash")
                        else None
                    ),
                    last_tested=datetime.now(),
                )

                return strategy

        except Exception as e:
            self.logger.error(f"Error testing technique {technique} for {domain}: {e}")

        return None

    def _technique_to_zapret_string(self, technique: str) -> str:
        """
        Convert technique name to zapret-compatible strategy string.

        Args:
            technique: Technique name

        Returns:
            Zapret-compatible command line string
        """
        technique_mapping = {
            "fakeddisorder": "--dpi-desync=fakeddisorder",
            "multisplit": "--dpi-desync=multisplit --dpi-desync-split-count=3",
            "multidisorder": "--dpi-desync=multidisorder --dpi-desync-split-count=3",
            "seqovl": "--dpi-desync=multisplit --dpi-desync-split-seqovl=10",
            "badsum_fooling": "--dpi-desync-fooling=badsum",
            "md5sig_fooling": "--dpi-desync-fooling=md5sig",
            "tlsrec_split": "--dpi-desync=tlsrec --dpi-desync-split-pos=5",
        }

        return technique_mapping.get(technique, f"--dpi-desync={technique}")

    def get_stats(self):
        """Get discovery statistics."""
        return {
            **self.stats,
            "discovered_strategies_count": len(self.discovered_strategies),
        }
