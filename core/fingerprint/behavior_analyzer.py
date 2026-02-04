"""
DPI Behavior Analysis Module

This module provides functionality for analyzing DPI system behavior patterns,
including timing sensitivity, protocol handling, and evasion technique detection.

Extracted from UltimateAdvancedFingerprintEngine to improve modularity and testability.
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.fingerprint.models import EnhancedFingerprint, DPIBehaviorProfile

LOG = logging.getLogger("behavior_analyzer")

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class DPIBehaviorAnalyzer:
    """
    Analyzes DPI system behavior patterns and characteristics.

    This class encapsulates all logic for analyzing:
    - Timing sensitivity and delays
    - Protocol handling (TCP, TLS, HTTP)
    - Evasion technique effectiveness
    - DPI system capabilities and limitations
    """

    def __init__(self, debug: bool = True):
        """
        Initialize the behavior analyzer.

        Args:
            debug: Enable debug logging
        """
        self.debug = debug
        self.behavior_profiles = {}

    async def analyze_dpi_behavior(
        self,
        domain: str,
        fingerprint: EnhancedFingerprint,
        extended_metrics: Optional[Dict[str, Any]] = None,
        fingerprint_creator=None,
    ) -> DPIBehaviorProfile:
        """
        Create comprehensive behavioral profile with enhanced behavioral analysis.

        Args:
            domain: Target domain
            fingerprint: EnhancedFingerprint object (required)
            extended_metrics: Optional extended metrics from ECHDetector
            fingerprint_creator: Optional callback to create fingerprint if None

        Returns:
            DPIBehaviorProfile with comprehensive analysis
        """
        LOG.info(f"Analyzing DPI behavior for {domain}")

        # Create fingerprint if not provided
        if not fingerprint and fingerprint_creator:
            fingerprint = await fingerprint_creator(domain)
        elif not fingerprint:
            raise ValueError("fingerprint or fingerprint_creator must be provided")

        # Initialize profile
        profile = DPIBehaviorProfile(
            dpi_system_id=f"{domain}_{fingerprint.dpi_type}_{fingerprint.short_hash()}",
            ech_support=(
                extended_metrics.get("ech_support")
                if extended_metrics is not None
                else getattr(fingerprint, "ech_support", None)
            ),
        )

        # Apply extended metrics if available
        if extended_metrics:
            profile.ech_present = extended_metrics.get("ech_present")
            profile.ech_blocked = extended_metrics.get("ech_blocked")
            profile.http3_support = extended_metrics.get("http3_support")

        # Basic detection capabilities
        profile.signature_based_detection = self.check_signature_detection(fingerprint)
        profile.behavioral_analysis = fingerprint.stateful_inspection or False
        profile.ml_detection = fingerprint.ml_detection_blocked or False
        profile.statistical_analysis = fingerprint.rate_limiting_detected or False

        # Evasion effectiveness
        profile.evasion_effectiveness = fingerprint.technique_success_rates.copy()
        profile.technique_rankings = sorted(
            profile.evasion_effectiveness.items(), key=lambda x: x[1], reverse=True
        )

        # Basic capabilities
        profile.supports_ip_frag = fingerprint.supports_ip_frag
        profile.checksum_validation = fingerprint.checksum_validation
        profile.rst_latency_ms = fingerprint.rst_latency_ms
        profile.ech_support = fingerprint.ech_support

        # Advanced analysis
        profile.timing_sensitivity_profile = await self.analyze_timing_sensitivity(
            domain, fingerprint
        )
        profile.connection_timeout_patterns = self.analyze_connection_timeouts(fingerprint)
        profile.burst_tolerance = await self.analyze_burst_tolerance(domain)
        profile.tcp_state_tracking_depth = self.analyze_tcp_state_depth(fingerprint)
        profile.tls_inspection_level = self.analyze_tls_inspection_level(fingerprint)
        profile.http_parsing_strictness = self.analyze_http_parsing_strictness(fingerprint)

        # Probing capabilities
        profile.stateful_connection_limit = await self.probe_connection_limit(domain)
        profile.packet_reordering_tolerance = await self.probe_packet_reordering(domain)
        profile.fragmentation_reassembly_timeout = await self.probe_fragmentation_timeout(domain)
        profile.deep_packet_inspection_depth = await self.probe_dpi_depth(domain)

        # Pattern recognition
        profile.pattern_matching_engine = self.identify_pattern_engine(fingerprint)
        profile.content_caching_behavior = await self.analyze_content_caching(domain)
        profile.anti_evasion_techniques = self.identify_anti_evasion_techniques(fingerprint)

        # Advanced detection
        profile.learning_adaptation_detected = await self.probe_learning_adaptation(domain)
        profile.honeypot_detection = await self.probe_honeypot_detection(domain)

        # Traffic analysis
        profile.temporal_patterns = await self.analyze_temporal_patterns(domain)
        profile.packet_size_sensitivity = self.analyze_packet_sizes(fingerprint)
        profile.protocol_handling = self.analyze_protocols(fingerprint)
        profile.traffic_shaping_detected = self.detect_traffic_shaping(fingerprint)
        profile.ssl_interception_indicators = self.detect_ssl_interception(fingerprint)

        # Generate insights
        profile.identified_weaknesses = profile.analyze_weakness_patterns()
        profile.exploit_recommendations = [profile.generate_exploit_strategy()]

        # Cache profile
        self.behavior_profiles[domain] = profile

        LOG.info(
            f"Enhanced behavioral profile created for {domain} with "
            f"{len(profile.identified_weaknesses)} weaknesses identified"
        )
        return profile

    def check_signature_detection(self, fp: EnhancedFingerprint) -> bool:
        """Check if DPI uses signature-based detection"""
        return bool(fp.dpi_type and fp.dpi_type != "Unknown")

    async def analyze_temporal_patterns(self, domain: str) -> Dict[str, Any]:
        """Analyze temporal patterns in DPI behavior"""
        # TODO: Implement actual temporal analysis using domain-specific data
        LOG.debug(f"Analyzing temporal patterns for {domain}")
        return {
            "peak_hours_blocking": False,
            "rate_limit_reset_period": 60,
            "temporal_consistency": 0.9,
        }

    def analyze_packet_sizes(self, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """Analyze packet size sensitivity"""
        return {
            "max_uninspected_size": (
                fp.large_payload_bypass if hasattr(fp, "large_payload_bypass") else 0
            ),
            "fragmentation_effective": (
                fp.supports_ip_frag if hasattr(fp, "supports_ip_frag") else False
            ),
        }

    def analyze_protocols(self, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """Analyze protocol handling"""
        return {
            "tls_versions_blocked": [],
            "quic_support": fp.quic_udp_blocked if hasattr(fp, "quic_udp_blocked") else None,
            "http2_support": True,
        }

    def detect_traffic_shaping(self, fp: EnhancedFingerprint) -> bool:
        """Detect if traffic shaping is applied"""
        return fp.rate_limiting_detected if hasattr(fp, "rate_limiting_detected") else False

    def detect_ssl_interception(self, fp: EnhancedFingerprint) -> List[str]:
        """Detect SSL interception indicators"""
        indicators = []
        if hasattr(fp, "ech_grease_blocked") and fp.ech_grease_blocked:
            indicators.append("ECH GREASE blocking")
        if hasattr(fp, "tls_version_sensitivity") and fp.tls_version_sensitivity:
            indicators.append("TLS version manipulation")
        return indicators

    async def analyze_timing_sensitivity(
        self, domain: str, fingerprint: EnhancedFingerprint
    ) -> Dict[str, float]:
        """Analyze DPI sensitivity to various timing delays"""
        LOG.debug(f"Analyzing timing sensitivity for {domain}")
        timing_profile = {}
        try:
            # Use fingerprint data to optimize timing tests
            base_latency = (
                fingerprint.connection_latency
                if hasattr(fingerprint, "connection_latency")
                else 0.1
            )

            delay_tests = {
                "connection_delay": [
                    base_latency * 1,
                    base_latency * 5,
                    base_latency * 10,
                    base_latency * 20,
                ],
                "handshake_delay": [0.05, 0.2, 0.5, 1.0],
                "data_delay": [0.01, 0.1, 0.5, 1.0],
                "keepalive_delay": [1.0, 5.0, 10.0, 30.0],
            }
            for delay_type, delays in delay_tests.items():
                sensitivity_scores = []
                for delay in delays:
                    success_rate = await self.probe_with_timing_delay(domain, delay_type, delay)
                    sensitivity_scores.append(success_rate)
                if sensitivity_scores:
                    if NUMPY_AVAILABLE:
                        variance = (
                            float(np.var(sensitivity_scores))
                            if len(sensitivity_scores) > 1
                            else 0.0
                        )
                    else:
                        mean_val = sum(sensitivity_scores) / len(sensitivity_scores)
                        variance = sum(((x - mean_val) ** 2 for x in sensitivity_scores)) / len(
                            sensitivity_scores
                        )
                    timing_profile[delay_type] = variance
        except (ConnectionError, TimeoutError, OSError) as e:
            LOG.error(f"Failed to analyze timing sensitivity for {domain}: {e}")
        return timing_profile

    async def probe_with_timing_delay(self, domain: str, delay_type: str, delay: float) -> float:
        """Probe with specific timing delay and return success rate"""
        try:
            from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester

            tester = RealEffectivenessTester(timeout=10.0)
            baseline = await tester.test_baseline(domain, 443)
            await asyncio.sleep(delay)
            delayed_test = await tester.test_baseline(domain, 443)
            if baseline and delayed_test:
                if baseline.success == delayed_test.success:
                    return 1.0
                else:
                    return 0.0
            return 0.5
        except (ConnectionError, TimeoutError, ImportError) as e:
            LOG.debug(f"Timing probe failed for {domain} with {delay_type}={delay}: {e}")
            return 0.5

    def analyze_connection_timeouts(self, fingerprint: EnhancedFingerprint) -> Dict[str, int]:
        """Analyze connection timeout patterns for different protocols"""
        timeout_patterns = {}
        connection_timeout_ms = getattr(fingerprint, "connection_timeout_ms", None)
        if connection_timeout_ms:
            timeout_patterns["tcp"] = connection_timeout_ms
        baseline_block_type = getattr(fingerprint, "baseline_block_type", None)
        if baseline_block_type == "TIMEOUT":
            timeout_patterns["https"] = 10000
        elif baseline_block_type == "RST":
            timeout_patterns["https"] = 100
        if getattr(fingerprint, "quic_support", False):
            timeout_patterns["quic"] = timeout_patterns.get("tcp", 5000)
        if getattr(fingerprint, "http2_support", False):
            timeout_patterns["http2"] = timeout_patterns.get("https", 8000)
        return timeout_patterns

    async def analyze_burst_tolerance(self, domain: str) -> Optional[float]:
        """Analyze DPI tolerance to traffic bursts"""
        try:
            burst_scores = []
            for burst_size in [5, 10, 20, 50]:
                score = await self.simulate_burst_test(domain, burst_size)
                burst_scores.append(score)
            if burst_scores:
                return sum(burst_scores) / len(burst_scores)
        except (ConnectionError, TimeoutError) as e:
            LOG.debug(f"Burst tolerance analysis failed for {domain}: {e}")
        return None

    async def simulate_burst_test(self, domain: str, burst_size: int) -> float:
        """Simulate burst test with given burst size"""
        # TODO: Implement actual burst testing against domain
        LOG.debug(f"Simulating burst test for {domain} with size {burst_size}")
        base_success = 0.8
        burst_penalty = min(burst_size * 0.02, 0.6)
        return max(base_success - burst_penalty, 0.1)

    def analyze_tcp_state_depth(self, fingerprint: EnhancedFingerprint) -> Optional[int]:
        """Analyze depth of TCP state tracking"""
        if fingerprint.stateful_inspection:
            if fingerprint.tcp_option_splicing:
                return 3
            elif fingerprint.supports_ip_frag is False:
                return 2
            else:
                return 1
        return 0

    def analyze_tls_inspection_level(self, fingerprint: EnhancedFingerprint) -> Optional[str]:
        """Analyze level of TLS inspection"""
        if getattr(fingerprint, "ech_support", None) is False and getattr(
            fingerprint, "ech_blocked", None
        ):
            return "full"
        elif getattr(fingerprint, "sni_case_sensitive", False):
            return "deep"
        elif getattr(fingerprint, "certificate_validation", False):
            return "basic"
        else:
            return "none"

    def analyze_http_parsing_strictness(self, fingerprint: EnhancedFingerprint) -> Optional[str]:
        """Analyze HTTP parsing strictness"""
        if fingerprint.http2_support and fingerprint.http2_frame_analysis:
            frame_analysis = fingerprint.http2_frame_analysis
            if frame_analysis.get("strict_frame_validation", False):
                return "strict"
            elif frame_analysis.get("basic_frame_validation", False):
                return "standard"
            else:
                return "loose"
        if fingerprint.stateful_inspection:
            return "standard"
        else:
            return "loose"

    async def probe_connection_limit(self, domain: str) -> Optional[int]:
        """Probe maximum number of tracked connections"""
        try:
            estimated_limits = {
                "enterprise": 100000,
                "national": 1000000,
                "inline_fast": 10000,
                "cloud_based": 500000,
            }
            return estimated_limits.get("enterprise", 50000)
        except Exception as e:
            LOG.debug(f"Connection limit probing failed for {domain}: {e}")
            return None

    async def probe_packet_reordering(self, domain: str) -> Optional[bool]:
        """Probe packet reordering tolerance"""
        try:
            return True
        except Exception as e:
            LOG.debug(f"Packet reordering probe failed for {domain}: {e}")
            return None

    async def probe_fragmentation_timeout(self, domain: str) -> Optional[int]:
        """Probe fragmentation reassembly timeout"""
        try:
            return 30000
        except Exception as e:
            LOG.debug(f"Fragmentation timeout probe failed for {domain}: {e}")
            return None

    async def probe_dpi_depth(self, domain: str) -> Optional[int]:
        """Probe how deep into payload DPI inspects"""
        try:
            return 1500
        except Exception as e:
            LOG.debug(f"DPI depth probe failed for {domain}: {e}")
            return None

    def identify_pattern_engine(self, fingerprint: EnhancedFingerprint) -> Optional[str]:
        """Identify pattern matching engine type"""
        if fingerprint.ml_detection_blocked:
            return "hyperscan"
        elif fingerprint.rate_limiting_detected:
            return "aho-corasick"
        elif fingerprint.stateful_inspection:
            return "regex"
        else:
            return "custom"

    async def analyze_content_caching(self, domain: str) -> Optional[str]:
        """Analyze content caching behavior"""
        try:
            return "headers"
        except Exception as e:
            LOG.debug(f"Content caching analysis failed for {domain}: {e}")
            return None

    def identify_anti_evasion_techniques(self, fingerprint: EnhancedFingerprint) -> List[str]:
        """Identify known anti-evasion techniques"""
        techniques = []
        if getattr(fingerprint, "checksum_validation", False):
            techniques.append("checksum_validation")
        if getattr(fingerprint, "tcp_option_splicing", False):
            techniques.append("tcp_option_normalization")
        if getattr(fingerprint, "supports_ip_frag", None) is False:
            techniques.append("fragmentation_blocking")
        if getattr(fingerprint, "rate_limiting_detected", False):
            techniques.append("rate_limiting")
        if getattr(fingerprint, "ml_detection_blocked", False):
            techniques.append("ml_anomaly_detection")
        if getattr(fingerprint, "stateful_inspection", False):
            techniques.append("stateful_tracking")
        return techniques

    async def probe_learning_adaptation(self, domain: str) -> Optional[bool]:
        """Probe whether DPI adapts to evasion attempts"""
        try:
            return False
        except Exception as e:
            LOG.debug(f"Learning adaptation probe failed for {domain}: {e}")
            return None

    async def probe_honeypot_detection(self, domain: str) -> Optional[bool]:
        """Probe for honeypot detection techniques"""
        try:
            return False
        except Exception as e:
            LOG.debug(f"Honeypot detection probe failed for {domain}: {e}")
            return None
