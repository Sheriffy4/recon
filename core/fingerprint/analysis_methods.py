"""
DPI Analysis Methods Module
Extracted from AdvancedFingerprinter for better organization and maintainability

This module contains all DPI analysis methods that analyze fingerprint data
and extract insights about DPI behavior.
"""

from typing import Dict, Any, Tuple
from core.fingerprint.advanced_models import DPIFingerprint, DPIType


class DPIAnalyzer:
    """
    Centralized DPI analysis methods for analyzing fingerprint data
    """

    def __init__(self, config, logger):
        """
        Initialize DPI Analyzer

        Args:
            config: FingerprintingConfig instance
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

    async def analyze_timing_sensitivity_detailed(
        self, domain: str, fingerprint: DPIFingerprint
    ) -> Dict[str, float]:
        """
        Detailed timing sensitivity analysis for specific domain

        Analyzes various timing characteristics to determine DPI sensitivity
        to timing-based evasion techniques.

        Args:
            domain: Target domain for domain-specific timing analysis
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Dict with timing sensitivity profile
        """
        timing_profile = {}

        # Domain-specific logging
        self.logger.debug(f"Analyzing timing sensitivity for domain: {domain}")

        # Connection delay sensitivity
        if hasattr(fingerprint, "rst_latency_ms") and fingerprint.rst_latency_ms:
            if fingerprint.rst_latency_ms < 100:
                timing_profile["connection_delay"] = 0.9
            elif fingerprint.rst_latency_ms < 500:
                timing_profile["connection_delay"] = 0.5
            else:
                timing_profile["connection_delay"] = 0.2

        # From timing probe results
        timing_probe = fingerprint.raw_metrics.get("timing_probe", {})
        if timing_probe.get("timing_sensitive"):
            timing_profile["overall_sensitivity"] = 0.8
        else:
            timing_profile["overall_sensitivity"] = 0.3

        # TLS handshake timing
        tls_latency = fingerprint.raw_metrics.get("tls_handshake_latency")
        if tls_latency:
            if tls_latency < 50:
                timing_profile["tls_sensitivity"] = 0.9
            elif tls_latency < 200:
                timing_profile["tls_sensitivity"] = 0.5
            else:
                timing_profile["tls_sensitivity"] = 0.2

        # Store domain-specific timing profile
        timing_profile["domain"] = domain

        return timing_profile

    async def analyze_burst_tolerance(self, domain: str, fingerprint: DPIFingerprint) -> float:
        """
        Analyze burst tolerance based on collected metrics for specific domain

        Determines how well the DPI handles traffic bursts, which can indicate
        vulnerability to burst-based evasion techniques.

        Args:
            domain: Target domain for domain-specific burst analysis
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Float between 0.0 and 1.0 indicating burst tolerance
        """
        # Domain-specific logging
        self.logger.debug(f"Analyzing burst tolerance for domain: {domain}")

        # Check for rate limiting indicators
        if getattr(fingerprint, "rate_limiting_detected", False):
            return 0.3  # Low tolerance

        # Check packet size limits
        max_payload = fingerprint.raw_metrics.get("packet_size_limits", {}).get("max_tcp_payload")
        if max_payload and max_payload > 9000:
            return 0.8  # High tolerance (supports jumbo frames)
        elif max_payload and max_payload < 1000:
            return 0.4  # Low tolerance

        return 0.6  # Default moderate tolerance

    def analyze_tcp_state_depth(self, fingerprint: DPIFingerprint) -> int:
        """
        Analyze TCP state tracking depth

        Determines how deeply the DPI tracks TCP connection state,
        which affects vulnerability to TCP-based evasion techniques.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Integer depth level (0-5)
        """
        depth = 0

        if getattr(fingerprint, "stateful_inspection", False):
            depth += 1
        if getattr(fingerprint, "sequence_number_anomalies", False):
            depth += 2
        if getattr(fingerprint, "tcp_window_manipulation", False):
            depth += 1
        if fingerprint.raw_metrics.get("packet_reordering_tolerant"):
            depth += 1

        return min(depth, 5)  # Cap at 5 levels

    def analyze_tls_inspection_level(self, fingerprint: DPIFingerprint) -> str:
        """
        Determine TLS inspection level

        Analyzes various TLS-related indicators to determine the depth
        of TLS inspection performed by the DPI.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            String indicating inspection level: "full", "deep", "moderate", "minimal", "legacy"
        """
        rm = fingerprint.raw_metrics

        # Check various indicators
        if rm.get("ech_support") is False and rm.get("ech_blocked"):
            return "full"  # Full TLS interception

        if rm.get("sni_sensitivity", {}).get("confirmed"):
            if rm.get("sni_probe", {}).get("sni_validation_type") == "strict_domain":
                return "deep"  # Deep inspection with validation
            else:
                return "moderate"  # Some SNI inspection

        if rm.get("tls_caps", {}).get("tls13_supported") is False:
            return "legacy"  # Blocks modern TLS

        return "minimal"  # Little to no TLS inspection

    def analyze_http_parsing_strictness(self, fingerprint: DPIFingerprint) -> str:
        """
        Analyze HTTP parsing strictness

        Determines how strictly the DPI parses HTTP traffic,
        which affects vulnerability to HTTP-based evasion techniques.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            String indicating strictness: "very_strict", "strict", "moderate", "lenient"
        """
        if getattr(fingerprint, "http_header_filtering", False):
            if getattr(fingerprint, "http_method_restrictions", None):
                return "very_strict"
            return "strict"

        if getattr(fingerprint, "content_inspection_depth", 0) > 0:
            return "moderate"

        return "lenient"

    def analyze_connection_timeouts(self, fingerprint: DPIFingerprint) -> Dict[str, int]:
        """
        Analyze connection timeout patterns

        Analyzes timeout behavior to understand DPI timing characteristics,
        which can inform timeout-based evasion strategies.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Dict with timeout values in milliseconds
        """
        timeouts = {}

        # TCP timeout
        if hasattr(fingerprint, "connection_timeout_ms"):
            timeouts["tcp"] = fingerprint.connection_timeout_ms

        # Block type based timeouts
        if fingerprint.block_type == "tcp_timeout":
            timeouts["default"] = 10000
        elif fingerprint.block_type == "connection_reset":
            timeouts["default"] = 100
        else:
            timeouts["default"] = 5000

        # Protocol specific
        rm = fingerprint.raw_metrics
        if rm.get("timing_patterns", {}).get("connect_time_ms"):
            timeouts["observed"] = int(rm["timing_patterns"]["connect_time_ms"])

        return timeouts

    def analyze_rst_ttl_stats(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """
        Analyze RST TTL statistics

        Analyzes the TTL (Time To Live) of RST packets to determine
        if they originate from the DPI or the actual server.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Dict with TTL analysis results
        """
        ttl = getattr(fingerprint, "rst_ttl", None)
        if ttl is None:
            return {"rst_ttl_level": "unknown"}

        if ttl <= 64:
            level = "low"
        elif ttl <= 128:
            level = "mid"
        else:
            level = "high"

        return {"rst_ttl_level": level, "rst_ttl": ttl}

    def heuristic_classification(self, fingerprint: DPIFingerprint) -> Tuple[DPIType, float]:
        """
        Enhanced heuristic DPI classification

        Uses heuristic rules to classify the DPI type based on observed behaviors.
        This is a fallback when ML classification is not available.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Tuple of (DPIType, confidence_score)
        """
        score = 0.1
        dpi_type = DPIType.UNKNOWN

        rm = getattr(fingerprint, "raw_metrics", {}) or {}

        # RST injection patterns (Roskomnadzor TSPU signature)
        if getattr(fingerprint, "rst_injection_detected", False):
            rst_ttl = getattr(fingerprint, "rst_ttl", None)
            if rst_ttl and rst_ttl <= 64:
                dpi_type = DPIType.ROSKOMNADZOR_TSPU
                score = 0.75

                # Additional TSPU indicators
                if getattr(fingerprint, "dns_hijacking_detected", False):
                    score += 0.1
                if rm.get("sni_sensitivity", {}).get("likely"):
                    score += 0.05

        # Commercial DPI patterns
        elif getattr(fingerprint, "http_header_filtering", False):
            dpi_type = DPIType.COMMERCIAL_DPI
            score = 0.6

            # Deep packet inspection indicators
            if getattr(fingerprint, "content_inspection_depth", 0) > 1000:
                score += 0.1
            if getattr(fingerprint, "stateful_inspection", False):
                score += 0.1

        # ISP transparent proxy patterns
        elif getattr(fingerprint, "http_response_modification", False):
            dpi_type = DPIType.ISP_TRANSPARENT_PROXY
            score = 0.65

            if getattr(fingerprint, "redirect_injection", False):
                score += 0.1

        # DNS-based blocking
        elif getattr(fingerprint, "dns_hijacking_detected", False):
            if getattr(fingerprint, "dns_response_modification", False):
                dpi_type = DPIType.COMMERCIAL_DPI
                score = 0.55
            else:
                dpi_type = DPIType.UNKNOWN
                score = 0.4

        # SNI-based blocking
        elif rm.get("sni_sensitivity", {}).get("confirmed"):
            dpi_type = DPIType.COMMERCIAL_DPI
            score = 0.5

            # Check for additional indicators
            if rm.get("sni_probe", {}).get("sni_validation_type") == "strict_domain":
                score += 0.15

        # QUIC blocking
        elif rm.get("quic_probe", {}).get("blocked"):
            dpi_type = DPIType.COMMERCIAL_DPI
            score = 0.45

        # Timing-based detection
        elif rm.get("timing_probe", {}).get("timing_sensitive"):
            dpi_type = DPIType.COMMERCIAL_DPI
            score = 0.4

        # Ensure score is in valid range
        score = max(0.0, min(1.0, score))

        return dpi_type, score

    def calculate_reliability_score(self, fingerprint: DPIFingerprint) -> float:
        """
        Calculate overall reliability score for the fingerprint

        Combines various confidence indicators to produce an overall
        reliability score for the fingerprint.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Float between 0.0 and 1.0 indicating reliability
        """
        score = 0.0
        factors = 0

        # Base confidence from classification
        if hasattr(fingerprint, "confidence"):
            score += fingerprint.confidence
            factors += 1

        # Analysis methods used
        if hasattr(fingerprint, "analysis_methods_used"):
            methods_count = len(fingerprint.analysis_methods_used)
            if methods_count > 0:
                score += min(methods_count / 5.0, 1.0)
                factors += 1

        # Data completeness
        rm = fingerprint.raw_metrics
        data_points = sum(
            [
                bool(rm.get("tcp_analysis")),
                bool(rm.get("http_analysis")),
                bool(rm.get("dns_analysis")),
                bool(rm.get("metrics_collection")),
                bool(rm.get("sni_probe")),
                bool(rm.get("timing_probe")),
            ]
        )
        if data_points > 0:
            score += data_points / 6.0
            factors += 1

        # Behavioral indicators
        behavioral_indicators = sum(
            [
                bool(getattr(fingerprint, "rst_injection_detected", False)),
                bool(getattr(fingerprint, "dns_hijacking_detected", False)),
                bool(getattr(fingerprint, "http_header_filtering", False)),
                bool(rm.get("sni_sensitivity", {}).get("confirmed")),
            ]
        )
        if behavioral_indicators > 0:
            score += behavioral_indicators / 4.0
            factors += 1

        # Calculate average
        if factors > 0:
            final_score = score / factors
        else:
            final_score = 0.1  # Minimum score

        return max(0.0, min(1.0, final_score))
