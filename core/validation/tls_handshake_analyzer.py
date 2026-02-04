"""
Enhanced TLS Handshake Analyzer for DPI Bypass Validation

This module provides TLS handshake analysis that accounts for DPI bypass effects,
packet timing correlation with HTTP responses, and bypass-aware validation logic.

Requirements: 2.1, 2.2, 2.3, 2.4
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum


class HandshakeCompleteness(Enum):
    """Enum for TLS handshake completeness levels."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING_SERVERHELLO = "missing_serverhello"
    MISSING_CLIENTHELLO = "missing_clienthello"
    NO_HANDSHAKE = "no_handshake"
    OUT_OF_ORDER = "out_of_order"


@dataclass
class TlsHandshakeContext:
    """Context information for TLS handshake analysis."""

    client_hello_count: int = 0
    server_hello_count: int = 0
    retransmission_count: int = 0
    total_packets: int = 0
    bypass_strategy_applied: bool = False
    packet_timing_ms: float = 0.0
    out_of_order_packets: int = 0
    fragmented_packets: int = 0
    completeness: HandshakeCompleteness = HandshakeCompleteness.NO_HANDSHAKE
    bypass_interference_detected: bool = False
    timing_anomalies: List[str] = field(default_factory=list)


@dataclass
class TlsAnalysisResult:
    """Result of TLS handshake analysis."""

    handshake_complete: bool
    context: TlsHandshakeContext
    confidence: float  # 0.0 to 1.0
    bypass_aware_assessment: str
    potential_causes: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class EnhancedTlsHandshakeAnalyzer:
    """
    Enhanced TLS handshake analyzer that accounts for DPI bypass effects.

    This analyzer provides bypass-aware TLS validation logic that can handle:
    - Out-of-order packets due to bypass strategies
    - Packet timing correlation with HTTP responses
    - DPI bypass interference detection
    - Adaptive validation criteria for different network environments

    Requirements: 2.1, 2.2, 2.3, 2.4
    """

    # Timing thresholds for bypass interference detection
    NORMAL_HANDSHAKE_TIME_MS = 100.0  # Normal handshake should complete within 100ms
    BYPASS_INTERFERENCE_THRESHOLD_MS = 500.0  # Beyond this suggests interference

    # Packet order analysis thresholds
    OUT_OF_ORDER_THRESHOLD_PERCENT = 20.0  # More than 20% out-of-order suggests bypass effects

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the enhanced TLS handshake analyzer."""
        self.logger = logger or logging.getLogger("EnhancedTlsAnalyzer")

    def analyze_handshake(
        self,
        telemetry: Dict[str, Any],
        bypass_strategy_applied: bool = False,
        http_response_time_ms: Optional[float] = None,
        network_environment: Optional[str] = None,
    ) -> TlsAnalysisResult:
        """
        Analyze TLS handshake with bypass strategy awareness.

        Args:
            telemetry: Raw telemetry data from packet capture
            bypass_strategy_applied: Whether a DPI bypass strategy was used
            http_response_time_ms: HTTP response timing for correlation

        Returns:
            TlsAnalysisResult with bypass-aware assessment

        Requirements: 2.1, 2.2, 2.3, 2.4
        """
        # Extract handshake context from telemetry
        context = self._extract_handshake_context(telemetry, bypass_strategy_applied)

        # Correlate with HTTP response timing if available
        if http_response_time_ms is not None:
            context.packet_timing_ms = http_response_time_ms
            self._analyze_timing_correlation(context, http_response_time_ms)

        # Determine handshake completeness
        context.completeness = self._assess_handshake_completeness(context)

        # Detect bypass interference
        context.bypass_interference_detected = self._detect_bypass_interference(context)

        # Generate bypass-aware assessment
        assessment = self._generate_bypass_aware_assessment(context)

        # Calculate confidence based on bypass awareness and network environment
        confidence = self._calculate_bypass_aware_confidence(context, network_environment)

        # Generate recommendations (including environment-specific ones)
        recommendations = self._generate_recommendations(context, network_environment)
        potential_causes = self._identify_potential_causes(context, network_environment)

        return TlsAnalysisResult(
            handshake_complete=self._is_handshake_complete(context),
            context=context,
            confidence=confidence,
            bypass_aware_assessment=assessment,
            potential_causes=potential_causes,
            recommendations=recommendations,
        )

    def _extract_handshake_context(
        self, telemetry: Dict[str, Any], bypass_strategy_applied: bool
    ) -> TlsHandshakeContext:
        """Extract TLS handshake context from telemetry data."""
        # Support different telemetry formats
        agg = telemetry.get("aggregate", {})

        client_hellos = telemetry.get(
            "client_hellos", telemetry.get("clienthellos", agg.get("clienthellos", 0))
        )
        server_hellos = telemetry.get(
            "server_hellos", telemetry.get("serverhellos", agg.get("serverhellos", 0))
        )

        retransmissions = telemetry.get(
            "retransmissions", telemetry.get("total_retransmissions_detected", 0)
        )

        total_packets = telemetry.get("total_packets", telemetry.get("packets_captured", 0))

        # Estimate out-of-order and fragmented packets from available data
        out_of_order = telemetry.get("out_of_order_packets", 0)
        fragmented = telemetry.get("fragmented_packets", 0)

        # If total packets is 0, try to estimate from other metrics
        if total_packets == 0:
            total_packets = client_hellos + server_hellos + retransmissions

        return TlsHandshakeContext(
            client_hello_count=client_hellos,
            server_hello_count=server_hellos,
            retransmission_count=retransmissions,
            total_packets=total_packets,
            bypass_strategy_applied=bypass_strategy_applied,
            out_of_order_packets=out_of_order,
            fragmented_packets=fragmented,
        )

    def _analyze_timing_correlation(
        self, context: TlsHandshakeContext, http_response_time_ms: float
    ) -> None:
        """
        Analyze timing correlation between TLS handshake and HTTP response.

        Requirements: 2.3 - Correlate HTTP responses with TLS handshake completion
        """
        context.packet_timing_ms = http_response_time_ms

        # Detect timing anomalies that might indicate bypass interference
        if http_response_time_ms > self.BYPASS_INTERFERENCE_THRESHOLD_MS:
            context.timing_anomalies.append(
                f"HTTP response time ({http_response_time_ms:.1f}ms) exceeds normal threshold"
            )

        # If we have HTTP response but no ServerHello, timing can help explain why
        if context.server_hello_count == 0 and context.client_hello_count > 0:
            if http_response_time_ms < self.NORMAL_HANDSHAKE_TIME_MS:
                context.timing_anomalies.append(
                    "Fast HTTP response without ServerHello suggests QUIC or HTTP-only redirect"
                )
            else:
                context.timing_anomalies.append(
                    "Slow HTTP response without ServerHello suggests TLS bypass or IPv6 leakage"
                )

    def _assess_handshake_completeness(self, context: TlsHandshakeContext) -> HandshakeCompleteness:
        """
        Assess the completeness of the TLS handshake.

        Requirements: 2.4 - Handle out-of-order packets due to bypass strategies
        """
        if context.client_hello_count == 0 and context.server_hello_count == 0:
            return HandshakeCompleteness.NO_HANDSHAKE

        if context.client_hello_count == 0:
            return HandshakeCompleteness.MISSING_CLIENTHELLO

        if context.server_hello_count == 0:
            return HandshakeCompleteness.MISSING_SERVERHELLO

        # Check for out-of-order packets that might indicate bypass effects
        if context.total_packets > 0:
            out_of_order_percent = (context.out_of_order_packets / context.total_packets) * 100
            if out_of_order_percent > self.OUT_OF_ORDER_THRESHOLD_PERCENT:
                return HandshakeCompleteness.OUT_OF_ORDER

        # Check for partial handshake (multiple ClientHellos, few ServerHellos)
        if context.client_hello_count > context.server_hello_count * 2:
            return HandshakeCompleteness.PARTIAL

        return HandshakeCompleteness.COMPLETE

    def _detect_bypass_interference(self, context: TlsHandshakeContext) -> bool:
        """
        Detect if DPI bypass strategies are interfering with TLS handshake analysis.

        Requirements: 2.1, 2.2 - Account for DPI bypass effects on TLS handshake
        """
        interference_indicators = 0

        # High retransmission rate with bypass strategy
        if context.bypass_strategy_applied and context.total_packets > 0:
            retrans_rate = (context.retransmission_count / context.total_packets) * 100
            if retrans_rate > 15.0:  # Higher threshold for bypass scenarios
                interference_indicators += 1

        # Out-of-order packets
        if context.total_packets > 0:
            out_of_order_rate = (context.out_of_order_packets / context.total_packets) * 100
            if out_of_order_rate > self.OUT_OF_ORDER_THRESHOLD_PERCENT:
                interference_indicators += 1

        # Timing anomalies
        if len(context.timing_anomalies) > 0:
            interference_indicators += 1

        # Missing ServerHello with bypass strategy applied
        if (
            context.bypass_strategy_applied
            and context.client_hello_count > 0
            and context.server_hello_count == 0
        ):
            interference_indicators += 1

        # Fragmented packets (common with bypass strategies)
        if context.fragmented_packets > context.total_packets * 0.3:  # More than 30% fragmented
            interference_indicators += 1

        return interference_indicators >= 2  # Need at least 2 indicators

    def _generate_bypass_aware_assessment(self, context: TlsHandshakeContext) -> str:
        """
        Generate a bypass-aware assessment of the TLS handshake.

        Requirements: 2.1, 2.2 - Account for potential TLS handshake disruption
        """
        if context.completeness == HandshakeCompleteness.COMPLETE:
            if context.bypass_interference_detected:
                return "Complete TLS handshake detected despite bypass strategy interference"
            else:
                return "Complete TLS handshake detected with normal packet flow"

        elif context.completeness == HandshakeCompleteness.MISSING_SERVERHELLO:
            if context.bypass_strategy_applied:
                return (
                    "Missing ServerHello with bypass strategy applied - "
                    "likely due to packet fragmentation or timing disruption"
                )
            else:
                return (
                    "Missing ServerHello without bypass strategy - "
                    "may indicate QUIC usage, IPv6 leakage, or actual blocking"
                )

        elif context.completeness == HandshakeCompleteness.OUT_OF_ORDER:
            return (
                "Out-of-order packets detected - "
                "consistent with DPI bypass strategy effects on packet flow"
            )

        elif context.completeness == HandshakeCompleteness.PARTIAL:
            if context.bypass_interference_detected:
                return (
                    "Partial TLS handshake with bypass interference - "
                    "connection may be working despite incomplete capture"
                )
            else:
                return "Partial TLS handshake detected - may indicate connection issues"

        elif context.completeness == HandshakeCompleteness.NO_HANDSHAKE:
            return "No TLS handshake detected - check packet capture configuration"

        else:  # MISSING_CLIENTHELLO
            if context.bypass_strategy_applied:
                return (
                    "Missing ClientHello with bypass strategy applied - "
                    "may indicate packet capture issues or bypass interference"
                )
            else:
                return "Missing ClientHello - unusual scenario requiring investigation"

    def _calculate_bypass_aware_confidence(
        self, context: TlsHandshakeContext, network_environment: Optional[str] = None
    ) -> float:
        """
        Calculate confidence level accounting for bypass strategy effects.

        Requirements: 2.1, 2.2 - Provide appropriate confidence scoring
        """
        # Reduce confidence based on completeness
        if context.completeness == HandshakeCompleteness.COMPLETE:
            confidence = 1.0
        elif context.completeness == HandshakeCompleteness.MISSING_SERVERHELLO:
            if context.bypass_strategy_applied:
                confidence = 0.7  # Higher confidence when bypass explains missing ServerHello
            else:
                confidence = 0.5  # Lower confidence when no clear explanation
        elif context.completeness == HandshakeCompleteness.OUT_OF_ORDER:
            confidence = 0.6  # Medium confidence - bypass can explain this
        elif context.completeness == HandshakeCompleteness.PARTIAL:
            confidence = 0.4
        else:
            confidence = 0.2

        # Adjust for bypass interference
        if context.bypass_interference_detected:
            if context.bypass_strategy_applied:
                # Expected interference - don't penalize as much
                confidence = max(confidence, 0.6)
            else:
                # Unexpected interference - reduce confidence
                confidence *= 0.8

        # Adjust for timing anomalies
        if len(context.timing_anomalies) > 0:
            confidence *= 0.9

        # Adjust for high retransmission rate
        if context.total_packets > 0:
            retrans_rate = (context.retransmission_count / context.total_packets) * 100
            if retrans_rate > 20.0:
                confidence *= 0.7

        # Apply network environment adjustments
        if network_environment:
            confidence = self._apply_network_environment_adjustments(
                confidence, network_environment, context
            )

        return max(0.1, min(1.0, confidence))  # Clamp between 0.1 and 1.0

    def _is_handshake_complete(self, context: TlsHandshakeContext) -> bool:
        """
        Determine if handshake should be considered complete for validation purposes.

        This uses bypass-aware logic that's more lenient when bypass strategies are applied.
        """
        if context.completeness == HandshakeCompleteness.COMPLETE:
            return True

        # With bypass strategies, we're more lenient about missing ServerHello
        if (
            context.completeness == HandshakeCompleteness.MISSING_SERVERHELLO
            and context.bypass_strategy_applied
            and not context.bypass_interference_detected
        ):
            # If bypass is applied but no interference detected,
            # missing ServerHello might be expected
            return (
                False  # Still consider incomplete, but with higher confidence in other validation
            )

        return False

    def _apply_network_environment_adjustments(
        self, confidence: float, network_environment: str, context: TlsHandshakeContext
    ) -> float:
        """Apply network environment-specific confidence adjustments."""
        if network_environment == "high_latency":
            # Be more lenient with high latency networks
            if context.completeness == HandshakeCompleteness.MISSING_SERVERHELLO:
                confidence = min(1.0, confidence + 0.1)

        elif network_environment == "unstable":
            # Reduce confidence for unstable networks
            confidence *= 0.9

        elif network_environment == "restricted":
            # Corporate environments may have different patterns
            if context.bypass_strategy_applied:
                confidence = min(1.0, confidence + 0.05)

        return confidence

    def _identify_potential_causes(
        self, context: TlsHandshakeContext, network_environment: Optional[str] = None
    ) -> List[str]:
        """Identify potential causes for handshake issues."""
        causes = []

        if context.completeness == HandshakeCompleteness.MISSING_SERVERHELLO:
            if context.bypass_strategy_applied:
                causes.extend(
                    [
                        "DPI bypass strategy may have fragmented or delayed ServerHello packets",
                        "Packet capture may have missed ServerHello due to timing changes",
                        "Bypass strategy may have caused packets to take different network path",
                    ]
                )
            else:
                causes.extend(
                    [
                        "Server may be using QUIC protocol instead of TLS",
                        "IPv6 traffic may be bypassing packet capture",
                        "Actual DPI blocking preventing ServerHello",
                        "Network latency or packet loss",
                    ]
                )

        if context.bypass_interference_detected:
            causes.extend(
                [
                    "High packet fragmentation due to bypass strategy",
                    "Out-of-order packet delivery caused by bypass routing",
                    "Timing disruption from bypass packet manipulation",
                ]
            )

        if len(context.timing_anomalies) > 0:
            causes.extend(
                [
                    "Network latency affecting handshake timing",
                    "Bypass strategy introducing timing delays",
                    "Server processing delays or load issues",
                ]
            )

        # Add network environment-specific causes
        if network_environment:
            causes.extend(self._get_environment_specific_causes(network_environment, context))

        return causes

    def _get_environment_specific_causes(
        self, network_environment: str, context: TlsHandshakeContext
    ) -> List[str]:
        """Get potential causes specific to network environment."""
        causes = []

        if network_environment == "high_latency":
            causes.extend(
                [
                    "Satellite or mobile network latency affecting handshake timing",
                    "Long-distance routing causing packet delays",
                    "Network congestion in high-latency environment",
                ]
            )

        elif network_environment == "unstable":
            causes.extend(
                [
                    "Network instability causing packet loss or reordering",
                    "WiFi interference or signal quality issues",
                    "Congested network infrastructure",
                ]
            )

        elif network_environment == "restricted":
            causes.extend(
                [
                    "Corporate firewall interference with TLS handshake",
                    "Proxy or gateway modifying packet flow",
                    "Network security policies affecting connections",
                ]
            )

        return causes

    def _generate_recommendations(
        self, context: TlsHandshakeContext, network_environment: Optional[str] = None
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        if context.completeness == HandshakeCompleteness.MISSING_SERVERHELLO:
            if context.bypass_strategy_applied:
                recommendations.extend(
                    [
                        "Consider adjusting bypass strategy parameters to reduce packet disruption",
                        "Verify packet capture is monitoring all network interfaces",
                        "Check if bypass strategy is causing packets to use different routes",
                    ]
                )
            else:
                recommendations.extend(
                    [
                        "Check if target site uses QUIC protocol",
                        "Verify IPv6 traffic is being captured",
                        "Test with different packet capture filters",
                        "Consider if this indicates actual blocking",
                    ]
                )

        if context.bypass_interference_detected:
            recommendations.extend(
                [
                    "Monitor packet capture during bypass strategy application",
                    "Consider using less aggressive bypass parameters",
                    "Verify bypass strategy is not causing excessive fragmentation",
                ]
            )

        if context.retransmission_count > 0:
            recommendations.extend(
                [
                    "Check network stability and latency",
                    "Consider if bypass strategy is too aggressive for current network",
                    "Monitor for consistent retransmission patterns",
                ]
            )

        # Add network environment-specific recommendations
        if network_environment:
            recommendations.extend(
                self._get_environment_specific_recommendations(network_environment)
            )

        return recommendations

    def _get_environment_specific_recommendations(self, network_environment: str) -> List[str]:
        """Get recommendations specific to network environment."""
        recommendations = []

        if network_environment == "high_latency":
            recommendations.extend(
                [
                    "Increase validation timeouts for high-latency networks",
                    "Consider using HTTP-only validation in satellite/mobile environments",
                    "Monitor for network environment changes during testing",
                ]
            )

        elif network_environment == "unstable":
            recommendations.extend(
                [
                    "Implement retry logic for unstable network conditions",
                    "Use multiple validation methods for cross-verification",
                    "Monitor network stability before making validation decisions",
                ]
            )

        elif network_environment == "restricted":
            recommendations.extend(
                [
                    "Check for corporate firewall or proxy configuration",
                    "Verify bypass strategies are compatible with network policies",
                    "Consider alternative validation approaches for restricted environments",
                ]
            )

        return recommendations
