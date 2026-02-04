"""
Validation Decision Engine for False Positive Validation Fix

This module implements the decision engine that combines HTTP and TLS analysis,
applies business logic for final validation decisions, and generates detailed
reasoning and troubleshooting hints.

Requirements: 4.3, 4.4, 5.1, 5.2
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum

from core.validation.http_response_classifier import (
    ResponseClassification,
    create_http_response_classifier,
)
from core.validation.tls_handshake_analyzer import (
    EnhancedTlsHandshakeAnalyzer,
    TlsAnalysisResult,
    HandshakeCompleteness,
)
from core.validation.edge_case_handler import (
    EdgeCaseContext,
    NetworkConditions,
    create_edge_case_handler,
)


class ValidationMethod(Enum):
    """Validation method selection."""

    HTTP_ONLY = "HTTP_ONLY"
    TLS_ONLY = "TLS_ONLY"
    COMBINED = "COMBINED"
    HTTP_PRIORITY = "HTTP_PRIORITY"  # HTTP takes precedence over TLS


@dataclass
class ValidationContext:
    """Context information for validation decision making."""

    http_response_code: int
    http_success: bool
    tls_handshake_complete: bool
    server_hello_count: int
    client_hello_count: int
    retransmission_count: int
    total_packets: int
    bypass_strategy_applied: bool
    pcap_analysis_available: bool
    network_timing_ms: float
    strategy_name: str = "unknown"


@dataclass
class ValidationDecision:
    """Final validation decision with detailed reasoning."""

    final_result: bool  # True = success, False = failure
    confidence_level: float  # 0.0 to 1.0
    primary_reason: str  # Main reason for decision
    contributing_factors: List[str] = field(default_factory=list)  # Additional factors
    troubleshooting_hints: List[str] = field(default_factory=list)  # Actionable advice
    validation_method: ValidationMethod = ValidationMethod.COMBINED
    http_classification: Optional[ResponseClassification] = None
    tls_analysis: Optional[TlsAnalysisResult] = None


class ValidationDecisionEngine:
    """
    Decision engine that combines HTTP and TLS analysis for final validation decisions.

    This engine implements business logic for determining validation success/failure,
    generates detailed reasoning for troubleshooting, and selects appropriate
    validation methods based on available data and context.

    Requirements: 4.3, 4.4, 5.1, 5.2
    """

    # Confidence thresholds for decision making
    HIGH_CONFIDENCE_THRESHOLD = 0.8
    MEDIUM_CONFIDENCE_THRESHOLD = 0.5

    # Retransmission thresholds
    RETRANSMISSION_THRESHOLD_PERCENT = 10.0
    STRICT_RETRANS_THRESHOLD_LOW_TRAFFIC = 1

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the validation decision engine."""
        self.logger = logger or logging.getLogger("ValidationDecisionEngine")
        self.http_classifier = create_http_response_classifier()
        self.tls_analyzer = EnhancedTlsHandshakeAnalyzer(logger)
        self.edge_case_handler = create_edge_case_handler(logger)

    def make_validation_decision(
        self, context: ValidationContext, telemetry: Optional[Dict[str, Any]] = None
    ) -> ValidationDecision:
        """
        Make final validation decision combining HTTP and TLS analysis with edge case handling.

        Requirements: 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 5.5

        Args:
            context: Validation context with all relevant information
            telemetry: Optional raw telemetry data for detailed analysis

        Returns:
            ValidationDecision with detailed reasoning and recommendations
        """
        self.logger.debug(
            "Making validation decision for strategy '%s', HTTP %d, bypass=%s",
            context.strategy_name,
            context.http_response_code,
            context.bypass_strategy_applied,
        )

        # Step 1: Analyze HTTP response
        http_classification = self.http_classifier.classify_response(context.http_response_code)

        # Step 2: Analyze TLS handshake if data available
        tls_analysis = None
        if context.pcap_analysis_available and telemetry:
            tls_analysis = self.tls_analyzer.analyze_handshake(
                telemetry, context.bypass_strategy_applied, context.network_timing_ms
            )

        # Step 3: Create edge case context for adaptive validation
        edge_case_context = self._create_edge_case_context(context, telemetry)

        # Step 4: Handle edge cases and network conditions
        edge_case_result = self._handle_edge_cases(
            edge_case_context, http_classification, tls_analysis, telemetry
        )

        # Step 5: Select validation method (considering edge case handling)
        validation_method = self._select_validation_method(
            context, http_classification, tls_analysis, edge_case_result
        )

        # Step 6: Apply business logic for final decision
        decision = self._apply_business_logic(
            context, http_classification, tls_analysis, validation_method
        )

        # Step 7: Apply edge case adjustments to confidence and reasoning
        self._apply_edge_case_adjustments(decision, edge_case_result, context)

        # Step 8: Generate detailed reasoning
        self._generate_detailed_reasoning(decision, context, http_classification, tls_analysis)

        # Step 9: Add troubleshooting hints (including edge case recommendations)
        self._add_troubleshooting_hints(
            decision, context, http_classification, tls_analysis, edge_case_result
        )

        self.logger.info(
            "Validation decision: %s (confidence=%.2f, method=%s) for strategy '%s'",
            "SUCCESS" if decision.final_result else "FAILURE",
            decision.confidence_level,
            decision.validation_method.value,
            context.strategy_name,
        )

        return decision

    def _create_edge_case_context(
        self, context: ValidationContext, telemetry: Optional[Dict[str, Any]] = None
    ) -> EdgeCaseContext:
        """Create edge case context from validation context and telemetry."""
        # Estimate network conditions from available data
        network_conditions = NetworkConditions(
            latency_ms=context.network_timing_ms,
            packet_loss_percent=self._estimate_packet_loss(context, telemetry),
            jitter_ms=self._estimate_jitter(telemetry),
            stability_score=self._calculate_stability_score(context, telemetry),
        )

        # Estimate PCAP completeness
        pcap_completeness = self._estimate_pcap_completeness(context, telemetry)

        # Estimate timing reliability
        timing_reliability = self._estimate_timing_reliability(context, telemetry)

        return EdgeCaseContext(
            network_conditions=network_conditions,
            pcap_completeness=pcap_completeness,
            timing_reliability=timing_reliability,
            bypass_strategy_complexity=self._assess_bypass_complexity(context.strategy_name),
            validation_timeout_ms=5000.0,  # Default timeout
            retry_count=0,
            max_retries=2,
        )

    def _handle_edge_cases(
        self,
        edge_case_context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification],
        tls_analysis: Optional[TlsAnalysisResult],
        telemetry: Optional[Dict[str, Any]],
    ) -> Optional[Any]:  # EdgeCaseHandlingResult
        """Handle various edge cases in validation."""
        # Handle network latency issues
        if (
            edge_case_context.network_conditions.latency_ms > 100.0
            or edge_case_context.network_conditions.packet_loss_percent > 2.0
        ):
            return self.edge_case_handler.handle_network_latency_issues(
                edge_case_context, http_classification, tls_analysis
            )

        # Handle partial TLS handshake
        if tls_analysis and tls_analysis.context.completeness != HandshakeCompleteness.COMPLETE:
            return self.edge_case_handler.handle_partial_tls_handshake(
                tls_analysis, edge_case_context, http_classification
            )

        # Handle incomplete PCAP data
        if edge_case_context.pcap_completeness < 0.7:
            return self.edge_case_handler.create_fallback_validation_methods(
                edge_case_context, http_classification, tls_analysis, telemetry
            )

        # Apply adaptive validation criteria
        return self.edge_case_handler.adapt_validation_criteria(
            edge_case_context, 0.5, True  # Default values
        )

    def _estimate_packet_loss(
        self, context: ValidationContext, telemetry: Optional[Dict[str, Any]]
    ) -> float:
        """Estimate packet loss percentage from available data."""
        if not telemetry or context.total_packets == 0:
            return 0.0

        return (context.retransmission_count / context.total_packets) * 100.0

    def _estimate_jitter(self, telemetry: Optional[Dict[str, Any]]) -> float:
        """Estimate network jitter from telemetry data."""
        # This is a simplified estimation - in practice, you'd analyze packet timing
        if not telemetry:
            return 0.0

        # Look for timing variations in telemetry
        timing_data = telemetry.get("timing_variations", [])
        if timing_data:
            return max(timing_data) - min(timing_data)

        return 0.0

    def _calculate_stability_score(
        self, context: ValidationContext, telemetry: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate network stability score (0.0 to 1.0)."""
        score = 1.0

        # Reduce score for high retransmissions
        if context.total_packets > 0:
            retrans_rate = context.retransmission_count / context.total_packets
            score *= 1.0 - min(retrans_rate, 0.5)  # Cap reduction at 50%

        # Reduce score for timing issues
        if context.network_timing_ms > 200.0:
            score *= 0.8

        # Reduce score for missing handshake components
        if context.client_hello_count == 0 or context.server_hello_count == 0:
            score *= 0.7

        return max(0.1, score)

    def _estimate_pcap_completeness(
        self, context: ValidationContext, telemetry: Optional[Dict[str, Any]]
    ) -> float:
        """Estimate PCAP data completeness (0.0 to 1.0)."""
        if not context.pcap_analysis_available:
            return 0.0

        completeness = 0.0

        # Check for basic handshake components
        if context.client_hello_count > 0:
            completeness += 0.3

        if context.server_hello_count > 0:
            completeness += 0.4

        # Check for reasonable packet count
        if context.total_packets > 5:
            completeness += 0.2

        # Check for low retransmission rate
        if context.total_packets > 0:
            retrans_rate = context.retransmission_count / context.total_packets
            if retrans_rate < 0.1:  # Less than 10% retransmissions
                completeness += 0.1

        return min(1.0, completeness)

    def _estimate_timing_reliability(
        self, context: ValidationContext, telemetry: Optional[Dict[str, Any]]
    ) -> float:
        """Estimate timing data reliability (0.0 to 1.0)."""
        reliability = 1.0

        # Reduce reliability for high latency
        if context.network_timing_ms > 500.0:
            reliability *= 0.5
        elif context.network_timing_ms > 200.0:
            reliability *= 0.8

        # Reduce reliability for bypass strategies that affect timing
        if context.bypass_strategy_applied:
            reliability *= 0.9

        # Reduce reliability for high retransmissions
        if context.total_packets > 0:
            retrans_rate = context.retransmission_count / context.total_packets
            reliability *= 1.0 - min(retrans_rate, 0.3)

        return max(0.1, reliability)

    def _assess_bypass_complexity(self, strategy_name: str) -> str:
        """Assess bypass strategy complexity based on name."""
        strategy_lower = strategy_name.lower()

        if any(term in strategy_lower for term in ["split", "fragment", "disorder"]):
            return "complex"
        elif any(term in strategy_lower for term in ["ttl", "fake", "disorder"]):
            return "moderate"
        else:
            return "simple"

    def _apply_edge_case_adjustments(
        self,
        decision: ValidationDecision,
        edge_case_result: Optional[Any],  # EdgeCaseHandlingResult
        context: ValidationContext,
    ) -> None:
        """Apply edge case handling adjustments to validation decision."""
        if not edge_case_result:
            return

        # Adjust confidence based on edge case analysis
        original_confidence = decision.confidence_level
        decision.confidence_level = min(
            decision.confidence_level, edge_case_result.adjusted_confidence
        )

        # Add edge case reasoning to primary reason
        if edge_case_result.reasoning:
            decision.primary_reason += f" {edge_case_result.reasoning}"

        # Add edge case recommendations
        if hasattr(edge_case_result, "recommendations"):
            decision.troubleshooting_hints.extend(edge_case_result.recommendations)

        # Add environment adaptations to contributing factors
        if hasattr(edge_case_result, "environment_adaptations"):
            decision.contributing_factors.extend(edge_case_result.environment_adaptations)

        self.logger.debug(
            "Edge case adjustments applied: confidence %.2f -> %.2f, method=%s",
            original_confidence,
            decision.confidence_level,
            (
                edge_case_result.fallback_method.value
                if hasattr(edge_case_result, "fallback_method")
                else "unknown"
            ),
        )

    def _select_validation_method(
        self,
        context: ValidationContext,
        http_classification: ResponseClassification,
        tls_analysis: Optional[TlsAnalysisResult],
        edge_case_result: Optional[Any] = None,  # EdgeCaseHandlingResult
    ) -> ValidationMethod:
        """
        Select appropriate validation method based on available data and context.

        Requirements: 4.4, 5.1, 5.2 - Implement validation method selection
        """
        # If no HTTP success, rely on TLS analysis
        if not context.http_success or context.http_response_code == 0:
            if context.pcap_analysis_available:
                return ValidationMethod.TLS_ONLY
            else:
                return ValidationMethod.HTTP_ONLY  # Fallback even for failures

        # If HTTP indicates success (200-399), prioritize HTTP
        if http_classification.is_success:
            if context.pcap_analysis_available and tls_analysis:
                # We have both - use HTTP priority method
                return ValidationMethod.HTTP_PRIORITY
            else:
                # Only HTTP available
                return ValidationMethod.HTTP_ONLY

        # HTTP indicates error (400+) - combine with TLS if available
        if context.pcap_analysis_available and tls_analysis:
            return ValidationMethod.COMBINED
        else:
            return ValidationMethod.HTTP_ONLY

    def _apply_business_logic(
        self,
        context: ValidationContext,
        http_classification: ResponseClassification,
        tls_analysis: Optional[TlsAnalysisResult],
        validation_method: ValidationMethod,
    ) -> ValidationDecision:
        """
        Apply business logic for final validation decision.

        Requirements: 4.3, 4.4 - Business logic for final validation decisions
        """
        decision = ValidationDecision(
            final_result=False,
            confidence_level=0.0,
            primary_reason="",
            validation_method=validation_method,
            http_classification=http_classification,
            tls_analysis=tls_analysis,
        )

        if validation_method == ValidationMethod.HTTP_ONLY:
            return self._decide_http_only(context, http_classification, decision)

        elif validation_method == ValidationMethod.TLS_ONLY:
            return self._decide_tls_only(context, tls_analysis, decision)

        elif validation_method == ValidationMethod.HTTP_PRIORITY:
            return self._decide_http_priority(context, http_classification, tls_analysis, decision)

        elif validation_method == ValidationMethod.COMBINED:
            return self._decide_combined(context, http_classification, tls_analysis, decision)

        else:
            # Fallback
            decision.final_result = False
            decision.confidence_level = 0.1
            decision.primary_reason = "Unknown validation method"
            return decision

    def _decide_http_only(
        self,
        context: ValidationContext,
        http_classification: ResponseClassification,
        decision: ValidationDecision,
    ) -> ValidationDecision:
        """Make decision based only on HTTP response."""
        if not context.http_success or context.http_response_code == 0:
            decision.final_result = False
            decision.confidence_level = 0.9
            decision.primary_reason = f"HTTP request failed (code {context.http_response_code})"
            return decision

        if http_classification.is_success:
            decision.final_result = True
            decision.confidence_level = http_classification.confidence
            decision.primary_reason = (
                f"HTTP {context.http_response_code} indicates successful communication"
            )
            return decision
        else:
            decision.final_result = False
            decision.confidence_level = 0.7
            decision.primary_reason = (
                f"HTTP {context.http_response_code} indicates communication failure"
            )
            return decision

    def _decide_tls_only(
        self,
        context: ValidationContext,
        tls_analysis: Optional[TlsAnalysisResult],
        decision: ValidationDecision,
    ) -> ValidationDecision:
        """Make decision based only on TLS analysis."""
        if not tls_analysis:
            decision.final_result = False
            decision.confidence_level = 0.2
            decision.primary_reason = "No TLS analysis available and HTTP failed"
            return decision

        # Check for no traffic scenario
        if context.client_hello_count == 0 and context.server_hello_count == 0:
            decision.final_result = False
            decision.confidence_level = 0.9
            decision.primary_reason = "No network traffic captured - configuration issue"
            return decision

        # Check retransmissions
        if self._has_high_retransmissions(context):
            decision.final_result = False
            decision.confidence_level = 0.8
            decision.primary_reason = "High packet loss detected"
            return decision

        # Use TLS handshake completeness
        if tls_analysis.handshake_complete:
            decision.final_result = True
            decision.confidence_level = tls_analysis.confidence
            decision.primary_reason = "Complete TLS handshake detected"
        else:
            decision.final_result = False
            decision.confidence_level = tls_analysis.confidence
            decision.primary_reason = "Incomplete TLS handshake"

        return decision

    def _decide_http_priority(
        self,
        context: ValidationContext,
        http_classification: ResponseClassification,
        tls_analysis: Optional[TlsAnalysisResult],
        decision: ValidationDecision,
    ) -> ValidationDecision:
        """
        Make decision prioritizing HTTP success over TLS analysis.

        This is the key method for fixing false positives where HTTP succeeds
        but TLS analysis is incomplete.
        """
        # HTTP success takes priority
        if http_classification.is_success:
            decision.final_result = True

            # Adjust confidence based on TLS analysis
            base_confidence = http_classification.confidence

            if tls_analysis and tls_analysis.handshake_complete:
                # Both HTTP and TLS success - highest confidence
                decision.confidence_level = min(1.0, base_confidence + 0.1)
                decision.primary_reason = (
                    f"HTTP {context.http_response_code} success with complete TLS handshake"
                )

            elif tls_analysis and not tls_analysis.handshake_complete:
                # HTTP success but incomplete TLS - this is our target scenario
                if context.bypass_strategy_applied:
                    # Bypass strategy explains TLS issues - maintain good confidence
                    decision.confidence_level = max(0.7, base_confidence * 0.9)
                    decision.primary_reason = f"HTTP {context.http_response_code} success (TLS incomplete due to bypass strategy)"
                else:
                    # No bypass strategy - slightly lower confidence but still success
                    decision.confidence_level = max(0.6, base_confidence * 0.8)
                    decision.primary_reason = f"HTTP {context.http_response_code} success (TLS incomplete - likely QUIC or IPv6)"

            else:
                # No TLS analysis available - rely on HTTP
                decision.confidence_level = base_confidence
                decision.primary_reason = (
                    f"HTTP {context.http_response_code} success (no TLS analysis available)"
                )

            return decision

        # HTTP not successful - fall back to combined analysis
        return self._decide_combined(context, http_classification, tls_analysis, decision)

    def _decide_combined(
        self,
        context: ValidationContext,
        http_classification: ResponseClassification,
        tls_analysis: Optional[TlsAnalysisResult],
        decision: ValidationDecision,
    ) -> ValidationDecision:
        """Make decision combining HTTP and TLS analysis."""
        # Check for no traffic scenario first
        if context.client_hello_count == 0 and context.server_hello_count == 0:
            decision.final_result = False
            decision.confidence_level = 0.9
            decision.primary_reason = "No network traffic captured - configuration issue"
            return decision

        # Check retransmissions
        if self._has_high_retransmissions(context):
            decision.final_result = False
            decision.confidence_level = 0.8
            decision.primary_reason = "High packet loss detected"
            return decision

        # Combine HTTP and TLS signals
        http_success = http_classification.is_success
        tls_success = tls_analysis.handshake_complete if tls_analysis else False

        if http_success and tls_success:
            # Both indicate success
            decision.final_result = True
            decision.confidence_level = min(
                1.0, (http_classification.confidence + tls_analysis.confidence) / 2
            )
            decision.primary_reason = (
                f"Both HTTP {context.http_response_code} and TLS handshake successful"
            )

        elif http_success and not tls_success:
            # HTTP success but TLS failure - ambiguous
            decision.final_result = True  # Lean towards success due to HTTP
            decision.confidence_level = 0.6
            decision.primary_reason = (
                f"HTTP {context.http_response_code} success but incomplete TLS handshake"
            )

        elif not http_success and tls_success:
            # TLS success but HTTP failure - likely server error
            decision.final_result = False
            decision.confidence_level = 0.7
            decision.primary_reason = (
                f"TLS handshake complete but HTTP {context.http_response_code} error"
            )

        else:
            # Both indicate failure
            decision.final_result = False
            decision.confidence_level = 0.8
            decision.primary_reason = (
                f"Both HTTP {context.http_response_code} and TLS handshake failed"
            )

        return decision

    def _has_high_retransmissions(self, context: ValidationContext) -> bool:
        """Check if retransmission rate is too high."""
        if context.total_packets == 0:
            return False

        # Strict check for low traffic
        if (
            context.total_packets < 10
            and context.retransmission_count > self.STRICT_RETRANS_THRESHOLD_LOW_TRAFFIC
        ):
            return True

        # Percentage check for higher traffic
        retrans_percent = (context.retransmission_count / context.total_packets) * 100
        return retrans_percent > self.RETRANSMISSION_THRESHOLD_PERCENT

    def _generate_detailed_reasoning(
        self,
        decision: ValidationDecision,
        context: ValidationContext,
        http_classification: ResponseClassification,
        tls_analysis: Optional[TlsAnalysisResult],
    ) -> None:
        """
        Generate detailed reasoning for validation decision.

        Requirements: 4.1, 4.2, 4.3 - Detailed reasoning generation
        """
        reasoning_parts = [decision.primary_reason]

        # Add HTTP analysis details
        if http_classification:
            if http_classification.is_redirect:
                reasoning_parts.append(
                    f"HTTP redirect ({http_classification.redirect_type.value if http_classification.redirect_type else 'unknown'}) "
                    f"indicates server is responding normally."
                )
            elif http_classification.category.value == "success":
                reasoning_parts.append(
                    "HTTP success code confirms successful server communication."
                )
            elif http_classification.category.value in ["client_error", "server_error"]:
                reasoning_parts.append(
                    f"HTTP {http_classification.category.value} may indicate blocking or server issues."
                )

        # Add TLS analysis details
        if tls_analysis:
            reasoning_parts.append(f"TLS analysis: {tls_analysis.bypass_aware_assessment}")

            if tls_analysis.context.bypass_interference_detected:
                reasoning_parts.append("Bypass strategy interference detected in packet flow.")

            if len(tls_analysis.context.timing_anomalies) > 0:
                reasoning_parts.append(
                    f"Timing anomalies detected: {', '.join(tls_analysis.context.timing_anomalies[:2])}"
                )

        # Add bypass strategy context
        if context.bypass_strategy_applied:
            reasoning_parts.append(
                "DPI bypass strategy was applied, which may affect packet capture and timing."
            )

        # Add confidence explanation
        if decision.confidence_level >= self.HIGH_CONFIDENCE_THRESHOLD:
            reasoning_parts.append("High confidence in this assessment.")
        elif decision.confidence_level >= self.MEDIUM_CONFIDENCE_THRESHOLD:
            reasoning_parts.append("Medium confidence - some ambiguity in the data.")
        else:
            reasoning_parts.append("Low confidence - conflicting or insufficient data.")

        decision.primary_reason = " ".join(reasoning_parts)

        # Add contributing factors
        if http_classification:
            if http_classification.is_success:
                decision.contributing_factors.append(f"HTTP {context.http_response_code} success")
            else:
                decision.contributing_factors.append(
                    f"HTTP {context.http_response_code} {http_classification.category.value}"
                )

        if tls_analysis:
            if tls_analysis.handshake_complete:
                decision.contributing_factors.append("Complete TLS handshake")
            else:
                decision.contributing_factors.append("Incomplete TLS handshake")

        if context.bypass_strategy_applied:
            decision.contributing_factors.append("DPI bypass strategy applied")

        if context.retransmission_count > 0:
            decision.contributing_factors.append(
                f"{context.retransmission_count} packet retransmissions"
            )

    def _add_troubleshooting_hints(
        self,
        decision: ValidationDecision,
        context: ValidationContext,
        http_classification: ResponseClassification,
        tls_analysis: Optional[TlsAnalysisResult],
        edge_case_result: Optional[Any] = None,  # EdgeCaseHandlingResult
    ) -> None:
        """
        Add actionable troubleshooting hints.

        Requirements: 4.1, 4.2, 4.3 - Actionable troubleshooting information
        """
        hints = []

        # HTTP-specific hints
        if not context.http_success or context.http_response_code == 0:
            hints.extend(
                [
                    "Check if target domain is accessible without bypass",
                    "Verify network connectivity and DNS resolution",
                    "Consider if domain is actually blocked",
                ]
            )

        if http_classification and http_classification.is_redirect:
            hints.extend(
                [
                    "Redirect responses typically indicate accessible domains",
                    "Consider if this is an HTTP to HTTPS redirect",
                    "Check if redirect target is the intended destination",
                ]
            )
        elif 400 <= context.http_response_code < 500:
            # Client errors
            hints.extend(
                [
                    "HTTP client errors may indicate partial blocking or access restrictions",
                    "Try accessing different pages on the same domain",
                    "Check if authentication or specific headers are required",
                ]
            )
        elif context.http_response_code >= 500:
            # Server errors
            hints.extend(
                [
                    "HTTP server errors are ambiguous for bypass validation",
                    "Server may be temporarily unavailable or overloaded",
                    "Retry test to check for consistency",
                    "Consider testing different endpoints on same domain",
                ]
            )

        # TLS-specific hints
        if tls_analysis:
            hints.extend(tls_analysis.recommendations)

            if not tls_analysis.handshake_complete:
                if context.bypass_strategy_applied:
                    hints.extend(
                        [
                            "Missing TLS data with bypass strategy is often expected",
                            "Consider adjusting bypass parameters if needed",
                            "Verify bypass strategy is appropriate for target",
                        ]
                    )
                else:
                    hints.extend(
                        [
                            "Check if target uses QUIC protocol instead of TLS",
                            "Verify IPv6 traffic is being captured",
                            "Consider if packet capture covers all interfaces",
                        ]
                    )

        # General troubleshooting
        if context.total_packets == 0:
            hints.extend(
                [
                    "No packets captured - check WinDivert configuration",
                    "Verify target IP matches packet filter",
                    "Ensure test traffic goes through monitored interface",
                ]
            )

        if self._has_high_retransmissions(context):
            hints.extend(
                [
                    "High packet loss may indicate network issues",
                    "Check if bypass strategy is too aggressive",
                    "Monitor network stability during testing",
                ]
            )

        # Confidence-based hints
        if decision.confidence_level < self.MEDIUM_CONFIDENCE_THRESHOLD:
            hints.extend(
                [
                    "Low confidence suggests ambiguous results",
                    "Consider retesting with different parameters",
                    "Manual verification may be needed",
                ]
            )

        decision.troubleshooting_hints = hints


def create_validation_decision_engine(
    logger: Optional[logging.Logger] = None,
) -> ValidationDecisionEngine:
    """
    Factory function for creating ValidationDecisionEngine instances.

    Args:
        logger: Optional logger instance

    Returns:
        Configured ValidationDecisionEngine instance
    """
    return ValidationDecisionEngine(logger)
