# core/bypass/validation/validator.py
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import logging

# Import HTTP response classifier for enhanced validation
from core.validation.http_response_classifier import (
    HttpResponseClassifier,
    ResponseCategory,
    create_http_response_classifier,
)

# Import edge case handler for adaptive validation
from core.validation.edge_case_handler import (
    EdgeCaseHandler,
    EdgeCaseContext,
    NetworkConditions,
    create_edge_case_handler,
)


@dataclass
class ValidationResult:
    """Результат валидации стратегии"""

    success: bool
    status: str
    error: Optional[str] = None
    metrics: Dict[str, int] = field(default_factory=dict)
    confidence: float = 1.0  # Confidence level (0.0 to 1.0)
    reasoning: str = ""  # Detailed reasoning for validation decision
    troubleshooting_hints: List[str] = field(default_factory=list)  # Actionable advice
    validation_method: str = "COMBINED"  # HTTP_ONLY, TLS_ONLY, COMBINED

    def _is_successful_redirect(self, response_code: int, has_server_hello: bool) -> bool:
        """
        Determine if an HTTP redirect indicates successful access rather than blocking.

        Args:
            response_code: HTTP response code
            has_server_hello: Whether ServerHello was found in PCAP

        Returns:
            True if this appears to be successful access with redirect
        """
        # HTTP 302 with ServerHello indicates successful connection with redirect
        if response_code == 302 and has_server_hello:
            return True

        # Other successful redirect codes
        if response_code in [301, 303, 307, 308] and has_server_hello:
            return True

        # Even without ServerHello, some redirects indicate access
        # (e.g., HTTP to HTTPS redirects)
        if response_code in [301, 302] and not has_server_hello:
            # This might be an HTTP to HTTPS redirect - not a block
            return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "status": self.status,
            "error": self.error,
            "metrics": self.metrics,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "troubleshooting_hints": self.troubleshooting_hints,
            "validation_method": self.validation_method,
        }


class StrategyResultValidator:
    """
    Централизованная валидация результатов тестирования стратегий.
    Решает проблему дублирования логики и "плавающих" критериев успеха.
    """

    # Пороги валидации
    # Допускаем до 10% ретрансмиссий (для плохих сетей), но не более
    RETRANSMISSION_THRESHOLD_PERCENT: float = 10.0
    # Если пакетов мало (например < 5), то даже 1 ретрансмиссия критична
    STRICT_RETRANS_THRESHOLD_LOW_TRAFFIC: int = 1

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("StrategyValidator")
        self.http_classifier = create_http_response_classifier()
        self.edge_case_handler = create_edge_case_handler(logger)

    def validate(
        self,
        http_success: bool,
        http_code: int,
        telemetry: Dict[str, Any],
        strategy_name: str = "unknown",
        network_timing_ms: float = 0.0,
    ) -> ValidationResult:
        """
        Enhanced validation with edge case handling and adaptive criteria.

        Requirements: 1.5, 4.1, 4.2, 4.4, 5.1, 5.2, 5.3, 5.4, 5.5

        Args:
            http_success: Whether HTTP request succeeded (curl/aiohttp returned 200-599)
            http_code: HTTP status code
            telemetry: Telemetry snapshot from engine (WinDivert)
            strategy_name: Strategy name for logging
            network_timing_ms: Network timing for edge case analysis

        Returns:
            ValidationResult with enhanced reasoning and confidence scoring
        """
        metrics = self._extract_metrics(telemetry)

        # Step 1: Classify HTTP response for intelligent validation
        http_classification = self.http_classifier.classify_response(http_code)

        # Step 2: Create edge case context for adaptive validation
        edge_case_context = self._create_edge_case_context(
            metrics, telemetry, network_timing_ms, strategy_name
        )

        # Step 3: Basic HTTP failure check with edge case considerations
        if not http_success or http_code == 0:
            result = self._create_http_failure_result(http_code, metrics, strategy_name)
            return self._apply_edge_case_adjustments(result, edge_case_context, http_classification)

        # Step 4: Enhanced validation logic with edge case handling
        if http_classification.is_success:
            result = self._validate_http_success_scenario(
                http_code, http_classification, metrics, strategy_name
            )
        else:
            result = self._validate_http_error_scenario(
                http_code, http_classification, metrics, strategy_name
            )

        # Step 5: Apply edge case adjustments to final result
        return self._apply_edge_case_adjustments(result, edge_case_context, http_classification)

    def _create_http_failure_result(
        self, http_code: int, metrics: Dict[str, int], strategy_name: str
    ) -> ValidationResult:
        """Create result for HTTP-level failures."""
        reasoning = f"HTTP request failed with code {http_code}. "
        troubleshooting = []

        if http_code == 0:
            reasoning += "No HTTP response received - likely connection refused or timeout."
            troubleshooting.extend(
                [
                    "Check if target domain is accessible",
                    "Verify network connectivity",
                    "Check if domain is actually blocked",
                ]
            )
        elif 400 <= http_code < 500:
            reasoning += "Client error - may indicate blocking or access restrictions."
            troubleshooting.extend(
                [
                    "Check if domain requires authentication",
                    "Verify request format and headers",
                    "Consider if this is legitimate blocking",
                ]
            )
        elif http_code >= 500:
            reasoning += "Server error - ambiguous for bypass validation."
            troubleshooting.extend(
                [
                    "Server may be temporarily unavailable",
                    "Could indicate partial blocking or server issues",
                    "Retry test to confirm consistency",
                ]
            )

        return ValidationResult(
            success=False,
            status="HTTP_FAILED",
            error=f"HTTP request failed (code {http_code})",
            metrics=metrics,
            confidence=0.9,
            reasoning=reasoning,
            troubleshooting_hints=troubleshooting,
            validation_method="HTTP_ONLY",
        )

    def _validate_http_success_scenario(
        self, http_code: int, http_classification, metrics: Dict[str, int], strategy_name: str
    ) -> ValidationResult:
        """
        Validate scenarios where HTTP indicates success (200-399).

        Requirements: 1.1, 1.2, 1.3, 1.4 - Prioritize HTTP success over PCAP analysis
        """
        server_hellos = metrics["server_hellos"]
        client_hellos = metrics["client_hellos"]

        # Check for no traffic scenario first
        if client_hellos == 0 and server_hellos == 0:
            return self._create_no_traffic_result(http_code, metrics, strategy_name)

        # For HTTP success codes, we prioritize HTTP-level success
        # but still provide detailed analysis of PCAP data

        if server_hellos == 0 and client_hellos > 0:
            # This is the classic "false positive" scenario we're fixing
            # HTTP success + ClientHello but no ServerHello
            return self._handle_missing_serverhello_with_http_success(
                http_code, http_classification, metrics, strategy_name
            )

        # Check for retransmission issues even with HTTP success
        retrans_result = self._check_retransmissions(metrics, strategy_name)
        if retrans_result is not None:
            # High retransmissions detected, but HTTP success is the primary signal.
            # Mark as success with degraded confidence instead of hard-fail.
            retrans_result.success = True
            retrans_result.status = "SUCCESS_WITH_RETRANSMISSIONS"
            retrans_result.error = None
            retrans_result.reasoning += (
                f" However, HTTP {http_code} indicates successful communication."
            )
            retrans_result.confidence = min(retrans_result.confidence, 0.6)
            retrans_result.troubleshooting_hints.append(
                "High retransmissions detected, but HTTP success suggests bypass is working (degraded quality)"
            )
            retrans_result.validation_method = "HTTP_PRIORITY"
            return retrans_result

        # All checks passed - successful validation
        return self._create_success_result(http_code, http_classification, metrics, strategy_name)

    def _handle_missing_serverhello_with_http_success(
        self, http_code: int, http_classification, metrics: Dict[str, int], strategy_name: str
    ) -> ValidationResult:
        """
        Handle the key scenario: HTTP success but missing ServerHello.

        Requirements: 1.5, 4.5, 5.3 - Intelligent false positive detection
        """
        reasoning = f"HTTP {http_code} ({http_classification.description}) indicates successful communication. "

        if http_classification.is_redirect:
            # Redirects are particularly likely to be legitimate
            reasoning += "Redirect responses typically indicate server is accessible and responding normally. "
            reasoning += "Missing ServerHello may be due to QUIC usage, HTTP-only redirect, or IPv6 leakage. "

            # For redirects, we lean towards success with medium confidence
            return ValidationResult(
                success=True,
                status="HTTP_SUCCESS_REDIRECT",
                error=None,
                metrics=metrics,
                confidence=0.8,
                reasoning=reasoning + "Prioritizing HTTP-level success over PCAP analysis.",
                troubleshooting_hints=[
                    "Consider if this is an HTTP to HTTPS redirect",
                    "Check if site uses QUIC protocol",
                    "Verify IPv6 traffic is not bypassing capture",
                    "This is likely legitimate access, not blocking",
                ],
                validation_method="HTTP_PRIORITY",
            )
        else:
            # Regular success codes (200, 201, etc.)
            reasoning += "Success response indicates server communication established. "
            reasoning += "Missing ServerHello suggests traffic may have bypassed TLS capture. "

            # For success codes, we still lean towards success but with slightly lower confidence
            return ValidationResult(
                success=True,
                status="HTTP_SUCCESS_NO_TLS",
                error=None,
                metrics=metrics,
                confidence=0.7,
                reasoning=reasoning + "HTTP success takes priority over incomplete PCAP data.",
                troubleshooting_hints=[
                    "Check if application uses QUIC instead of TLS",
                    "Verify packet capture covers all network interfaces",
                    "Consider if IPv6 traffic is being missed",
                    "HTTP success strongly suggests site is accessible",
                ],
                validation_method="HTTP_PRIORITY",
            )

    def _validate_http_error_scenario(
        self, http_code: int, http_classification, metrics: Dict[str, int], strategy_name: str
    ) -> ValidationResult:
        """Validate scenarios where HTTP indicates error (400+)."""
        # For error codes, we rely more on PCAP analysis
        server_hellos = metrics["server_hellos"]
        client_hellos = metrics["client_hellos"]

        if client_hellos == 0 and server_hellos == 0:
            return self._create_no_traffic_result(http_code, metrics, strategy_name)

        # Check retransmissions
        retrans_result = self._check_retransmissions(metrics, strategy_name)
        if retrans_result is not None:
            return retrans_result

        # HTTP error with TLS handshake - ambiguous result
        reasoning = (
            f"HTTP {http_code} ({http_classification.description}) with TLS handshake detected. "
        )

        if 400 <= http_code < 500:
            reasoning += "Client error may indicate blocking or access restrictions."
            confidence = 0.6  # Ambiguous - could be blocking or legitimate error
            troubleshooting = [
                "Client errors may indicate partial blocking",
                "Check if error is consistent across different requests",
                "Consider if authentication or specific headers are required",
            ]
        else:  # 500+ errors
            reasoning += "Server error is ambiguous for bypass validation."
            confidence = 0.4  # Very ambiguous
            troubleshooting = [
                "Server errors don't clearly indicate blocking",
                "Retry test to check for consistency",
                "Consider testing different endpoints on same domain",
            ]

        return ValidationResult(
            success=False,
            status="HTTP_ERROR_WITH_TLS",
            error=f"HTTP error {http_code} with TLS handshake",
            metrics=metrics,
            confidence=confidence,
            reasoning=reasoning,
            troubleshooting_hints=troubleshooting,
            validation_method="COMBINED",
        )

    def _create_no_traffic_result(
        self, http_code: int, metrics: Dict[str, int], strategy_name: str
    ) -> ValidationResult:
        """Create result for no traffic scenarios."""
        self.logger.warning(
            f"⚠️ [{strategy_name}] NO TRAFFIC: Engine saw 0 packets. Check IP/Filter."
        )

        return ValidationResult(
            success=False,
            status="NO_TRAFFIC_SEEN",
            error="Engine captured 0 packets (Test configuration error)",
            metrics=metrics,
            confidence=0.9,
            reasoning="No network traffic captured by engine. This indicates a configuration issue rather than blocking.",
            troubleshooting_hints=[
                "Check if target IP matches packet filter",
                "Verify WinDivert is capturing on correct interface",
                "Ensure test traffic is going through monitored path",
                "Check if domain resolves to expected IP address",
            ],
            validation_method="TLS_ONLY",
        )

    def _check_retransmissions(
        self, metrics: Dict[str, int], strategy_name: str
    ) -> Optional[ValidationResult]:
        """Check for high retransmission rates."""
        retrans = metrics["retransmissions"]
        total = metrics["total_packets"]

        if total == 0:
            return None

        retrans_percent = (retrans / total) * 100

        # Strict check for low traffic
        if total < 10 and retrans > self.STRICT_RETRANS_THRESHOLD_LOW_TRAFFIC:
            self.logger.warning(
                f"⚠️ [{strategy_name}] HIGH LOSS (Low Traffic): {retrans}/{total} packets lost."
            )
            return ValidationResult(
                success=False,
                status="HIGH_RETRANSMISSIONS",
                error=f"Packet loss detected ({retrans} retransmissions)",
                metrics=metrics,
                confidence=0.8,
                reasoning=f"High packet loss detected: {retrans} retransmissions out of {total} total packets. This may indicate network issues or DPI interference.",
                troubleshooting_hints=[
                    "High packet loss may indicate DPI interference",
                    "Check network stability and latency",
                    "Consider if bypass strategy is too aggressive",
                    "Retry test to confirm consistency",
                ],
                validation_method="TLS_ONLY",
            )

        # Percentage check for higher traffic
        if retrans_percent > self.RETRANSMISSION_THRESHOLD_PERCENT:
            self.logger.warning(
                f"⚠️ [{strategy_name}] HIGH LOSS: {retrans_percent:.1f}% ({retrans}/{total})"
            )
            return ValidationResult(
                success=False,
                status="HIGH_RETRANSMISSIONS",
                error=f"High packet loss: {retrans_percent:.1f}%",
                metrics=metrics,
                confidence=0.7,
                reasoning=f"Retransmission rate of {retrans_percent:.1f}% exceeds threshold of {self.RETRANSMISSION_THRESHOLD_PERCENT}%. This suggests network issues or DPI interference.",
                troubleshooting_hints=[
                    f"Retransmission rate ({retrans_percent:.1f}%) is above threshold",
                    "Check if bypass strategy is causing connection instability",
                    "Monitor network conditions during testing",
                    "Consider adjusting strategy parameters",
                ],
                validation_method="TLS_ONLY",
            )

        return None

    def _create_success_result(
        self, http_code: int, http_classification, metrics: Dict[str, int], strategy_name: str
    ) -> ValidationResult:
        """Create successful validation result."""
        reasoning = (
            f"HTTP {http_code} ({http_classification.description}) with complete TLS handshake. "
        )
        reasoning += "All validation checks passed successfully."

        return ValidationResult(
            success=True,
            status="SUCCESS",
            error=None,
            metrics=metrics,
            confidence=1.0,
            reasoning=reasoning,
            troubleshooting_hints=[],
            validation_method="COMBINED",
        )

    def _extract_metrics(self, telemetry: Dict[str, Any]) -> Dict[str, int]:
        """Безопасное извлечение метрик из телеметрии."""
        # Поддержка разных форматов телеметрии (aggregate или flat)
        agg = telemetry.get("aggregate", {})

        # Support both underscore and non-underscore formats
        server_hellos = telemetry.get(
            "server_hellos", telemetry.get("serverhellos", agg.get("serverhellos", 0))
        )
        client_hellos = telemetry.get(
            "client_hellos", telemetry.get("clienthellos", agg.get("clienthellos", 0))
        )

        # Ретрансмиссии могут быть в корне или в unified_engine
        retrans = telemetry.get(
            "retransmissions",
            telemetry.get(
                "total_retransmissions_detected", getattr(telemetry, "_retransmission_count", 0)
            ),
        )

        # Общее число пакетов (приблизительно)
        total = telemetry.get("total_packets", telemetry.get("packets_captured", 0))
        if total == 0:
            # Пытаемся восстановить по сегментам
            total = agg.get("segments_sent", 0) + server_hellos + client_hellos

        return {
            "client_hellos": client_hellos,
            "server_hellos": server_hellos,
            "retransmissions": retrans,
            "total_packets": total,
        }

    def _create_edge_case_context(
        self,
        metrics: Dict[str, int],
        telemetry: Dict[str, Any],
        network_timing_ms: float,
        strategy_name: str,
    ) -> EdgeCaseContext:
        """Create edge case context for adaptive validation."""
        # Estimate network conditions
        packet_loss_percent = 0.0
        if metrics["total_packets"] > 0:
            packet_loss_percent = (metrics["retransmissions"] / metrics["total_packets"]) * 100.0

        network_conditions = NetworkConditions(
            latency_ms=network_timing_ms,
            packet_loss_percent=packet_loss_percent,
            jitter_ms=self._estimate_jitter(telemetry),
            stability_score=self._calculate_stability_score(metrics, telemetry),
        )

        # Estimate PCAP completeness
        pcap_completeness = self._estimate_pcap_completeness(metrics)

        # Estimate timing reliability
        timing_reliability = self._estimate_timing_reliability(network_timing_ms, metrics)

        return EdgeCaseContext(
            network_conditions=network_conditions,
            pcap_completeness=pcap_completeness,
            timing_reliability=timing_reliability,
            bypass_strategy_complexity=self._assess_bypass_complexity(strategy_name),
            validation_timeout_ms=5000.0,
            retry_count=0,
            max_retries=2,
        )

    def _estimate_jitter(self, telemetry: Dict[str, Any]) -> float:
        """Estimate network jitter from telemetry."""
        # Simplified jitter estimation
        timing_variations = telemetry.get("timing_variations", [])
        if timing_variations and len(timing_variations) > 1:
            return max(timing_variations) - min(timing_variations)
        return 0.0

    def _calculate_stability_score(
        self, metrics: Dict[str, int], telemetry: Dict[str, Any]
    ) -> float:
        """Calculate network stability score."""
        score = 1.0

        # Reduce score for high retransmissions
        if metrics["total_packets"] > 0:
            retrans_rate = metrics["retransmissions"] / metrics["total_packets"]
            score *= 1.0 - min(retrans_rate, 0.5)

        # Reduce score for missing handshake components
        if metrics["client_hellos"] == 0 or metrics["server_hellos"] == 0:
            score *= 0.7

        return max(0.1, score)

    def _estimate_pcap_completeness(self, metrics: Dict[str, int]) -> float:
        """Estimate PCAP data completeness."""
        completeness = 0.0

        if metrics["client_hellos"] > 0:
            completeness += 0.3

        if metrics["server_hellos"] > 0:
            completeness += 0.4

        if metrics["total_packets"] > 5:
            completeness += 0.2

        if metrics["total_packets"] > 0:
            retrans_rate = metrics["retransmissions"] / metrics["total_packets"]
            if retrans_rate < 0.1:
                completeness += 0.1

        return min(1.0, completeness)

    def _estimate_timing_reliability(
        self, network_timing_ms: float, metrics: Dict[str, int]
    ) -> float:
        """Estimate timing data reliability."""
        reliability = 1.0

        if network_timing_ms > 500.0:
            reliability *= 0.5
        elif network_timing_ms > 200.0:
            reliability *= 0.8

        if metrics["total_packets"] > 0:
            retrans_rate = metrics["retransmissions"] / metrics["total_packets"]
            reliability *= 1.0 - min(retrans_rate, 0.3)

        return max(0.1, reliability)

    def _assess_bypass_complexity(self, strategy_name: str) -> str:
        """Assess bypass strategy complexity."""
        strategy_lower = strategy_name.lower()

        if any(term in strategy_lower for term in ["split", "fragment", "disorder"]):
            return "complex"
        elif any(term in strategy_lower for term in ["ttl", "fake"]):
            return "moderate"
        else:
            return "simple"

    def _apply_edge_case_adjustments(
        self, result: ValidationResult, edge_case_context: EdgeCaseContext, http_classification
    ) -> ValidationResult:
        """Apply edge case handling adjustments to validation result."""
        # Handle network latency issues
        if (
            edge_case_context.network_conditions.latency_ms > 100.0
            or edge_case_context.network_conditions.packet_loss_percent > 2.0
        ):

            edge_result = self.edge_case_handler.handle_network_latency_issues(
                edge_case_context, http_classification
            )

            # Adjust confidence and add recommendations
            result.confidence = min(result.confidence, edge_result.adjusted_confidence)
            result.reasoning += f" {edge_result.reasoning}"
            result.troubleshooting_hints.extend(edge_result.recommendations)

        # Handle incomplete PCAP data
        if edge_case_context.pcap_completeness < 0.7:
            edge_result = self.edge_case_handler.create_fallback_validation_methods(
                edge_case_context, http_classification
            )

            # Update validation method and add recommendations
            result.validation_method = edge_result.fallback_method.value
            result.troubleshooting_hints.extend(edge_result.recommendations)

        # Apply adaptive validation criteria
        adapt_result = self.edge_case_handler.adapt_validation_criteria(
            edge_case_context, result.confidence, result.success
        )

        # Final confidence adjustment
        result.confidence = min(result.confidence, adapt_result.adjusted_confidence)

        # Add environment adaptations to reasoning
        if (
            hasattr(adapt_result, "environment_adaptations")
            and adapt_result.environment_adaptations
        ):
            result.reasoning += (
                f" Environment adaptations: {', '.join(adapt_result.environment_adaptations)}."
            )

        return result
