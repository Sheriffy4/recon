from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, TypedDict, Protocol
from enum import Enum
from decimal import Decimal

"""
Edge Case Handler for False Positive Validation Fix

This module implements graceful handling of network latency, timing issues,
partial TLS handshake validation, fallback validation methods for incomplete
PCAP data, and adaptive validation criteria for different network environments.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

try:
    # Optional runtime dependencies (project may ship subsets).
    from core.validation.http_response_classifier import ResponseClassification  # type: ignore
except Exception:  # pragma: no cover
    ResponseClassification = Any  # type: ignore[misc,assignment]

try:
    from core.validation.tls_handshake_analyzer import (  # type: ignore
        TlsAnalysisResult,
        HandshakeCompleteness,
    )
except Exception:  # pragma: no cover
    TlsAnalysisResult = Any  # type: ignore[misc,assignment]

    class HandshakeCompleteness(Enum):  # type: ignore[no-redef]
        COMPLETE = "complete"
        PARTIAL = "partial"
        MISSING_SERVERHELLO = "missing_serverhello"
        UNKNOWN = "unknown"


class NetworkEnvironment(Enum):
    """Types of network environments with different validation criteria."""

    HIGH_LATENCY = "high_latency"  # Satellite, mobile networks
    UNSTABLE = "unstable"  # Congested networks, poor WiFi
    RESTRICTED = "restricted"  # Corporate firewalls, proxies
    NORMAL = "normal"  # Standard broadband
    UNKNOWN = "unknown"  # Cannot determine environment


class ValidationFallbackMethod(Enum):
    """Available fallback validation methods."""

    HTTP_ONLY = "http_only"
    TIMING_BASED = "timing_based"
    PARTIAL_TLS = "partial_tls"
    HEURISTIC = "heuristic"
    MINIMAL = "minimal"


# Type definitions for better type safety
class TelemetryData(TypedDict, total=False):
    """Type definition for telemetry data."""
    total_packets: int
    retransmissions: int
    timing_variations: List[float]
    client_hellos: int
    server_hellos: int


class HandshakeAssessment(TypedDict):
    """Type definition for handshake assessment."""
    has_client_hello: bool
    has_server_hello: bool
    handshake_ratio: float
    completeness_level: Any
    bypass_interference: bool
    timing_issues: bool


class DataAssessment(TypedDict):
    """Type definition for data assessment."""
    has_http: bool
    has_tls: bool
    has_telemetry: bool
    pcap_completeness: float
    timing_reliability: float
    http_success: bool
    tls_confidence: float


@dataclass
class NetworkConditions:
    """Current network conditions affecting validation."""

    latency_ms: float = 0.0
    packet_loss_percent: float = 0.0
    jitter_ms: float = 0.0
    bandwidth_estimate_kbps: Optional[float] = None
    environment: NetworkEnvironment = NetworkEnvironment.UNKNOWN
    stability_score: float = 1.0  # 0.0 (unstable) to 1.0 (stable)


@dataclass
class EdgeCaseContext:
    """Context for edge case handling decisions."""

    network_conditions: NetworkConditions
    pcap_completeness: float  # 0.0 (no data) to 1.0 (complete)
    timing_reliability: float  # 0.0 (unreliable) to 1.0 (reliable)
    bypass_strategy_complexity: str = "simple"  # simple, moderate, complex
    validation_timeout_ms: float = 5000.0
    retry_count: int = 0
    max_retries: int = 2


@dataclass
class EdgeCaseHandlingResult:
    """Result of edge case handling with adaptive validation."""

    should_proceed: bool
    fallback_method: ValidationFallbackMethod
    adjusted_confidence: float
    timeout_adjustment_ms: float
    reasoning: str
    recommendations: List[str] = field(default_factory=list)
    environment_adaptations: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ValidationThresholds:
    """Immutable configuration for validation thresholds."""
    
    # Network environment thresholds
    high_latency_ms: float = 200.0
    unstable_packet_loss_percent: float = 5.0
    high_jitter_ms: float = 50.0
    
    # Confidence reduction caps
    max_latency_reduction: float = 0.5
    max_loss_reduction: float = 0.4
    max_jitter_reduction: float = 0.3
    
    # Minimum values
    min_confidence: float = 0.1
    min_stability_score: float = 0.1
    min_proceed_threshold: float = 0.2
    
    # Completeness weights
    client_hello_weight: float = 0.3
    server_hello_weight: float = 0.4
    packet_count_weight: float = 0.2
    retransmission_weight: float = 0.1


@dataclass(frozen=True)
class EnvironmentConfig:
    """Configuration for different network environments."""
    timeout_multiplier: float
    confidence_threshold: float
    
    @classmethod
    def get_config(cls, environment: NetworkEnvironment) -> 'EnvironmentConfig':
        """Get configuration for specific environment."""
        configs = {
            NetworkEnvironment.HIGH_LATENCY: cls(3.0, 0.4),
            NetworkEnvironment.UNSTABLE: cls(2.5, 0.3),
            NetworkEnvironment.RESTRICTED: cls(2.0, 0.5),
            NetworkEnvironment.NORMAL: cls(1.0, 0.6),
            NetworkEnvironment.UNKNOWN: cls(1.5, 0.4),
        }
        return configs.get(environment, cls(1.5, 0.4))


class EdgeCaseHandler:
    """
    Handles edge cases in validation with adaptive criteria for different environments.

    This handler provides:
    - Graceful handling of network latency and timing issues
    - Partial TLS handshake validation
    - Fallback validation methods for incomplete PCAP data
    - Adaptive validation criteria for different network environments

    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
    """

    @staticmethod
    def _safe_get_nested_attr(obj: Any, path: str, default: Any = None) -> Any:
        """
        Safe nested getattr for partially available analysis objects.
        
        Args:
            obj: Object to extract attribute from
            path: Dot-separated attribute path (e.g., "context.completeness.value")
            default: Default value if attribute not found
            
        Returns:
            Attribute value or default
        """
        try:
            current = obj
            for part in path.split("."):
                if current is None:
                    return default
                current = getattr(current, part, None)
                if current is None:
                    return default
            return current
        except Exception:
            return default

    @staticmethod
    def _is_http_success(http_classification: Optional[Any]) -> bool:
        """
        Safe check for HTTP success status.
        
        Args:
            http_classification: HTTP classification object
            
        Returns:
            True if HTTP indicates success, False otherwise
        """
        if http_classification is None:
            return False
        try:
            return bool(getattr(http_classification, "is_success", False))
        except Exception:
            return False

    @staticmethod
    def _get_tls_confidence(tls_analysis: Optional[Any]) -> float:
        """
        Safe extraction of TLS confidence value.
        
        Args:
            tls_analysis: TLS analysis object
            
        Returns:
            Confidence value or 0.0
        """
        if tls_analysis is None:
            return 0.0
        try:
            confidence = getattr(tls_analysis, "confidence", 0.0)
            return float(confidence) if confidence is not None else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _get_tls_context(tls_analysis: Optional[Any]) -> Optional[Any]:
        """
        Safe extraction of TLS context.
        
        Args:
            tls_analysis: TLS analysis object
            
        Returns:
            TLS context or None
        """
        if tls_analysis is None:
            return None
        try:
            return getattr(tls_analysis, "context", None)
        except Exception:
            return None

    @staticmethod
    def _safe_division(numerator: float, denominator: float, default: float = 0.0) -> float:
        """
        Safe division with zero check.
        
        Args:
            numerator: Numerator value
            denominator: Denominator value
            default: Default value if division by zero
            
        Returns:
            Division result or default
        """
        if denominator == 0:
            return default
        try:
            return numerator / denominator
        except (ZeroDivisionError, TypeError, ValueError):
            return default

    def _clamp(self, value: float, min_val: float, max_val: float) -> float:
        """
        Clamp value between min and max.
        
        Args:
            value: Value to clamp
            min_val: Minimum value
            max_val: Maximum value
            
        Returns:
            Clamped value
        """
        return max(min_val, min(value, max_val))

    def __init__(self, 
                 logger: Optional[logging.Logger] = None,
                 thresholds: Optional[ValidationThresholds] = None):
        """Initialize the edge case handler."""
        self.logger = logger or logging.getLogger("EdgeCaseHandler")
        self.thresholds = thresholds or ValidationThresholds()
        self.logger.info("EdgeCaseHandler initialized with thresholds: %s", self.thresholds)

    def create_context(
        self, 
        telemetry: TelemetryData, 
        http_code: int, 
        network_timing_ms: float
    ) -> EdgeCaseContext:
        """
        Create edge case context from telemetry and network data.

        Args:
            telemetry: Network telemetry data
            http_code: HTTP response code
            network_timing_ms: Network timing in milliseconds

        Returns:
            EdgeCaseContext for edge case handling
        """
        if network_timing_ms < 0:
            self.logger.warning("Negative network timing: %.2fms, using 0", network_timing_ms)
            network_timing_ms = 0.0
            
        # Estimate network conditions from telemetry
        total_packets = telemetry.get("total_packets", 0)
        retransmissions = telemetry.get("retransmissions", 0)
        
        packet_loss_percent = self._safe_division(
            retransmissions, 
            total_packets, 
            default=0.0
        ) * 100.0

        network_conditions = NetworkConditions(
            latency_ms=network_timing_ms,
            packet_loss_percent=packet_loss_percent,
            jitter_ms=self._estimate_jitter(telemetry),
            stability_score=self._calculate_stability_score(telemetry),
        )

        # Estimate PCAP completeness
        pcap_completeness = self._estimate_pcap_completeness(telemetry)

        # Estimate timing reliability
        timing_reliability = self._estimate_timing_reliability(network_timing_ms, telemetry)

        return EdgeCaseContext(
            network_conditions=network_conditions,
            pcap_completeness=pcap_completeness,
            timing_reliability=timing_reliability,
            bypass_strategy_complexity="simple",  # Default
            validation_timeout_ms=5000.0,
            retry_count=0,
            max_retries=2,
        )

    def _estimate_jitter(self, telemetry: TelemetryData) -> float:
        """
        Estimate network jitter from telemetry.
        
        Args:
            telemetry: Telemetry data
            
        Returns:
            Estimated jitter in milliseconds
        """
        # Simplified jitter estimation
        timing_variations = telemetry.get("timing_variations", [])
        if timing_variations and len(timing_variations) > 1:
            return float(max(timing_variations) - min(timing_variations))
        return 0.0

    def _calculate_stability_score(self, telemetry: TelemetryData) -> float:
        """
        Calculate network stability score from telemetry.
        
        Args:
            telemetry: Telemetry data
            
        Returns:
            Stability score between 0.1 and 1.0
        """
        score = 1.0

        total_packets = telemetry.get("total_packets", 0)
        retransmissions = telemetry.get("retransmissions", 0)

        # Reduce score for high retransmissions
        retrans_rate = self._safe_division(retransmissions, total_packets, 0.0)
        score *= 1.0 - min(retrans_rate, 0.5)

        # Reduce score for missing handshake components
        client_hellos = telemetry.get("client_hellos", 0)
        server_hellos = telemetry.get("server_hellos", 0)

        if client_hellos == 0 or server_hellos == 0:
            score *= 0.7

        return max(self.thresholds.min_stability_score, score)

    def _estimate_pcap_completeness(self, telemetry: TelemetryData) -> float:
        """
        Estimate PCAP data completeness from telemetry.
        
        Args:
            telemetry: Telemetry data
            
        Returns:
            Completeness score between 0.0 and 1.0
        """
        completeness = 0.0

        client_hellos = telemetry.get("client_hellos", 0)
        server_hellos = telemetry.get("server_hellos", 0)
        total_packets = telemetry.get("total_packets", 0)
        retransmissions = telemetry.get("retransmissions", 0)

        if client_hellos > 0:
            completeness += self.thresholds.client_hello_weight

        if server_hellos > 0:
            completeness += self.thresholds.server_hello_weight

        if total_packets > 5:
            completeness += self.thresholds.packet_count_weight

        retrans_rate = self._safe_division(retransmissions, total_packets, 1.0)
        if retrans_rate < 0.1:
            completeness += self.thresholds.retransmission_weight

        return min(1.0, completeness)

    def _estimate_timing_reliability(
        self, network_timing_ms: float, telemetry: TelemetryData
    ) -> float:
        """
        Estimate timing data reliability.
        
        Args:
            network_timing_ms: Network timing in milliseconds
            telemetry: Telemetry data
            
        Returns:
            Reliability score between 0.1 and 1.0
        """
        reliability = 1.0

        if network_timing_ms > 500.0:
            reliability *= 0.5
        elif network_timing_ms > 200.0:
            reliability *= 0.8

        total_packets = telemetry.get("total_packets", 0)
        retransmissions = telemetry.get("retransmissions", 0)
        
        retrans_rate = self._safe_division(retransmissions, total_packets, 0.0)
        reliability *= 1.0 - min(retrans_rate, 0.3)

        return max(self.thresholds.min_stability_score, reliability)

    def handle_network_latency_issues(
        self,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification] = None,
        tls_analysis: Optional[TlsAnalysisResult] = None,
    ) -> EdgeCaseHandlingResult:
        """
        Handle network latency and timing issues gracefully.

        Requirements: 5.1 - Graceful handling of network latency and timing issues

        Args:
            context: Edge case context with network conditions
            http_classification: HTTP response classification if available
            tls_analysis: TLS analysis result if available

        Returns:
            EdgeCaseHandlingResult with latency-aware adaptations
        """
        self.logger.debug(
            "Handling network latency issues: latency=%.1fms, jitter=%.1fms",
            context.network_conditions.latency_ms,
            context.network_conditions.jitter_ms,
        )

        # Detect network environment
        environment = self._detect_network_environment(context.network_conditions)
        context.network_conditions.environment = environment

        # Calculate timeout adjustment
        env_config = EnvironmentConfig.get_config(environment)
        adjusted_timeout = context.validation_timeout_ms * env_config.timeout_multiplier

        # Determine appropriate fallback method
        fallback_method = self._select_latency_aware_fallback(
            context, http_classification, tls_analysis
        )

        # Adjust confidence based on network conditions
        confidence_adjustment = self._calculate_latency_confidence_adjustment(
            context.network_conditions
        )

        # Generate reasoning and recommendations
        reasoning = self._generate_latency_reasoning(context.network_conditions, environment)
        recommendations = self._generate_latency_recommendations(environment)
        adaptations = self._generate_environment_adaptations(environment)

        return EdgeCaseHandlingResult(
            should_proceed=True,
            fallback_method=fallback_method,
            adjusted_confidence=confidence_adjustment,
            timeout_adjustment_ms=adjusted_timeout - context.validation_timeout_ms,
            reasoning=reasoning,
            recommendations=recommendations,
            environment_adaptations=adaptations,
        )

    def handle_partial_tls_handshake(
        self,
        tls_analysis: TlsAnalysisResult,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification] = None,
    ) -> EdgeCaseHandlingResult:
        """
        Implement partial TLS handshake validation.

        Requirements: 5.2 - Implement partial TLS handshake validation

        Args:
            tls_analysis: TLS analysis result with partial handshake
            context: Edge case context
            http_classification: HTTP response classification if available

        Returns:
            EdgeCaseHandlingResult with partial TLS validation
        """
        completeness_val = self._safe_get_nested_attr(tls_analysis, "context.completeness.value", "unknown")
        confidence_float = self._get_tls_confidence(tls_analysis)
        self.logger.debug(
            "Handling partial TLS handshake: completeness=%s, confidence=%.2f",
            completeness_val,
            confidence_float,
        )

        # Assess what parts of the handshake we have
        handshake_assessment = self._assess_partial_handshake(tls_analysis)

        # Determine if partial handshake is sufficient for validation
        is_sufficient = self._is_partial_handshake_sufficient(
            tls_analysis, context, http_classification
        )

        # Calculate adjusted confidence for partial handshake
        adjusted_confidence = self._calculate_partial_handshake_confidence(
            tls_analysis, context, http_classification
        )

        # Select appropriate validation method
        if is_sufficient:
            fallback_method = ValidationFallbackMethod.PARTIAL_TLS
        elif http_classification and self._is_http_success(http_classification):
            fallback_method = ValidationFallbackMethod.HTTP_ONLY
        else:
            fallback_method = ValidationFallbackMethod.HEURISTIC

        # Generate reasoning and recommendations
        reasoning = self._generate_partial_tls_reasoning(
            tls_analysis, handshake_assessment, is_sufficient
        )
        recommendations = self._generate_partial_tls_recommendations(tls_analysis, context)

        return EdgeCaseHandlingResult(
            should_proceed=is_sufficient
            or (http_classification is not None and self._is_http_success(http_classification)),
            fallback_method=fallback_method,
            adjusted_confidence=adjusted_confidence,
            timeout_adjustment_ms=0.0,
            reasoning=reasoning,
            recommendations=recommendations,
        )

    def create_fallback_validation_methods(
        self,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification] = None,
        tls_analysis: Optional[TlsAnalysisResult] = None,
        telemetry: Optional[TelemetryData] = None,
    ) -> EdgeCaseHandlingResult:
        """
        Create fallback validation methods for incomplete PCAP data.

        Requirements: 5.3 - Create fallback validation methods for incomplete PCAP data

        Args:
            context: Edge case context
            http_classification: HTTP response classification if available
            tls_analysis: TLS analysis result if available
            telemetry: Raw telemetry data if available

        Returns:
            EdgeCaseHandlingResult with appropriate fallback method
        """
        self.logger.debug(
            "Creating fallback validation: pcap_completeness=%.2f, timing_reliability=%.2f",
            context.pcap_completeness,
            context.timing_reliability,
        )

        # Assess data availability
        data_assessment = self._assess_data_availability(
            context, http_classification, tls_analysis, telemetry
        )

        # Select best available fallback method
        fallback_method = self._select_best_fallback_method(
            data_assessment, context, http_classification, tls_analysis
        )

        # Calculate confidence for fallback method
        fallback_confidence = self._calculate_fallback_confidence(
            fallback_method, data_assessment, context
        )

        # Generate reasoning and recommendations
        reasoning = self._generate_fallback_reasoning(fallback_method, data_assessment, context)
        recommendations = self._generate_fallback_recommendations(fallback_method, data_assessment)

        return EdgeCaseHandlingResult(
            should_proceed=fallback_confidence > self.thresholds.min_proceed_threshold,
            fallback_method=fallback_method,
            adjusted_confidence=fallback_confidence,
            timeout_adjustment_ms=0.0,
            reasoning=reasoning,
            recommendations=recommendations,
        )

    def adapt_validation_criteria(
        self, context: EdgeCaseContext, base_confidence: float, validation_result: bool
    ) -> EdgeCaseHandlingResult:
        """
        Add adaptive validation criteria for different network environments.

        Requirements: 5.4, 5.5 - Adaptive validation criteria for different environments

        Args:
            context: Edge case context with network environment
            base_confidence: Base confidence from validation
            validation_result: Initial validation result

        Returns:
            EdgeCaseHandlingResult with environment-adapted criteria
        """
        environment = context.network_conditions.environment

        self.logger.debug(
            "Adapting validation criteria for environment: %s, base_confidence=%.2f",
            environment.value,
            base_confidence,
        )

        # Get environment-specific threshold
        env_config = EnvironmentConfig.get_config(environment)
        min_threshold = env_config.confidence_threshold

        # Apply environment-specific adjustments
        adjusted_confidence = self._apply_environment_adjustments(
            base_confidence, context.network_conditions, environment
        )

        # Determine if result should be adjusted based on environment
        should_proceed = adjusted_confidence >= min_threshold

        # Select appropriate method for this environment
        fallback_method = self._select_environment_appropriate_method(
            environment, adjusted_confidence, validation_result
        )

        # Generate environment-specific reasoning
        reasoning = self._generate_environment_reasoning(
            environment, base_confidence, adjusted_confidence, min_threshold
        )

        recommendations = self._generate_environment_recommendations(environment)
        adaptations = self._generate_environment_adaptations(environment)

        return EdgeCaseHandlingResult(
            should_proceed=should_proceed,
            fallback_method=fallback_method,
            adjusted_confidence=adjusted_confidence,
            timeout_adjustment_ms=0.0,
            reasoning=reasoning,
            recommendations=recommendations,
            environment_adaptations=adaptations,
        )

    def _detect_network_environment(self, conditions: NetworkConditions) -> NetworkEnvironment:
        """
        Detect network environment based on conditions.
        
        Args:
            conditions: Current network conditions
            
        Returns:
            Detected network environment
        """
        if conditions.latency_ms > self.thresholds.high_latency_ms:
            return NetworkEnvironment.HIGH_LATENCY

        if conditions.packet_loss_percent > self.thresholds.unstable_packet_loss_percent:
            return NetworkEnvironment.UNSTABLE

        if conditions.jitter_ms > self.thresholds.high_jitter_ms:
            return NetworkEnvironment.UNSTABLE

        if conditions.stability_score < 0.7:
            return NetworkEnvironment.UNSTABLE

        # Check for restricted environment indicators
        if conditions.latency_ms > 100.0 and conditions.packet_loss_percent > 1.0:
            return NetworkEnvironment.RESTRICTED

        if conditions.latency_ms < 50.0 and conditions.packet_loss_percent < 1.0:
            return NetworkEnvironment.NORMAL

        return NetworkEnvironment.UNKNOWN

    def _select_latency_aware_fallback(
        self,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification],
        tls_analysis: Optional[TlsAnalysisResult],
    ) -> ValidationFallbackMethod:
        """Select appropriate fallback method for latency conditions."""
        environment = context.network_conditions.environment

        # High latency environments should rely more on HTTP
        if environment == NetworkEnvironment.HIGH_LATENCY:
            if http_classification and self._is_http_success(http_classification):
                return ValidationFallbackMethod.HTTP_ONLY
            else:
                return ValidationFallbackMethod.TIMING_BASED

        # Unstable environments need robust methods
        if environment == NetworkEnvironment.UNSTABLE:
            if http_classification:
                return ValidationFallbackMethod.HTTP_ONLY
            elif tls_analysis and self._get_tls_confidence(tls_analysis) > 0.3:
                return ValidationFallbackMethod.PARTIAL_TLS
            else:
                return ValidationFallbackMethod.HEURISTIC

        # Default to timing-based for other environments
        return ValidationFallbackMethod.TIMING_BASED

    def _calculate_latency_confidence_adjustment(self, conditions: NetworkConditions) -> float:
        """
        Calculate confidence adjustment based on latency conditions.
        
        Args:
            conditions: Network conditions
            
        Returns:
            Confidence adjustment multiplier
        """
        base_adjustment = 1.0

        # Reduce confidence for high latency
        if conditions.latency_ms > self.thresholds.high_latency_ms:
            latency_factor = min(
                conditions.latency_ms / 1000.0, 
                self.thresholds.max_latency_reduction
            )
            base_adjustment *= 1.0 - latency_factor

        # Reduce confidence for packet loss
        if conditions.packet_loss_percent > 0:
            loss_factor = min(
                conditions.packet_loss_percent / 20.0, 
                self.thresholds.max_loss_reduction
            )
            base_adjustment *= 1.0 - loss_factor

        # Reduce confidence for high jitter
        if conditions.jitter_ms > self.thresholds.high_jitter_ms:
            jitter_factor = min(
                conditions.jitter_ms / 200.0, 
                self.thresholds.max_jitter_reduction
            )
            base_adjustment *= 1.0 - jitter_factor

        # Apply stability score
        base_adjustment *= conditions.stability_score

        return max(self.thresholds.min_confidence, base_adjustment)

    def _assess_partial_handshake(self, tls_analysis: TlsAnalysisResult) -> HandshakeAssessment:
        """Assess what parts of the TLS handshake are available."""
        context = self._get_tls_context(tls_analysis)
        client_hellos = int(getattr(context, "client_hello_count", 0) or 0) if context else 0
        server_hellos = int(getattr(context, "server_hello_count", 0) or 0) if context else 0
        completeness = getattr(context, "completeness", HandshakeCompleteness.UNKNOWN) if context else HandshakeCompleteness.UNKNOWN
        bypass_interference = bool(getattr(context, "bypass_interference_detected", False)) if context else False
        timing_anomalies = getattr(context, "timing_anomalies", []) if context else []

        return {
            "has_client_hello": client_hellos > 0,
            "has_server_hello": server_hellos > 0,
            "handshake_ratio": self._safe_division(server_hellos, client_hellos, 0.0),
            "completeness_level": completeness,
            "bypass_interference": bypass_interference,
            "timing_issues": len(timing_anomalies) > 0,
        }

    def _is_partial_handshake_sufficient(
        self,
        tls_analysis: TlsAnalysisResult,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification],
    ) -> bool:
        """
        Determine if partial handshake is sufficient for validation.
        
        Args:
            tls_analysis: TLS analysis result
            context: Edge case context
            http_classification: HTTP classification if available
            
        Returns:
            True if partial handshake is sufficient
        """
        handshake_context = self._get_tls_context(tls_analysis)
        if handshake_context is None:
            return False

        completeness = getattr(handshake_context, "completeness", HandshakeCompleteness.UNKNOWN)
        completeness_val = getattr(completeness, "value", completeness)

        # Complete handshake is always sufficient
        if completeness == HandshakeCompleteness.COMPLETE or completeness_val == "complete":
            return True

        # With HTTP success, partial handshake may be sufficient
        if http_classification is not None and self._is_http_success(http_classification):
            # ClientHello without ServerHello can be sufficient with HTTP success
            if (
                completeness == HandshakeCompleteness.MISSING_SERVERHELLO
                or completeness_val == "missing_serverhello"
            ) and int(getattr(handshake_context, "client_hello_count", 0) or 0) > 0:
                return True

        # In high latency environments, be more lenient
        if context.network_conditions.environment == NetworkEnvironment.HIGH_LATENCY:
            if int(getattr(handshake_context, "client_hello_count", 0) or 0) > 0:
                return True

        # Partial handshake with bypass strategy may be sufficient
        if (
            (completeness == HandshakeCompleteness.PARTIAL or completeness_val == "partial")
            and bool(getattr(handshake_context, "bypass_strategy_applied", False))
            and self._get_tls_confidence(tls_analysis) > 0.4
        ):
            return True

        return False

    def _calculate_partial_handshake_confidence(
        self,
        tls_analysis: TlsAnalysisResult,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification],
    ) -> float:
        """
        Calculate confidence for partial handshake validation.
        
        Args:
            tls_analysis: TLS analysis result
            context: Edge case context
            http_classification: HTTP classification if available
            
        Returns:
            Adjusted confidence score
        """
        base_confidence = self._get_tls_confidence(tls_analysis)

        # Boost confidence if HTTP also indicates success
        if http_classification is not None and self._is_http_success(http_classification):
            base_confidence = min(1.0, base_confidence + 0.2)

        # Adjust for network environment
        environment = context.network_conditions.environment
        if environment in [NetworkEnvironment.HIGH_LATENCY, NetworkEnvironment.UNSTABLE]:
            # Be more lenient in challenging environments
            base_confidence = min(1.0, base_confidence + 0.1)

        # Adjust for bypass strategy
        tls_ctx = self._get_tls_context(tls_analysis)
        if tls_ctx is not None and bool(getattr(tls_ctx, "bypass_strategy_applied", False)):
            # Bypass strategies can explain partial handshakes
            base_confidence = min(1.0, base_confidence + 0.15)

        return max(self.thresholds.min_confidence, base_confidence)

    def _assess_data_availability(
        self,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification],
        tls_analysis: Optional[TlsAnalysisResult],
        telemetry: Optional[TelemetryData],
    ) -> DataAssessment:
        """
        Assess what validation data is available.
        
        Args:
            context: Edge case context
            http_classification: HTTP classification if available
            tls_analysis: TLS analysis if available
            telemetry: Telemetry data if available
            
        Returns:
            Data assessment dictionary
        """
        return {
            "has_http": http_classification is not None,
            "has_tls": tls_analysis is not None,
            "has_telemetry": telemetry is not None and len(telemetry) > 0,
            "pcap_completeness": context.pcap_completeness,
            "timing_reliability": context.timing_reliability,
            "http_success": self._is_http_success(http_classification),
            "tls_confidence": self._get_tls_confidence(tls_analysis),
        }

    def _select_best_fallback_method(
        self,
        data_assessment: DataAssessment,
        context: EdgeCaseContext,
        http_classification: Optional[ResponseClassification],
        tls_analysis: Optional[TlsAnalysisResult],
    ) -> ValidationFallbackMethod:
        """
        Select the best available fallback validation method.
        
        Args:
            data_assessment: Assessment of available data
            context: Edge case context
            http_classification: HTTP classification if available
            tls_analysis: TLS analysis if available
            
        Returns:
            Best fallback validation method
        """
        # Prioritize HTTP if available and successful
        if data_assessment["has_http"] and data_assessment["http_success"]:
            return ValidationFallbackMethod.HTTP_ONLY

        # Use partial TLS if available with reasonable confidence
        if data_assessment["has_tls"] and data_assessment["tls_confidence"] > 0.3:
            return ValidationFallbackMethod.PARTIAL_TLS

        # Use timing-based if timing is reliable
        if data_assessment["timing_reliability"] > 0.6:
            return ValidationFallbackMethod.TIMING_BASED

        # Use heuristic if we have some data
        if (
            data_assessment["has_http"]
            or data_assessment["has_tls"]
            or data_assessment["pcap_completeness"] > 0.2
        ):
            return ValidationFallbackMethod.HEURISTIC

        # Last resort - minimal validation
        return ValidationFallbackMethod.MINIMAL

    def _calculate_fallback_confidence(
        self,
        fallback_method: ValidationFallbackMethod,
        data_assessment: DataAssessment,
        context: EdgeCaseContext,
    ) -> float:
        """
        Calculate confidence for fallback validation method.
        
        Args:
            fallback_method: Selected fallback method
            data_assessment: Assessment of available data
            context: Edge case context
            
        Returns:
            Confidence score for fallback method
        """
        base_confidence = 0.5  # Start with medium confidence

        if fallback_method == ValidationFallbackMethod.HTTP_ONLY:
            if data_assessment["http_success"]:
                base_confidence = 0.8
            else:
                base_confidence = 0.3

        elif fallback_method == ValidationFallbackMethod.PARTIAL_TLS:
            base_confidence = data_assessment["tls_confidence"]

        elif fallback_method == ValidationFallbackMethod.TIMING_BASED:
            base_confidence = data_assessment["timing_reliability"] * 0.7

        elif fallback_method == ValidationFallbackMethod.HEURISTIC:
            # Combine available signals
            signals = 0
            confidence_sum = 0.0

            if data_assessment["has_http"]:
                signals += 1
                confidence_sum += 0.6 if data_assessment["http_success"] else 0.3

            if data_assessment["has_tls"]:
                signals += 1
                confidence_sum += data_assessment["tls_confidence"]

            if data_assessment["pcap_completeness"] > 0.2:
                signals += 1
                confidence_sum += data_assessment["pcap_completeness"] * 0.5

            base_confidence = self._safe_division(confidence_sum, signals, 0.2)

        else:  # MINIMAL
            base_confidence = 0.2

        # Adjust for network conditions
        network_adjustment = self._calculate_latency_confidence_adjustment(
            context.network_conditions
        )

        return max(self.thresholds.min_confidence, base_confidence * network_adjustment)

    def _apply_environment_adjustments(
        self, base_confidence: float, conditions: NetworkConditions, environment: NetworkEnvironment
    ) -> float:
        """
        Apply environment-specific confidence adjustments.
        
        Args:
            base_confidence: Base confidence score
            conditions: Network conditions
            environment: Detected network environment
            
        Returns:
            Adjusted confidence score
        """
        adjusted = base_confidence

        if environment == NetworkEnvironment.HIGH_LATENCY:
            # Be more lenient with high latency
            adjusted = min(1.0, adjusted + 0.1)

        elif environment == NetworkEnvironment.UNSTABLE:
            # Reduce confidence for unstable networks
            adjusted *= 0.9

        elif environment == NetworkEnvironment.RESTRICTED:
            # Corporate environments may have different patterns
            adjusted = min(1.0, adjusted + 0.05)

        # Apply stability score
        adjusted *= conditions.stability_score

        return max(self.thresholds.min_confidence, adjusted)

    def _select_environment_appropriate_method(
        self, environment: NetworkEnvironment, confidence: float, validation_result: bool
    ) -> ValidationFallbackMethod:
        """Select validation method appropriate for environment."""
        if environment == NetworkEnvironment.HIGH_LATENCY:
            return ValidationFallbackMethod.HTTP_ONLY

        elif environment == NetworkEnvironment.UNSTABLE:
            if confidence > 0.5:
                return ValidationFallbackMethod.PARTIAL_TLS
            else:
                return ValidationFallbackMethod.HEURISTIC

        elif environment == NetworkEnvironment.RESTRICTED:
            return ValidationFallbackMethod.HTTP_ONLY

        else:  # NORMAL or UNKNOWN
            if confidence > 0.6:
                return ValidationFallbackMethod.PARTIAL_TLS
            else:
                return ValidationFallbackMethod.TIMING_BASED

    def _generate_latency_reasoning(
        self, conditions: NetworkConditions, environment: NetworkEnvironment
    ) -> str:
        """
        Generate reasoning for latency handling.
        
        Args:
            conditions: Network conditions
            environment: Detected network environment
            
        Returns:
            Human-readable reasoning string
        """
        parts = [f"Network environment detected as {environment.value}."]

        if conditions.latency_ms > self.thresholds.high_latency_ms:
            parts.append(f"High latency ({conditions.latency_ms:.1f}ms) detected.")

        if conditions.packet_loss_percent > 0:
            parts.append(f"Packet loss ({conditions.packet_loss_percent:.1f}%) observed.")

        if conditions.jitter_ms > self.thresholds.high_jitter_ms:
            parts.append(f"High jitter ({conditions.jitter_ms:.1f}ms) affecting timing.")

        parts.append("Validation criteria adapted for network conditions.")

        return " ".join(parts)

    def _generate_latency_recommendations(self, environment: NetworkEnvironment) -> List[str]:
        """Generate recommendations for latency handling."""
        recommendations = []

        if environment == NetworkEnvironment.HIGH_LATENCY:
            recommendations.extend(
                [
                    "Consider increasing validation timeouts for high-latency networks",
                    "Prioritize HTTP-level validation over timing-sensitive methods",
                    "Monitor for satellite or mobile network characteristics",
                ]
            )

        elif environment == NetworkEnvironment.UNSTABLE:
            recommendations.extend(
                [
                    "Implement retry logic for unstable network conditions",
                    "Use multiple validation methods for cross-verification",
                    "Consider network stability before making final decisions",
                ]
            )

        elif environment == NetworkEnvironment.RESTRICTED:
            recommendations.extend(
                [
                    "Check for corporate firewall or proxy interference",
                    "Verify bypass strategies are appropriate for restricted environments",
                    "Consider alternative validation approaches for corporate networks",
                ]
            )

        return recommendations

    def _generate_environment_adaptations(self, environment: NetworkEnvironment) -> List[str]:
        """
        Generate environment-specific adaptations.
        
        Args:
            environment: Network environment
            
        Returns:
            List of adaptations applied
        """
        adaptations = []

        env_config = EnvironmentConfig.get_config(environment)
        multiplier = env_config.timeout_multiplier
        if multiplier > 1.0:
            adaptations.append(
                f"Timeout multiplier set to {multiplier:.1f}x for {environment.value} environment"
            )

        threshold = env_config.confidence_threshold
        adaptations.append(
            f"Confidence threshold adjusted to {threshold:.1f} for {environment.value}"
        )

        return adaptations

    def _generate_partial_tls_reasoning(
        self,
        tls_analysis: TlsAnalysisResult,
        handshake_assessment: HandshakeAssessment,
        is_sufficient: bool,
    ) -> str:
        """
        Generate reasoning for partial TLS handshake handling.
        
        Args:
            tls_analysis: TLS analysis result
            handshake_assessment: Assessment of handshake completeness
            is_sufficient: Whether partial handshake is sufficient
            
        Returns:
            Human-readable reasoning string
        """
        context = self._get_tls_context(tls_analysis)
        completeness_val = getattr(
            getattr(context, "completeness", HandshakeCompleteness.UNKNOWN),
            "value",
            "unknown"
        ) if context else "unknown"
        
        parts = [f"Partial TLS handshake detected: {completeness_val}."]

        if (
            handshake_assessment["has_client_hello"]
            and not handshake_assessment["has_server_hello"]
        ):
            parts.append("ClientHello present but ServerHello missing.")

        if handshake_assessment["bypass_interference"]:
            parts.append("Bypass strategy interference detected in handshake.")

        if handshake_assessment["timing_issues"]:
            parts.append("Timing anomalies observed during handshake.")

        if is_sufficient:
            parts.append("Partial handshake deemed sufficient for validation.")
        else:
            parts.append("Partial handshake insufficient, requiring fallback validation.")

        return " ".join(parts)

    def _generate_partial_tls_recommendations(
        self, tls_analysis: TlsAnalysisResult, context: EdgeCaseContext
    ) -> List[str]:
        """
        Generate recommendations for partial TLS handshake handling.
        
        Args:
            tls_analysis: TLS analysis result
            context: Edge case context
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        tls_ctx = self._get_tls_context(tls_analysis)
        if tls_ctx is None:
            return recommendations

        completeness = getattr(tls_ctx, "completeness", HandshakeCompleteness.UNKNOWN)
        if completeness == HandshakeCompleteness.MISSING_SERVERHELLO:
            recommendations.extend(
                [
                    "Check if target uses QUIC protocol instead of TLS",
                    "Verify packet capture covers all network interfaces",
                    "Consider IPv6 traffic bypass in packet capture",
                ]
            )

        bypass_interference = bool(getattr(tls_ctx, "bypass_interference_detected", False))
        if bypass_interference:
            recommendations.extend(
                [
                    "Monitor bypass strategy effects on packet capture",
                    "Consider adjusting bypass parameters to reduce interference",
                    "Verify bypass strategy compatibility with validation requirements",
                ]
            )

        if context.network_conditions.environment == NetworkEnvironment.HIGH_LATENCY:
            recommendations.extend(
                [
                    "Increase handshake timeout for high-latency environments",
                    "Consider network latency in handshake timing analysis",
                ]
            )

        return recommendations

    def _generate_fallback_reasoning(
        self,
        fallback_method: ValidationFallbackMethod,
        data_assessment: DataAssessment,
        context: EdgeCaseContext,
    ) -> str:
        """
        Generate reasoning for fallback validation method selection.
        
        Args:
            fallback_method: Selected fallback method
            data_assessment: Assessment of available data
            context: Edge case context
            
        Returns:
            Human-readable reasoning string
        """
        parts = [f"Selected {fallback_method.value} fallback validation method."]

        if fallback_method == ValidationFallbackMethod.HTTP_ONLY:
            parts.append("HTTP response data available and reliable.")

        elif fallback_method == ValidationFallbackMethod.PARTIAL_TLS:
            parts.append("Partial TLS data available with acceptable confidence.")

        elif fallback_method == ValidationFallbackMethod.TIMING_BASED:
            parts.append("Timing data reliable enough for validation.")

        elif fallback_method == ValidationFallbackMethod.HEURISTIC:
            parts.append("Multiple partial data sources combined for validation.")

        else:  # MINIMAL
            parts.append("Limited data available, using minimal validation criteria.")

        parts.append(f"PCAP completeness: {context.pcap_completeness:.1%}")

        return " ".join(parts)

    def _generate_fallback_recommendations(
        self, fallback_method: ValidationFallbackMethod, data_assessment: DataAssessment
    ) -> List[str]:
        """
        Generate recommendations for fallback validation methods.
        
        Args:
            fallback_method: Selected fallback method
            data_assessment: Assessment of available data
            
        Returns:
            List of recommendations
        """
        recommendations = []

        if fallback_method == ValidationFallbackMethod.MINIMAL:
            recommendations.extend(
                [
                    "Improve packet capture configuration for better data quality",
                    "Check network interface and filter settings",
                    "Consider retesting with different validation parameters",
                ]
            )

        if not data_assessment["has_tls"]:
            recommendations.extend(
                [
                    "Verify TLS packet capture is working correctly",
                    "Check if target uses alternative protocols (QUIC, HTTP/3)",
                ]
            )

        if data_assessment["pcap_completeness"] < 0.5:
            recommendations.extend(
                [
                    "Investigate packet capture completeness issues",
                    "Monitor for buffer overflows or timing problems",
                ]
            )

        return recommendations

    def _generate_environment_reasoning(
        self,
        environment: NetworkEnvironment,
        base_confidence: float,
        adjusted_confidence: float,
        threshold: float,
    ) -> str:
        """Generate reasoning for environment-specific adaptations."""
        parts = [
            f"Network environment: {environment.value}.",
            f"Base confidence: {base_confidence:.2f}, adjusted: {adjusted_confidence:.2f}.",
            f"Environment threshold: {threshold:.2f}.",
        ]

        if adjusted_confidence >= threshold:
            parts.append("Validation criteria met for this environment.")
        else:
            parts.append("Validation criteria not met, consider retry or alternative methods.")

        return " ".join(parts)

    def _generate_environment_recommendations(self, environment: NetworkEnvironment) -> List[str]:
        """Generate environment-specific recommendations."""
        recommendations = []

        if environment == NetworkEnvironment.HIGH_LATENCY:
            recommendations.extend(
                [
                    "Use longer timeouts for high-latency networks",
                    "Prioritize HTTP validation over timing-sensitive methods",
                    "Consider satellite or mobile network optimizations",
                ]
            )

        elif environment == NetworkEnvironment.UNSTABLE:
            recommendations.extend(
                [
                    "Implement robust retry mechanisms",
                    "Use multiple validation approaches for reliability",
                    "Monitor network stability trends",
                ]
            )

        elif environment == NetworkEnvironment.RESTRICTED:
            recommendations.extend(
                [
                    "Account for corporate firewall effects",
                    "Verify bypass compatibility with network policies",
                    "Consider proxy or gateway interference",
                ]
            )

        elif environment == NetworkEnvironment.UNKNOWN:
            recommendations.extend(
                [
                    "Gather more network condition data",
                    "Use conservative validation thresholds",
                    "Monitor for environment classification improvements",
                ]
            )

        return recommendations


def create_edge_case_handler(
    logger: Optional[logging.Logger] = None,
    thresholds: Optional[ValidationThresholds] = None,
) -> EdgeCaseHandler:
    """
    Factory function for creating EdgeCaseHandler instances.

    Args:
        logger: Optional logger instance
        thresholds: Optional custom validation thresholds

    Returns:
        Configured EdgeCaseHandler instance
    """
    return EdgeCaseHandler(logger, thresholds)
