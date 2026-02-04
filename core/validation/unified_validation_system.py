"""
Unified Validation System for False Positive Validation Fix.

This module integrates all validation components into a unified system with
comprehensive logging, backward compatibility, enhanced validation logic,
and performance optimization through caching.

Requirements: All requirements (1.1-5.5)
"""

import logging
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from core.bypass.validation.validator import StrategyResultValidator, ValidationResult
from core.validation.http_response_classifier import HttpResponseClassifier
from core.validation.decision_engine import ValidationDecisionEngine, ValidationContext
from core.validation.tls_handshake_analyzer import EnhancedTlsHandshakeAnalyzer
from core.validation.edge_case_handler import EdgeCaseHandler


@dataclass
class UnifiedValidationResult:
    """Enhanced validation result with detailed component analysis."""

    # Core validation result
    success: bool
    status: str
    error: Optional[str]
    metrics: Dict[str, Any]

    # Component-specific results
    http_classification: Optional[Any] = None
    tls_analysis: Optional[Any] = None
    decision_analysis: Optional[Any] = None
    edge_case_handling: Optional[Any] = None

    # Enhanced reasoning
    detailed_reasoning: List[str] = None
    troubleshooting_hints: List[str] = None
    confidence_score: float = 0.0
    validation_method: str = "LEGACY"


class UnifiedValidationSystem:
    """
    Unified validation system that integrates all enhanced validation components.

    This system provides:
    - HTTP-level success prioritization
    - TLS handshake analysis with bypass awareness
    - Intelligent false positive detection
    - Detailed reasoning and troubleshooting hints
    - Performance optimization through caching
    - Backward compatibility with existing validation interface

    Requirements: All requirements (1.1-5.5)
    """

    def __init__(
        self, logger: Optional[logging.Logger] = None, enable_performance_cache: bool = False
    ):
        """Initialize the unified validation system."""
        self.logger = logger or logging.getLogger("UnifiedValidationSystem")

        # Initialize all validation components
        self.legacy_validator = StrategyResultValidator()
        self.http_classifier = HttpResponseClassifier()
        self.decision_engine = ValidationDecisionEngine(logger)
        self.tls_analyzer = EnhancedTlsHandshakeAnalyzer(logger)
        self.edge_handler = EdgeCaseHandler(logger)

        # Performance tracking
        self._validation_count = 0
        self._total_validation_time = 0.0
        self._enable_performance_cache = enable_performance_cache

        self.logger.info(
            "UnifiedValidationSystem initialized with all components (cache=%s)",
            enable_performance_cache,
        )

    def validate_enhanced(
        self,
        http_success: bool,
        http_code: int,
        telemetry: Dict[str, Any],
        strategy_name: str,
        enable_enhanced_logic: bool = True,
    ) -> UnifiedValidationResult:
        """
        Enhanced validation with detailed component analysis and performance tracking.

        Args:
            http_success: Whether HTTP request succeeded
            http_code: HTTP response code
            telemetry: Network telemetry data
            strategy_name: Name of bypass strategy used
            enable_enhanced_logic: Whether to use enhanced validation logic

        Returns:
            UnifiedValidationResult with detailed analysis
        """
        start_time = time.time()

        self.logger.debug(
            "Starting enhanced validation: HTTP %d, strategy=%s, enhanced=%s",
            http_code,
            strategy_name,
            enable_enhanced_logic,
        )

        # Step 1: Get legacy validation result for comparison
        legacy_result = self.legacy_validator.validate(
            http_success=http_success,
            http_code=http_code,
            telemetry=telemetry,
            strategy_name=strategy_name,
        )

        if not enable_enhanced_logic:
            # Return legacy result wrapped in unified format
            return self._wrap_legacy_result(legacy_result)

        # Step 2: Enhanced HTTP classification
        http_classification = self.http_classifier.classify_response(http_code)

        # Step 3: Enhanced TLS analysis
        tls_analysis = self.tls_analyzer.analyze_handshake(telemetry)

        # Step 4: Create validation context
        context = self._create_validation_context(
            http_success, http_code, telemetry, strategy_name, tls_analysis
        )

        # Step 5: Decision engine analysis
        decision = self.decision_engine.make_validation_decision(context, telemetry)

        # Step 6: Edge case handling
        edge_result = self._handle_edge_cases(context, http_classification, tls_analysis)

        # Step 7: Generate unified result
        unified_result = self._generate_unified_result(
            legacy_result, http_classification, tls_analysis, decision, edge_result
        )

        # Track performance metrics
        validation_time = time.time() - start_time
        self._validation_count += 1
        self._total_validation_time += validation_time

        self.logger.info(
            "Enhanced validation complete: %s (confidence=%.2f, method=%s, time=%.3fs)",
            "SUCCESS" if unified_result.success else unified_result.status,
            unified_result.confidence_score,
            unified_result.validation_method,
            validation_time,
        )

        return unified_result

    def validate_legacy_compatible(
        self, http_success: bool, http_code: int, telemetry: Dict[str, Any], strategy_name: str
    ) -> ValidationResult:
        """
        Legacy-compatible validation interface.

        This method maintains backward compatibility while optionally applying
        enhanced logic based on configuration.

        Args:
            http_success: Whether HTTP request succeeded
            http_code: HTTP response code
            telemetry: Network telemetry data
            strategy_name: Name of bypass strategy used

        Returns:
            ValidationResult compatible with existing code
        """
        # Use enhanced validation but return legacy format
        enhanced_result = self.validate_enhanced(
            http_success, http_code, telemetry, strategy_name, enable_enhanced_logic=True
        )

        # Convert to legacy format
        return ValidationResult(
            success=enhanced_result.success,
            status=enhanced_result.status,
            error=enhanced_result.error,
            metrics=enhanced_result.metrics,
        )

    def _create_validation_context(
        self,
        http_success: bool,
        http_code: int,
        telemetry: Dict[str, Any],
        strategy_name: str,
        tls_analysis: Any,
    ) -> ValidationContext:
        """Create validation context from input parameters."""
        # Extract metrics safely
        metrics = self.legacy_validator._extract_metrics(telemetry)

        return ValidationContext(
            http_response_code=http_code,
            http_success=http_success,
            tls_handshake_complete=tls_analysis.handshake_complete,
            server_hello_count=metrics.get("server_hellos", 0),
            client_hello_count=metrics.get("client_hellos", 0),
            retransmission_count=metrics.get("retransmissions", 0),
            total_packets=metrics.get("total_packets", 0),
            bypass_strategy_applied=True,  # Assume bypass was applied
            pcap_analysis_available=bool(telemetry),
            network_timing_ms=50.0,  # Default timing
            strategy_name=strategy_name,
        )

    def _handle_edge_cases(
        self, context: ValidationContext, http_classification: Any, tls_analysis: Any
    ) -> Any:
        """Handle edge cases using the edge case handler."""
        try:
            # Create edge case context
            edge_context = self.edge_handler.create_context(
                telemetry={
                    "server_hellos": context.server_hello_count,
                    "client_hellos": context.client_hello_count,
                    "retransmissions": context.retransmission_count,
                    "total_packets": context.total_packets,
                },
                http_code=context.http_response_code,
                network_timing_ms=context.network_timing_ms,
            )

            # Handle specific edge cases
            if http_classification.is_success and not tls_analysis.handshake_complete:
                return self.edge_handler.handle_missing_tls_with_http_success(edge_context)
            elif context.retransmission_count > 0:
                return self.edge_handler.handle_network_conditions(edge_context)
            else:
                return None

        except Exception as e:
            self.logger.warning("Edge case handling failed: %s", e)
            return None

    def _generate_unified_result(
        self,
        legacy_result: ValidationResult,
        http_classification: Any,
        tls_analysis: Any,
        decision: Any,
        edge_result: Any,
    ) -> UnifiedValidationResult:
        """Generate unified validation result from all component analyses."""

        # Determine final success based on enhanced logic
        enhanced_success = self._determine_enhanced_success(
            legacy_result, http_classification, tls_analysis, decision
        )

        # Generate detailed reasoning
        reasoning = self._generate_detailed_reasoning(
            legacy_result, http_classification, tls_analysis, decision, edge_result
        )

        # Generate troubleshooting hints
        hints = self._generate_troubleshooting_hints(
            legacy_result, http_classification, tls_analysis, edge_result
        )

        # Calculate confidence score
        confidence = self._calculate_confidence_score(http_classification, tls_analysis, decision)

        # Determine validation method
        validation_method = self._determine_validation_method(
            http_classification, tls_analysis, decision
        )

        return UnifiedValidationResult(
            success=enhanced_success,
            status=legacy_result.status if not enhanced_success else "ENHANCED_SUCCESS",
            error=legacy_result.error,
            metrics=legacy_result.metrics,
            http_classification=http_classification,
            tls_analysis=tls_analysis,
            decision_analysis=decision,
            edge_case_handling=edge_result,
            detailed_reasoning=reasoning,
            troubleshooting_hints=hints,
            confidence_score=confidence,
            validation_method=validation_method,
        )

    def _determine_enhanced_success(
        self,
        legacy_result: ValidationResult,
        http_classification: Any,
        tls_analysis: Any,
        decision: Any,
    ) -> bool:
        """Determine success using enhanced logic."""

        # Priority 1: HTTP success codes (200-399) override TLS issues
        if http_classification.is_success:
            self.logger.debug("HTTP success detected, prioritizing over TLS analysis")
            return True

        # Priority 2: Use decision engine result if available
        if hasattr(decision, "final_result"):
            return decision.final_result

        # Priority 3: Fall back to legacy result
        return legacy_result.success

    def _generate_detailed_reasoning(
        self,
        legacy_result: ValidationResult,
        http_classification: Any,
        tls_analysis: Any,
        decision: Any,
        edge_result: Any,
    ) -> List[str]:
        """Generate detailed reasoning for the validation decision."""
        reasoning = []

        # HTTP analysis reasoning
        if http_classification.is_success:
            reasoning.append(
                f"HTTP {http_classification.status_code} indicates successful communication"
            )
            if http_classification.is_redirect:
                reasoning.append("Redirect responses show server is accessible and responding")

        # TLS analysis reasoning
        if tls_analysis.handshake_complete:
            reasoning.append("Complete TLS handshake confirms secure connection establishment")
        else:
            reasoning.append("Incomplete TLS handshake detected")
            if tls_analysis.context.client_hello_count > 0:
                reasoning.append("ClientHello packets indicate traffic went through bypass engine")

        # Decision engine reasoning
        if hasattr(decision, "primary_reason"):
            reasoning.append(f"Decision engine: {decision.primary_reason}")

        # Edge case reasoning
        if edge_result and hasattr(edge_result, "reasoning"):
            reasoning.append(f"Edge case handling: {edge_result.reasoning}")

        # Legacy reasoning
        if legacy_result.error:
            reasoning.append(f"Legacy validation: {legacy_result.error}")

        return reasoning

    def _generate_troubleshooting_hints(
        self,
        legacy_result: ValidationResult,
        http_classification: Any,
        tls_analysis: Any,
        edge_result: Any,
    ) -> List[str]:
        """Generate troubleshooting hints for validation issues."""
        hints = []

        # HTTP-specific hints
        if not http_classification.is_success:
            if 400 <= http_classification.status_code < 500:
                hints.append("Client error codes may indicate blocking or access restrictions")
            elif http_classification.status_code >= 500:
                hints.append("Server error codes suggest server-side issues, not blocking")

        # TLS-specific hints
        if not tls_analysis.handshake_complete:
            if tls_analysis.context.client_hello_count == 0:
                hints.append(
                    "No ClientHello packets suggest traffic didn't go through bypass engine"
                )
            else:
                hints.append("Missing ServerHello with present ClientHello may indicate:")
                hints.append("  - QUIC/HTTP3 usage bypassing traditional TLS")
                hints.append("  - IPv6 traffic leaking around IPv4 bypass")
                hints.append("  - Timing issues in packet capture")

        # Edge case hints
        if edge_result and hasattr(edge_result, "troubleshooting_hints"):
            hints.extend(edge_result.troubleshooting_hints)

        return hints

    def _calculate_confidence_score(
        self, http_classification: Any, tls_analysis: Any, decision: Any
    ) -> float:
        """Calculate confidence score for the validation decision."""
        confidence = 0.0

        # HTTP confidence component
        if hasattr(http_classification, "confidence"):
            confidence += http_classification.confidence * 0.4

        # TLS confidence component
        if hasattr(tls_analysis, "confidence"):
            confidence += tls_analysis.confidence * 0.4

        # Decision confidence component
        if hasattr(decision, "confidence_level"):
            confidence += decision.confidence_level * 0.2

        return min(1.0, max(0.0, confidence))

    def _determine_validation_method(
        self, http_classification: Any, tls_analysis: Any, decision: Any
    ) -> str:
        """Determine which validation method was primarily used."""

        if http_classification.is_success and not tls_analysis.handshake_complete:
            return "HTTP_PRIORITY"
        elif tls_analysis.handshake_complete and http_classification.is_success:
            return "COMBINED"
        elif hasattr(decision, "validation_method"):
            return decision.validation_method
        else:
            return "LEGACY"

    def _wrap_legacy_result(self, legacy_result: ValidationResult) -> UnifiedValidationResult:
        """Wrap legacy result in unified format."""
        return UnifiedValidationResult(
            success=legacy_result.success,
            status=legacy_result.status,
            error=legacy_result.error,
            metrics=legacy_result.metrics,
            detailed_reasoning=[legacy_result.error] if legacy_result.error else [],
            troubleshooting_hints=[],
            confidence_score=0.5,  # Default confidence for legacy
            validation_method="LEGACY",
        )

    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics for the validation system.

        Returns:
            Dictionary containing performance metrics
        """
        avg_time = (
            self._total_validation_time / self._validation_count
            if self._validation_count > 0
            else 0.0
        )

        return {
            "total_validations": self._validation_count,
            "total_time_seconds": self._total_validation_time,
            "average_time_ms": avg_time * 1000,
            "validations_per_second": (
                self._validation_count / self._total_validation_time
                if self._total_validation_time > 0
                else 0.0
            ),
            "performance_cache_enabled": self._enable_performance_cache,
        }

    def reset_performance_stats(self) -> None:
        """Reset performance tracking statistics."""
        self._validation_count = 0
        self._total_validation_time = 0.0
        self.logger.info("Performance statistics reset")


def create_unified_validation_system(
    logger: Optional[logging.Logger] = None, enable_performance_cache: bool = False
) -> UnifiedValidationSystem:
    """
    Factory function for creating UnifiedValidationSystem instances.

    Args:
        logger: Optional logger instance
        enable_performance_cache: Whether to enable performance caching

    Returns:
        Configured UnifiedValidationSystem instance
    """
    return UnifiedValidationSystem(logger, enable_performance_cache)


def create_performance_optimized_system(
    logger: Optional[logging.Logger] = None,
    cache_size: int = 1000,
    cache_ttl: float = 300.0,
    enable_batch_processing: bool = True,
):
    """
    Factory function for creating performance-optimized validation system.

    Args:
        logger: Optional logger instance
        cache_size: Maximum cache size
        cache_ttl: Cache time-to-live in seconds
        enable_batch_processing: Whether to enable batch processing

    Returns:
        PerformanceOptimizedValidator wrapping UnifiedValidationSystem
    """
    from core.validation.performance_cache import create_performance_optimized_validator

    system = create_unified_validation_system(logger, enable_performance_cache=True)
    return create_performance_optimized_validator(
        system, cache_size, cache_ttl, enable_batch_processing, logger
    )
