"""
ResultValidator component for centralized validation logic.

This module implements the IResultValidator interface to provide centralized
validation of bypass strategy test results using both HTTP response data
and telemetry metrics.

Feature: unified-engine-refactoring
Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 6.3, 6.5
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass

from core.unified_engine_models import (
    ValidationResult,
    ValidationStatus,
    BypassDefaults,
    error_context,
)

LOG = logging.getLogger(__name__)


class IResultValidator(ABC):
    """
    Interface for result validation components.

    Requirement 2.1: Single centralized validation component interface.
    """

    @abstractmethod
    def validate(
        self,
        http_success: bool,
        http_code: int,
        telemetry: Dict[str, Any],
        connection_verified: bool = True,
    ) -> ValidationResult:
        """
        Validate test results using HTTP response and telemetry.

        Args:
            http_success: Whether HTTP request was successful
            http_code: HTTP response code
            telemetry: Telemetry data from bypass engine
            connection_verified: Whether connection target was verified

        Returns:
            ValidationResult with validation outcome and reasoning
        """
        pass

    @abstractmethod
    def set_thresholds(self, **thresholds) -> None:
        """
        Configure validation thresholds.

        Args:
            **thresholds: Threshold configuration parameters
        """
        pass


@dataclass
class ValidationThresholds:
    """
    Configuration for validation thresholds.

    Requirement 6.3: Use relative rather than absolute thresholds.
    """

    retransmission_threshold_percent: float = BypassDefaults.RETRANSMISSION_THRESHOLD_PERCENT
    min_packets_for_validation: int = BypassDefaults.MIN_PACKETS_FOR_VALIDATION
    ghost_connection_server_hello_threshold: int = 1
    high_retransmission_multiplier: float = 2.0

    def __post_init__(self):
        """Validate threshold values."""
        if self.retransmission_threshold_percent < 0 or self.retransmission_threshold_percent > 100:
            raise ValueError("retransmission_threshold_percent must be between 0 and 100")
        if self.min_packets_for_validation < 0:
            raise ValueError("min_packets_for_validation must be non-negative")
        if self.ghost_connection_server_hello_threshold < 0:
            raise ValueError("ghost_connection_server_hello_threshold must be non-negative")


class ResultValidator(IResultValidator):
    """
    Centralized validation logic for bypass strategy test results.

    This component provides consistent validation across all testing methods
    by implementing centralized logic for:
    - Ghost connection detection (HTTP success + no ServerHello)
    - Retransmission threshold validation
    - Detailed validation reasoning and transparency

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 6.3, 6.5
    """

    def __init__(self, thresholds: Optional[ValidationThresholds] = None):
        """
        Initialize the result validator.

        Args:
            thresholds: Validation threshold configuration
        """
        self.thresholds = thresholds or ValidationThresholds()
        self.logger = LOG
        self.logger.info("ResultValidator initialized with thresholds: %s", self.thresholds)

    def validate(
        self,
        http_success: bool,
        http_code: int,
        telemetry: Dict[str, Any],
        connection_verified: bool = True,
    ) -> ValidationResult:
        """
        Validate test results using HTTP response and telemetry.

        Requirement 2.1: Single centralized validation component.
        Requirement 2.2: Consistent validation logic across all testing methods.
        Requirement 2.3: Validate results using both HTTP success and telemetry data.
        Requirement 2.4: Ghost connection detection (HTTP success + no ServerHello).
        Requirement 2.5: Retransmission threshold validation.
        Requirement 6.5: Detailed validation reasoning and transparency.

        Args:
            http_success: Whether HTTP request was successful
            http_code: HTTP response code
            telemetry: Telemetry data from bypass engine
            connection_verified: Whether connection target was verified

        Returns:
            ValidationResult with validation outcome and reasoning
        """
        with error_context("result_validation", self.logger):
            self.logger.debug(
                "Validating results: http_success=%s, http_code=%d, "
                "connection_verified=%s, telemetry_keys=%s",
                http_success,
                http_code,
                connection_verified,
                list(telemetry.keys()),
            )

            # Initialize validation state
            validation_warnings = []
            reasoning_parts = []

            # Step 1: Check basic HTTP success
            if not http_success:
                reasoning_parts.append(f"HTTP request failed with code {http_code}")
                return ValidationResult(
                    success=False,
                    status=ValidationStatus.HTTP_FAILED,
                    error=f"HTTP request failed with code {http_code}",
                    metrics=telemetry,
                    confidence=1.0,
                    reasoning="; ".join(reasoning_parts),
                )

            reasoning_parts.append(f"HTTP request succeeded with code {http_code}")

            # Step 2: Extract telemetry metrics
            server_hellos = telemetry.get("server_hellos", 0)
            client_hellos = telemetry.get("client_hellos", 0)
            retransmissions = telemetry.get("retransmissions", 0)
            total_packets = telemetry.get("total_packets", 0)

            self.logger.debug(
                "Telemetry: server_hellos=%d, client_hellos=%d, "
                "retransmissions=%d, total_packets=%d",
                server_hellos,
                client_hellos,
                retransmissions,
                total_packets,
            )

            # Step 3: Ghost connection detection (Requirement 2.4)
            ghost_connection_detected = self._detect_ghost_connection(
                http_success, server_hellos, reasoning_parts
            )

            if ghost_connection_detected:
                return ValidationResult(
                    success=False,
                    status=ValidationStatus.FALSE_POSITIVE,
                    error="Ghost connection detected: HTTP success without ServerHello",
                    metrics=telemetry,
                    confidence=0.9,
                    reasoning="; ".join(reasoning_parts),
                )

            # Step 4: Check if we have sufficient traffic for validation
            if total_packets < self.thresholds.min_packets_for_validation:
                reasoning_parts.append(
                    f"Insufficient traffic for validation: {total_packets} packets "
                    f"(minimum: {self.thresholds.min_packets_for_validation})"
                )
                return ValidationResult(
                    success=False,
                    status=ValidationStatus.NO_TRAFFIC,
                    error="Insufficient network traffic for validation",
                    metrics=telemetry,
                    confidence=0.5,
                    reasoning="; ".join(reasoning_parts),
                )

            reasoning_parts.append(f"Sufficient traffic detected: {total_packets} packets")

            # Step 5: Retransmission threshold validation (Requirement 2.5)
            high_retransmissions_detected = self._validate_retransmission_threshold(
                retransmissions, total_packets, reasoning_parts
            )

            if high_retransmissions_detected:
                return ValidationResult(
                    success=False,
                    status=ValidationStatus.HIGH_RETRANSMISSIONS,
                    error="Retransmission rate exceeds threshold",
                    metrics=telemetry,
                    confidence=0.8,
                    reasoning="; ".join(reasoning_parts),
                )

            # Step 6: Check TLS handshake completion
            if client_hellos > 0 and server_hellos == 0:
                reasoning_parts.append(
                    f"TLS handshake incomplete: {client_hellos} ClientHello(s) "
                    f"but no ServerHello"
                )
                return ValidationResult(
                    success=False,
                    status=ValidationStatus.NO_HANDSHAKE,
                    error="TLS handshake not completed",
                    metrics=telemetry,
                    confidence=0.7,
                    reasoning="; ".join(reasoning_parts),
                )

            # Step 7: Connection target verification
            if not connection_verified:
                validation_warnings.append("Connection target not verified")
                reasoning_parts.append("Connection target verification failed")

            # Step 8: Success case
            reasoning_parts.append("All validation checks passed")

            # Calculate confidence based on telemetry quality
            confidence = self._calculate_confidence(telemetry, validation_warnings)

            self.logger.info("Validation successful: status=SUCCESS, confidence=%.2f", confidence)

            return ValidationResult(
                success=True,
                status=ValidationStatus.SUCCESS,
                error=None,
                metrics=telemetry,
                confidence=confidence,
                reasoning="; ".join(reasoning_parts),
            )

    def _detect_ghost_connection(
        self, http_success: bool, server_hellos: int, reasoning_parts: list
    ) -> bool:
        """
        Detect ghost connections (HTTP success + no ServerHello).

        Requirement 2.4: Ghost connection detection.

        Args:
            http_success: Whether HTTP request was successful
            server_hellos: Number of ServerHello packets detected
            reasoning_parts: List to append reasoning to

        Returns:
            True if ghost connection is detected
        """
        if http_success and server_hellos < self.thresholds.ghost_connection_server_hello_threshold:
            reasoning_parts.append(
                f"Ghost connection detected: HTTP success but only {server_hellos} "
                f"ServerHello(s) (threshold: {self.thresholds.ghost_connection_server_hello_threshold})"
            )
            self.logger.warning(
                "Ghost connection detected: HTTP success with %d ServerHello packets", server_hellos
            )
            return True

        reasoning_parts.append(f"No ghost connection: {server_hellos} ServerHello(s) detected")
        return False

    def _validate_retransmission_threshold(
        self, retransmissions: int, total_packets: int, reasoning_parts: list
    ) -> bool:
        """
        Validate retransmission rate against threshold.

        Requirement 2.5: Retransmission threshold validation.
        Requirement 6.3: Use relative rather than absolute thresholds.

        Args:
            retransmissions: Number of retransmitted packets
            total_packets: Total number of packets
            reasoning_parts: List to append reasoning to

        Returns:
            True if retransmission rate exceeds threshold
        """
        if total_packets == 0:
            reasoning_parts.append("Cannot calculate retransmission rate: no packets")
            return False

        # Calculate relative retransmission rate (Requirement 6.3)
        retransmission_rate = (retransmissions / total_packets) * 100.0

        if retransmission_rate > self.thresholds.retransmission_threshold_percent:
            reasoning_parts.append(
                f"High retransmission rate: {retransmission_rate:.1f}% "
                f"(threshold: {self.thresholds.retransmission_threshold_percent}%)"
            )
            self.logger.warning(
                "High retransmission rate detected: %.1f%% (%d/%d packets)",
                retransmission_rate,
                retransmissions,
                total_packets,
            )
            return True

        reasoning_parts.append(
            f"Acceptable retransmission rate: {retransmission_rate:.1f}% "
            f"(threshold: {self.thresholds.retransmission_threshold_percent}%)"
        )
        return False

    def _calculate_confidence(self, telemetry: Dict[str, Any], warnings: list) -> float:
        """
        Calculate confidence score based on telemetry quality.

        Args:
            telemetry: Telemetry data
            warnings: List of validation warnings

        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 1.0

        # Reduce confidence for warnings
        confidence_penalty = len(warnings) * 0.1

        # Reduce confidence for missing telemetry data
        expected_keys = ["server_hellos", "client_hellos", "retransmissions", "total_packets"]
        missing_keys = [key for key in expected_keys if key not in telemetry]
        confidence_penalty += len(missing_keys) * 0.05

        # Reduce confidence for zero values in critical metrics
        if telemetry.get("total_packets", 0) == 0:
            confidence_penalty += 0.2

        final_confidence = max(0.1, base_confidence - confidence_penalty)

        self.logger.debug(
            "Confidence calculation: base=%.2f, penalty=%.2f, final=%.2f",
            base_confidence,
            confidence_penalty,
            final_confidence,
        )

        return final_confidence

    def set_thresholds(self, **thresholds) -> None:
        """
        Configure validation thresholds.

        Args:
            **thresholds: Threshold configuration parameters
        """
        # Update thresholds while preserving existing values
        current_values = {
            "retransmission_threshold_percent": self.thresholds.retransmission_threshold_percent,
            "min_packets_for_validation": self.thresholds.min_packets_for_validation,
            "ghost_connection_server_hello_threshold": self.thresholds.ghost_connection_server_hello_threshold,
            "high_retransmission_multiplier": self.thresholds.high_retransmission_multiplier,
        }

        # Update with provided values
        current_values.update(thresholds)

        # Create new thresholds object
        self.thresholds = ValidationThresholds(**current_values)

        self.logger.info("Updated validation thresholds: %s", self.thresholds)

    def get_thresholds(self) -> ValidationThresholds:
        """
        Get current validation thresholds.

        Returns:
            Current threshold configuration
        """
        return self.thresholds


def create_result_validator(
    retransmission_threshold_percent: float = BypassDefaults.RETRANSMISSION_THRESHOLD_PERCENT,
    min_packets_for_validation: int = BypassDefaults.MIN_PACKETS_FOR_VALIDATION,
    **kwargs,
) -> ResultValidator:
    """
    Factory function for creating ResultValidator instances.

    Args:
        retransmission_threshold_percent: Threshold for retransmission rate
        min_packets_for_validation: Minimum packets required for validation
        **kwargs: Additional threshold parameters

    Returns:
        Configured ResultValidator instance
    """
    thresholds = ValidationThresholds(
        retransmission_threshold_percent=retransmission_threshold_percent,
        min_packets_for_validation=min_packets_for_validation,
        **kwargs,
    )

    return ResultValidator(thresholds)
