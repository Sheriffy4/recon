#!/usr/bin/env python3
"""
Type definitions for reliability validation system.

This module contains all enums and dataclasses used across the validation system.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional


class ValidationMethod(Enum):
    """Validation methods for reliability checking."""

    HTTP_RESPONSE = "http_response"
    CONTENT_CHECK = "content_check"
    TIMING_ANALYSIS = "timing_analysis"
    MULTI_REQUEST = "multi_request"
    DEEP_INSPECTION = "deep_inspection"
    DNS_RESOLUTION = "dns_resolution"
    SSL_HANDSHAKE = "ssl_handshake"
    HEADER_ANALYSIS = "header_analysis"
    PAYLOAD_VERIFICATION = "payload_verification"


class ReliabilityLevel(Enum):
    """Reliability levels for validation results."""

    EXCELLENT = "excellent"  # 95-100% reliability
    VERY_GOOD = "very_good"  # 85-94% reliability
    GOOD = "good"  # 70-84% reliability
    MODERATE = "moderate"  # 50-69% reliability
    POOR = "poor"  # 30-49% reliability
    UNRELIABLE = "unreliable"  # 0-29% reliability


class AccessibilityStatus(Enum):
    """Status of domain accessibility."""

    ACCESSIBLE = "accessible"
    BLOCKED = "blocked"
    PARTIALLY_BLOCKED = "partially_blocked"
    TIMEOUT = "timeout"
    DNS_ERROR = "dns_error"
    SSL_ERROR = "ssl_error"
    UNKNOWN = "unknown"


@dataclass
class ValidationResult:
    """Result of a single validation method."""

    method: ValidationMethod
    success: bool
    response_time: float
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method.value if isinstance(self.method, Enum) else self.method,
            "success": self.success,
            "response_time": self.response_time,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class AccessibilityResult:
    """Result of multi-level accessibility checking."""

    domain: str
    port: int
    status: AccessibilityStatus
    validation_results: List[ValidationResult]
    reliability_score: float
    false_positive_detected: bool
    bypass_effectiveness: float
    total_tests: int
    successful_tests: int
    average_response_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "port": self.port,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "validation_results": [r.to_dict() for r in self.validation_results],
            "reliability_score": self.reliability_score,
            "false_positive_detected": self.false_positive_detected,
            "bypass_effectiveness": self.bypass_effectiveness,
            "total_tests": self.total_tests,
            "successful_tests": self.successful_tests,
            "average_response_time": self.average_response_time,
            "metadata": self.metadata,
        }


@dataclass
class StrategyEffectivenessResult:
    """Result of strategy effectiveness evaluation."""

    strategy_id: str
    domain: str
    port: int
    effectiveness_score: float
    reliability_level: ReliabilityLevel
    accessibility_results: List[AccessibilityResult]
    false_positive_rate: float
    consistency_score: float
    performance_score: float
    recommendation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "domain": self.domain,
            "port": self.port,
            "effectiveness_score": self.effectiveness_score,
            "reliability_level": (
                self.reliability_level.value
                if isinstance(self.reliability_level, Enum)
                else self.reliability_level
            ),
            "accessibility_results": [r.to_dict() for r in self.accessibility_results],
            "false_positive_rate": self.false_positive_rate,
            "consistency_score": self.consistency_score,
            "performance_score": self.performance_score,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
        }
