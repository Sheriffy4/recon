"""
Data models for root cause analysis.

This module contains all dataclass models used in root cause analysis:
- RootCauseType: Enum of possible root cause types
- ConfidenceLevel: Enum of confidence levels
- Evidence: Supporting evidence for root causes
- RootCause: Root cause of bypass failure
- CorrelatedCause: Root cause correlated with historical data
- Hypothesis: Hypothesis about failure cause and fix
- ValidatedHypothesis: Validated hypothesis with evidence
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum
import statistics


def _clamp01(value: float) -> float:
    """Clamp numeric value into [0.0, 1.0]."""
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


class RootCauseType(Enum):
    """Types of root causes for bypass failures."""

    MISSING_FAKE_PACKETS = "missing_fake_packets"
    INCORRECT_TTL = "incorrect_ttl"
    WRONG_SPLIT_POSITION = "wrong_split_position"
    MISSING_FOOLING_METHOD = "missing_fooling_method"
    SEQUENCE_OVERLAP_ERROR = "sequence_overlap_error"
    TIMING_ISSUES = "timing_issues"
    CHECKSUM_VALIDATION_ERROR = "checksum_validation_error"
    PACKET_ORDER_ERROR = "packet_order_error"
    STRATEGY_PARAMETER_MISMATCH = "strategy_parameter_mismatch"
    ENGINE_TELEMETRY_ANOMALY = "engine_telemetry_anomaly"


class ConfidenceLevel(Enum):
    """Confidence levels for root cause analysis."""

    VERY_HIGH = "very_high"  # 0.9-1.0
    HIGH = "high"  # 0.7-0.9
    MEDIUM = "medium"  # 0.5-0.7
    LOW = "low"  # 0.3-0.5
    VERY_LOW = "very_low"  # 0.0-0.3


@dataclass
class Evidence:
    """Evidence supporting a root cause hypothesis."""

    type: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = "pcap_analysis"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "description": self.description,
            "data": self.data,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class RootCause:
    """Represents a root cause of bypass failure."""

    cause_type: RootCauseType
    description: str
    affected_components: List[str]
    evidence: List[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    fix_complexity: str = "MODERATE"  # SIMPLE, MODERATE, COMPLEX

    # Impact assessment
    impact_on_success: float = 0.0  # 0.0 to 1.0
    blocking_severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL

    # Fix information
    suggested_fixes: List[str] = field(default_factory=list)
    code_locations: List[str] = field(default_factory=list)
    test_requirements: List[str] = field(default_factory=list)

    # Historical correlation
    historical_frequency: float = 0.0  # How often this cause appears
    similar_cases: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Post-initialization processing."""
        self.confidence = _clamp01(self.confidence)
        self.impact_on_success = _clamp01(self.impact_on_success)
        self.recalculate_blocking_severity()

    def recalculate_blocking_severity(self) -> None:
        """Recalculate blocking severity from current impact_on_success."""
        # Auto-determine blocking severity based on impact
        if self.impact_on_success >= 0.8:
            self.blocking_severity = "CRITICAL"
        elif self.impact_on_success >= 0.6:
            self.blocking_severity = "HIGH"
        elif self.impact_on_success >= 0.3:
            self.blocking_severity = "MEDIUM"
        else:
            self.blocking_severity = "LOW"

    def add_evidence(self, evidence: Evidence):
        """Add supporting evidence."""
        self.evidence.append(evidence)
        # Recalculate confidence based on evidence
        if self.evidence:
            self.confidence = _clamp01(statistics.mean([e.confidence for e in self.evidence]))

    def get_confidence_level(self) -> ConfidenceLevel:
        """Get confidence level enum."""
        if self.confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif self.confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif self.confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cause_type": self.cause_type.value,
            "description": self.description,
            "affected_components": self.affected_components,
            "confidence": self.confidence,
            "confidence_level": self.get_confidence_level().value,
            "fix_complexity": self.fix_complexity,
            "impact_on_success": self.impact_on_success,
            "blocking_severity": self.blocking_severity,
            "suggested_fixes": self.suggested_fixes,
            "code_locations": self.code_locations,
            "test_requirements": self.test_requirements,
            "historical_frequency": self.historical_frequency,
            "similar_cases": self.similar_cases,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class CorrelatedCause:
    """Root cause correlated with historical data."""

    root_cause: RootCause
    historical_matches: List[Dict[str, Any]] = field(default_factory=list)
    correlation_strength: float = 0.0
    pattern_frequency: float = 0.0
    success_rate_impact: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "root_cause": self.root_cause.to_dict(),
            "historical_matches": self.historical_matches,
            "correlation_strength": self.correlation_strength,
            "pattern_frequency": self.pattern_frequency,
            "success_rate_impact": self.success_rate_impact,
        }


@dataclass
class Hypothesis:
    """Hypothesis about failure cause and potential fix."""

    description: str
    root_causes: List[RootCause]
    predicted_fix: str
    confidence: float
    testable_predictions: List[str] = field(default_factory=list)
    validation_criteria: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "description": self.description,
            "predicted_fix": self.predicted_fix,
            "confidence": self.confidence,
            "testable_predictions": self.testable_predictions,
            "validation_criteria": self.validation_criteria,
            "root_causes": [rc.to_dict() for rc in self.root_causes],
        }


@dataclass
class ValidatedHypothesis:
    """Hypothesis that has been validated against evidence."""

    hypothesis: Hypothesis
    validation_score: float
    supporting_evidence: List[Evidence] = field(default_factory=list)
    contradicting_evidence: List[Evidence] = field(default_factory=list)
    is_validated: bool = False

    def __post_init__(self):
        """Post-initialization processing."""
        # NOTE:
        # Evidence lists are often populated after instantiation (see HypothesisValidator),
        # so is_validated should be recalculated there. Keep a sane default here.
        self.validation_score = _clamp01(self.validation_score)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hypothesis": self.hypothesis.to_dict(),
            "validation_score": self.validation_score,
            "is_validated": self.is_validated,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "contradicting_evidence": [e.to_dict() for e in self.contradicting_evidence],
        }
