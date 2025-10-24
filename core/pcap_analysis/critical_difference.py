"""
CriticalDifference data model for PCAP analysis difference detection.
"""

from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional
from enum import Enum


class DifferenceCategory(Enum):
    """Categories of differences that can be detected."""

    SEQUENCE = "sequence"
    TIMING = "timing"
    CHECKSUM = "checksum"
    TTL = "ttl"
    STRATEGY = "strategy"
    PAYLOAD = "payload"
    FLAGS = "flags"
    WINDOW = "window"
    ORDERING = "ordering"


class ImpactLevel(Enum):
    """Impact levels for differences."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FixComplexity(Enum):
    """Complexity levels for fixing differences."""

    SIMPLE = "SIMPLE"
    MODERATE = "MODERATE"
    COMPLEX = "COMPLEX"


@dataclass
class Evidence:
    """Evidence supporting a difference detection."""

    type: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "description": self.description,
            "data": self.data,
            "confidence": self.confidence,
        }


@dataclass
class CriticalDifference:
    """
    Represents a critical difference between recon and zapret packet behavior.

    This model captures differences with confidence scoring and impact assessment
    to enable prioritization of fixes.
    """

    # Core identification
    category: DifferenceCategory
    description: str

    # Values being compared
    recon_value: Any
    zapret_value: Any

    # Impact and priority assessment
    impact_level: ImpactLevel
    confidence: float  # 0.0 to 1.0
    fix_priority: int  # 1 (highest) to 10 (lowest)
    fix_complexity: FixComplexity = FixComplexity.MODERATE

    # Supporting evidence
    evidence: List[Evidence] = field(default_factory=list)

    # Context information
    packet_indices: List[int] = field(
        default_factory=list
    )  # Indices of affected packets
    connection_key: Optional[str] = None
    timestamp_range: Optional[tuple] = None

    # Fix information
    suggested_fix: Optional[str] = None
    code_location: Optional[str] = None
    test_cases: List[str] = field(default_factory=list)

    # Metadata
    detection_method: str = "automatic"
    tags: List[str] = field(default_factory=list)
    related_differences: List[str] = field(
        default_factory=list
    )  # IDs of related differences

    def __post_init__(self):
        """Post-initialization validation and processing."""
        # Ensure confidence is in valid range
        self.confidence = max(0.0, min(1.0, self.confidence))

        # Ensure fix_priority is in valid range
        self.fix_priority = max(1, min(10, self.fix_priority))

        # Auto-generate tags based on category and impact
        if not self.tags:
            self.tags = [
                self.category.value,
                self.impact_level.value.lower(),
                f"priority_{self.fix_priority}",
            ]

    def add_evidence(
        self,
        evidence_type: str,
        description: str,
        data: Dict[str, Any] = None,
        confidence: float = 1.0,
    ):
        """Add supporting evidence for this difference."""
        evidence = Evidence(
            type=evidence_type,
            description=description,
            data=data or {},
            confidence=confidence,
        )
        self.evidence.append(evidence)

    def calculate_severity_score(self) -> float:
        """
        Calculate a numerical severity score for prioritization.

        Returns:
            float: Severity score (0.0 to 10.0, higher is more severe)
        """
        # Base score from impact level
        impact_scores = {
            ImpactLevel.CRITICAL: 10.0,
            ImpactLevel.HIGH: 7.5,
            ImpactLevel.MEDIUM: 5.0,
            ImpactLevel.LOW: 2.5,
        }

        base_score = impact_scores[self.impact_level]

        # Adjust by confidence
        confidence_adjusted = base_score * self.confidence

        # Adjust by fix priority (inverse relationship)
        priority_factor = (11 - self.fix_priority) / 10.0

        # Adjust by complexity (simpler fixes get slight boost)
        complexity_factors = {
            FixComplexity.SIMPLE: 1.1,
            FixComplexity.MODERATE: 1.0,
            FixComplexity.COMPLEX: 0.9,
        }

        complexity_factor = complexity_factors[self.fix_complexity]

        # Calculate final score
        severity_score = confidence_adjusted * priority_factor * complexity_factor

        return min(10.0, max(0.0, severity_score))

    def is_blocking(self) -> bool:
        """Check if this difference is likely blocking successful bypass."""
        blocking_indicators = [
            self.impact_level in [ImpactLevel.CRITICAL, ImpactLevel.HIGH],
            self.confidence >= 0.8,
            self.fix_priority <= 3,
            self.category
            in [
                DifferenceCategory.SEQUENCE,
                DifferenceCategory.TTL,
                DifferenceCategory.STRATEGY,
            ],
        ]

        return sum(blocking_indicators) >= 2

    def get_fix_urgency(self) -> str:
        """Get human-readable fix urgency level."""
        severity = self.calculate_severity_score()

        if severity >= 8.0:
            return "IMMEDIATE"
        elif severity >= 6.0:
            return "HIGH"
        elif severity >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "category": self.category.value,
            "description": self.description,
            "recon_value": str(self.recon_value),
            "zapret_value": str(self.zapret_value),
            "impact_level": self.impact_level.value,
            "confidence": self.confidence,
            "fix_priority": self.fix_priority,
            "fix_complexity": self.fix_complexity.value,
            "severity_score": self.calculate_severity_score(),
            "is_blocking": self.is_blocking(),
            "fix_urgency": self.get_fix_urgency(),
            "evidence": [e.to_dict() for e in self.evidence],
            "packet_indices": self.packet_indices,
            "connection_key": self.connection_key,
            "timestamp_range": self.timestamp_range,
            "suggested_fix": self.suggested_fix,
            "code_location": self.code_location,
            "test_cases": self.test_cases,
            "detection_method": self.detection_method,
            "tags": self.tags,
            "related_differences": self.related_differences,
        }

    def __str__(self) -> str:
        """String representation for debugging."""
        return (
            f"CriticalDifference({self.category.value}, "
            f"{self.impact_level.value}, "
            f"confidence={self.confidence:.2f}, "
            f"priority={self.fix_priority})"
        )

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"CriticalDifference(category={self.category.value}, "
            f"description='{self.description}', "
            f"impact={self.impact_level.value}, "
            f"confidence={self.confidence}, "
            f"priority={self.fix_priority})"
        )


@dataclass
class DifferenceGroup:
    """Group of related differences for batch processing."""

    name: str
    differences: List[CriticalDifference] = field(default_factory=list)
    group_severity: Optional[float] = None
    fix_order: List[int] = field(default_factory=list)  # Indices in order of fixing

    def add_difference(self, difference: CriticalDifference):
        """Add a difference to this group."""
        self.differences.append(difference)
        self._recalculate_group_severity()

    def _recalculate_group_severity(self):
        """Recalculate group severity based on contained differences."""
        if not self.differences:
            self.group_severity = 0.0
            return

        # Use weighted average with emphasis on highest severity
        severities = [d.calculate_severity_score() for d in self.differences]
        max_severity = max(severities)
        avg_severity = sum(severities) / len(severities)

        # Weight towards maximum severity
        self.group_severity = (max_severity * 0.7) + (avg_severity * 0.3)

    def get_fix_order(self) -> List[CriticalDifference]:
        """Get differences in recommended fix order."""
        # Sort by severity score (descending) and fix priority (ascending)
        sorted_diffs = sorted(
            self.differences,
            key=lambda d: (-d.calculate_severity_score(), d.fix_priority),
        )
        return sorted_diffs

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "group_severity": self.group_severity,
            "difference_count": len(self.differences),
            "differences": [d.to_dict() for d in self.differences],
            "fix_order": [d.to_dict() for d in self.get_fix_order()],
        }
