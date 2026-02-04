"""
Factory for creating root causes from various sources.

This module contains the CauseFactory class that creates RootCause objects
from differences, anomalies, and missing techniques.
"""

from typing import Optional
from .models import RootCauseType, Evidence, RootCause
from .critical_difference import CriticalDifference, DifferenceCategory, ImpactLevel
from .pattern_recognizer import Anomaly, AnomalyType, EvasionTechnique


class CauseFactory:
    """Factory for creating root causes from various sources."""

    def __init__(self):
        """Initialize cause factory."""
        self._cause_mapping = {
            DifferenceCategory.TTL: RootCauseType.INCORRECT_TTL,
            DifferenceCategory.SEQUENCE: RootCauseType.SEQUENCE_OVERLAP_ERROR,
            DifferenceCategory.CHECKSUM: RootCauseType.CHECKSUM_VALIDATION_ERROR,
            DifferenceCategory.TIMING: RootCauseType.TIMING_ISSUES,
            DifferenceCategory.STRATEGY: RootCauseType.STRATEGY_PARAMETER_MISMATCH,
            DifferenceCategory.ORDERING: RootCauseType.PACKET_ORDER_ERROR,
        }

        self._anomaly_mapping = {
            AnomalyType.MISSING_FAKE_PACKET: RootCauseType.MISSING_FAKE_PACKETS,
            AnomalyType.INCORRECT_TTL: RootCauseType.INCORRECT_TTL,
            AnomalyType.WRONG_SPLIT_POSITION: RootCauseType.WRONG_SPLIT_POSITION,
            AnomalyType.MISSING_FOOLING_METHOD: RootCauseType.MISSING_FOOLING_METHOD,
            AnomalyType.INCORRECT_SEQUENCE_OVERLAP: RootCauseType.SEQUENCE_OVERLAP_ERROR,
            AnomalyType.TIMING_DEVIATION: RootCauseType.TIMING_ISSUES,
            AnomalyType.VALID_CHECKSUM_IN_FAKE: RootCauseType.CHECKSUM_VALIDATION_ERROR,
            AnomalyType.UNEXPECTED_PACKET_ORDER: RootCauseType.PACKET_ORDER_ERROR,
        }

        self._technique_mapping = {
            EvasionTechnique.FAKE_PACKET_INJECTION: RootCauseType.MISSING_FAKE_PACKETS,
            EvasionTechnique.TTL_MANIPULATION: RootCauseType.INCORRECT_TTL,
            EvasionTechnique.CHECKSUM_CORRUPTION: RootCauseType.CHECKSUM_VALIDATION_ERROR,
            EvasionTechnique.PAYLOAD_SPLITTING: RootCauseType.WRONG_SPLIT_POSITION,
        }

    def create_from_difference(self, diff: CriticalDifference, helpers) -> Optional[RootCause]:
        """Create root cause from a critical difference."""
        cause_type = self._cause_mapping.get(diff.category)
        if not cause_type:
            return None

        # Create evidence from difference
        evidence = Evidence(
            type="critical_difference",
            description=f"Difference detected: {diff.description}",
            data={
                "recon_value": str(diff.recon_value),
                "zapret_value": str(diff.zapret_value),
                "category": diff.category.value,
                "impact_level": diff.impact_level.value,
            },
            confidence=diff.confidence,
            source="difference_detector",
        )

        # Determine affected components
        affected_components = helpers.determine_affected_components(cause_type)

        # Create root cause
        cause = RootCause(
            cause_type=cause_type,
            description=f"{cause_type.value.replace('_', ' ').title()}: {diff.description}",
            affected_components=affected_components,
            confidence=diff.confidence,
            impact_on_success=helpers.calculate_impact_from_difference(diff),
            fix_complexity=diff.fix_complexity.value,
        )

        cause.add_evidence(evidence)

        # Add suggested fixes
        cause.suggested_fixes = helpers.generate_fixes_for_cause_type(cause_type, diff)
        cause.code_locations = helpers.identify_code_locations(cause_type)
        cause.test_requirements = helpers.generate_test_requirements(cause_type)

        return cause

    def create_from_anomaly(self, anomaly: Anomaly, helpers) -> Optional[RootCause]:
        """Create root cause from anomaly."""
        cause_type = self._anomaly_mapping.get(anomaly.anomaly_type)
        if not cause_type:
            return None

        # Create evidence from anomaly
        evidence = Evidence(
            type="anomaly_detection",
            description=anomaly.description,
            data={
                "anomaly_type": anomaly.anomaly_type.value,
                "severity": anomaly.severity,
                "expected_behavior": anomaly.expected_behavior,
                "actual_behavior": anomaly.actual_behavior,
            },
            confidence=anomaly.confidence,
            source="pattern_recognizer",
        )

        # Create root cause
        cause = RootCause(
            cause_type=cause_type,
            description=f"{cause_type.value.replace('_', ' ').title()}: {anomaly.description}",
            affected_components=helpers.determine_affected_components(cause_type),
            confidence=anomaly.confidence,
            impact_on_success=helpers.calculate_impact_from_anomaly(anomaly),
        )

        cause.add_evidence(evidence)

        # Add fix suggestions from anomaly
        if anomaly.fix_suggestion:
            cause.suggested_fixes.append(anomaly.fix_suggestion)

        cause.code_locations = helpers.identify_code_locations(cause_type)
        cause.test_requirements = helpers.generate_test_requirements(cause_type)

        return cause

    def create_from_missing_technique(self, technique: EvasionTechnique, helpers) -> RootCause:
        """Create root cause from missing evasion technique."""
        cause_type = self._technique_mapping.get(
            technique, RootCauseType.STRATEGY_PARAMETER_MISMATCH
        )

        # Create evidence
        evidence = Evidence(
            type="missing_technique",
            description=f"Missing evasion technique: {technique.value}",
            data={"technique": technique.value},
            confidence=0.8,
            source="pattern_analysis",
        )

        # Create root cause
        cause = RootCause(
            cause_type=cause_type,
            description=f"Missing {technique.value.replace('_', ' ')} implementation",
            affected_components=helpers.determine_affected_components(cause_type),
            confidence=0.8,
            impact_on_success=0.7,
        )

        cause.add_evidence(evidence)
        cause.suggested_fixes = [f"Implement {technique.value} in recon"]
        cause.code_locations = helpers.identify_code_locations(cause_type)

        return cause
