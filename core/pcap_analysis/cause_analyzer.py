"""
Analyzer for identifying root causes from various sources.

This module contains the CauseAnalyzer class that analyzes differences,
patterns, and anomalies to identify root causes.
"""

from typing import List, Optional
from .models import RootCause, Evidence, RootCauseType
from .pattern_recognizer import EvasionPattern, EvasionTechnique, Anomaly


class CauseAnalyzer:
    """Analyzer for identifying root causes from patterns and anomalies."""

    def __init__(self, factory, helpers):
        """Initialize cause analyzer with factory and helpers."""
        self._factory = factory
        self._helpers = helpers

    def analyze_difference_causes(self, differences) -> List[RootCause]:
        """Analyze root causes from critical differences."""
        causes = []

        for diff in differences:
            cause = self._factory.create_from_difference(diff, self._helpers)
            if cause:
                causes.append(cause)

        return causes

    def analyze_pattern_causes(self, patterns, anomalies) -> List[RootCause]:
        """Analyze root causes from pattern analysis."""
        causes = []
        patterns = patterns or []
        anomalies = anomalies or []

        # Analyze anomalies
        for anomaly in anomalies:
            cause = self._factory.create_from_anomaly(anomaly, self._helpers)
            if cause:
                causes.append(cause)

        # Analyze pattern deficiencies
        expected_techniques = {
            EvasionTechnique.FAKE_PACKET_INJECTION,
            EvasionTechnique.TTL_MANIPULATION,
            EvasionTechnique.CHECKSUM_CORRUPTION,
            EvasionTechnique.PAYLOAD_SPLITTING,
        }

        detected_techniques = {p.technique for p in patterns if p.confidence >= 0.7}
        missing_techniques = expected_techniques - detected_techniques

        for technique in missing_techniques:
            cause = self._factory.create_from_missing_technique(technique, self._helpers)
            if cause:
                causes.append(cause)

        return causes

    def analyze_missing_patterns(self, patterns: List[EvasionPattern]) -> List[RootCause]:
        """Analyze causes from missing expected patterns."""
        causes = []

        # Check for expected fakeddisorder pattern
        has_fake_injection = any(
            p.technique == EvasionTechnique.FAKE_PACKET_INJECTION
            for p in patterns
            if p.confidence >= 0.7
        )
        has_payload_splitting = any(
            p.technique == EvasionTechnique.PAYLOAD_SPLITTING
            for p in patterns
            if p.confidence >= 0.7
        )

        if not has_fake_injection:
            cause = RootCause(
                cause_type=RootCauseType.MISSING_FAKE_PACKETS,
                description="Fake packet injection pattern not detected",
                affected_components=["fake_packet_generator", "attack_engine"],
                confidence=0.8,
                impact_on_success=0.9,
            )

            evidence = Evidence(
                type="missing_pattern",
                description="Expected fake packet injection pattern not found",
                confidence=0.8,
                source="pattern_analysis",
            )
            cause.add_evidence(evidence)
            causes.append(cause)

        if not has_payload_splitting:
            cause = RootCause(
                cause_type=RootCauseType.WRONG_SPLIT_POSITION,
                description="Payload splitting pattern not detected",
                affected_components=["payload_splitter", "attack_engine"],
                confidence=0.7,
                impact_on_success=0.8,
            )

            evidence = Evidence(
                type="missing_pattern",
                description="Expected payload splitting pattern not found",
                confidence=0.7,
                source="pattern_analysis",
            )
            cause.add_evidence(evidence)
            causes.append(cause)

        return causes
