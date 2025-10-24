"""
Root cause analysis engine for PCAP comparison failures.

This module implements the RootCauseAnalyzer class that identifies failure causes,
correlates with historical data, generates hypotheses, and validates them using
evidence from PCAP analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import json
import statistics

from .critical_difference import CriticalDifference, DifferenceCategory, ImpactLevel
from .pattern_recognizer import EvasionPattern, Anomaly, AnomalyType, EvasionTechnique
from .packet_info import PacketInfo


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
        self.confidence = max(0.0, min(1.0, self.confidence))
        self.impact_on_success = max(0.0, min(1.0, self.impact_on_success))

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
            self.confidence = statistics.mean([e.confidence for e in self.evidence])

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
        # Determine if hypothesis is validated
        support_score = sum(e.confidence for e in self.supporting_evidence)
        contradict_score = sum(e.confidence for e in self.contradicting_evidence)

        if support_score > contradict_score and self.validation_score >= 0.7:
            self.is_validated = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hypothesis": self.hypothesis.to_dict(),
            "validation_score": self.validation_score,
            "is_validated": self.is_validated,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "contradicting_evidence": [
                e.to_dict() for e in self.contradicting_evidence
            ],
        }


class RootCauseAnalyzer:
    """Root cause analysis engine for failure cause identification."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize root cause analyzer."""
        self.config = config or {}

        # Analysis thresholds
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)
        self.correlation_threshold = self.config.get("correlation_threshold", 0.5)
        self.validation_threshold = self.config.get("validation_threshold", 0.6)

        # Historical data cache
        self._historical_data: Optional[Dict[str, Any]] = None
        self._pattern_database: Dict[str, List[Dict[str, Any]]] = {}

        # Analysis cache
        self._analysis_cache: Dict[str, List[RootCause]] = {}

    def analyze_failure_causes(
        self,
        differences: List[CriticalDifference],
        patterns: List[EvasionPattern],
        anomalies: List[Anomaly] = None,
    ) -> List[RootCause]:
        """Analyze failure causes from differences, patterns, and anomalies."""
        if not differences and not patterns:
            return []

        anomalies = anomalies or []
        root_causes = []

        # Analyze critical differences
        root_causes.extend(self._analyze_difference_causes(differences))

        # Analyze pattern anomalies
        root_causes.extend(self._analyze_pattern_causes(patterns, anomalies))

        # Analyze missing patterns
        root_causes.extend(self._analyze_missing_patterns(patterns))

        # Deduplicate and merge similar causes
        root_causes = self._deduplicate_causes(root_causes)

        # Sort by confidence and impact
        root_causes.sort(key=lambda rc: (-rc.confidence, -rc.impact_on_success))

        return root_causes

    def correlate_with_historical_data(
        self, causes: List[RootCause], summary_data: Dict[str, Any]
    ) -> List[CorrelatedCause]:
        """Correlate root causes with historical data from recon_summary.json."""
        if not causes:
            return []

        self._historical_data = summary_data
        correlated_causes = []

        for cause in causes:
            correlation = self._correlate_single_cause(cause, summary_data)
            correlated_causes.append(correlation)

        # Sort by correlation strength
        correlated_causes.sort(key=lambda cc: -cc.correlation_strength)

        return correlated_causes

    def generate_hypotheses(self, causes: List[RootCause]) -> List[Hypothesis]:
        """Generate hypotheses for different failure scenarios."""
        if not causes:
            return []

        hypotheses = []

        # Group causes by type for hypothesis generation
        cause_groups = self._group_causes_by_type(causes)

        # Generate hypotheses for each group
        for cause_type, grouped_causes in cause_groups.items():
            hypothesis = self._generate_hypothesis_for_group(cause_type, grouped_causes)
            if hypothesis:
                hypotheses.append(hypothesis)

        # Generate combined hypotheses for related causes
        combined_hypotheses = self._generate_combined_hypotheses(causes)
        hypotheses.extend(combined_hypotheses)

        # Sort by confidence
        hypotheses.sort(key=lambda h: -h.confidence)

        return hypotheses

    def validate_hypotheses(
        self,
        hypotheses: List[Hypothesis],
        recon_packets: List[PacketInfo] = None,
        zapret_packets: List[PacketInfo] = None,
    ) -> List[ValidatedHypothesis]:
        """Validate hypotheses using evidence from PCAP analysis."""
        if not hypotheses:
            return []

        validated_hypotheses = []

        for hypothesis in hypotheses:
            validation = self._validate_single_hypothesis(
                hypothesis, recon_packets, zapret_packets
            )
            validated_hypotheses.append(validation)

        # Sort by validation score
        validated_hypotheses.sort(key=lambda vh: -vh.validation_score)

        return validated_hypotheses

    def load_historical_data(self, summary_file_path: str) -> bool:
        """Load historical data from recon_summary.json file."""
        try:
            with open(summary_file_path, "r", encoding="utf-8") as f:
                self._historical_data = json.load(f)
            return True
        except Exception as e:
            print(f"Failed to load historical data: {e}")
            return False

    def _analyze_difference_causes(
        self, differences: List[CriticalDifference]
    ) -> List[RootCause]:
        """Analyze root causes from critical differences."""
        causes = []

        for diff in differences:
            cause = self._create_cause_from_difference(diff)
            if cause:
                causes.append(cause)

        return causes

    def _create_cause_from_difference(
        self, diff: CriticalDifference
    ) -> Optional[RootCause]:
        """Create root cause from a critical difference."""
        cause_mapping = {
            DifferenceCategory.TTL: RootCauseType.INCORRECT_TTL,
            DifferenceCategory.SEQUENCE: RootCauseType.SEQUENCE_OVERLAP_ERROR,
            DifferenceCategory.CHECKSUM: RootCauseType.CHECKSUM_VALIDATION_ERROR,
            DifferenceCategory.TIMING: RootCauseType.TIMING_ISSUES,
            DifferenceCategory.STRATEGY: RootCauseType.STRATEGY_PARAMETER_MISMATCH,
            DifferenceCategory.ORDERING: RootCauseType.PACKET_ORDER_ERROR,
        }

        cause_type = cause_mapping.get(diff.category)
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
        affected_components = self._determine_affected_components(cause_type)

        # Create root cause
        cause = RootCause(
            cause_type=cause_type,
            description=f"{cause_type.value.replace('_', ' ').title()}: {diff.description}",
            affected_components=affected_components,
            confidence=diff.confidence,
            impact_on_success=self._calculate_impact_from_difference(diff),
            fix_complexity=diff.fix_complexity.value,
        )

        cause.add_evidence(evidence)

        # Add suggested fixes
        cause.suggested_fixes = self._generate_fixes_for_cause_type(cause_type, diff)
        cause.code_locations = self._identify_code_locations(cause_type)
        cause.test_requirements = self._generate_test_requirements(cause_type)

        return cause

    def _analyze_pattern_causes(
        self, patterns: List[EvasionPattern], anomalies: List[Anomaly]
    ) -> List[RootCause]:
        """Analyze root causes from pattern analysis."""
        causes = []

        # Analyze anomalies
        for anomaly in anomalies:
            cause = self._create_cause_from_anomaly(anomaly)
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
            cause = self._create_cause_from_missing_technique(technique)
            if cause:
                causes.append(cause)

        return causes

    def _create_cause_from_anomaly(self, anomaly: Anomaly) -> Optional[RootCause]:
        """Create root cause from anomaly."""
        anomaly_mapping = {
            AnomalyType.MISSING_FAKE_PACKET: RootCauseType.MISSING_FAKE_PACKETS,
            AnomalyType.INCORRECT_TTL: RootCauseType.INCORRECT_TTL,
            AnomalyType.WRONG_SPLIT_POSITION: RootCauseType.WRONG_SPLIT_POSITION,
            AnomalyType.MISSING_FOOLING_METHOD: RootCauseType.MISSING_FOOLING_METHOD,
            AnomalyType.INCORRECT_SEQUENCE_OVERLAP: RootCauseType.SEQUENCE_OVERLAP_ERROR,
            AnomalyType.TIMING_DEVIATION: RootCauseType.TIMING_ISSUES,
            AnomalyType.VALID_CHECKSUM_IN_FAKE: RootCauseType.CHECKSUM_VALIDATION_ERROR,
            AnomalyType.UNEXPECTED_PACKET_ORDER: RootCauseType.PACKET_ORDER_ERROR,
        }

        cause_type = anomaly_mapping.get(anomaly.anomaly_type)
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
            affected_components=self._determine_affected_components(cause_type),
            confidence=anomaly.confidence,
            impact_on_success=self._calculate_impact_from_anomaly(anomaly),
        )

        cause.add_evidence(evidence)

        # Add fix suggestions from anomaly
        if anomaly.fix_suggestion:
            cause.suggested_fixes.append(anomaly.fix_suggestion)

        cause.code_locations = self._identify_code_locations(cause_type)
        cause.test_requirements = self._generate_test_requirements(cause_type)

        return cause

    def _create_cause_from_missing_technique(
        self, technique: EvasionTechnique
    ) -> RootCause:
        """Create root cause from missing evasion technique."""
        technique_mapping = {
            EvasionTechnique.FAKE_PACKET_INJECTION: RootCauseType.MISSING_FAKE_PACKETS,
            EvasionTechnique.TTL_MANIPULATION: RootCauseType.INCORRECT_TTL,
            EvasionTechnique.CHECKSUM_CORRUPTION: RootCauseType.CHECKSUM_VALIDATION_ERROR,
            EvasionTechnique.PAYLOAD_SPLITTING: RootCauseType.WRONG_SPLIT_POSITION,
        }

        cause_type = technique_mapping.get(
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
            affected_components=self._determine_affected_components(cause_type),
            confidence=0.8,
            impact_on_success=0.7,
        )

        cause.add_evidence(evidence)
        cause.suggested_fixes = [f"Implement {technique.value} in recon"]
        cause.code_locations = self._identify_code_locations(cause_type)

        return cause

    def _analyze_missing_patterns(
        self, patterns: List[EvasionPattern]
    ) -> List[RootCause]:
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

    def _correlate_single_cause(
        self, cause: RootCause, summary_data: Dict[str, Any]
    ) -> CorrelatedCause:
        """Correlate a single root cause with historical data."""
        correlation = CorrelatedCause(root_cause=cause)

        # Analyze strategy effectiveness data
        strategy_data = summary_data.get("strategy_effectiveness", {})
        failing_strategies = strategy_data.get("top_failing", [])

        # Look for patterns in failing strategies
        correlation.historical_matches = self._find_historical_matches(
            cause, failing_strategies
        )
        correlation.correlation_strength = self._calculate_correlation_strength(
            cause, correlation.historical_matches
        )

        # Calculate pattern frequency
        total_strategies = summary_data.get("total_strategies_tested", 1)
        correlation.pattern_frequency = len(correlation.historical_matches) / max(
            1, total_strategies
        )

        # Analyze success rate impact
        correlation.success_rate_impact = self._calculate_success_rate_impact(
            cause, summary_data
        )

        return correlation

    def _find_historical_matches(
        self, cause: RootCause, failing_strategies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find historical matches for a root cause."""
        matches = []

        for strategy in failing_strategies:
            if self._strategy_matches_cause(strategy, cause):
                matches.append(strategy)

        return matches

    def _strategy_matches_cause(
        self, strategy: Dict[str, Any], cause: RootCause
    ) -> bool:
        """Check if a strategy failure matches a root cause."""
        strategy_str = strategy.get("strategy", "").lower()
        telemetry = strategy.get("engine_telemetry", {})

        # Match based on cause type
        if cause.cause_type == RootCauseType.MISSING_FAKE_PACKETS:
            return telemetry.get("fake_packets_sent", 0) == 0

        elif cause.cause_type == RootCauseType.INCORRECT_TTL:
            return "ttl=" in strategy_str

        elif cause.cause_type == RootCauseType.WRONG_SPLIT_POSITION:
            return "split-pos=" in strategy_str or "split_pos=" in strategy_str

        elif cause.cause_type == RootCauseType.MISSING_FOOLING_METHOD:
            return (
                "fooling=" in strategy_str
                or "badsum" in strategy_str
                or "badseq" in strategy_str
            )

        elif cause.cause_type == RootCauseType.ENGINE_TELEMETRY_ANOMALY:
            return (
                telemetry.get("segments_sent", 0) == 0
                and telemetry.get("fake_packets_sent", 0) == 0
            )

        return False

    def _calculate_correlation_strength(
        self, cause: RootCause, matches: List[Dict[str, Any]]
    ) -> float:
        """Calculate correlation strength between cause and historical data."""
        if not matches:
            return 0.0

        # Base correlation on number of matches and cause confidence
        match_score = min(1.0, len(matches) * 0.2)
        confidence_score = cause.confidence

        # Adjust based on match quality
        quality_scores = []
        for match in matches:
            quality = self._assess_match_quality(cause, match)
            quality_scores.append(quality)

        avg_quality = statistics.mean(quality_scores) if quality_scores else 0.5

        return match_score * 0.4 + confidence_score * 0.3 + avg_quality * 0.3

    def _assess_match_quality(self, cause: RootCause, match: Dict[str, Any]) -> float:
        """Assess the quality of a historical match."""
        quality = 0.5  # Base quality

        # Higher quality if strategy has detailed telemetry
        telemetry = match.get("engine_telemetry", {})
        if telemetry:
            quality += 0.2

        # Higher quality if strategy has specific parameters
        strategy_str = match.get("strategy", "")
        if any(param in strategy_str for param in ["ttl=", "split-pos=", "fooling="]):
            quality += 0.2

        # Higher quality if failure is consistent (0% success rate)
        if match.get("success_rate", 0) == 0.0:
            quality += 0.1

        return min(1.0, quality)

    def _calculate_success_rate_impact(
        self, cause: RootCause, summary_data: Dict[str, Any]
    ) -> float:
        """Calculate the impact of this cause on success rate."""
        overall_success_rate = summary_data.get("key_metrics", {}).get(
            "overall_success_rate", 0.0
        )

        # If overall success rate is 0, this cause has high impact
        if overall_success_rate == 0.0:
            return cause.impact_on_success

        # Otherwise, estimate impact based on cause severity
        return cause.impact_on_success * (1.0 - overall_success_rate)

    def _group_causes_by_type(
        self, causes: List[RootCause]
    ) -> Dict[RootCauseType, List[RootCause]]:
        """Group root causes by type."""
        groups = {}
        for cause in causes:
            if cause.cause_type not in groups:
                groups[cause.cause_type] = []
            groups[cause.cause_type].append(cause)
        return groups

    def _generate_hypothesis_for_group(
        self, cause_type: RootCauseType, causes: List[RootCause]
    ) -> Optional[Hypothesis]:
        """Generate hypothesis for a group of similar causes."""
        if not causes:
            return None

        # Calculate group confidence
        group_confidence = statistics.mean([c.confidence for c in causes])

        # Generate hypothesis based on cause type
        hypothesis_templates = {
            RootCauseType.MISSING_FAKE_PACKETS: {
                "description": "Recon is not generating fake packets as expected by the fakeddisorder strategy",
                "predicted_fix": "Implement fake packet generation with correct TTL and checksum corruption",
                "testable_predictions": [
                    "Adding fake packet generation will increase fake_packets_sent telemetry",
                    "Fake packets should have TTL=3 and invalid checksums",
                    "Fake packets should be sent before real segments",
                ],
                "validation_criteria": [
                    "PCAP shows fake packets with TTL=3",
                    "Engine telemetry shows fake_packets_sent > 0",
                    "Fake packets have corrupted checksums",
                ],
            },
            RootCauseType.INCORRECT_TTL: {
                "description": "TTL values in fake packets do not match zapret behavior",
                "predicted_fix": "Set fake packet TTL to 3 to match zapret configuration",
                "testable_predictions": [
                    "Setting TTL=3 will make fake packets identical to zapret",
                    "DPI will ignore fake packets with low TTL",
                ],
                "validation_criteria": [
                    "All fake packets have TTL=3",
                    "TTL matches zapret PCAP exactly",
                ],
            },
            RootCauseType.WRONG_SPLIT_POSITION: {
                "description": "Payload split position does not match zapret implementation",
                "predicted_fix": "Adjust split position to match zapret (likely position 3)",
                "testable_predictions": [
                    "Correct split position will create identical segment sizes",
                    "Split segments will have proper sequence overlap",
                ],
                "validation_criteria": [
                    "Split position matches zapret PCAP",
                    "Segment sizes are identical to zapret",
                ],
            },
        }

        template = hypothesis_templates.get(cause_type)
        if not template:
            return None

        hypothesis = Hypothesis(
            description=template["description"],
            root_causes=causes,
            predicted_fix=template["predicted_fix"],
            confidence=group_confidence,
            testable_predictions=template["testable_predictions"],
            validation_criteria=template["validation_criteria"],
        )

        return hypothesis

    def _generate_combined_hypotheses(
        self, causes: List[RootCause]
    ) -> List[Hypothesis]:
        """Generate hypotheses that combine multiple related causes."""
        combined_hypotheses = []

        # Look for fakeddisorder-specific combination
        fake_packet_causes = [
            c for c in causes if c.cause_type == RootCauseType.MISSING_FAKE_PACKETS
        ]
        ttl_causes = [c for c in causes if c.cause_type == RootCauseType.INCORRECT_TTL]
        split_causes = [
            c for c in causes if c.cause_type == RootCauseType.WRONG_SPLIT_POSITION
        ]

        if len(fake_packet_causes) + len(ttl_causes) + len(split_causes) >= 2:
            combined_causes = fake_packet_causes + ttl_causes + split_causes
            avg_confidence = statistics.mean([c.confidence for c in combined_causes])

            hypothesis = Hypothesis(
                description="Recon's fakeddisorder implementation has multiple issues preventing successful bypass",
                root_causes=combined_causes,
                predicted_fix="Comprehensive fakeddisorder fix: implement fake packets with TTL=3, correct split position, and proper sequence overlap",
                confidence=avg_confidence,
                testable_predictions=[
                    "Complete fakeddisorder fix will match zapret behavior exactly",
                    "All telemetry metrics will match zapret patterns",
                    "Success rate will improve significantly",
                ],
                validation_criteria=[
                    "PCAP comparison shows identical packet sequences",
                    "All strategy parameters match zapret",
                    "Domain bypass success matches zapret",
                ],
            )

            combined_hypotheses.append(hypothesis)

        return combined_hypotheses

    def _validate_single_hypothesis(
        self,
        hypothesis: Hypothesis,
        recon_packets: List[PacketInfo] = None,
        zapret_packets: List[PacketInfo] = None,
    ) -> ValidatedHypothesis:
        """Validate a single hypothesis against available evidence."""
        validation = ValidatedHypothesis(hypothesis=hypothesis, validation_score=0.0)

        # Validate against PCAP evidence if available
        if recon_packets and zapret_packets:
            pcap_validation = self._validate_against_pcap(
                hypothesis, recon_packets, zapret_packets
            )
            validation.supporting_evidence.extend(pcap_validation["supporting"])
            validation.contradicting_evidence.extend(pcap_validation["contradicting"])

        # Validate against historical data
        if self._historical_data:
            historical_validation = self._validate_against_historical_data(hypothesis)
            validation.supporting_evidence.extend(historical_validation["supporting"])
            validation.contradicting_evidence.extend(
                historical_validation["contradicting"]
            )

        # Calculate validation score
        support_score = sum(e.confidence for e in validation.supporting_evidence)
        contradict_score = sum(e.confidence for e in validation.contradicting_evidence)

        total_evidence = len(validation.supporting_evidence) + len(
            validation.contradicting_evidence
        )
        if total_evidence > 0:
            validation.validation_score = (
                support_score - contradict_score
            ) / total_evidence
            validation.validation_score = max(
                0.0, min(1.0, validation.validation_score)
            )
        else:
            validation.validation_score = (
                hypothesis.confidence * 0.5
            )  # Default to half confidence

        return validation

    def _validate_against_pcap(
        self,
        hypothesis: Hypothesis,
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
    ) -> Dict[str, List[Evidence]]:
        """Validate hypothesis against PCAP evidence."""
        supporting = []
        contradicting = []

        # Check for fake packet evidence
        if any(
            "fake packet" in rc.description.lower() for rc in hypothesis.root_causes
        ):
            recon_fake_count = sum(1 for p in recon_packets if p.ttl <= 5)
            zapret_fake_count = sum(1 for p in zapret_packets if p.ttl <= 5)

            if recon_fake_count < zapret_fake_count:
                supporting.append(
                    Evidence(
                        type="pcap_validation",
                        description=f"PCAP confirms missing fake packets: recon={recon_fake_count}, zapret={zapret_fake_count}",
                        confidence=0.9,
                        source="pcap_comparison",
                    )
                )
            else:
                contradicting.append(
                    Evidence(
                        type="pcap_validation",
                        description=f"PCAP shows adequate fake packets: recon={recon_fake_count}, zapret={zapret_fake_count}",
                        confidence=0.7,
                        source="pcap_comparison",
                    )
                )

        # Check for TTL evidence
        if any("ttl" in rc.description.lower() for rc in hypothesis.root_causes):
            recon_ttls = [p.ttl for p in recon_packets if p.ttl <= 10]
            zapret_ttls = [p.ttl for p in zapret_packets if p.ttl <= 10]

            if recon_ttls and zapret_ttls:
                recon_avg_ttl = statistics.mean(recon_ttls)
                zapret_avg_ttl = statistics.mean(zapret_ttls)

                if abs(recon_avg_ttl - zapret_avg_ttl) > 1:
                    supporting.append(
                        Evidence(
                            type="pcap_validation",
                            description=f"PCAP confirms TTL mismatch: recon avg={recon_avg_ttl:.1f}, zapret avg={zapret_avg_ttl:.1f}",
                            confidence=0.8,
                            source="pcap_comparison",
                        )
                    )

        return {"supporting": supporting, "contradicting": contradicting}

    def _validate_against_historical_data(
        self, hypothesis: Hypothesis
    ) -> Dict[str, List[Evidence]]:
        """Validate hypothesis against historical data."""
        supporting = []
        contradicting = []

        if not self._historical_data:
            return {"supporting": supporting, "contradicting": contradicting}

        # Check telemetry data
        failing_strategies = self._historical_data.get(
            "strategy_effectiveness", {}
        ).get("top_failing", [])

        for strategy in failing_strategies:
            telemetry = strategy.get("engine_telemetry", {})

            # Check for fake packet hypothesis
            if any(
                "fake packet" in rc.description.lower() for rc in hypothesis.root_causes
            ):
                if telemetry.get("fake_packets_sent", 0) == 0:
                    supporting.append(
                        Evidence(
                            type="historical_validation",
                            description=f"Historical data confirms no fake packets sent in strategy: {strategy.get('strategy', 'unknown')}",
                            confidence=0.8,
                            source="historical_analysis",
                        )
                    )

        return {"supporting": supporting, "contradicting": contradicting}

    def _deduplicate_causes(self, causes: List[RootCause]) -> List[RootCause]:
        """Remove duplicate or very similar root causes."""
        if not causes:
            return causes

        deduplicated = []
        seen_types = set()

        for cause in causes:
            # Simple deduplication by cause type
            if cause.cause_type not in seen_types:
                deduplicated.append(cause)
                seen_types.add(cause.cause_type)
            else:
                # Merge evidence into existing cause of same type
                existing = next(
                    c for c in deduplicated if c.cause_type == cause.cause_type
                )
                existing.evidence.extend(cause.evidence)
                # Update confidence to average
                if existing.evidence:
                    existing.confidence = statistics.mean(
                        [e.confidence for e in existing.evidence]
                    )

        return deduplicated

    def _determine_affected_components(self, cause_type: RootCauseType) -> List[str]:
        """Determine which components are affected by a cause type."""
        component_mapping = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "fake_packet_generator",
                "attack_engine",
                "packet_sender",
            ],
            RootCauseType.INCORRECT_TTL: ["packet_builder", "fake_packet_generator"],
            RootCauseType.WRONG_SPLIT_POSITION: [
                "payload_splitter",
                "segment_generator",
            ],
            RootCauseType.MISSING_FOOLING_METHOD: [
                "checksum_corruptor",
                "sequence_manipulator",
            ],
            RootCauseType.SEQUENCE_OVERLAP_ERROR: [
                "sequence_calculator",
                "segment_generator",
            ],
            RootCauseType.TIMING_ISSUES: ["packet_scheduler", "timing_controller"],
            RootCauseType.CHECKSUM_VALIDATION_ERROR: [
                "checksum_calculator",
                "packet_validator",
            ],
            RootCauseType.PACKET_ORDER_ERROR: ["packet_scheduler", "sequence_manager"],
            RootCauseType.STRATEGY_PARAMETER_MISMATCH: [
                "strategy_parser",
                "parameter_validator",
            ],
            RootCauseType.ENGINE_TELEMETRY_ANOMALY: [
                "telemetry_collector",
                "metrics_reporter",
            ],
        }

        return component_mapping.get(cause_type, ["unknown_component"])

    def _calculate_impact_from_difference(self, diff: CriticalDifference) -> float:
        """Calculate impact on success from a critical difference."""
        impact_mapping = {
            ImpactLevel.CRITICAL: 0.9,
            ImpactLevel.HIGH: 0.7,
            ImpactLevel.MEDIUM: 0.5,
            ImpactLevel.LOW: 0.3,
        }

        base_impact = impact_mapping.get(diff.impact_level, 0.5)

        # Adjust by confidence
        return base_impact * diff.confidence

    def _calculate_impact_from_anomaly(self, anomaly: Anomaly) -> float:
        """Calculate impact on success from an anomaly."""
        severity_mapping = {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}

        base_impact = severity_mapping.get(anomaly.severity, 0.5)

        # Adjust by confidence
        return base_impact * anomaly.confidence

    def _generate_fixes_for_cause_type(
        self, cause_type: RootCauseType, diff: CriticalDifference
    ) -> List[str]:
        """Generate suggested fixes for a cause type."""
        fix_templates = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "Implement fake packet generation in attack engine",
                "Add fake packet injection before real segments",
                "Ensure fake packets have correct TTL and corrupted checksums",
            ],
            RootCauseType.INCORRECT_TTL: [
                f"Set fake packet TTL to {diff.zapret_value} to match zapret",
                "Update TTL configuration in packet builder",
                "Validate TTL values in fake packet generation",
            ],
            RootCauseType.WRONG_SPLIT_POSITION: [
                f"Adjust split position to {diff.zapret_value}",
                "Fix payload splitting algorithm",
                "Validate split position calculation",
            ],
            RootCauseType.MISSING_FOOLING_METHOD: [
                "Implement badsum fooling method",
                "Implement badseq fooling method",
                "Add checksum corruption to fake packets",
            ],
            RootCauseType.SEQUENCE_OVERLAP_ERROR: [
                "Fix sequence number overlap calculation",
                "Ensure proper sequence number progression",
                "Validate segment sequence numbers",
            ],
        }

        return fix_templates.get(
            cause_type, ["Fix implementation to match zapret behavior"]
        )

    def _identify_code_locations(self, cause_type: RootCauseType) -> List[str]:
        """Identify likely code locations for a cause type."""
        location_mapping = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                "recon/core/packet/packet_builder.py",
            ],
            RootCauseType.INCORRECT_TTL: [
                "recon/core/packet/packet_builder.py",
                "recon/core/bypass/packet/builder.py",
            ],
            RootCauseType.WRONG_SPLIT_POSITION: [
                "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                "recon/core/packet/packet_builder.py",
            ],
            RootCauseType.MISSING_FOOLING_METHOD: [
                "recon/core/bypass/techniques/primitives.py",
                "recon/core/packet/packet_builder.py",
            ],
        }

        return location_mapping.get(cause_type, ["unknown_location"])

    def _generate_test_requirements(self, cause_type: RootCauseType) -> List[str]:
        """Generate test requirements for a cause type."""
        test_templates = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "Test fake packet generation",
                "Verify fake packet count in telemetry",
                "Compare PCAP with zapret",
            ],
            RootCauseType.INCORRECT_TTL: [
                "Test TTL values in fake packets",
                "Verify TTL matches zapret configuration",
                "Test TTL impact on bypass success",
            ],
            RootCauseType.WRONG_SPLIT_POSITION: [
                "Test split position calculation",
                "Verify segment sizes match zapret",
                "Test split position impact on bypass",
            ],
        }

        return test_templates.get(cause_type, ["Test fix implementation"])
