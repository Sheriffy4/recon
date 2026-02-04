"""
Root cause analysis engine for PCAP comparison failures.

This module implements the RootCauseAnalyzer class that identifies failure causes,
correlates with historical data, generates hypotheses, and validates them using
evidence from PCAP analysis.
"""

from typing import List, Dict, Optional, Any
import json
import logging

from .critical_difference import CriticalDifference
from .pattern_recognizer import EvasionPattern, Anomaly
from .packet_info import PacketInfo

# Import models from separate module
from .models import (
    RootCauseType,
    ConfidenceLevel,
    Evidence,
    RootCause,
    CorrelatedCause,
    Hypothesis,
    ValidatedHypothesis,
)

# Import factory and helpers
from .cause_factory import CauseFactory
from .cause_helpers import CauseHelpers
from .cause_analyzer import CauseAnalyzer
from .historical_correlator import HistoricalCorrelator
from .hypothesis_generator import HypothesisGenerator
from .hypothesis_validator import HypothesisValidator

# Re-export models for backward compatibility
__all__ = [
    "RootCauseType",
    "ConfidenceLevel",
    "Evidence",
    "RootCause",
    "CorrelatedCause",
    "Hypothesis",
    "ValidatedHypothesis",
    "RootCauseAnalyzer",
]

LOG = logging.getLogger(__name__)


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

        # Initialize components
        self._factory = CauseFactory()
        self._helpers = CauseHelpers()
        self._analyzer = CauseAnalyzer(self._factory, self._helpers)
        self._correlator = HistoricalCorrelator()
        self._hypothesis_gen = HypothesisGenerator()
        self._validator = HypothesisValidator()

    def analyze_failure_causes(
        self,
        differences: List[CriticalDifference],
        patterns: List[EvasionPattern],
        anomalies: List[Anomaly] = None,
    ) -> List[RootCause]:
        """Analyze failure causes from differences, patterns, and anomalies."""
        if not differences and not patterns and not anomalies:
            return []

        anomalies = anomalies or []
        root_causes = []

        # Analyze critical differences
        root_causes.extend(self._analyzer.analyze_difference_causes(differences))

        # Analyze pattern anomalies
        root_causes.extend(self._analyzer.analyze_pattern_causes(patterns, anomalies))

        # Analyze missing patterns
        root_causes.extend(self._analyzer.analyze_missing_patterns(patterns))

        # Deduplicate and merge similar causes
        root_causes = self._validator.deduplicate_causes(root_causes)

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
        self._validator.set_historical_data(summary_data)
        correlated_causes = []

        for cause in causes:
            correlation = self._correlator.correlate_single_cause(cause, summary_data)
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
        cause_groups = self._hypothesis_gen.group_causes_by_type(causes)

        # Generate hypotheses for each group
        for cause_type, grouped_causes in cause_groups.items():
            hypothesis = self._hypothesis_gen.generate_hypothesis_for_group(
                cause_type, grouped_causes
            )
            if hypothesis:
                hypotheses.append(hypothesis)

        # Generate combined hypotheses for related causes
        combined_hypotheses = self._hypothesis_gen.generate_combined_hypotheses(causes)
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
            validation = self._validator.validate_single_hypothesis(
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
        except (FileNotFoundError, json.JSONDecodeError, IOError, OSError) as e:
            # Keep print for backwards compatibility; also log for observability.
            LOG.warning("Failed to load historical data from %s: %s", summary_file_path, e)
            print(f"Failed to load historical data: {e}")
            return False
