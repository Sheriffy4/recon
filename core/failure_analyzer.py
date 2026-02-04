# recon/core/failure_analyzer.py
from typing import List, Dict, Any
import logging
from collections import Counter, defaultdict

from core.failure_analysis.models import (
    FailurePattern,
    FailureAnalysisResult,
    FAILURE_PATTERNS,
    TECHNIQUE_EFFECTIVENESS,
)
from core.failure_analysis.failure_classifier import classify_failure_type
from core.failure_analysis.pattern_detector import detect_failure_patterns
from core.failure_analysis.recommendation_engine import (
    generate_strategic_recommendations,
    determine_next_focus,
    get_technique_recommendations,
)
from core.failure_analysis.dpi_insights_extractor import extract_dpi_insights
from core.failure_analysis.legacy_adapter import analyze_failures as legacy_analyze_failures

LOG = logging.getLogger("FailureAnalyzer")


class FailureAnalyzer:
    """
    Анализирует причины неудач и предлагает решения.
    Enhanced version for integration with ClosedLoopManager.
    """

    # Reference to knowledge base from models
    FAILURE_PATTERNS = FAILURE_PATTERNS
    TECHNIQUE_EFFECTIVENESS = TECHNIQUE_EFFECTIVENESS

    def analyze_failures(self, test_results: List[Dict]) -> Dict[str, Any]:
        """
        Legacy method for backward compatibility.
        Delegates to legacy_adapter module.
        Анализирует паттерны неудач и выдает рекомендации.
        """
        return legacy_analyze_failures(test_results, self.FAILURE_PATTERNS)

    def analyze_closed_loop_failures(
        self, effectiveness_results: List[Any]
    ) -> FailureAnalysisResult:
        """
        Enhanced failure analysis for closed loop integration.
        Analyzes EffectivenessResult objects from real testing.

        Args:
            effectiveness_results: List of EffectivenessResult objects

        Returns:
            FailureAnalysisResult with detailed analysis and strategic recommendations
        """
        if not effectiveness_results:
            return FailureAnalysisResult(
                total_failures=0,
                failure_breakdown={},
                detected_patterns=[],
                strategic_recommendations=["No test results available for analysis"],
            )

        # Collect failure data
        failure_types = Counter()
        failed_techniques = defaultdict(list)
        success_rates = []
        latency_patterns = defaultdict(list)
        # Map to track failures per (dpi_type, attack_name) - enhanced from root file
        fingerprint_failure_map = defaultdict(lambda: defaultdict(int))

        failed_tests = 0

        for result in effectiveness_results:
            success_rates.append(result.effectiveness_score)
            technique = getattr(result.bypass, "attack_name", "unknown")

            # Collect latency patterns for all results (not just failures)
            if hasattr(result, "bypass") and hasattr(result.bypass, "latency_ms"):
                latency_patterns[technique].append(result.bypass.latency_ms)

            # Get fingerprint info if available (enhanced from root file)
            dpi_type = "unknown"
            if (
                hasattr(result, "fingerprint")
                and result.fingerprint
                and isinstance(result.fingerprint, dict)
            ):
                dpi_type = result.fingerprint.get("dpi_type", "unknown")

            # Track total runs for this pair
            fingerprint_failure_map[(dpi_type, technique)]["total_runs"] += 1

            # Classify as failure if effectiveness is very low
            if result.effectiveness_score < 0.2:
                failed_tests += 1

                # Determine failure type from result
                failure_type = self._classify_failure_type(result)
                failure_types[failure_type] += 1

                # Track which techniques failed
                failed_techniques[failure_type].append(technique)
                fingerprint_failure_map[(dpi_type, technique)]["failures"] += 1

        # Detect patterns (now with fingerprint_failure_map support)
        detected_patterns = self._detect_failure_patterns(
            failure_types,
            failed_techniques,
            success_rates,
            latency_patterns,
            fingerprint_failure_map,
        )

        # Generate strategic recommendations
        strategic_recommendations = self._generate_strategic_recommendations(
            detected_patterns, failed_techniques, success_rates
        )

        # Determine next iteration focus
        next_iteration_focus = self._determine_next_focus(detected_patterns, failed_techniques)

        # Extract DPI behavior insights
        dpi_insights = self._extract_dpi_insights(effectiveness_results, failure_types)

        return FailureAnalysisResult(
            total_failures=failed_tests,
            failure_breakdown=dict(failure_types),
            detected_patterns=detected_patterns,
            strategic_recommendations=strategic_recommendations,
            next_iteration_focus=next_iteration_focus,
            dpi_behavior_insights=dpi_insights,
        )

    def _classify_failure_type(self, result: Any) -> str:
        """
        Classify the type of failure based on EffectivenessResult.
        Delegates to failure_classifier module.

        Args:
            result: EffectivenessResult object

        Returns:
            String classification of failure type
        """
        return classify_failure_type(result, fingerprint_aware=True)

    def _detect_failure_patterns(
        self,
        failure_types: Counter,
        failed_techniques: Dict[str, List[str]],
        success_rates: List[float],
        latency_patterns: Dict[str, List[float]],
        fingerprint_failure_map: Dict = None,
    ) -> List[FailurePattern]:
        """
        Detect patterns in failures to provide insights.
        Delegates to pattern_detector module.

        Args:
            failure_types: Counter of failure types
            failed_techniques: Map of failure types to failed techniques
            success_rates: List of effectiveness scores
            latency_patterns: Map of techniques to latency measurements
            fingerprint_failure_map: Optional map of (dpi_type, attack) to failure stats

        Returns:
            List of detected FailurePattern objects
        """
        return detect_failure_patterns(
            failure_types,
            failed_techniques,
            success_rates,
            latency_patterns,
            fingerprint_failure_map,
        )

    def _generate_strategic_recommendations(
        self,
        patterns: List[FailurePattern],
        failed_techniques: Dict[str, List[str]],
        success_rates: List[float],
    ) -> List[str]:
        """
        Generate high-level strategic recommendations based on detected patterns.
        Delegates to recommendation_engine module.

        Returns:
            List of strategic recommendation strings
        """
        return generate_strategic_recommendations(patterns, failed_techniques, success_rates)

    def _determine_next_focus(
        self, patterns: List[FailurePattern], failed_techniques: Dict[str, List[str]]
    ) -> List[str]:
        """
        Determine what the next iteration should focus on.
        Delegates to recommendation_engine module.

        Returns:
            List of focus areas for next iteration
        """
        return determine_next_focus(patterns, failed_techniques)

    def _extract_dpi_insights(
        self, effectiveness_results: List[Any], failure_types: Counter
    ) -> Dict[str, Any]:
        """
        Extract insights about DPI behavior from test results.
        Delegates to dpi_insights_extractor module.

        Returns:
            Dictionary with DPI behavior insights
        """
        return extract_dpi_insights(effectiveness_results, failure_types)

    def get_technique_recommendations_for_failure_type(self, failure_type: str) -> List[str]:
        """
        Get recommended techniques for a specific failure type.
        Delegates to recommendation_engine module.

        Args:
            failure_type: Type of failure observed

        Returns:
            List of recommended technique names
        """
        return get_technique_recommendations(failure_type)
