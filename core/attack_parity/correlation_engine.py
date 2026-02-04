"""
Correlation engine for matching attack events with packet modifications.

This module implements the CorrelationEngine interface to correlate logged attack
events with actual packet modifications detected in PCAP files, validating truth
consistency and attack semantic accuracy.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import logging
from collections import defaultdict

from .interfaces import CorrelationEngine
from .models import (
    AttackEvent,
    PacketModification,
    CorrelationResult,
    TruthViolation,
    PacketModificationSpec,
)
from .timing_utils import calculate_intervals
from .semantic_validators import validate_attack_specific_semantics
from .modification_matcher import ModificationMatcher
from .timing_analysis_helpers import detect_attack_bursts, generate_timing_recommendations
from .combination_validators import CombinationValidator
from .attack_type_matching import attack_type_matches_modification_type


logger = logging.getLogger(__name__)


class AttackCorrelationEngine(CorrelationEngine):
    """
    Concrete implementation of CorrelationEngine for attack parity analysis.

    This engine correlates logged attack events with packet modifications detected
    in PCAP files to validate truth consistency and semantic accuracy.
    """

    def __init__(self, timing_tolerance: float = 0.1):
        """
        Initialize the correlation engine.

        Args:
            timing_tolerance: Acceptable time difference in seconds for matching
        """
        self.timing_tolerance = timing_tolerance
        self.logger = logging.getLogger(__name__)
        self.matcher = ModificationMatcher(timing_tolerance)

    def correlate_logs_with_pcap(
        self, attacks: List[AttackEvent], modifications: List[PacketModification]
    ) -> CorrelationResult:
        """
        Correlate attack events with packet modifications.

        Args:
            attacks: List of attack events from logs
            modifications: List of packet modifications from PCAP

        Returns:
            CorrelationResult containing correlation analysis
        """
        self.logger.info(
            f"Correlating {len(attacks)} attacks with {len(modifications)} modifications"
        )

        # Group modifications by timing windows
        modification_groups = self._group_modifications_by_time(modifications)

        # Track correlation results
        semantically_correct = []
        semantically_incorrect = []
        truth_violations = []
        matched_modifications = set()

        # Correlate each attack with modifications
        for attack in attacks:
            correlation_result = self._correlate_single_attack(
                attack, modification_groups, matched_modifications
            )

            if correlation_result["is_correct"]:
                semantically_correct.append(attack)
            else:
                semantically_incorrect.append(attack)

            # Check for truth violations
            if correlation_result["violations"]:
                truth_violations.extend(correlation_result["violations"])

            # Mark modifications as matched
            matched_modifications.update(correlation_result["matched_modification_ids"])

        # Find orphaned modifications
        orphaned_modifications = self._find_orphaned_modifications(
            modifications, matched_modifications
        )

        # Calculate accuracy metrics
        metrics = self._calculate_metrics(
            attacks, modifications, semantically_correct, matched_modifications
        )

        return CorrelationResult(
            semantically_correct_attacks=semantically_correct,
            semantically_incorrect_attacks=semantically_incorrect,
            truth_consistency_violations=truth_violations,
            orphaned_modifications=orphaned_modifications,
            semantic_accuracy=metrics["semantic_accuracy"],
            truth_consistency_score=metrics["truth_consistency_score"],
        )

    def match_timing_windows(
        self, log_time: datetime, pcap_time: datetime, tolerance: float
    ) -> bool:
        """
        Check if two timestamps fall within acceptable tolerance.

        Args:
            log_time: Timestamp from log entry
            pcap_time: Timestamp from PCAP data
            tolerance: Acceptable time difference in seconds

        Returns:
            True if timestamps are within tolerance, False otherwise
        """
        # Soft-guard: coerce non-datetime timestamps to datetime where possible.
        # This avoids hard failures if upstream data contains ints/floats/isoformat strings.
        log_dt = self._coerce_timestamp(log_time)
        pcap_dt = self._coerce_timestamp(pcap_time)
        if log_dt is None or pcap_dt is None:
            self.logger.warning(
                "Cannot compare timing windows; unsupported timestamps: log_time=%r (%s), pcap_time=%r (%s)",
                log_time,
                type(log_time).__name__,
                pcap_time,
                type(pcap_time).__name__,
            )
            return False

        time_diff = abs((log_dt - pcap_dt).total_seconds())
        return time_diff <= tolerance

    def _coerce_timestamp(self, value: Any) -> Optional[datetime]:
        """
        Best-effort coercion of a timestamp into datetime.

        Supported:
        - datetime
        - int/float (unix epoch seconds)
        - isoformat strings (datetime.fromisoformat)

        Returns:
            datetime on success, None on failure.
        """
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value)
            except (OverflowError, OSError, ValueError):
                return None
        if isinstance(value, str):
            try:
                # ISO 8601 / fromisoformat-compatible
                return datetime.fromisoformat(value)
            except ValueError:
                return None
        return None

    def _group_modifications_by_time(
        self, modifications: List[PacketModification]
    ) -> Dict[datetime, List[PacketModification]]:
        """
        Group packet modifications by time windows for efficient correlation.

        Args:
            modifications: List of packet modifications

        Returns:
            Dictionary mapping time windows to modifications
        """
        groups = defaultdict(list)
        skipped = 0

        for mod in modifications:
            raw_ts = getattr(mod, "timestamp", None)
            ts = self._coerce_timestamp(raw_ts)
            if ts is None:
                skipped += 1
                self.logger.warning(
                    "Skipping PacketModification with unsupported timestamp type/value: %r (type=%s)",
                    raw_ts,
                    type(raw_ts).__name__,
                )
                continue

            # Round timestamp to nearest second for grouping
            time_key = ts.replace(microsecond=0)

            # Optional: keep coerced timestamp for downstream consumers that read mod.timestamp
            # without changing mod's external interface. If mod.timestamp is writable, update it.
            try:
                mod.timestamp = ts
            except Exception:  # nosec B110
                # Timestamp attribute may be read-only; ignore.
                pass

            groups[time_key].append(mod)

        if skipped:
            self.logger.warning("Skipped %d modifications due to invalid timestamps", skipped)

        return dict(groups)

    def _find_orphaned_modifications(
        self, modifications: List[PacketModification], matched_modifications: set
    ) -> List[PacketModification]:
        """
        Find modifications not matched to any attack.

        Args:
            modifications: All packet modifications
            matched_modifications: Set of matched modification IDs

        Returns:
            List of orphaned modifications
        """
        return [mod for mod in modifications if id(mod) not in matched_modifications]

    def _calculate_metrics(
        self,
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
        semantically_correct: List[AttackEvent],
        matched_modifications: set,
    ) -> Dict[str, float]:
        """
        Calculate accuracy metrics for correlation.

        Args:
            attacks: All attack events
            modifications: All packet modifications
            semantically_correct: List of semantically correct attacks
            matched_modifications: Set of matched modification IDs

        Returns:
            Dictionary with semantic_accuracy and truth_consistency_score
        """
        total_attacks = len(attacks)
        semantic_accuracy = len(semantically_correct) / total_attacks if total_attacks > 0 else 0.0

        total_modifications = len(modifications)
        matched_count = len(matched_modifications)
        truth_consistency_score = (
            matched_count / total_modifications if total_modifications > 0 else 0.0
        )

        return {
            "semantic_accuracy": semantic_accuracy,
            "truth_consistency_score": truth_consistency_score,
        }

    def _correlate_single_attack(
        self,
        attack: AttackEvent,
        modification_groups: Dict[datetime, List[PacketModification]],
        matched_modifications: set,
    ) -> Dict[str, Any]:
        """
        Correlate a single attack event with packet modifications.

        Args:
            attack: Attack event to correlate
            modification_groups: Grouped packet modifications by time
            matched_modifications: Set of already matched modification IDs

        Returns:
            Dictionary containing correlation results for this attack
        """
        result = {
            "is_correct": False,
            "violations": [],
            "matched_modification_ids": set(),
            "matched_modifications": [],
        }

        # Find modifications within timing window
        candidate_modifications = self.matcher.find_candidate_modifications(
            attack, modification_groups, self.match_timing_windows
        )

        # Filter out already matched modifications
        available_modifications = [
            mod for mod in candidate_modifications if id(mod) not in matched_modifications
        ]

        if not available_modifications:
            # No modifications found - potential truth violation
            violation = TruthViolation(
                attack_event=attack,
                expected_modifications=attack.expected_modifications,
                actual_modifications=[],
                violation_type="missing_modifications",
                description=f"No packet modifications found for {attack.attack_type} attack at {attack.timestamp}",
            )
            result["violations"].append(violation)
            return result

        # Match modifications to expected specifications
        matched_mods, unmatched_expected = self.matcher.match_modifications_to_expected(
            available_modifications, attack.expected_modifications
        )

        result["matched_modifications"] = matched_mods
        result["matched_modification_ids"] = {id(mod) for mod in matched_mods}

        # Check semantic correctness
        if self._validate_semantic_correctness(attack, matched_mods):
            result["is_correct"] = True

        # Check for truth violations
        if unmatched_expected:
            violation = TruthViolation(
                attack_event=attack,
                expected_modifications=unmatched_expected,
                actual_modifications=matched_mods,
                violation_type="incomplete_modifications",
                description=f"Expected modifications not found for {attack.attack_type} attack",
            )
            result["violations"].append(violation)

        # Check for unexpected modifications
        unexpected_mods = self._find_unexpected_modifications(
            matched_mods, attack.expected_modifications
        )
        if unexpected_mods:
            violation = TruthViolation(
                attack_event=attack,
                expected_modifications=attack.expected_modifications,
                actual_modifications=unexpected_mods,
                violation_type="unexpected_modifications",
                description=f"Unexpected modifications found for {attack.attack_type} attack",
            )
            result["violations"].append(violation)

        return result

    def _find_candidate_modifications(
        self, attack: AttackEvent, modification_groups: Dict[datetime, List[PacketModification]]
    ) -> List[PacketModification]:
        """
        Find packet modifications that could match the given attack (delegated to matcher).

        Args:
            attack: Attack event to find modifications for
            modification_groups: Grouped modifications by time

        Returns:
            List of candidate packet modifications
        """
        return self.matcher.find_candidate_modifications(
            attack, modification_groups, self.match_timing_windows
        )

    def _modification_matches_target(
        self, modification: PacketModification, attack: AttackEvent
    ) -> bool:
        """
        Check if a packet modification matches the attack target (delegated to matcher).

        Args:
            modification: Packet modification to check
            attack: Attack event with target information

        Returns:
            True if modification matches attack target
        """
        return self.matcher.modification_matches_target(modification, attack)

    def _match_modifications_to_expected(
        self, modifications: List[PacketModification], expected: List[PacketModificationSpec]
    ) -> Tuple[List[PacketModification], List[PacketModificationSpec]]:
        """
        Match actual modifications to expected specifications (delegated to matcher).

        Args:
            modifications: Actual packet modifications
            expected: Expected modification specifications

        Returns:
            Tuple of (matched modifications, unmatched expected specs)
        """
        return self.matcher.match_modifications_to_expected(modifications, expected)

    def _validate_semantic_correctness(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """
        Validate that modifications are semantically correct for the attack.

        Args:
            attack: Attack event with canonical definition
            modifications: Actual packet modifications

        Returns:
            True if modifications are semantically correct
        """
        if not modifications:
            return False

        # Check that all expected modifications are present
        expected_specs = attack.expected_modifications

        for expected_spec in expected_specs:
            if not any(expected_spec.matches_modification(mod) for mod in modifications):
                return False

        # Validate attack-specific semantics
        return validate_attack_specific_semantics(attack, modifications)

    def _validate_attack_specific_semantics(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """
        Validate attack-specific semantic rules (delegated to semantic_validators).

        Args:
            attack: Attack event with type and parameters
            modifications: Actual packet modifications

        Returns:
            True if attack-specific semantics are valid
        """
        return validate_attack_specific_semantics(attack, modifications)

    def _validate_split_semantics(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """Validate split attack semantics (delegated to semantic_validators)."""
        from .semantic_validators import validate_split_semantics

        return validate_split_semantics(attack, modifications)

    def _validate_multisplit_semantics(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """Validate multisplit attack semantics (delegated to semantic_validators)."""
        from .semantic_validators import validate_multisplit_semantics

        return validate_multisplit_semantics(attack, modifications)

    def _validate_disorder_semantics(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """Validate disorder attack semantics (delegated to semantic_validators)."""
        from .semantic_validators import validate_disorder_semantics

        return validate_disorder_semantics(attack, modifications)

    def _validate_fake_semantics(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """Validate fake attack semantics (delegated to semantic_validators)."""
        from .semantic_validators import validate_fake_semantics

        return validate_fake_semantics(attack, modifications)

    def _validate_combo_semantics(
        self, attack: AttackEvent, modifications: List[PacketModification]
    ) -> bool:
        """Validate combination attack semantics (delegated to semantic_validators)."""
        from .semantic_validators import validate_combo_semantics

        return validate_combo_semantics(attack, modifications)

    def _find_unexpected_modifications(
        self, modifications: List[PacketModification], expected: List[PacketModificationSpec]
    ) -> List[PacketModification]:
        """
        Find modifications that don't match any expected specification.

        Args:
            modifications: Actual packet modifications
            expected: Expected modification specifications

        Returns:
            List of unexpected modifications
        """
        unexpected = []

        for mod in modifications:
            if not any(spec.matches_modification(mod) for spec in expected):
                unexpected.append(mod)

        return unexpected


class TimingAnalyzer:
    """
    Analyzer for timing-related correlation and validation.

    This class provides specialized timing analysis capabilities for
    validating timestamp alignment and timing window correlation.
    """

    def __init__(self, default_tolerance: float = 0.1):
        """
        Initialize timing analyzer.

        Args:
            default_tolerance: Default timing tolerance in seconds
        """
        self.default_tolerance = default_tolerance

    def validate_timestamp_alignment(
        self,
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
        tolerance: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Validate timestamp alignment between attacks and modifications.

        Args:
            attacks: List of attack events
            modifications: List of packet modifications
            tolerance: Timing tolerance in seconds

        Returns:
            Dictionary containing alignment validation results
        """
        if tolerance is None:
            tolerance = self.default_tolerance

        alignment_results = {
            "aligned_pairs": [],
            "misaligned_pairs": [],
            "orphaned_attacks": [],
            "orphaned_modifications": [],
            "average_time_diff": 0.0,
            "max_time_diff": 0.0,
            "alignment_score": 0.0,
        }

        matched_attacks = set()
        matched_modifications = set()
        time_diffs = []

        # Find aligned pairs
        self._find_aligned_pairs(
            attacks,
            modifications,
            tolerance,
            alignment_results,
            matched_attacks,
            matched_modifications,
            time_diffs,
        )

        # Find orphaned items
        self._find_orphaned_items(
            attacks, modifications, matched_attacks, matched_modifications, alignment_results
        )

        # Calculate statistics
        self._calculate_alignment_statistics(alignment_results, time_diffs, attacks, modifications)

        return alignment_results

    def _find_aligned_pairs(
        self,
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
        tolerance: float,
        alignment_results: Dict[str, Any],
        matched_attacks: set,
        matched_modifications: set,
        time_diffs: List[float],
    ):
        """Find aligned attack-modification pairs within tolerance."""
        for attack in attacks:
            best_match = None
            best_time_diff = float("inf")

            for mod in modifications:
                if id(mod) in matched_modifications:
                    continue

                time_diff = abs((attack.timestamp - mod.timestamp).total_seconds())

                if time_diff <= tolerance and time_diff < best_time_diff:
                    best_match = mod
                    best_time_diff = time_diff

            if best_match:
                alignment_results["aligned_pairs"].append((attack, best_match))
                matched_attacks.add(id(attack))
                matched_modifications.add(id(best_match))
                time_diffs.append(best_time_diff)
            else:
                # Find closest modification for misalignment analysis
                if modifications:
                    closest_mod = min(
                        modifications,
                        key=lambda m: abs((attack.timestamp - m.timestamp).total_seconds()),
                    )
                    closest_diff = abs((attack.timestamp - closest_mod.timestamp).total_seconds())
                    alignment_results["misaligned_pairs"].append(
                        (attack, closest_mod, closest_diff)
                    )

    def _find_orphaned_items(
        self,
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
        matched_attacks: set,
        matched_modifications: set,
        alignment_results: Dict[str, Any],
    ):
        """Find orphaned attacks and modifications."""
        alignment_results["orphaned_attacks"] = [
            attack for attack in attacks if id(attack) not in matched_attacks
        ]
        alignment_results["orphaned_modifications"] = [
            mod for mod in modifications if id(mod) not in matched_modifications
        ]

    def _calculate_alignment_statistics(
        self,
        alignment_results: Dict[str, Any],
        time_diffs: List[float],
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
    ):
        """Calculate alignment statistics."""
        if time_diffs:
            alignment_results["average_time_diff"] = sum(time_diffs) / len(time_diffs)
            alignment_results["max_time_diff"] = max(time_diffs)

        total_items = len(attacks) + len(modifications)
        aligned_items = len(alignment_results["aligned_pairs"]) * 2
        alignment_results["alignment_score"] = (
            aligned_items / total_items if total_items > 0 else 0.0
        )

    def analyze_timing_windows(
        self,
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
        window_sizes: List[float] = None,
    ) -> Dict[str, Any]:
        """
        Analyze correlation accuracy across different timing windows.

        Args:
            attacks: List of attack events
            modifications: List of packet modifications
            window_sizes: List of window sizes to test (in seconds)

        Returns:
            Dictionary containing timing window analysis results
        """
        if window_sizes is None:
            window_sizes = [0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]

        results = {"window_analysis": [], "optimal_window": 0.1, "correlation_by_window": {}}

        best_score = 0.0

        for window_size in window_sizes:
            alignment_result = self.validate_timestamp_alignment(
                attacks, modifications, tolerance=window_size
            )

            window_result = {
                "window_size": window_size,
                "alignment_score": alignment_result["alignment_score"],
                "aligned_pairs": len(alignment_result["aligned_pairs"]),
                "misaligned_pairs": len(alignment_result["misaligned_pairs"]),
                "average_time_diff": alignment_result["average_time_diff"],
            }

            results["window_analysis"].append(window_result)
            results["correlation_by_window"][window_size] = alignment_result["alignment_score"]

            if alignment_result["alignment_score"] > best_score:
                best_score = alignment_result["alignment_score"]
                results["optimal_window"] = window_size

        return results

    def detect_timing_discrepancies(
        self,
        attacks: List[AttackEvent],
        modifications: List[PacketModification],
        threshold: float = 1.0,
    ) -> List[Dict[str, Any]]:
        """
        Detect significant timing discrepancies between attacks and modifications.

        Args:
            attacks: List of attack events
            modifications: List of packet modifications
            threshold: Threshold for significant discrepancy (in seconds)

        Returns:
            List of timing discrepancy reports
        """
        discrepancies = []

        for attack in attacks:
            # Find closest modification
            if not modifications:
                continue

            closest_mod = min(
                modifications, key=lambda m: abs((attack.timestamp - m.timestamp).total_seconds())
            )

            time_diff = abs((attack.timestamp - closest_mod.timestamp).total_seconds())

            if time_diff > threshold:
                discrepancy = {
                    "attack": attack,
                    "closest_modification": closest_mod,
                    "time_difference": time_diff,
                    "attack_timestamp": attack.timestamp,
                    "modification_timestamp": closest_mod.timestamp,
                    "severity": "high" if time_diff > threshold * 2 else "medium",
                }
                discrepancies.append(discrepancy)

        return discrepancies

    def validate_timing_consistency(
        self, attacks: List[AttackEvent], modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """
        Comprehensive timing consistency validation.

        Args:
            attacks: List of attack events
            modifications: List of packet modifications

        Returns:
            Dictionary containing comprehensive timing validation results
        """
        results = {
            "timestamp_alignment": self.validate_timestamp_alignment(attacks, modifications),
            "timing_windows": self.analyze_timing_windows(attacks, modifications),
            "discrepancies": self.detect_timing_discrepancies(attacks, modifications),
            "consistency_score": 0.0,
            "recommendations": [],
        }

        # Calculate overall consistency score
        results["consistency_score"] = self._calculate_consistency_score(results, attacks)

        # Generate recommendations
        results["recommendations"] = self._generate_consistency_recommendations(results, attacks)

        return results

    def _calculate_consistency_score(
        self, results: Dict[str, Any], attacks: List[AttackEvent]
    ) -> float:
        """Calculate overall timing consistency score."""
        alignment_score = results["timestamp_alignment"]["alignment_score"]
        window_score = (
            max(results["timing_windows"]["correlation_by_window"].values())
            if results["timing_windows"]["correlation_by_window"]
            else 0.0
        )
        discrepancy_penalty = min(1.0, len(results["discrepancies"]) / max(1, len(attacks)))

        return (alignment_score + window_score) / 2 * (1 - discrepancy_penalty)

    def _generate_consistency_recommendations(
        self, results: Dict[str, Any], attacks: List[AttackEvent]
    ) -> List[str]:
        """Generate recommendations based on consistency analysis."""
        recommendations = []

        alignment_score = results["timestamp_alignment"]["alignment_score"]
        if alignment_score < 0.5:
            recommendations.append("Consider increasing timing tolerance for better alignment")

        if len(results["discrepancies"]) > len(attacks) * 0.3:
            recommendations.append(
                "High number of timing discrepancies detected - check clock synchronization"
            )

        optimal_window = results["timing_windows"]["optimal_window"]
        if optimal_window > 1.0:
            recommendations.append(
                f"Consider using larger timing window ({optimal_window}s) for better correlation"
            )

        return recommendations

    def analyze_attack_timing_patterns(self, attacks: List[AttackEvent]) -> Dict[str, Any]:
        """
        Analyze timing patterns within attack sequences.

        Args:
            attacks: List of attack events to analyze

        Returns:
            Dictionary containing timing pattern analysis
        """
        if len(attacks) < 2:
            return {
                "intervals": [],
                "average_interval": 0.0,
                "interval_variance": 0.0,
                "timing_regularity": 0.0,
                "burst_detection": [],
            }

        # Sort attacks by timestamp
        sorted_attacks = sorted(attacks, key=lambda a: a.timestamp)

        # Calculate intervals between consecutive attacks
        intervals = calculate_intervals(sorted_attacks)

        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals) if intervals else 0.0
        variance = (
            sum((x - avg_interval) ** 2 for x in intervals) / len(intervals) if intervals else 0.0
        )

        # Calculate timing regularity (inverse of coefficient of variation)
        cv = (variance**0.5) / avg_interval if avg_interval > 0 else float("inf")
        regularity = 1.0 / (1.0 + cv) if cv != float("inf") else 0.0

        # Detect bursts (clusters of attacks in short time periods)
        bursts = detect_attack_bursts(sorted_attacks)

        return {
            "intervals": intervals,
            "average_interval": avg_interval,
            "interval_variance": variance,
            "timing_regularity": regularity,
            "burst_detection": bursts,
        }

    def _detect_attack_bursts(
        self, sorted_attacks: List[AttackEvent], burst_threshold: float = 0.1
    ) -> List[Dict[str, Any]]:
        """
        Detect bursts of attacks occurring in rapid succession (delegated to helpers).

        Args:
            sorted_attacks: Attacks sorted by timestamp
            burst_threshold: Maximum interval to consider part of a burst (seconds)

        Returns:
            List of detected burst information
        """
        return detect_attack_bursts(sorted_attacks, burst_threshold)

    def validate_cross_mode_timing(
        self, discovery_attacks: List[AttackEvent], service_attacks: List[AttackEvent]
    ) -> Dict[str, Any]:
        """
        Validate timing consistency between discovery and service modes.

        Args:
            discovery_attacks: Attacks from discovery mode
            service_attacks: Attacks from service mode

        Returns:
            Dictionary containing cross-mode timing validation results
        """
        discovery_patterns = self.analyze_attack_timing_patterns(discovery_attacks)
        service_patterns = self.analyze_attack_timing_patterns(service_attacks)

        # Compare timing characteristics
        interval_diff = abs(
            discovery_patterns["average_interval"] - service_patterns["average_interval"]
        )
        regularity_diff = abs(
            discovery_patterns["timing_regularity"] - service_patterns["timing_regularity"]
        )

        # Calculate similarity score
        max_interval = max(
            discovery_patterns["average_interval"], service_patterns["average_interval"], 1.0
        )
        interval_similarity = 1.0 - (interval_diff / max_interval)
        regularity_similarity = 1.0 - regularity_diff

        timing_similarity = (interval_similarity + regularity_similarity) / 2

        return {
            "discovery_patterns": discovery_patterns,
            "service_patterns": service_patterns,
            "interval_difference": interval_diff,
            "regularity_difference": regularity_diff,
            "timing_similarity_score": timing_similarity,
            "is_timing_consistent": timing_similarity > 0.8,
            "recommendations": generate_timing_recommendations(
                discovery_patterns, service_patterns, timing_similarity
            ),
        }

    def _generate_timing_recommendations(
        self,
        discovery_patterns: Dict[str, Any],
        service_patterns: Dict[str, Any],
        similarity_score: float,
    ) -> List[str]:
        """Generate recommendations based on timing analysis (delegated to helpers)."""
        return generate_timing_recommendations(
            discovery_patterns, service_patterns, similarity_score
        )


class CombinationCorrelationEngine:
    """
    Specialized engine for correlating attack combinations and validating
    connection preservation rules.
    """

    def __init__(self, timing_tolerance: float = 0.1):
        """
        Initialize combination correlation engine.

        Args:
            timing_tolerance: Timing tolerance for combination correlation
        """
        self.timing_tolerance = timing_tolerance
        self.base_engine = AttackCorrelationEngine(timing_tolerance)
        self.validator = CombinationValidator()
        self.logger = logging.getLogger(__name__)

    def correlate_combination_sequences(
        self, combination_attacks: List[AttackEvent], modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """
        Correlate multi-attack combination sequences with packet modifications.

        Args:
            combination_attacks: List of attacks that form combinations
            modifications: List of packet modifications from PCAP

        Returns:
            Dictionary containing combination correlation results
        """
        # Group attacks by combination sequences
        combination_sequences = self._identify_combination_sequences(combination_attacks)

        results = {
            "combination_sequences": combination_sequences,
            "sequence_correlations": [],
            "connection_preservation_results": [],
            "interaction_validations": [],
            "overall_combination_accuracy": 0.0,
        }

        # Process each sequence
        successful_correlations = self._process_combination_sequences(
            combination_sequences, modifications, results
        )

        # Calculate overall accuracy
        results["overall_combination_accuracy"] = (
            successful_correlations / len(combination_sequences)
            if len(combination_sequences) > 0
            else 0.0
        )

        return results

    def _process_combination_sequences(
        self,
        combination_sequences: List[List[AttackEvent]],
        modifications: List[PacketModification],
        results: Dict[str, Any],
    ) -> int:
        """
        Process all combination sequences and collect results.

        Args:
            combination_sequences: List of attack sequences
            modifications: Available packet modifications
            results: Results dictionary to populate

        Returns:
            Number of successful correlations
        """
        successful_correlations = 0

        for sequence in combination_sequences:
            # Correlate this combination sequence
            sequence_result = self._correlate_combination_sequence(sequence, modifications)
            results["sequence_correlations"].append(sequence_result)

            # Validate connection preservation
            preservation_result = self.validator.validate_connection_preservation(
                sequence, sequence_result["matched_modifications"]
            )
            results["connection_preservation_results"].append(preservation_result)

            # Validate attack interactions
            interaction_result = self.validator.validate_attack_interactions(
                sequence, sequence_result["matched_modifications"]
            )
            results["interaction_validations"].append(interaction_result)

            if sequence_result["is_successful"]:
                successful_correlations += 1

        return successful_correlations

    def _identify_combination_sequences(
        self, attacks: List[AttackEvent]
    ) -> List[List[AttackEvent]]:
        """
        Identify sequences of attacks that form combinations.

        Args:
            attacks: List of attack events

        Returns:
            List of attack sequences representing combinations
        """
        # Sort attacks by timestamp
        sorted_attacks = sorted(attacks, key=lambda a: a.timestamp)

        sequences = []
        current_sequence = []
        combination_window = 2.0  # 2 second window for combinations

        for attack in sorted_attacks:
            if not current_sequence:
                current_sequence = [attack]
            else:
                # Check if this attack is part of the current combination
                time_diff = (attack.timestamp - current_sequence[-1].timestamp).total_seconds()

                if time_diff <= combination_window and self.validator.attacks_can_combine(
                    current_sequence[-1], attack
                ):
                    current_sequence.append(attack)
                else:
                    # End current sequence if it has multiple attacks
                    if len(current_sequence) > 1:
                        sequences.append(current_sequence)
                    current_sequence = [attack]

        # Handle final sequence
        if len(current_sequence) > 1:
            sequences.append(current_sequence)

        return sequences

    def _attacks_can_combine(self, attack1: AttackEvent, attack2: AttackEvent) -> bool:
        """
        Check if two attacks can be part of the same combination (delegated to validator).

        Args:
            attack1: First attack
            attack2: Second attack

        Returns:
            True if attacks can combine
        """
        return self.validator.attacks_can_combine(attack1, attack2)

    def _correlate_combination_sequence(
        self, sequence: List[AttackEvent], modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """
        Correlate a single combination sequence with modifications.

        Args:
            sequence: Sequence of attacks forming a combination
            modifications: Available packet modifications

        Returns:
            Dictionary containing sequence correlation results
        """
        result = {
            "sequence": sequence,
            "matched_modifications": [],
            "unmatched_attacks": [],
            "timing_analysis": {},
            "is_successful": False,
        }

        # Find candidate modifications within time window
        candidate_modifications = self._find_candidate_modifications_for_sequence(
            sequence, modifications
        )

        # Match attacks to modifications
        matched_mods, unmatched_attacks = self._match_sequence_attacks_to_modifications(
            sequence, candidate_modifications
        )

        result["matched_modifications"] = matched_mods
        result["unmatched_attacks"] = unmatched_attacks
        result["is_successful"] = len(unmatched_attacks) == 0

        # Analyze timing within the sequence
        result["timing_analysis"] = self._analyze_sequence_timing(sequence, matched_mods)

        return result

    def _find_candidate_modifications_for_sequence(
        self, sequence: List[AttackEvent], modifications: List[PacketModification]
    ) -> List[PacketModification]:
        """Find modifications within the sequence time window."""
        sequence_start = min(attack.timestamp for attack in sequence)
        sequence_end = max(attack.timestamp for attack in sequence)

        return [
            mod
            for mod in modifications
            if sequence_start
            <= mod.timestamp
            <= sequence_end + timedelta(seconds=self.timing_tolerance)
        ]

    def _match_sequence_attacks_to_modifications(
        self, sequence: List[AttackEvent], candidate_modifications: List[PacketModification]
    ) -> Tuple[List[PacketModification], List[AttackEvent]]:
        """Match each attack in sequence to modifications."""
        matched_mods = []
        unmatched_attacks = []
        remaining_candidates = candidate_modifications.copy()

        for attack in sequence:
            attack_mods = self._find_modifications_for_attack(attack, remaining_candidates)
            if attack_mods:
                matched_mods.extend(attack_mods)
                # Remove matched modifications from candidates
                remaining_candidates = [
                    mod for mod in remaining_candidates if mod not in attack_mods
                ]
            else:
                unmatched_attacks.append(attack)

        return matched_mods, unmatched_attacks

    def _find_modifications_for_attack(
        self, attack: AttackEvent, candidate_modifications: List[PacketModification]
    ) -> List[PacketModification]:
        """
        Find modifications that match a specific attack within a combination.

        Args:
            attack: Attack to find modifications for
            candidate_modifications: Available modifications

        Returns:
            List of matching modifications
        """
        matching_mods = []

        for mod in candidate_modifications:
            if self._modification_matches_attack(mod, attack):
                matching_mods.append(mod)

        return matching_mods

    def _modification_matches_attack(
        self, modification: PacketModification, attack: AttackEvent
    ) -> bool:
        """Check if modification matches attack (timing, target, type)."""
        # Check timing
        time_diff = abs((attack.timestamp - modification.timestamp).total_seconds())
        if time_diff > self.timing_tolerance:
            return False

        # Check target matching
        if not self._modification_targets_attack(modification, attack):
            return False

        # Check attack type compatibility
        return self._modification_matches_attack_type(modification, attack)

    def _modification_targets_attack(
        self, modification: PacketModification, attack: AttackEvent
    ) -> bool:
        """Check if modification targets the same destination as attack."""
        return (
            modification.original_packet.dst_ip == attack.target_ip
            or modification.modified_packet.dst_ip == attack.target_ip
        )

    def _modification_matches_attack_type(
        self, modification: PacketModification, attack: AttackEvent
    ) -> bool:
        """Check if modification type matches attack type."""
        return attack_type_matches_modification_type(
            getattr(attack, "attack_type", None), getattr(modification, "modification_type", None)
        )

    def _analyze_sequence_timing(
        self, sequence: List[AttackEvent], modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """
        Analyze timing characteristics of a combination sequence (delegated to validator).

        Args:
            sequence: Attack sequence
            modifications: Matched modifications

        Returns:
            Dictionary containing timing analysis
        """
        return self.validator.analyze_sequence_timing(sequence, modifications)

    def _validate_connection_preservation(
        self, sequence: List[AttackEvent], modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """
        Validate that attack combinations preserve network connection integrity (delegated to validator).

        Args:
            sequence: Attack sequence
            modifications: Packet modifications from the sequence

        Returns:
            Dictionary containing connection preservation validation results
        """
        return self.validator.validate_connection_preservation(sequence, modifications)

    def _check_fragmentation_integrity(
        self, modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """Check that packet fragmentation maintains integrity (delegated to validator)."""
        return self.validator.check_fragmentation_integrity(modifications)

    def _check_tcp_sequence_validity(
        self, modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """Check that TCP sequence numbers remain valid (delegated to validator)."""
        return self.validator.check_tcp_sequence_validity(modifications)

    def _check_content_preservation(
        self, modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """Check that essential content is preserved across modifications (delegated to validator)."""
        return self.validator.check_content_preservation(modifications)

    def _validate_attack_interactions(
        self, sequence: List[AttackEvent], modifications: List[PacketModification]
    ) -> Dict[str, Any]:
        """
        Validate that attack interactions follow canonical combination rules (delegated to validator).

        Args:
            sequence: Attack sequence
            modifications: Packet modifications

        Returns:
            Dictionary containing interaction validation results
        """
        return self.validator.validate_attack_interactions(sequence, modifications)

    def _get_interaction_timing_constraints(
        self, attack_type1: str, attack_type2: str
    ) -> Optional[Dict[str, float]]:
        """Get timing constraints for attack type interactions (delegated to validator)."""
        return self.validator.get_interaction_timing_constraints(attack_type1, attack_type2)

    def _check_parameter_consistency(self, sequence: List[AttackEvent]) -> Dict[str, Any]:
        """Check that parameters are consistent across attack sequence (delegated to validator)."""
        return self.validator.check_parameter_consistency(sequence)

    def detect_combination_failures(
        self, combination_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Detect failed attack combinations and identify problematic interactions.

        Args:
            combination_results: Results from combination correlation

        Returns:
            List of detected combination failures
        """
        failures = []

        for i, sequence_result in enumerate(combination_results["sequence_correlations"]):
            preservation_result = combination_results["connection_preservation_results"][i]
            interaction_result = combination_results["interaction_validations"][i]

            # Check for correlation failures
            self._check_correlation_failure(sequence_result, failures)

            # Check for preservation failures
            self._check_preservation_failure(sequence_result, preservation_result, failures)

            # Check for interaction failures
            self._check_interaction_failure(sequence_result, interaction_result, failures)

        return failures

    def _check_correlation_failure(
        self, sequence_result: Dict[str, Any], failures: List[Dict[str, Any]]
    ):
        """Check and record correlation failures."""
        if not sequence_result["is_successful"]:
            failure = {
                "failure_type": "correlation_failure",
                "sequence": sequence_result["sequence"],
                "unmatched_attacks": sequence_result["unmatched_attacks"],
                "description": f"Failed to correlate {len(sequence_result['unmatched_attacks'])} attacks in combination",
            }
            failures.append(failure)

    def _check_preservation_failure(
        self,
        sequence_result: Dict[str, Any],
        preservation_result: Dict[str, Any],
        failures: List[Dict[str, Any]],
    ):
        """Check and record connection preservation failures."""
        if not preservation_result["connection_preserved"]:
            failure = {
                "failure_type": "connection_preservation_failure",
                "sequence": sequence_result["sequence"],
                "violations": preservation_result["violations"],
                "preservation_score": preservation_result["preservation_score"],
                "description": f"Connection preservation failed with score {preservation_result['preservation_score']}",
            }
            failures.append(failure)

    def _check_interaction_failure(
        self,
        sequence_result: Dict[str, Any],
        interaction_result: Dict[str, Any],
        failures: List[Dict[str, Any]],
    ):
        """Check and record interaction failures."""
        if not interaction_result["interactions_valid"]:
            failure = {
                "failure_type": "interaction_failure",
                "sequence": sequence_result["sequence"],
                "violations": interaction_result["interaction_violations"],
                "description": "Attack interaction rules violated",
            }
            failures.append(failure)
