"""
Parity checker implementation for comparing attack application between modes.

This module implements the ParityChecker interface to analyze differences between
discovery mode and service mode attack applications, ensuring universal attack
semantics consistency across execution modes.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
import logging

from .interfaces import ParityChecker as ParityCheckerInterface
from .models import (
    AttackSequence,
    AttackEvent,
    ParityResult,
    ParameterDiff,
    ExecutionMode,
    PacketModification,
    ModificationType,
    TimingInfo,
)

logger = logging.getLogger(__name__)


class ParityChecker(ParityCheckerInterface):
    """
    Concrete implementation of ParityChecker for cross-mode analysis.

    Compares attack sequences between discovery and service modes to identify
    differences in attack application, parameter usage, and timing patterns.
    """

    def __init__(self, timing_tolerance: float = 0.1):
        """
        Initialize the parity checker.

        Args:
            timing_tolerance: Acceptable timing difference ratio (0.1 = 10%)
        """
        self.timing_tolerance = timing_tolerance
        self.logger = logging.getLogger(__name__)

    def compare_attack_sequences(
        self, discovery_attacks: List[AttackSequence], service_attacks: List[AttackSequence]
    ) -> ParityResult:
        """
        Compare attack sequences between discovery and service modes.

        Args:
            discovery_attacks: Attack sequences from discovery mode
            service_attacks: Attack sequences from service mode

        Returns:
            ParityResult containing comprehensive comparison analysis
        """
        self.logger.info(
            f"Comparing {len(discovery_attacks)} discovery sequences "
            f"with {len(service_attacks)} service sequences"
        )

        # Group sequences by domain for comparison
        discovery_by_domain = self._group_sequences_by_domain(discovery_attacks)
        service_by_domain = self._group_sequences_by_domain(service_attacks)

        # Find matching sequences between modes
        matching_sequences = self._find_matching_sequences(discovery_by_domain, service_by_domain)

        # Analyze parameter differences
        parameter_differences = []
        timing_differences = []

        for discovery_seq, service_seq in matching_sequences:
            param_diffs = self.analyze_parameter_differences(discovery_seq, service_seq)
            parameter_differences.extend(param_diffs)

            timing_diff = self._analyze_timing_differences(discovery_seq, service_seq)
            if timing_diff:
                timing_differences.append(timing_diff)

        # Calculate overall parity score
        parity_score = self._calculate_parity_score(
            discovery_attacks,
            service_attacks,
            matching_sequences,
            parameter_differences,
            timing_differences,
        )

        result = ParityResult(
            discovery_sequences=discovery_attacks,
            service_sequences=service_attacks,
            matching_sequences=matching_sequences,
            parameter_differences=parameter_differences,
            timing_differences=timing_differences,
            parity_score=parity_score,
        )

        self.logger.info(f"Parity analysis complete. Score: {parity_score:.3f}")
        return result

    def analyze_parameter_differences(
        self, seq1: AttackSequence, seq2: AttackSequence
    ) -> List[ParameterDiff]:
        """
        Analyze parameter differences between two attack sequences.

        Args:
            seq1: First attack sequence (typically discovery mode)
            seq2: Second attack sequence (typically service mode)

        Returns:
            List of ParameterDiff objects describing differences
        """
        differences = []

        # Compare attack types and counts
        seq1_types = seq1.get_attack_types()
        seq2_types = seq2.get_attack_types()

        if seq1_types != seq2_types:
            differences.append(
                ParameterDiff(
                    parameter_name="attack_types",
                    value1=seq1_types,
                    value2=seq2_types,
                    impact_description="Different attack types used between modes",
                )
            )

        # Compare individual attack parameters
        for i, (attack1, attack2) in enumerate(zip(seq1.attacks, seq2.attacks)):
            if attack1.attack_type == attack2.attack_type:
                param_diffs = self._compare_attack_parameters(attack1, attack2, i)
                differences.extend(param_diffs)

        # Compare packet counts
        seq1_packets = seq1.get_total_packets()
        seq2_packets = seq2.get_total_packets()

        if seq1_packets != seq2_packets:
            differences.append(
                ParameterDiff(
                    parameter_name="total_packets",
                    value1=seq1_packets,
                    value2=seq2_packets,
                    impact_description=f"Packet count difference: {abs(seq1_packets - seq2_packets)} packets",
                )
            )

        # Compare success rates
        if abs(seq1.success_rate - seq2.success_rate) > 0.05:  # 5% tolerance
            differences.append(
                ParameterDiff(
                    parameter_name="success_rate",
                    value1=seq1.success_rate,
                    value2=seq2.success_rate,
                    impact_description=f"Success rate difference: {abs(seq1.success_rate - seq2.success_rate):.2%}",
                )
            )

        return differences

    def _group_sequences_by_domain(
        self, sequences: List[AttackSequence]
    ) -> Dict[str, List[AttackSequence]]:
        """Group attack sequences by target domain."""
        grouped = defaultdict(list)
        for seq in sequences:
            grouped[seq.domain].append(seq)
        return dict(grouped)

    def _find_matching_sequences(
        self,
        discovery_by_domain: Dict[str, List[AttackSequence]],
        service_by_domain: Dict[str, List[AttackSequence]],
    ) -> List[Tuple[AttackSequence, AttackSequence]]:
        """
        Find matching sequences between discovery and service modes.

        Sequences are considered matching if they target the same domain
        and have similar attack patterns.
        """
        matching_sequences = []

        # Find domains present in both modes
        common_domains = set(discovery_by_domain.keys()) & set(service_by_domain.keys())

        for domain in common_domains:
            discovery_seqs = discovery_by_domain[domain]
            service_seqs = service_by_domain[domain]

            # For each discovery sequence, find the best matching service sequence
            for disc_seq in discovery_seqs:
                best_match = self._find_best_matching_sequence(disc_seq, service_seqs)
                if best_match:
                    matching_sequences.append((disc_seq, best_match))

        return matching_sequences

    def _find_best_matching_sequence(
        self, target_seq: AttackSequence, candidate_seqs: List[AttackSequence]
    ) -> Optional[AttackSequence]:
        """
        Find the best matching sequence from candidates.

        Matching is based on attack type similarity and timing proximity.
        """
        if not candidate_seqs:
            return None

        best_match = None
        best_score = 0.0

        target_types = set(target_seq.get_attack_types())

        for candidate in candidate_seqs:
            candidate_types = set(candidate.get_attack_types())

            # Calculate similarity score based on attack types
            if target_types and candidate_types:
                intersection = len(target_types & candidate_types)
                union = len(target_types | candidate_types)
                type_similarity = intersection / union if union > 0 else 0.0
            else:
                type_similarity = 0.0

            # Consider timing similarity (if both have timing info)
            timing_similarity = self._calculate_timing_similarity(target_seq, candidate)

            # Combined score
            overall_score = (type_similarity * 0.7) + (timing_similarity * 0.3)

            if overall_score > best_score and overall_score > 0.5:  # Minimum threshold
                best_score = overall_score
                best_match = candidate

        return best_match

    def _calculate_timing_similarity(self, seq1: AttackSequence, seq2: AttackSequence) -> float:
        """Calculate timing similarity between two sequences."""
        # If either sequence has no duration info, return neutral score
        if seq1.total_duration.total_seconds() == 0 or seq2.total_duration.total_seconds() == 0:
            return 0.5

        duration1 = seq1.total_duration.total_seconds()
        duration2 = seq2.total_duration.total_seconds()

        # Calculate relative difference
        max_duration = max(duration1, duration2)
        min_duration = min(duration1, duration2)

        if max_duration == 0:
            return 1.0

        similarity = min_duration / max_duration
        return similarity

    def _compare_attack_parameters(
        self, attack1: AttackEvent, attack2: AttackEvent, attack_index: int
    ) -> List[ParameterDiff]:
        """Compare parameters between two individual attacks."""
        differences = []

        # Get all parameter keys from both attacks
        all_keys = set(attack1.parameters.keys()) | set(attack2.parameters.keys())

        for key in all_keys:
            val1 = attack1.parameters.get(key)
            val2 = attack2.parameters.get(key)

            if val1 != val2:
                differences.append(
                    ParameterDiff(
                        parameter_name=f"attack_{attack_index}_{key}",
                        value1=val1,
                        value2=val2,
                        impact_description=f"Parameter '{key}' differs in {attack1.attack_type} attack",
                    )
                )

        # Compare packet counts
        if attack1.packet_count != attack2.packet_count:
            differences.append(
                ParameterDiff(
                    parameter_name=f"attack_{attack_index}_packet_count",
                    value1=attack1.packet_count,
                    value2=attack2.packet_count,
                    impact_description=f"Packet count differs in {attack1.attack_type} attack",
                )
            )

        return differences

    def _analyze_timing_differences(
        self, discovery_seq: AttackSequence, service_seq: AttackSequence
    ) -> Optional[Dict[str, Any]]:
        """Analyze timing differences between sequences."""
        disc_duration = discovery_seq.total_duration.total_seconds()
        serv_duration = service_seq.total_duration.total_seconds()

        if disc_duration == 0 and serv_duration == 0:
            return None

        # Calculate relative difference
        if disc_duration == 0 or serv_duration == 0:
            relative_diff = 1.0  # 100% difference
        else:
            relative_diff = abs(disc_duration - serv_duration) / max(disc_duration, serv_duration)

        # Only report if difference exceeds tolerance
        if relative_diff > self.timing_tolerance:
            return {
                "domain": discovery_seq.domain,
                "discovery_duration": disc_duration,
                "service_duration": serv_duration,
                "relative_difference": relative_diff,
                "absolute_difference": abs(disc_duration - serv_duration),
                "exceeds_tolerance": True,
            }

        return None

    def _calculate_parity_score(
        self,
        discovery_attacks: List[AttackSequence],
        service_attacks: List[AttackSequence],
        matching_sequences: List[Tuple[AttackSequence, AttackSequence]],
        parameter_differences: List[ParameterDiff],
        timing_differences: List[Dict[str, Any]],
    ) -> float:
        """
        Calculate overall parity score between modes.

        Score ranges from 0.0 (no parity) to 1.0 (perfect parity).
        """
        if not discovery_attacks and not service_attacks:
            return 1.0  # Perfect parity if both are empty

        if not discovery_attacks or not service_attacks:
            return 0.0  # No parity if one mode has no data

        # Base score from sequence matching
        total_sequences = len(discovery_attacks) + len(service_attacks)
        matched_sequences = len(matching_sequences) * 2  # Count both sides
        sequence_score = matched_sequences / total_sequences if total_sequences > 0 else 0.0

        # Penalty for parameter differences
        if matching_sequences:
            avg_param_diffs = len(parameter_differences) / len(matching_sequences)
            param_penalty = min(avg_param_diffs * 0.1, 0.5)  # Max 50% penalty
        else:
            param_penalty = 0.5  # High penalty if no matches

        # Penalty for timing differences
        if matching_sequences:
            timing_penalty = len(timing_differences) / len(matching_sequences) * 0.2
            timing_penalty = min(timing_penalty, 0.3)  # Max 30% penalty
        else:
            timing_penalty = 0.0

        # Calculate final score
        final_score = sequence_score - param_penalty - timing_penalty
        return max(0.0, min(1.0, final_score))

    def analyze_protocol_stage_differences(
        self, discovery_seq: AttackSequence, service_seq: AttackSequence
    ) -> List[Dict[str, Any]]:
        """
        Analyze differences in protocol stage timing between modes.

        This method examines when attacks are applied relative to network
        protocol stages (handshake, data transfer, etc.).
        """
        differences = []

        # Compare timing of first attack relative to connection start
        if discovery_seq.attacks and service_seq.attacks:
            disc_first = discovery_seq.attacks[0]
            serv_first = service_seq.attacks[0]

            # If both have timing info, compare protocol stage timing
            if (
                disc_first.timing_info
                and serv_first.timing_info
                and disc_first.timing_info.start_time
                and serv_first.timing_info.start_time
            ):

                # This is a simplified analysis - in practice, you'd need more
                # sophisticated protocol stage detection
                disc_start_offset = 0  # Would calculate from connection start
                serv_start_offset = 0  # Would calculate from connection start

                if abs(disc_start_offset - serv_start_offset) > 0.1:  # 100ms tolerance
                    differences.append(
                        {
                            "type": "protocol_stage_timing",
                            "attack_type": disc_first.attack_type,
                            "discovery_offset": disc_start_offset,
                            "service_offset": serv_start_offset,
                            "difference": abs(disc_start_offset - serv_start_offset),
                        }
                    )

        return differences

    def detect_semantic_inconsistencies(
        self, discovery_seq: AttackSequence, service_seq: AttackSequence
    ) -> List[Dict[str, Any]]:
        """
        Detect semantic inconsistencies in attack application.

        This method identifies cases where the same attack type produces
        different packet modifications between modes.
        """
        inconsistencies = []

        # Group packet modifications by attack type
        disc_mods_by_type = self._group_modifications_by_attack_type(
            discovery_seq.packet_modifications
        )
        serv_mods_by_type = self._group_modifications_by_attack_type(
            service_seq.packet_modifications
        )

        # Compare modifications for each attack type
        all_attack_types = set(disc_mods_by_type.keys()) | set(serv_mods_by_type.keys())

        for attack_type in all_attack_types:
            disc_mods = disc_mods_by_type.get(attack_type, [])
            serv_mods = serv_mods_by_type.get(attack_type, [])

            # Compare modification patterns
            inconsistency = self._compare_modification_patterns(attack_type, disc_mods, serv_mods)
            if inconsistency:
                inconsistencies.append(inconsistency)

        return inconsistencies

    def _group_modifications_by_attack_type(
        self, modifications: List[PacketModification]
    ) -> Dict[str, List[PacketModification]]:
        """Group packet modifications by inferred attack type."""
        grouped = defaultdict(list)

        for mod in modifications:
            # Use attack signature if available, otherwise infer from modification type
            attack_type = mod.attack_signature or mod.modification_type.value
            grouped[attack_type].append(mod)

        return dict(grouped)

    def _compare_modification_patterns(
        self,
        attack_type: str,
        disc_mods: List[PacketModification],
        serv_mods: List[PacketModification],
    ) -> Optional[Dict[str, Any]]:
        """Compare modification patterns for a specific attack type."""
        if not disc_mods and not serv_mods:
            return None

        # If one mode has modifications but the other doesn't
        if not disc_mods or not serv_mods:
            return {
                "type": "missing_modifications",
                "attack_type": attack_type,
                "discovery_count": len(disc_mods),
                "service_count": len(serv_mods),
                "description": f"Attack {attack_type} has modifications in only one mode",
            }

        # Compare modification counts
        if len(disc_mods) != len(serv_mods):
            return {
                "type": "modification_count_mismatch",
                "attack_type": attack_type,
                "discovery_count": len(disc_mods),
                "service_count": len(serv_mods),
                "description": f"Different number of modifications for {attack_type}",
            }

        # Compare modification types
        disc_types = [mod.modification_type for mod in disc_mods]
        serv_types = [mod.modification_type for mod in serv_mods]

        if set(disc_types) != set(serv_types):
            return {
                "type": "modification_type_mismatch",
                "attack_type": attack_type,
                "discovery_types": [t.value for t in disc_types],
                "service_types": [t.value for t in serv_types],
                "description": f"Different modification types for {attack_type}",
            }

        return None
