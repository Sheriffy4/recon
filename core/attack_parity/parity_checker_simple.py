"""
Simple parity checker for testing imports.
"""

from typing import List, Dict, Any, Optional
from .interfaces import ParityChecker as ParityCheckerInterface
from .models import AttackSequence, ParityResult, ParameterDiff


class ParityChecker(ParityCheckerInterface):
    """Simple implementation for testing."""

    def __init__(self, timing_tolerance: float = 0.1):
        self.timing_tolerance = timing_tolerance

    def compare_attack_sequences(
        self, discovery_attacks: List[AttackSequence], service_attacks: List[AttackSequence]
    ) -> ParityResult:
        """Simple comparison implementation."""
        # Calculate basic parity score
        if not discovery_attacks and not service_attacks:
            parity_score = 1.0  # Perfect parity if both are empty
        elif not discovery_attacks or not service_attacks:
            parity_score = 0.0  # No parity if one mode has no data
        else:
            # Simple parity calculation based on sequence count similarity
            total_sequences = len(discovery_attacks) + len(service_attacks)
            min_sequences = min(len(discovery_attacks), len(service_attacks))
            parity_score = (2 * min_sequences) / total_sequences if total_sequences > 0 else 1.0

        return ParityResult(
            discovery_sequences=discovery_attacks,
            service_sequences=service_attacks,
            matching_sequences=[],
            parameter_differences=[],
            timing_differences=[],
            parity_score=parity_score,
        )

    def analyze_parameter_differences(
        self, seq1: AttackSequence, seq2: AttackSequence
    ) -> List[ParameterDiff]:
        """Simple parameter analysis."""
        # Check for basic parameter differences
        differences = []

        if seq1.attacks and seq2.attacks:
            attack1 = seq1.attacks[0]
            attack2 = seq2.attacks[0]

            if attack1.attack_type == attack2.attack_type:
                # Compare parameters
                for key in set(attack1.parameters.keys()) | set(attack2.parameters.keys()):
                    val1 = attack1.parameters.get(key)
                    val2 = attack2.parameters.get(key)

                    if val1 != val2:
                        differences.append(
                            ParameterDiff(
                                parameter_name=key,
                                value1=val1,
                                value2=val2,
                                impact_description=f"Parameter '{key}' differs",
                            )
                        )

        return differences

    def analyze_protocol_stage_differences(
        self, discovery_seq: AttackSequence, service_seq: AttackSequence
    ) -> List[Dict[str, Any]]:
        """Analyze differences in protocol stage timing between modes."""
        # Simple implementation - return empty list for now
        return []

    def detect_semantic_inconsistencies(
        self, discovery_seq: AttackSequence, service_seq: AttackSequence
    ) -> List[Dict[str, Any]]:
        """Detect semantic inconsistencies in attack application."""
        # Simple implementation - return empty list for now
        return []
