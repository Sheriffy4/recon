"""
Combination attack validation logic.

This module provides specialized validation for attack combinations,
extracted from CombinationCorrelationEngine to reduce god class complexity.
"""

from typing import List, Dict, Any, Optional


class CombinationValidator:
    """
    Validator for attack combination sequences and connection preservation.
    """

    def __init__(self):
        """Initialize combination validator."""
        pass

    def attacks_can_combine(self, attack1, attack2) -> bool:
        """
        Check if two attacks can be part of the same combination.

        Args:
            attack1: First attack
            attack2: Second attack

        Returns:
            True if attacks can combine
        """
        # Same target domain/IP
        if attack1.target_domain != attack2.target_domain or attack1.target_ip != attack2.target_ip:
            return False

        # Different attack types (combinations involve multiple types)
        if attack1.attack_type == attack2.attack_type:
            return False

        # Check for known combination patterns
        combo_patterns = [
            {"disorder", "multisplit"},
            {"fake", "split"},
            {"disorder", "fake"},
            {"split", "multisplit"},
        ]

        attack_types = {attack1.attack_type, attack2.attack_type}
        return any(attack_types.issubset(pattern) for pattern in combo_patterns)

    def analyze_sequence_timing(self, sequence: List, modifications: List) -> Dict[str, Any]:
        """
        Analyze timing characteristics of a combination sequence.

        Args:
            sequence: Attack sequence
            modifications: Matched modifications

        Returns:
            Dictionary containing timing analysis
        """
        from .timing_utils import calculate_intervals

        if len(sequence) < 2:
            return {"intervals": [], "total_duration": 0.0, "timing_regularity": 1.0}

        # Calculate intervals between attacks
        sorted_attacks = sorted(sequence, key=lambda a: a.timestamp)
        intervals = calculate_intervals(sorted_attacks)

        total_duration = (
            sorted_attacks[-1].timestamp - sorted_attacks[0].timestamp
        ).total_seconds()

        # Calculate timing regularity
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            cv = (variance**0.5) / avg_interval if avg_interval > 0 else float("inf")
            regularity = 1.0 / (1.0 + cv) if cv != float("inf") else 0.0
        else:
            regularity = 1.0

        return {
            "intervals": intervals,
            "total_duration": total_duration,
            "timing_regularity": regularity,
            "modification_count": len(modifications),
        }

    def validate_connection_preservation(
        self, sequence: List, modifications: List
    ) -> Dict[str, Any]:
        """
        Validate that attack combinations preserve network connection integrity.

        Args:
            sequence: Attack sequence
            modifications: Packet modifications from the sequence

        Returns:
            Dictionary containing connection preservation validation results
        """
        result = {
            "sequence_id": "unknown_sequence",
            "connection_preserved": True,
            "violations": [],
            "preservation_score": 1.0,
            "checks_performed": [],
        }

        if not sequence:
            result["connection_preserved"] = False
            result["violations"].append("Empty combination sequence")
            result["preservation_score"] = 0.0
            return result

        # Keep original ID format when sequence exists
        result["sequence_id"] = f"{sequence[0].target_domain}_{sequence[0].timestamp.isoformat()}"

        if not modifications:
            result["connection_preserved"] = False
            result["violations"].append("No modifications found for combination sequence")
            result["preservation_score"] = 0.0
            return result

        # Check 1: Packet fragmentation integrity
        fragmentation_check = self.check_fragmentation_integrity(modifications)
        result["checks_performed"].append("fragmentation_integrity")
        if not fragmentation_check["passed"]:
            result["connection_preserved"] = False
            result["violations"].extend(fragmentation_check["violations"])

        # Check 2: TCP sequence number validity
        tcp_check = self.check_tcp_sequence_validity(modifications)
        result["checks_performed"].append("tcp_sequence_validity")
        if not tcp_check["passed"]:
            result["connection_preserved"] = False
            result["violations"].extend(tcp_check["violations"])

        # Check 3: Content preservation across modifications
        content_check = self.check_content_preservation(modifications)
        result["checks_performed"].append("content_preservation")
        if not content_check["passed"]:
            result["connection_preserved"] = False
            result["violations"].extend(content_check["violations"])

        # Calculate preservation score
        passed_checks = sum(
            1 for check in [fragmentation_check, tcp_check, content_check] if check["passed"]
        )
        result["preservation_score"] = passed_checks / 3.0

        return result

    def check_fragmentation_integrity(self, modifications: List) -> Dict[str, Any]:
        """Check that packet fragmentation maintains integrity."""
        result = {"passed": True, "violations": []}

        # Group modifications by connection
        connections = {}
        for mod in modifications:
            conn_key = mod.original_packet.get_connection_tuple()
            if conn_key not in connections:
                connections[conn_key] = []
            connections[conn_key].append(mod)

        # Check each connection
        for conn_key, conn_mods in connections.items():
            # Check that total content size is preserved
            total_original_size = sum(mod.original_packet.size for mod in conn_mods)
            total_modified_size = sum(mod.modified_packet.size for mod in conn_mods)

            # Allow for reasonable fragmentation overhead
            if total_modified_size > total_original_size * 1.1:  # 10% overhead allowance
                result["passed"] = False
                result["violations"].append(
                    f"Connection {conn_key}: Modified size ({total_modified_size}) "
                    f"exceeds original ({total_original_size}) by more than 10%"
                )

        return result

    def check_tcp_sequence_validity(self, modifications: List) -> Dict[str, Any]:
        """Check that TCP sequence numbers remain valid."""
        result = {"passed": True, "violations": []}

        tcp_modifications = [
            mod for mod in modifications if mod.original_packet.protocol.upper() == "TCP"
        ]

        for mod in tcp_modifications:
            orig_seq = mod.original_packet.sequence_number
            mod_seq = mod.modified_packet.sequence_number

            if orig_seq is not None and mod_seq is not None:
                # Sequence numbers should be reasonable (not wildly different)
                seq_diff = abs(mod_seq - orig_seq)
                if seq_diff > 1000000:  # Arbitrary large difference threshold
                    result["passed"] = False
                    result["violations"].append(
                        f"Large TCP sequence number change: {orig_seq} -> {mod_seq}"
                    )

        return result

    def check_content_preservation(self, modifications: List) -> Dict[str, Any]:
        """Check that essential content is preserved across modifications."""
        result = {"passed": True, "violations": []}

        # Check that modifications don't completely eliminate content
        for mod in modifications:
            if mod.original_packet.payload_size > 0 and mod.modified_packet.payload_size == 0:
                result["passed"] = False
                result["violations"].append("Modification eliminated all payload content")

        return result

    def validate_attack_interactions(self, sequence: List, modifications: List) -> Dict[str, Any]:
        """
        Validate that attack interactions follow canonical combination rules.

        Args:
            sequence: Attack sequence
            modifications: Packet modifications

        Returns:
            Dictionary containing interaction validation results
        """
        result = {
            "sequence_types": [attack.attack_type for attack in sequence],
            "interactions_valid": True,
            "interaction_violations": [],
            "timing_compliance": True,
            "parameter_consistency": True,
        }

        if len(sequence) < 2:
            return result

        # SR6 fix: modifications parameter is now used to validate interaction observability.
        if not modifications:
            result["interactions_valid"] = False
            result["timing_compliance"] = False
            result["interaction_violations"].append(
                "No modifications provided for interaction validation"
            )
            return result

        # Minimal sanity: ensure there is at least some modification activity for the sequence.
        # (Do not overfit to exact types to avoid false negatives.)
        if len(modifications) < 1:
            result["interactions_valid"] = False
            result["interaction_violations"].append("Empty modifications list")
            return result

        # Check timing constraints between attacks
        for i in range(len(sequence) - 1):
            attack1, attack2 = sequence[i], sequence[i + 1]
            time_diff = (attack2.timestamp - attack1.timestamp).total_seconds()

            # Validate timing constraints based on attack types
            expected_constraints = self.get_interaction_timing_constraints(
                attack1.attack_type, attack2.attack_type
            )

            if expected_constraints:
                if not (
                    expected_constraints["min_delay"]
                    <= time_diff
                    <= expected_constraints["max_delay"]
                ):
                    result["timing_compliance"] = False
                    result["interaction_violations"].append(
                        f"Timing violation between {attack1.attack_type} and {attack2.attack_type}: "
                        f"{time_diff}s not in range [{expected_constraints['min_delay']}, {expected_constraints['max_delay']}]"
                    )

        # Check parameter consistency
        param_consistency = self.check_parameter_consistency(sequence)
        if not param_consistency["consistent"]:
            result["parameter_consistency"] = False
            result["interaction_violations"].extend(param_consistency["violations"])

        result["interactions_valid"] = (
            result["timing_compliance"] and result["parameter_consistency"]
        )

        return result

    def get_interaction_timing_constraints(
        self, attack_type1: str, attack_type2: str
    ) -> Optional[Dict[str, float]]:
        """Get timing constraints for attack type interactions."""
        # Define known interaction timing constraints
        constraints = {
            ("multisplit", "disorder"): {"min_delay": 0.0, "max_delay": 0.1},
            ("split", "fake"): {"min_delay": 0.0, "max_delay": 0.05},
            ("disorder", "fake"): {"min_delay": 0.0, "max_delay": 0.2},
        }

        key = (attack_type1, attack_type2)
        return constraints.get(key)

    def check_parameter_consistency(self, sequence: List) -> Dict[str, Any]:
        """Check that parameters are consistent across attack sequence."""
        result = {"consistent": True, "violations": []}

        # Check that all attacks target the same domain/IP
        domains = {attack.target_domain for attack in sequence}
        ips = {attack.target_ip for attack in sequence}

        if len(domains) > 1:
            result["consistent"] = False
            result["violations"].append(f"Multiple target domains in sequence: {domains}")

        if len(ips) > 1:
            result["consistent"] = False
            result["violations"].append(f"Multiple target IPs in sequence: {ips}")

        return result
