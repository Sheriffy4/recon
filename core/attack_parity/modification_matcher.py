"""
Modification matching logic for attack correlation.

This module provides utilities for matching packet modifications to attack events,
extracted from the correlation engine to reduce feature envy and improve cohesion.
"""

from datetime import datetime
from typing import Dict, List, Tuple
from .attack_type_matching import modification_matches_attack_type


class ModificationMatcher:
    """
    Matcher for correlating packet modifications with attack events.
    """

    def __init__(self, timing_tolerance: float = 0.1):
        """
        Initialize modification matcher.

        Args:
            timing_tolerance: Acceptable time difference in seconds for matching
        """
        self.timing_tolerance = timing_tolerance

    def find_candidate_modifications(
        self, attack, modification_groups: Dict[datetime, List], match_timing_windows_func
    ) -> List:
        """
        Find packet modifications that could match the given attack.

        Args:
            attack: Attack event to find modifications for
            modification_groups: Grouped modifications by time
            match_timing_windows_func: Function to check timing windows

        Returns:
            List of candidate packet modifications
        """
        # We keep candidate collection broad (to avoid false negatives),
        # but *prefer* candidates whose modification_type matches attack.attack_type.
        preferred = []
        others = []

        seen_ids = set()
        attack_time = attack.timestamp
        attack_type = getattr(attack, "attack_type", None)

        # Check time windows around the attack timestamp
        for time_key, mods in modification_groups.items():
            if match_timing_windows_func(attack_time, time_key, self.timing_tolerance):
                # Filter by target IP if available
                for mod in mods:
                    if self.modification_matches_target(mod, attack):
                        mid = id(mod)
                        if mid not in seen_ids:
                            # Prefer type-matching candidates, but keep all.
                            if attack_type and modification_matches_attack_type(mod, attack_type):
                                preferred.append(mod)
                            else:
                                others.append(mod)
                            seen_ids.add(mid)
            else:
                # Also check individual modification timestamps (not just grouped time)
                for mod in mods:
                    if match_timing_windows_func(attack_time, mod.timestamp, self.timing_tolerance):
                        if self.modification_matches_target(mod, attack):
                            mid = id(mod)
                            if mid not in seen_ids:
                                if attack_type and modification_matches_attack_type(
                                    mod, attack_type
                                ):
                                    preferred.append(mod)
                                else:
                                    others.append(mod)
                                seen_ids.add(mid)

        # Keep behavior stable: still return all candidates, but with more relevant ones first.
        return preferred + others

    def modification_matches_target(self, modification, attack) -> bool:
        """
        Check if a packet modification matches the attack target.

        Args:
            modification: Packet modification to check
            attack: Attack event with target information

        Returns:
            True if modification matches attack target
        """
        # Check if modification involves the target IP
        original_packet = modification.original_packet
        modified_packet = modification.modified_packet

        target_ips = [attack.target_ip]

        # Check if any packet in the modification involves the target
        return (
            original_packet.dst_ip in target_ips
            or original_packet.src_ip in target_ips
            or modified_packet.dst_ip in target_ips
            or modified_packet.src_ip in target_ips
        )

    def match_modifications_to_expected(
        self, modifications: List, expected: List
    ) -> Tuple[List, List]:
        """
        Match actual modifications to expected specifications.

        Args:
            modifications: Actual packet modifications
            expected: Expected modification specifications

        Returns:
            Tuple of (matched modifications, unmatched expected specs)
        """
        matched_modifications = []
        unmatched_expected = expected.copy()

        for mod in modifications:
            for i, expected_spec in enumerate(unmatched_expected):
                if expected_spec.matches_modification(mod):
                    matched_modifications.append(mod)
                    unmatched_expected.pop(i)
                    break

        return matched_modifications, unmatched_expected
