"""
Attack-Specific Validators - Validates attack-specific requirements.

This module provides validation for specific attack types including:
- Fake attacks (fake packet detection)
- Split attacks (payload splitting validation)
- Disorder attacks (packet reordering validation)
"""

from typing import List


class AttackValidator:
    """
    Validates attack-specific requirements.

    This validator checks attack-specific constraints that are unique to
    each attack type (fake, split, disorder).
    """

    def __init__(self, validation_detail_class, validation_severity_class):
        """
        Initialize AttackValidator.

        Args:
            validation_detail_class: ValidationDetail class for creating details
            validation_severity_class: ValidationSeverity enum for severity levels
        """
        self.ValidationDetail = validation_detail_class
        self.ValidationSeverity = validation_severity_class

    def validate_fake_attack(
        self,
        packets: List,
        result,
    ):
        """
        Validate fake attack specific requirements.

        Checks that at least one fake packet is present in the attack.

        Args:
            packets: List of PacketData objects
            result: ValidationResult to update
        """
        fake_packets = [p for p in packets if p.is_fake_packet()]

        if not fake_packets:
            result.add_detail(
                self.ValidationDetail(
                    aspect="fake_attack",
                    passed=False,
                    expected="At least 1 fake packet",
                    actual="0 fake packets",
                    message="No fake packet detected",
                    severity=self.ValidationSeverity.CRITICAL,
                )
            )

    def validate_split_attack(
        self,
        packets: List,
        split_pos: int,
        result,
    ):
        """
        Validate split attack specific requirements.

        Checks that at least 2 packets with payload exist for split attacks.

        Args:
            packets: List of PacketData objects
            split_pos: Split position parameter (if None, validation is skipped)
            result: ValidationResult to update
        """
        if split_pos is None:
            return

        payload_packets = [p for p in packets if p.payload_length > 0]
        if len(payload_packets) < 2:
            result.add_detail(
                self.ValidationDetail(
                    aspect="split_attack",
                    passed=False,
                    expected="At least 2 packets with payload",
                    actual=f"{len(payload_packets)} packets",
                    message="Split attack requires at least 2 packets",
                    severity=self.ValidationSeverity.ERROR,
                )
            )

    def validate_disorder_attack(
        self,
        packets: List,
        result,
    ):
        """
        Validate disorder attack specific requirements.

        Checks that at least 2 packets with payload exist for disorder attacks.

        Args:
            packets: List of PacketData objects
            result: ValidationResult to update
        """
        payload_packets = [p for p in packets if p.payload_length > 0]

        if len(payload_packets) < 2:
            result.add_detail(
                self.ValidationDetail(
                    aspect="disorder_attack",
                    passed=False,
                    expected="At least 2 packets with payload",
                    actual=f"{len(payload_packets)} packets",
                    message="Disorder attack requires at least 2 packets",
                    severity=self.ValidationSeverity.ERROR,
                )
            )
