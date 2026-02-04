"""
TTL (Time-To-Live) validation utilities.

This module provides validation logic for TTL values in DPI bypass attacks,
extracted from PacketValidator to reduce feature envy and improve testability.
"""

from typing import List, Optional, Any


class TTLValidator:
    """
    Validates TTL values for various attack types.

    This class encapsulates TTL validation logic that was previously
    in PacketValidator, reducing feature envy and improving testability.
    """

    def __init__(self, validation_detail_class, validation_severity_class):
        """
        Initialize TTL validator.

        Args:
            validation_detail_class: ValidationDetail class for creating details
            validation_severity_class: ValidationSeverity enum for severity levels
        """
        self.ValidationDetail = validation_detail_class
        self.ValidationSeverity = validation_severity_class

    def validate_ttl(
        self,
        packets: List[Any],
        params: dict,
        result: Any,
        attack_name: str,
    ):
        """
        Validate TTL values based on attack type.

        For fake attacks:
        - Fake packets should have specified TTL (or fake_ttl)
        - Real packets should have default TTL (64 or 128)

        Args:
            packets: List of PacketData objects
            params: Attack parameters
            result: ValidationResult to update
            attack_name: Name of the attack
        """
        # Get expected TTL values
        expected_ttl = params.get("ttl")
        expected_fake_ttl = params.get("fake_ttl", expected_ttl)

        if attack_name in ["fake", "fakeddisorder"]:
            self.validate_fake_attack_ttl(packets, expected_fake_ttl, result)
        else:
            # For other attacks, just check for reasonable TTL values
            self.validate_generic_ttl(packets, result)

    def validate_fake_attack_ttl(
        self,
        packets: List[Any],
        expected_fake_ttl: Optional[int],
        result: Any,
    ):
        """
        Validate TTL for fake attacks.

        Args:
            packets: List of PacketData objects
            expected_fake_ttl: Expected TTL for fake packets
            result: ValidationResult to update
        """
        if expected_fake_ttl is None:
            result.add_detail(
                self.ValidationDetail(
                    aspect="ttl",
                    passed=False,
                    expected="TTL parameter specified",
                    actual="No TTL parameter",
                    message="TTL parameter not specified for fake attack",
                    severity=self.ValidationSeverity.WARNING,
                )
            )
            return

        # Identify fake and real packets
        fake_packets = [p for p in packets if p.is_fake_packet()]
        real_packets = [p for p in packets if not p.is_fake_packet()]

        # Validate fake packets have correct TTL
        for fake_packet in fake_packets:
            if fake_packet.ttl != expected_fake_ttl:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=False,
                        expected=f"ttl={expected_fake_ttl}",
                        actual=f"ttl={fake_packet.ttl}",
                        message=f"Fake packet {fake_packet.index} has wrong TTL",
                        severity=self.ValidationSeverity.CRITICAL,
                        packet_index=fake_packet.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=True,
                        message=f"Fake packet {fake_packet.index} has correct TTL: {fake_packet.ttl}",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=fake_packet.index,
                    )
                )

        # Validate real packets have default TTL
        default_ttls = [64, 128, 255]  # Common default TTLs
        for real_packet in real_packets:
            if real_packet.ttl not in default_ttls:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=False,
                        expected=f"ttl in {default_ttls}",
                        actual=f"ttl={real_packet.ttl}",
                        message=f"Real packet {real_packet.index} has unexpected TTL",
                        severity=self.ValidationSeverity.WARNING,
                        packet_index=real_packet.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=True,
                        message=f"Real packet {real_packet.index} has default TTL: {real_packet.ttl}",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=real_packet.index,
                    )
                )

    def validate_generic_ttl(self, packets: List[Any], result: Any):
        """
        Generic TTL validation for non-fake attacks.

        Args:
            packets: List of PacketData objects
            result: ValidationResult to update
        """
        for packet in packets:
            # Check for unreasonably low TTL
            if packet.ttl < 1:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=False,
                        expected="ttl >= 1",
                        actual=f"ttl={packet.ttl}",
                        message=f"Packet {packet.index} has invalid TTL",
                        severity=self.ValidationSeverity.ERROR,
                        packet_index=packet.index,
                    )
                )
            # Check for unreasonably high TTL
            elif packet.ttl > 255:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=False,
                        expected="ttl <= 255",
                        actual=f"ttl={packet.ttl}",
                        message=f"Packet {packet.index} has invalid TTL",
                        severity=self.ValidationSeverity.ERROR,
                        packet_index=packet.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="ttl",
                        passed=True,
                        message=f"Packet {packet.index} has valid TTL: {packet.ttl}",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=packet.index,
                    )
                )
