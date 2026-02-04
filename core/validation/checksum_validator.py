"""
Checksum validation utilities.

This module provides validation logic for TCP checksums in DPI bypass attacks,
extracted from PacketValidator to reduce feature envy and improve testability.
"""

from typing import List, Dict, Any


class ChecksumValidator:
    """
    Validates TCP checksums for various attack types.

    This class encapsulates checksum validation logic that was previously
    in PacketValidator, reducing feature envy and improving testability.
    """

    def __init__(self, validation_detail_class, validation_severity_class):
        """
        Initialize checksum validator.

        Args:
            validation_detail_class: ValidationDetail class for creating details
            validation_severity_class: ValidationSeverity enum for severity levels
        """
        self.ValidationDetail = validation_detail_class
        self.ValidationSeverity = validation_severity_class

    def validate_checksums(
        self,
        packets: List[Any],
        params: Dict[str, Any],
        result: Any,
    ):
        """
        Validate checksums are correct/corrupted as specified.

        For attacks with badsum fooling:
        - Fake packets should have bad checksum
        - Real packets should have good checksum
        - Detect WinDivert checksum recalculation

        Args:
            packets: List of PacketData objects
            params: Attack parameters
            result: ValidationResult to update
        """
        # runtime often uses "fooling_methods"
        fooling = params.get("fooling", params.get("fooling_methods", []))

        # Check if badsum is specified
        has_badsum = "badsum" in fooling if isinstance(fooling, list) else fooling == "badsum"

        if not has_badsum:
            # No badsum specified, all packets should have good checksums
            self.validate_all_good_checksums(packets, result)
            return

        # Identify fake and real packets
        fake_packets = [p for p in packets if p.is_fake_packet()]
        real_packets = [p for p in packets if not p.is_fake_packet()]

        # Validate fake packets have bad checksums
        for fake_packet in fake_packets:
            if fake_packet.checksum_valid:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="checksum",
                        passed=False,
                        expected="bad checksum",
                        actual="good checksum",
                        message=f"Fake packet {fake_packet.index} should have bad checksum but has good checksum",
                        severity=self.ValidationSeverity.CRITICAL,
                        packet_index=fake_packet.index,
                    )
                )

                # Check if this might be WinDivert recalculation
                if fake_packet.ttl <= 3:
                    result.add_detail(
                        self.ValidationDetail(
                            aspect="checksum",
                            passed=False,
                            expected="bad checksum preserved",
                            actual="checksum recalculated",
                            message=f"WinDivert may have recalculated checksum for packet {fake_packet.index}",
                            severity=self.ValidationSeverity.CRITICAL,
                            packet_index=fake_packet.index,
                        )
                    )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="checksum",
                        passed=True,
                        message=f"Fake packet {fake_packet.index} has bad checksum as expected",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=fake_packet.index,
                    )
                )

        # Validate real packets have good checksums
        for real_packet in real_packets:
            if not real_packet.checksum_valid:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="checksum",
                        passed=False,
                        expected="good checksum",
                        actual="bad checksum",
                        message=f"Real packet {real_packet.index} should have good checksum but has bad checksum",
                        severity=self.ValidationSeverity.ERROR,
                        packet_index=real_packet.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="checksum",
                        passed=True,
                        message=f"Real packet {real_packet.index} has good checksum",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=real_packet.index,
                    )
                )

        # Check for WinDivert recalculation pattern
        self.detect_windivert_recalculation(packets, result)

    def validate_all_good_checksums(self, packets: List[Any], result: Any):
        """
        Validate all packets have good checksums when badsum is not specified.

        Args:
            packets: List of PacketData objects
            result: ValidationResult to update
        """
        for packet in packets:
            if not packet.checksum_valid:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="checksum",
                        passed=False,
                        expected="good checksum",
                        actual="bad checksum",
                        message=f"Packet {packet.index} has bad checksum but badsum not specified",
                        severity=self.ValidationSeverity.WARNING,
                        packet_index=packet.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="checksum",
                        passed=True,
                        message=f"Packet {packet.index} has good checksum",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=packet.index,
                    )
                )

    def detect_windivert_recalculation(self, packets: List[Any], result: Any):
        """
        Detect if WinDivert is recalculating checksums.

        WinDivert may recalculate checksums even when we want bad checksums.
        This is a critical issue that breaks badsum fooling.

        Args:
            packets: List of PacketData objects
            result: ValidationResult to update
        """
        fake_packets = [p for p in packets if p.is_fake_packet()]

        # If all fake packets have good checksums, WinDivert is likely recalculating
        if fake_packets and all(p.checksum_valid for p in fake_packets):
            result.add_detail(
                self.ValidationDetail(
                    aspect="checksum",
                    passed=False,
                    expected="At least one fake packet with bad checksum",
                    actual="All fake packets have good checksums",
                    message="WinDivert is recalculating checksums - badsum fooling will not work",
                    severity=self.ValidationSeverity.CRITICAL,
                )
            )
