"""
Sequence number validation utilities.

This module provides validation logic for TCP sequence numbers in DPI bypass attacks,
extracted from PacketValidator to reduce complexity and feature envy.
"""

from typing import List, Dict, Any


class SequenceValidator:
    """
    Validates TCP sequence numbers for various attack types.

    This class encapsulates sequence validation logic that was previously
    scattered across PacketValidator methods, reducing feature envy and
    improving testability.
    """

    def __init__(self, validation_detail_class, validation_severity_class):
        """
        Initialize sequence validator.

        Args:
            validation_detail_class: ValidationDetail class for creating details
            validation_severity_class: ValidationSeverity enum for severity levels
        """
        self.ValidationDetail = validation_detail_class
        self.ValidationSeverity = validation_severity_class

    def validate_sequence_numbers(
        self,
        packets: List[Any],
        params: Dict[str, Any],
        result: Any,
        attack_name: str,
    ):
        """
        Validate sequence numbers based on attack type.

        Args:
            packets: List of PacketData objects
            params: Attack parameters
            result: ValidationResult to update
            attack_name: Name of the attack
        """
        if attack_name == "fakeddisorder":
            self.validate_fakeddisorder_sequence(packets, params, result)
        elif attack_name in ["split", "disorder", "multisplit", "multidisorder"]:
            self.validate_split_sequence(packets, result)
        else:
            self.validate_generic_sequence(packets, result)

    def validate_fakeddisorder_sequence(
        self,
        packets: List[Any],
        params: Dict[str, Any],
        result: Any,
    ):
        """
        Validate sequence numbers for fakeddisorder attack.

        Expected pattern:
        1. Fake packet with seq = original_seq
        2. Real packet 2 with seq = original_seq + split_pos
        3. Real packet 1 with seq = original_seq
        """
        if len(packets) < 3:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=False,
                    expected="At least 3 packets",
                    actual=f"{len(packets)} packets",
                    message="Fakeddisorder requires at least 3 packets (fake + 2 real)",
                    severity=self.ValidationSeverity.CRITICAL,
                )
            )
            return

        # Identify fake and real packets
        fake_packets = [p for p in packets if p.is_fake_packet()]
        real_packets = [p for p in packets if not p.is_fake_packet()]

        if not fake_packets:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=False,
                    expected="At least 1 fake packet",
                    actual="0 fake packets",
                    message="No fake packet detected in fakeddisorder attack",
                    severity=self.ValidationSeverity.CRITICAL,
                )
            )
            return

        if len(real_packets) < 2:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=False,
                    expected="At least 2 real packets",
                    actual=f"{len(real_packets)} real packets",
                    message="Fakeddisorder requires at least 2 real packets",
                    severity=self.ValidationSeverity.CRITICAL,
                )
            )
            return

        # Get first fake packet and real packets
        fake_packet = fake_packets[0]

        # Find the real packet with lowest sequence number (original_seq)
        real_packets_sorted = sorted(real_packets, key=lambda p: p.sequence_num)
        original_seq = real_packets_sorted[0].sequence_num

        # Validate fake packet sequence number
        if fake_packet.sequence_num != original_seq:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=False,
                    expected=f"fake_seq={original_seq}",
                    actual=f"fake_seq={fake_packet.sequence_num}",
                    message=f"Fake packet has wrong sequence number (packet {fake_packet.index})",
                    severity=self.ValidationSeverity.CRITICAL,
                    packet_index=fake_packet.index,
                )
            )
        else:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=True,
                    message=f"Fake packet sequence number correct: {fake_packet.sequence_num}",
                    severity=self.ValidationSeverity.INFO,
                    packet_index=fake_packet.index,
                )
            )

        # Validate real packets are sequential
        overlap_size = params.get("overlap_size", 0)

        for i in range(len(real_packets_sorted) - 1):
            current_packet = real_packets_sorted[i]
            next_packet = real_packets_sorted[i + 1]

            # Calculate expected next sequence number
            expected_next_seq = current_packet.sequence_num + current_packet.payload_length

            # Account for overlap
            if overlap_size > 0:
                expected_next_seq -= overlap_size

            if next_packet.sequence_num != expected_next_seq:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=False,
                        expected=f"seq={expected_next_seq}",
                        actual=f"seq={next_packet.sequence_num}",
                        message=f"Real packet {i+1} has wrong sequence number (packet {next_packet.index})",
                        severity=self.ValidationSeverity.ERROR,
                        packet_index=next_packet.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=True,
                        message=f"Real packet {i+1} sequence number correct",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=next_packet.index,
                    )
                )

        # Validate overlap calculations if specified
        if overlap_size > 0:
            self.validate_overlap(real_packets_sorted, overlap_size, result)

    def validate_split_sequence(
        self,
        packets: List[Any],
        result: Any,
    ):
        """
        Validate sequence numbers for split/disorder attacks.

        Note: params parameter removed as it was unused (SR10).
        """
        if len(packets) < 2:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=False,
                    expected="At least 2 packets",
                    actual=f"{len(packets)} packets",
                    message="Split attack requires at least 2 packets",
                    severity=self.ValidationSeverity.ERROR,
                )
            )
            return

        # Get packets with payload (skip handshake packets)
        payload_packets = [p for p in packets if p.payload_length > 0]

        if len(payload_packets) < 2:
            result.add_detail(
                self.ValidationDetail(
                    aspect="sequence_numbers",
                    passed=False,
                    expected="At least 2 packets with payload",
                    actual=f"{len(payload_packets)} packets with payload",
                    message="Split attack requires at least 2 packets with payload",
                    severity=self.ValidationSeverity.ERROR,
                )
            )
            return

        # Sort by sequence number
        sorted_packets = sorted(payload_packets, key=lambda p: p.sequence_num)

        # Validate sequential sequence numbers
        for i in range(len(sorted_packets) - 1):
            current = sorted_packets[i]
            next_pkt = sorted_packets[i + 1]

            expected_seq = current.sequence_num + current.payload_length

            if next_pkt.sequence_num != expected_seq:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=False,
                        expected=f"seq={expected_seq}",
                        actual=f"seq={next_pkt.sequence_num}",
                        message=f"Packet {i+1} has non-sequential sequence number",
                        severity=self.ValidationSeverity.ERROR,
                        packet_index=next_pkt.index,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=True,
                        message=f"Packet {i+1} sequence number correct",
                        severity=self.ValidationSeverity.INFO,
                        packet_index=next_pkt.index,
                    )
                )

    def validate_generic_sequence(
        self,
        packets: List[Any],
        result: Any,
    ):
        """
        Generic sequence number validation for other attacks.

        Note: params parameter removed as it was unused (SR11).
        """
        payload_packets = [p for p in packets if p.payload_length > 0]

        if len(payload_packets) < 2:
            return  # Not enough packets to validate sequence

        # Check for reasonable sequence numbers
        for packet in payload_packets:
            if packet.sequence_num == 0:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=False,
                        expected="Non-zero sequence number",
                        actual="seq=0",
                        message=f"Packet {packet.index} has zero sequence number",
                        severity=self.ValidationSeverity.WARNING,
                        packet_index=packet.index,
                    )
                )

    def validate_overlap(self, packets: List[Any], overlap_size: int, result: Any):
        """
        Validate overlap calculations for fakeddisorder.
        """
        if len(packets) < 2:
            return

        for i in range(len(packets) - 1):
            current = packets[i]
            next_pkt = packets[i + 1]

            # Check if there's actual overlap
            overlap_start = current.sequence_num + current.payload_length - overlap_size
            overlap_end = current.sequence_num + current.payload_length

            if next_pkt.sequence_num >= overlap_start and next_pkt.sequence_num < overlap_end:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=True,
                        message=f"Overlap detected between packets {i} and {i+1}: {overlap_size} bytes",
                        severity=self.ValidationSeverity.INFO,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="sequence_numbers",
                        passed=False,
                        expected=f"Overlap of {overlap_size} bytes",
                        actual="No overlap detected",
                        message=f"Expected overlap not found between packets {i} and {i+1}",
                        severity=self.ValidationSeverity.WARNING,
                    )
                )
