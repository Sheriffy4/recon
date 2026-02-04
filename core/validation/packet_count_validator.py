"""
Packet count and order validation utilities.

This module provides validation logic for packet counts and ordering in DPI bypass attacks,
extracted from PacketValidator to reduce complexity and feature envy.
"""

from typing import List, Dict, Any, Optional, Tuple, Union


class PacketCountValidator:
    """
    Validates packet counts and ordering for various attack types.

    This class encapsulates packet count and order validation logic.
    """

    def __init__(self, validation_detail_class, validation_severity_class):
        """Initialize packet count validator."""
        self.ValidationDetail = validation_detail_class
        self.ValidationSeverity = validation_severity_class

    def validate_packet_count(
        self,
        packets: List[Any],
        params: Dict[str, Any],
        result: Any,
        attack_name: str,
    ):
        """Validate correct number of packets generated."""
        actual_count = len(packets)
        expected_count = self.get_expected_packet_count(attack_name, params)

        if expected_count is None:
            result.add_detail(
                self.ValidationDetail(
                    aspect="packet_count",
                    passed=True,
                    message=f"Packet count validation skipped for {attack_name}",
                    severity=self.ValidationSeverity.INFO,
                )
            )
            return

        # Validate packet count
        if isinstance(expected_count, tuple):
            min_count, max_count = expected_count
            if actual_count < min_count or actual_count > max_count:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_count",
                        passed=False,
                        expected=f"{min_count}-{max_count} packets",
                        actual=f"{actual_count} packets",
                        message=f"Unexpected packet count for {attack_name}",
                        severity=self.ValidationSeverity.ERROR,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_count",
                        passed=True,
                        message=f"Packet count correct: {actual_count} packets",
                        severity=self.ValidationSeverity.INFO,
                    )
                )
        else:
            if actual_count != expected_count:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_count",
                        passed=False,
                        expected=f"{expected_count} packets",
                        actual=f"{actual_count} packets",
                        message=f"Unexpected packet count for {attack_name}",
                        severity=self.ValidationSeverity.ERROR,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_count",
                        passed=True,
                        message=f"Packet count correct: {actual_count} packets",
                        severity=self.ValidationSeverity.INFO,
                    )
                )

    def get_expected_packet_count(
        self, attack_name: str, params: Dict[str, Any]
    ) -> Optional[Union[int, Tuple[int, int]]]:
        """Get expected packet count for attack type."""
        if attack_name == "fake":
            return 2
        elif attack_name == "split":
            return 2
        elif attack_name == "fakeddisorder":
            return 3
        elif attack_name == "disorder":
            return (2, 10)
        elif attack_name == "multisplit":
            return (3, 10)
        elif attack_name == "multidisorder":
            return (3, 10)
        else:
            return None

    def validate_packet_order(self, packets: List[Any], attack_name: str, result: Any):
        """Validate packet order is correct for attack type."""
        if attack_name == "fakeddisorder":
            self._validate_fakeddisorder_order(packets, result)
        elif attack_name == "disorder":
            self._validate_disorder_order(packets, result)

    def _validate_fakeddisorder_order(self, packets: List[Any], result: Any):
        """Validate order for fakeddisorder attack."""
        if len(packets) < 3:
            return

        # Important: order/sequence checks must be done on payload packets,
        # otherwise SYN/ACK/ACK noise breaks logic.
        payload_packets = [p for p in packets if getattr(p, "payload_length", 0) > 0]
        if len(payload_packets) < 2:
            return

        fake_packets = [p for p in payload_packets if p.is_fake_packet()]
        real_packets = [p for p in payload_packets if not p.is_fake_packet()]

        if not fake_packets or len(real_packets) < 2:
            return

        # Check if fake packet comes first
        fake_index = packets.index(fake_packets[0])  # keep original sequence index
        if fake_index != 0:
            result.add_detail(
                self.ValidationDetail(
                    aspect="packet_order",
                    passed=False,
                    expected="Fake packet first",
                    actual=f"Fake packet at index {fake_index}",
                    message="Fake packet should be sent first in fakeddisorder",
                    severity=self.ValidationSeverity.WARNING,
                )
            )
        else:
            result.add_detail(
                self.ValidationDetail(
                    aspect="packet_order",
                    passed=True,
                    message="Fake packet sent first as expected",
                    severity=self.ValidationSeverity.INFO,
                )
            )

        # Check if real packets are in disorder
        if len(real_packets) >= 2:
            first_real = real_packets[0]
            second_real = real_packets[1]

            if first_real.sequence_num < second_real.sequence_num:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_order",
                        passed=False,
                        expected="Real packets in disorder (part2 before part1)",
                        actual="Real packets in order",
                        message="Real packets should be sent in disorder",
                        severity=self.ValidationSeverity.WARNING,
                    )
                )
            else:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_order",
                        passed=True,
                        message="Real packets sent in disorder as expected",
                        severity=self.ValidationSeverity.INFO,
                    )
                )

    def _validate_disorder_order(self, packets: List[Any], result: Any):
        """Validate order for disorder attack."""
        payload_packets = [p for p in packets if p.payload_length > 0]
        if len(payload_packets) < 2:
            return

        # Check if sequence numbers are not in order
        seq_nums = [p.sequence_num for p in payload_packets]
        is_ordered = all(seq_nums[i] <= seq_nums[i + 1] for i in range(len(seq_nums) - 1))

        if is_ordered:
            result.add_detail(
                self.ValidationDetail(
                    aspect="packet_order",
                    passed=False,
                    expected="Packets in disorder",
                    actual="Packets in order",
                    message="Packets should be sent in disorder",
                    severity=self.ValidationSeverity.WARNING,
                )
            )
        else:
            result.add_detail(
                self.ValidationDetail(
                    aspect="packet_order",
                    passed=True,
                    message="Packets sent in disorder as expected",
                    severity=self.ValidationSeverity.INFO,
                )
            )

    def validate_packet_sizes(
        self,
        packets: List[Any],
        params: Dict[str, Any],
        result: Any,
    ):
        """Validate packet sizes are reasonable."""
        for packet in packets:
            if packet.payload_length > 65535:
                result.add_detail(
                    self.ValidationDetail(
                        aspect="packet_size",
                        passed=False,
                        expected="payload_length <= 65535",
                        actual=f"payload_length={packet.payload_length}",
                        message=f"Packet {packet.index} has unreasonably large payload",
                        severity=self.ValidationSeverity.ERROR,
                        packet_index=packet.index,
                    )
                )

            # Check for split position if specified
            split_pos = params.get("split_pos")
            if split_pos is not None:
                if abs(packet.payload_length - split_pos) <= 10:
                    result.add_detail(
                        self.ValidationDetail(
                            aspect="packet_size",
                            passed=True,
                            message=f"Packet {packet.index} size matches split_pos: {packet.payload_length}",
                            severity=self.ValidationSeverity.INFO,
                            packet_index=packet.index,
                        )
                    )
