"""
PCAP analyzer implementation for attack pattern detection.

This module provides concrete implementation of the PCAPAnalyzer interface
for analyzing network packet captures and detecting attack patterns.
"""

import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from .interfaces import PCAPAnalyzer
from .models import (
    PacketModification,
    PacketInfo,
    DetectedAttack,
    TimingAnalysis,
    TimingInfo,
    ModificationType,
    detect_packet_modifications,
    group_modifications_by_attack,
    classify_attack_from_modifications,
)

try:
    from scapy.all import rdpcap, Packet, IP, TCP, UDP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

    # Mock classes for when Scapy is not available
    class Packet:
        pass

    class IP:
        pass

    class TCP:
        pass

    class UDP:
        pass


class DefaultPCAPAnalyzer(PCAPAnalyzer):
    """Default implementation of PCAP analyzer for attack pattern detection."""

    def __init__(self, timing_tolerance: float = 0.1):
        """Initialize the PCAP analyzer.

        Args:
            timing_tolerance: Tolerance for timing analysis in seconds
        """
        self.timing_tolerance = timing_tolerance
        self._packet_cache: Dict[str, List[PacketInfo]] = {}

    def analyze_pcap_file(self, file_path: str) -> List[PacketModification]:
        """Analyze a PCAP file to extract packet modifications.

        Args:
            file_path: Path to the PCAP file to analyze

        Returns:
            List of PacketModification objects found in the PCAP

        Raises:
            FileNotFoundError: If the PCAP file doesn't exist
            ValueError: If the file cannot be parsed
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        if not SCAPY_AVAILABLE:
            # Return empty list if Scapy is not available
            return []

        try:
            # Read packets from PCAP file
            packets = rdpcap(file_path)
            packet_infos = self._extract_packet_info(packets)

            # Cache the packets for this file
            self._packet_cache[file_path] = packet_infos

            # Detect modifications between packets
            modifications = detect_packet_modifications(packet_infos)

            return modifications

        except Exception as e:
            raise ValueError(f"Failed to parse PCAP file {file_path}: {e}")

    def detect_attack_patterns(self, packets: List[Any]) -> List[DetectedAttack]:
        """Detect attack patterns in packet data.

        Args:
            packets: List of packet objects to analyze (Scapy packets or PacketInfo)

        Returns:
            List of DetectedAttack objects representing identified patterns
        """
        if not packets:
            return []

        # Convert to PacketInfo if needed
        if isinstance(packets[0], PacketInfo):
            packet_infos = packets
        else:
            packet_infos = self._extract_packet_info(packets)

        # Detect modifications
        modifications = detect_packet_modifications(packet_infos)

        # Group modifications by attack
        attack_groups = group_modifications_by_attack(modifications, self.timing_tolerance)

        detected_attacks = []
        for i, group in enumerate(attack_groups):
            if not group:
                continue

            # Classify the attack type
            attack_type = classify_attack_from_modifications(group)
            if not attack_type:
                continue

            # Calculate timing info
            start_time = min(mod.timestamp for mod in group)
            end_time = max(mod.timestamp for mod in group)
            timing_info = TimingInfo(
                start_time=start_time,
                end_time=end_time,
                duration=end_time - start_time,
                packet_intervals=[
                    (group[j].timestamp - group[j - 1].timestamp).total_seconds()
                    for j in range(1, len(group))
                ],
            )

            # Extract parameters from modifications
            parameters = self._extract_attack_parameters(group)

            # Calculate confidence based on pattern consistency
            confidence = self._calculate_confidence(group, attack_type)

            detected_attack = DetectedAttack(
                attack_type=attack_type,
                confidence=confidence,
                packet_indices=[mod.packet_index for mod in group],
                timing_info=timing_info,
                parameters=parameters,
            )

            detected_attacks.append(detected_attack)

        # Detect combination patterns
        combination_attacks = self._detect_combination_patterns(detected_attacks, modifications)
        detected_attacks.extend(combination_attacks)

        return detected_attacks

    def extract_timing_info(self, packets: List[Any]) -> TimingAnalysis:
        """Extract timing information from packet data.

        Args:
            packets: List of packet objects to analyze

        Returns:
            TimingAnalysis object containing timing statistics
        """
        if not packets:
            return TimingAnalysis(
                total_duration=timedelta(0),
                packet_intervals=[],
                attack_timings=[],
                average_interval=0.0,
                timing_variance=0.0,
            )

        # Convert to PacketInfo if needed
        if isinstance(packets[0], PacketInfo):
            packet_infos = packets
        else:
            packet_infos = self._extract_packet_info(packets)

        if len(packet_infos) < 2:
            return TimingAnalysis(
                total_duration=timedelta(0),
                packet_intervals=[],
                attack_timings=[],
                average_interval=0.0,
                timing_variance=0.0,
            )

        # Calculate packet intervals
        intervals = []
        for i in range(1, len(packet_infos)):
            interval = (packet_infos[i].timestamp - packet_infos[i - 1].timestamp).total_seconds()
            intervals.append(interval)

        # Calculate total duration
        total_duration = packet_infos[-1].timestamp - packet_infos[0].timestamp

        # Detect attack timings
        detected_attacks = self.detect_attack_patterns(packet_infos)
        attack_timings = [attack.timing_info for attack in detected_attacks if attack.timing_info]

        # Calculate statistics
        average_interval = sum(intervals) / len(intervals) if intervals else 0.0
        variance = (
            sum((x - average_interval) ** 2 for x in intervals) / len(intervals)
            if intervals
            else 0.0
        )

        return TimingAnalysis(
            total_duration=total_duration,
            packet_intervals=intervals,
            attack_timings=attack_timings,
            average_interval=average_interval,
            timing_variance=variance,
        )

    def _extract_packet_info(self, packets: List[Any]) -> List[PacketInfo]:
        """Extract PacketInfo objects from Scapy packets.

        Args:
            packets: List of Scapy packet objects

        Returns:
            List of PacketInfo objects
        """
        packet_infos = []

        for i, packet in enumerate(packets):
            try:
                # Extract basic packet information
                timestamp = datetime.fromtimestamp(float(packet.time))
                size = len(packet)

                # Extract IP layer info
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    ttl = ip_layer.ttl
                    protocol = ip_layer.proto
                    fragment_offset = ip_layer.frag

                    # Convert protocol number to name
                    protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, str(protocol))
                else:
                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"
                    ttl = 0
                    protocol_name = "UNKNOWN"
                    fragment_offset = 0

                # Extract transport layer info
                src_port = None
                dst_port = None
                sequence_number = None
                acknowledgment_number = None
                flags = {}

                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    sequence_number = tcp_layer.seq
                    acknowledgment_number = tcp_layer.ack

                    # Extract TCP flags
                    flags = {
                        "FIN": bool(tcp_layer.flags & 0x01),
                        "SYN": bool(tcp_layer.flags & 0x02),
                        "RST": bool(tcp_layer.flags & 0x04),
                        "PSH": bool(tcp_layer.flags & 0x08),
                        "ACK": bool(tcp_layer.flags & 0x10),
                        "URG": bool(tcp_layer.flags & 0x20),
                    }
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport

                # Calculate payload size
                payload_size = len(packet.payload) if hasattr(packet, "payload") else 0

                # Generate checksum (simplified)
                checksum = f"{hash(bytes(packet)) & 0xFFFF:04x}"

                packet_info = PacketInfo(
                    timestamp=timestamp,
                    size=size,
                    protocol=protocol_name,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    flags=flags,
                    payload_size=payload_size,
                    sequence_number=sequence_number,
                    acknowledgment_number=acknowledgment_number,
                    ttl=ttl,
                    checksum=checksum,
                    fragment_offset=fragment_offset,
                )

                packet_infos.append(packet_info)

            except Exception as e:
                # Skip malformed packets
                continue

        return packet_infos

    def _extract_attack_parameters(self, modifications: List[PacketModification]) -> Dict[str, Any]:
        """Extract attack parameters from packet modifications.

        Args:
            modifications: List of packet modifications

        Returns:
            Dictionary of extracted parameters
        """
        parameters = {}

        if not modifications:
            return parameters

        # Extract common parameters based on modification types
        mod_types = [mod.modification_type for mod in modifications]

        # Count splits for multisplit detection
        split_count = sum(1 for t in mod_types if t == ModificationType.SPLIT)
        if split_count > 0:
            parameters["split_count"] = split_count

        # Extract size changes for split attacks
        size_changes = []
        for mod in modifications:
            if mod.modification_type == ModificationType.SPLIT:
                original_size = mod.original_packet.size
                modified_size = mod.modified_packet.size
                size_changes.append(original_size - modified_size)

        if size_changes:
            parameters["size_reductions"] = size_changes
            parameters["total_size_reduction"] = sum(size_changes)

        # Extract TTL changes
        ttl_changes = []
        for mod in modifications:
            if mod.modification_type == ModificationType.TTL_MODIFICATION:
                original_ttl = mod.original_packet.ttl
                modified_ttl = mod.modified_packet.ttl
                if original_ttl and modified_ttl:
                    ttl_changes.append(modified_ttl - original_ttl)

        if ttl_changes:
            parameters["ttl_changes"] = ttl_changes

        # Extract timing parameters
        if len(modifications) > 1:
            intervals = []
            for i in range(1, len(modifications)):
                interval = (
                    modifications[i].timestamp - modifications[i - 1].timestamp
                ).total_seconds()
                intervals.append(interval)

            parameters["modification_intervals"] = intervals
            parameters["total_attack_duration"] = (
                modifications[-1].timestamp - modifications[0].timestamp
            ).total_seconds()

        return parameters

    def _calculate_confidence(
        self, modifications: List[PacketModification], attack_type: str
    ) -> float:
        """Calculate confidence score for detected attack pattern.

        Args:
            modifications: List of packet modifications
            attack_type: Detected attack type

        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not modifications:
            return 0.0

        confidence = 0.5  # Base confidence

        # Increase confidence based on pattern consistency
        mod_types = [mod.modification_type for mod in modifications]

        # Check for consistent modification types
        if attack_type == "split" and all(t == ModificationType.SPLIT for t in mod_types):
            confidence += 0.3
        elif attack_type == "multisplit" and all(t == ModificationType.SPLIT for t in mod_types):
            confidence += 0.2
        elif attack_type == "disorder" and all(t == ModificationType.DISORDER for t in mod_types):
            confidence += 0.3

        # Increase confidence based on timing consistency
        if len(modifications) > 1:
            intervals = []
            for i in range(1, len(modifications)):
                interval = (
                    modifications[i].timestamp - modifications[i - 1].timestamp
                ).total_seconds()
                intervals.append(interval)

            # Check if intervals are consistent (low variance)
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                if variance < 0.01:  # Low variance indicates consistent timing
                    confidence += 0.2

        # Ensure confidence is within bounds
        return min(1.0, max(0.0, confidence))

    def get_cached_packets(self, file_path: str) -> Optional[List[PacketInfo]]:
        """Get cached packet information for a file.

        Args:
            file_path: Path to the PCAP file

        Returns:
            Cached packet information or None if not cached
        """
        return self._packet_cache.get(file_path)

    def clear_cache(self):
        """Clear the packet cache."""
        self._packet_cache.clear()

    def _detect_combination_patterns(
        self, detected_attacks: List[DetectedAttack], modifications: List[PacketModification]
    ) -> List[DetectedAttack]:
        """Detect combination attack patterns from individual attacks.

        Args:
            detected_attacks: List of individual detected attacks
            modifications: All packet modifications

        Returns:
            List of detected combination attacks
        """
        if len(detected_attacks) < 2:
            return []

        combination_attacks = []

        # Sort attacks by timing
        sorted_attacks = sorted(detected_attacks, key=lambda a: a.timing_info.start_time)

        # Look for known combination patterns
        for i in range(len(sorted_attacks) - 1):
            for j in range(i + 1, len(sorted_attacks)):
                attack1 = sorted_attacks[i]
                attack2 = sorted_attacks[j]

                # Check timing proximity (attacks should be close in time)
                time_diff = (
                    attack2.timing_info.start_time - attack1.timing_info.end_time
                ).total_seconds()
                if time_diff > 1.0:  # More than 1 second apart
                    continue

                # Detect specific combination patterns
                combination = self._identify_combination_pattern(attack1, attack2, time_diff)
                if combination:
                    combination_attacks.append(combination)

        # Look for multi-attack sequences (more than 2 attacks)
        multi_combinations = self._detect_multi_attack_sequences(sorted_attacks)
        combination_attacks.extend(multi_combinations)

        return combination_attacks

    def _identify_combination_pattern(
        self, attack1: DetectedAttack, attack2: DetectedAttack, time_diff: float
    ) -> Optional[DetectedAttack]:
        """Identify specific combination patterns between two attacks.

        Args:
            attack1: First attack in sequence
            attack2: Second attack in sequence
            time_diff: Time difference between attacks in seconds

        Returns:
            DetectedAttack for combination or None if no pattern matches
        """
        # Smart combo: disorder + multisplit
        if (attack1.attack_type == "multisplit" and attack2.attack_type == "disorder") or (
            attack1.attack_type == "disorder" and attack2.attack_type == "multisplit"
        ):

            # Use conservative confidence calculation
            base_confidence = min(attack1.confidence, attack2.confidence)
            combination_confidence = base_confidence * 0.5  # Much more conservative

            return DetectedAttack(
                attack_type="smart_combo_disorder_multisplit",
                confidence=combination_confidence,
                packet_indices=attack1.packet_indices + attack2.packet_indices,
                timing_info=TimingInfo(
                    start_time=min(attack1.timing_info.start_time, attack2.timing_info.start_time),
                    end_time=max(attack1.timing_info.end_time, attack2.timing_info.end_time),
                    duration=max(attack1.timing_info.end_time, attack2.timing_info.end_time)
                    - min(attack1.timing_info.start_time, attack2.timing_info.start_time),
                    packet_intervals=attack1.timing_info.packet_intervals
                    + attack2.timing_info.packet_intervals,
                ),
                parameters={
                    "component_attacks": [attack1.attack_type, attack2.attack_type],
                    "time_separation": time_diff,
                    "attack1_params": attack1.parameters,
                    "attack2_params": attack2.parameters,
                },
            )

        # Smart combo: fake + split
        if (attack1.attack_type == "split" and attack2.attack_type == "fake") or (
            attack1.attack_type == "fake" and attack2.attack_type == "split"
        ):

            # Use conservative confidence calculation
            base_confidence = min(attack1.confidence, attack2.confidence)
            combination_confidence = base_confidence * 0.5  # Much more conservative

            return DetectedAttack(
                attack_type="smart_combo_fake_split",
                confidence=combination_confidence,
                packet_indices=attack1.packet_indices + attack2.packet_indices,
                timing_info=TimingInfo(
                    start_time=min(attack1.timing_info.start_time, attack2.timing_info.start_time),
                    end_time=max(attack1.timing_info.end_time, attack2.timing_info.end_time),
                    duration=max(attack1.timing_info.end_time, attack2.timing_info.end_time)
                    - min(attack1.timing_info.start_time, attack2.timing_info.start_time),
                    packet_intervals=attack1.timing_info.packet_intervals
                    + attack2.timing_info.packet_intervals,
                ),
                parameters={
                    "component_attacks": [attack1.attack_type, attack2.attack_type],
                    "time_separation": time_diff,
                    "attack1_params": attack1.parameters,
                    "attack2_params": attack2.parameters,
                },
            )

        # Generic combination for other patterns
        if time_diff < 0.1:  # Very close in time
            # Use very conservative confidence calculation
            base_confidence = min(attack1.confidence, attack2.confidence)
            # Ensure combination confidence is significantly lower than component confidence
            combination_confidence = base_confidence * 0.5  # Much more conservative
            # Debug: print confidence calculation
            # print(f"DEBUG: attack1.confidence={attack1.confidence}, attack2.confidence={attack2.confidence}")
            # print(f"DEBUG: base_confidence={base_confidence}, combination_confidence={combination_confidence}")

            return DetectedAttack(
                attack_type=f"combo_{attack1.attack_type}_{attack2.attack_type}",
                confidence=combination_confidence,
                packet_indices=attack1.packet_indices + attack2.packet_indices,
                timing_info=TimingInfo(
                    start_time=min(attack1.timing_info.start_time, attack2.timing_info.start_time),
                    end_time=max(attack1.timing_info.end_time, attack2.timing_info.end_time),
                    duration=max(attack1.timing_info.end_time, attack2.timing_info.end_time)
                    - min(attack1.timing_info.start_time, attack2.timing_info.start_time),
                    packet_intervals=attack1.timing_info.packet_intervals
                    + attack2.timing_info.packet_intervals,
                ),
                parameters={
                    "component_attacks": [attack1.attack_type, attack2.attack_type],
                    "time_separation": time_diff,
                    "attack1_params": attack1.parameters,
                    "attack2_params": attack2.parameters,
                },
            )

        return None

    def _detect_multi_attack_sequences(
        self, sorted_attacks: List[DetectedAttack]
    ) -> List[DetectedAttack]:
        """Detect sequences of multiple attacks (3 or more).

        Args:
            sorted_attacks: List of attacks sorted by timing

        Returns:
            List of detected multi-attack combinations
        """
        multi_combinations = []

        if len(sorted_attacks) < 3:
            return multi_combinations

        # Look for sequences of 3+ attacks within a short time window
        for i in range(len(sorted_attacks) - 2):
            sequence = [sorted_attacks[i]]

            for j in range(i + 1, len(sorted_attacks)):
                current_attack = sorted_attacks[j]
                last_attack = sequence[-1]

                # Check if this attack is close enough to be part of the sequence
                time_diff = (
                    current_attack.timing_info.start_time - last_attack.timing_info.end_time
                ).total_seconds()

                if time_diff <= 0.5:  # Within 500ms
                    sequence.append(current_attack)
                else:
                    break  # Sequence broken

            # If we have a sequence of 3+ attacks, create a combination
            if len(sequence) >= 3:
                attack_types = [attack.attack_type for attack in sequence]

                # Use very conservative confidence for multi-attack combinations
                base_confidence = min(attack.confidence for attack in sequence)
                combination_confidence = (
                    base_confidence * 0.3
                )  # Very conservative for complex combinations

                multi_combination = DetectedAttack(
                    attack_type=f'multi_combo_{"_".join(attack_types)}',
                    confidence=combination_confidence,
                    packet_indices=[idx for attack in sequence for idx in attack.packet_indices],
                    timing_info=TimingInfo(
                        start_time=sequence[0].timing_info.start_time,
                        end_time=sequence[-1].timing_info.end_time,
                        duration=sequence[-1].timing_info.end_time
                        - sequence[0].timing_info.start_time,
                        packet_intervals=[
                            interval
                            for attack in sequence
                            for interval in attack.timing_info.packet_intervals
                        ],
                    ),
                    parameters={
                        "component_attacks": attack_types,
                        "sequence_length": len(sequence),
                        "total_duration": (
                            sequence[-1].timing_info.end_time - sequence[0].timing_info.start_time
                        ).total_seconds(),
                        "component_params": [attack.parameters for attack in sequence],
                    },
                )

                multi_combinations.append(multi_combination)

        return multi_combinations

    def validate_combination_integrity(
        self, combination_attack: DetectedAttack, packet_infos: List[PacketInfo]
    ) -> bool:
        """Validate that a combination attack preserves connection integrity.

        Args:
            combination_attack: The detected combination attack
            packet_infos: Original packet information

        Returns:
            True if combination preserves connection integrity
        """
        if not combination_attack.attack_type.startswith(
            ("smart_combo_", "combo_", "multi_combo_")
        ):
            return True  # Not a combination attack

        # Check connection preservation rules
        packet_indices = combination_attack.packet_indices
        if not packet_indices:
            return False

        # Get packets involved in the combination
        involved_packets = [packet_infos[i] for i in packet_indices if i < len(packet_infos)]

        if not involved_packets:
            return False

        # Check basic integrity rules

        # 1. All packets should belong to the same connection
        first_packet = involved_packets[0]
        connection_tuple = first_packet.get_connection_tuple()

        for packet in involved_packets[1:]:
            if packet.get_connection_tuple() != connection_tuple:
                return False  # Different connections

        # 2. For TCP, sequence numbers should be reasonable
        if first_packet.protocol == "TCP":
            tcp_packets = [p for p in involved_packets if p.sequence_number is not None]
            if len(tcp_packets) > 1:
                # Check that sequence numbers are in reasonable range
                seq_numbers = [p.sequence_number for p in tcp_packets]
                seq_range = max(seq_numbers) - min(seq_numbers)

                # Sequence numbers shouldn't jump too much (indicating connection break)
                if seq_range > 100000:  # Arbitrary large jump threshold
                    return False

        # 3. Timing should be reasonable (not too spread out)
        if combination_attack.timing_info.duration.total_seconds() > 5.0:  # More than 5 seconds
            return False

        return True

    def detect_combination_failures(
        self, combination_attack: DetectedAttack, packet_infos: List[PacketInfo]
    ) -> List[str]:
        """Detect potential failure conditions in combination attacks.

        Args:
            combination_attack: The detected combination attack
            packet_infos: Original packet information

        Returns:
            List of detected failure conditions
        """
        failures = []

        if not combination_attack.attack_type.startswith(
            ("smart_combo_", "combo_", "multi_combo_")
        ):
            return failures

        packet_indices = combination_attack.packet_indices
        if not packet_indices:
            return failures

        involved_packets = [packet_infos[i] for i in packet_indices if i < len(packet_infos)]

        # Check for TCP RST packets (connection reset)
        for packet in involved_packets:
            if packet.protocol == "TCP" and packet.flags.get("RST", False):
                failures.append("tcp_connection_reset")

        # Check for fragmentation issues
        fragment_packets = [
            p for p in involved_packets if p.fragment_offset and p.fragment_offset > 0
        ]
        if len(fragment_packets) > 0:
            # Check if fragments are properly ordered
            fragment_offsets = [p.fragment_offset for p in fragment_packets]
            if fragment_offsets != sorted(fragment_offsets):
                failures.append("fragments_out_of_order")

        # Check for timing issues
        if combination_attack.timing_info.duration.total_seconds() > 2.0:
            failures.append("excessive_timing_spread")

        # Check for packet loss indicators
        if combination_attack.attack_type == "smart_combo_disorder_multisplit":
            # For disorder+multisplit, check if all fragments are present
            expected_fragments = combination_attack.parameters.get("attack1_params", {}).get(
                "split_count", 1
            )
            actual_fragments = len(
                [p for p in involved_packets if p.size < involved_packets[0].size]
            )

            if actual_fragments < expected_fragments:
                failures.append("missing_fragments")

        return failures
