"""
Data models for attack parity analysis system.

This module defines all the data structures used throughout the attack parity
analysis system, including attack events, packet modifications, and analysis results.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Union
import json


class ExecutionMode(Enum):
    """Execution mode for attack application."""

    DISCOVERY = "discovery"
    SERVICE = "service"


class ModificationType(Enum):
    """Type of packet modification."""

    SPLIT = "split"
    MULTISPLIT = "multisplit"
    DISORDER = "disorder"
    FAKE = "fake"
    TTL_MODIFICATION = "ttl_modification"
    CHECKSUM_MODIFICATION = "checksum_modification"
    FRAGMENT = "fragment"
    DUPLICATE = "duplicate"


class InteractionType(Enum):
    """Type of interaction between attacks in combinations."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    NESTED = "nested"


class ConflictResolution(Enum):
    """How to resolve conflicts between attacks."""

    FIRST_WINS = "first_wins"
    LAST_WINS = "last_wins"
    MERGE = "merge"
    ABORT = "abort"


@dataclass
class TimingInfo:
    """Timing information for attack application."""

    start_time: datetime
    end_time: datetime
    duration: timedelta
    packet_intervals: List[float] = field(default_factory=list)


@dataclass
class TimingConstraint:
    """Timing constraints for attack interactions."""

    min_delay: float
    max_delay: float
    synchronization_required: bool = False


@dataclass
class PacketInfo:
    """Information about a network packet."""

    timestamp: datetime
    size: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Dict[str, bool] = field(default_factory=dict)
    payload_size: int = 0
    sequence_number: Optional[int] = None
    acknowledgment_number: Optional[int] = None
    ttl: Optional[int] = None
    checksum: Optional[str] = None
    fragment_offset: Optional[int] = None
    payload_hash: Optional[str] = None

    def compare_with(self, other: "PacketInfo") -> Dict[str, Any]:
        """Compare this packet with another and return differences.

        Args:
            other: Another PacketInfo to compare with

        Returns:
            Dictionary containing field differences
        """
        differences = {}

        # Compare basic fields
        for field in [
            "size",
            "protocol",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "payload_size",
            "sequence_number",
            "acknowledgment_number",
            "ttl",
            "checksum",
            "fragment_offset",
            "payload_hash",
        ]:
            self_val = getattr(self, field)
            other_val = getattr(other, field)
            if self_val != other_val:
                differences[field] = {"original": self_val, "modified": other_val}

        # Compare flags
        if self.flags != other.flags:
            differences["flags"] = {"original": self.flags, "modified": other.flags}

        return differences

    def get_connection_tuple(self) -> tuple:
        """Get connection tuple for packet matching."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


@dataclass
class PacketModificationSpec:
    """Specification for expected packet modifications."""

    modification_type: ModificationType
    target_fields: List[str]
    expected_values: Optional[Dict[str, Any]] = None
    conditions: List[str] = field(default_factory=list)

    def matches_modification(self, modification: "PacketModification") -> bool:
        """Check if a packet modification matches this specification."""
        return modification.modification_type == self.modification_type and all(
            field in modification.modified_fields for field in self.target_fields
        )


@dataclass
class ModificationEffect:
    """Effect of a parameter on packet modifications."""

    parameter_name: str
    effect_description: str
    affected_fields: List[str]
    value_mapping: Optional[Dict[str, Any]] = None


@dataclass
class CombinationConstraint:
    """Constraint for combining attacks."""

    constraint_type: str
    description: str
    incompatible_attacks: List[str] = field(default_factory=list)
    required_order: List[str] = field(default_factory=list)


@dataclass
class AttackDefinition:
    """Canonical definition of an attack type."""

    attack_type: str
    description: str
    expected_packet_modifications: List[PacketModificationSpec]
    parameter_effects: Dict[str, ModificationEffect] = field(default_factory=dict)
    invariants: List[str] = field(default_factory=list)
    combination_constraints: List[CombinationConstraint] = field(default_factory=list)

    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate that parameters are consistent with this attack definition."""
        for param_name, effect in self.parameter_effects.items():
            if param_name in parameters:
                # Basic validation - can be extended
                if effect.value_mapping and parameters[param_name] not in effect.value_mapping:
                    return False
        return True


@dataclass
class InteractionRule:
    """Rule defining how attacks interact when combined."""

    primary_attack: str
    secondary_attack: str
    interaction_type: InteractionType
    timing_constraints: TimingConstraint
    parameter_dependencies: Dict[str, Any] = field(default_factory=dict)
    conflict_resolution: ConflictResolution = ConflictResolution.FIRST_WINS


@dataclass
class AttackCombination:
    """Definition of how multiple attacks are combined."""

    combination_name: str
    attack_sequence: List[str]
    interaction_rules: List[InteractionRule]
    connection_preservation_rules: List[str] = field(default_factory=list)
    expected_combined_modifications: List[PacketModificationSpec] = field(default_factory=list)
    failure_conditions: List[str] = field(default_factory=list)


@dataclass
class AttackEvent:
    """Single attack application event extracted from logs."""

    timestamp: datetime
    attack_type: str
    canonical_definition: AttackDefinition
    target_domain: str
    target_ip: str
    parameters: Dict[str, Any]
    execution_mode: ExecutionMode
    expected_modifications: List[PacketModificationSpec]
    packet_count: int = 0
    timing_info: Optional[TimingInfo] = None
    strategy_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "attack_type": self.attack_type,
            "target_domain": self.target_domain,
            "target_ip": self.target_ip,
            "parameters": self.parameters,
            "execution_mode": self.execution_mode.value,
            "packet_count": self.packet_count,
            "strategy_id": self.strategy_id,
        }


@dataclass
class PacketModification:
    """Actual packet modification detected in PCAP analysis."""

    timestamp: datetime
    packet_index: int
    modification_type: ModificationType
    original_packet: PacketInfo
    modified_packet: PacketInfo
    modified_fields: List[str] = field(default_factory=list)
    attack_signature: Optional[str] = None
    confidence: float = 1.0

    def __post_init__(self):
        """Calculate modified fields after initialization."""
        if not self.modified_fields:
            differences = self.original_packet.compare_with(self.modified_packet)
            self.modified_fields = list(differences.keys())

    def matches_expected(self, expected: PacketModificationSpec) -> bool:
        """Check if this modification matches expected specification."""
        return expected.matches_modification(self)

    def get_modification_details(self) -> Dict[str, Any]:
        """Get detailed information about the modification."""
        differences = self.original_packet.compare_with(self.modified_packet)
        return {
            "modification_type": self.modification_type.value,
            "timestamp": self.timestamp.isoformat(),
            "packet_index": self.packet_index,
            "modified_fields": self.modified_fields,
            "field_changes": differences,
            "attack_signature": self.attack_signature,
            "confidence": self.confidence,
        }

    @classmethod
    def detect_modification_type(
        cls, original: PacketInfo, modified: PacketInfo
    ) -> ModificationType:
        """Detect the type of modification based on packet differences.

        Args:
            original: Original packet info
            modified: Modified packet info

        Returns:
            Detected modification type
        """
        differences = original.compare_with(modified)

        # Check for split patterns (size differences)
        if "size" in differences and modified.size < original.size:
            return ModificationType.SPLIT

        # Check for disorder patterns (sequence number changes)
        if "sequence_number" in differences:
            return ModificationType.DISORDER

        # Check for TTL modifications
        if "ttl" in differences:
            return ModificationType.TTL_MODIFICATION

        # Check for checksum modifications
        if "checksum" in differences:
            return ModificationType.CHECKSUM_MODIFICATION

        # Check for fragmentation
        if "fragment_offset" in differences:
            return ModificationType.FRAGMENT

        # Default to generic modification
        return ModificationType.SPLIT


@dataclass
class AttackSequence:
    """Complete sequence of related attack applications."""

    domain: str
    mode: ExecutionMode
    attacks: List[AttackEvent]
    total_duration: timedelta
    success_rate: float
    packet_modifications: List[PacketModification] = field(default_factory=list)

    def get_attack_types(self) -> List[str]:
        """Get list of attack types in this sequence."""
        return [attack.attack_type for attack in self.attacks]

    def get_total_packets(self) -> int:
        """Get total number of packets in this sequence."""
        return sum(attack.packet_count for attack in self.attacks)


@dataclass
class TruthViolation:
    """Violation of truth consistency between logs and PCAP."""

    attack_event: AttackEvent
    expected_modifications: List[PacketModificationSpec]
    actual_modifications: List[PacketModification]
    violation_type: str
    description: str


@dataclass
class CorrelationResult:
    """Results of correlating log entries with PCAP evidence."""

    semantically_correct_attacks: List[AttackEvent]
    semantically_incorrect_attacks: List[AttackEvent]
    truth_consistency_violations: List[TruthViolation]
    orphaned_modifications: List[PacketModification]
    semantic_accuracy: float
    truth_consistency_score: float

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        total_attacks = len(self.semantically_correct_attacks) + len(
            self.semantically_incorrect_attacks
        )
        return {
            "total_attacks_analyzed": total_attacks,
            "semantically_correct": len(self.semantically_correct_attacks),
            "semantically_incorrect": len(self.semantically_incorrect_attacks),
            "truth_violations": len(self.truth_consistency_violations),
            "orphaned_modifications": len(self.orphaned_modifications),
            "semantic_accuracy": self.semantic_accuracy,
            "truth_consistency_score": self.truth_consistency_score,
        }


@dataclass
class ParameterDiff:
    """Differences in parameters between attack sequences."""

    parameter_name: str
    value1: Any
    value2: Any
    impact_description: str


@dataclass
class ParityResult:
    """Results of comparing attack application between modes."""

    discovery_sequences: List[AttackSequence]
    service_sequences: List[AttackSequence]
    matching_sequences: List[tuple[AttackSequence, AttackSequence]]
    parameter_differences: List[ParameterDiff]
    timing_differences: List[Dict[str, Any]]
    parity_score: float

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of parity analysis."""
        return {
            "discovery_sequences": len(self.discovery_sequences),
            "service_sequences": len(self.service_sequences),
            "matching_sequences": len(self.matching_sequences),
            "parameter_differences": len(self.parameter_differences),
            "timing_differences": len(self.timing_differences),
            "parity_score": self.parity_score,
        }


@dataclass
class DetectedAttack:
    """Attack pattern detected in PCAP analysis."""

    attack_type: str
    confidence: float
    packet_indices: List[int]
    timing_info: TimingInfo
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimingAnalysis:
    """Timing analysis results from PCAP data."""

    total_duration: timedelta
    packet_intervals: List[float]
    attack_timings: List[TimingInfo]
    average_interval: float
    timing_variance: float


# Utility functions for packet modification detection


def detect_packet_modifications(packets: List[PacketInfo]) -> List[PacketModification]:
    """Detect modifications between consecutive packets.

    Args:
        packets: List of packet information objects

    Returns:
        List of detected packet modifications
    """
    modifications = []

    for i in range(len(packets) - 1):
        current = packets[i]
        next_packet = packets[i + 1]

        # Check if packets are related (same connection)
        if current.get_connection_tuple() == next_packet.get_connection_tuple():
            differences = current.compare_with(next_packet)

            if differences:  # If there are differences, it's a modification
                mod_type = PacketModification.detect_modification_type(current, next_packet)
                modification = PacketModification(
                    timestamp=next_packet.timestamp,
                    packet_index=i + 1,
                    modification_type=mod_type,
                    original_packet=current,
                    modified_packet=next_packet,
                    modified_fields=list(differences.keys()),
                )
                modifications.append(modification)

    return modifications


def group_modifications_by_attack(
    modifications: List[PacketModification], time_window: float = 1.0
) -> List[List[PacketModification]]:
    """Group packet modifications that likely belong to the same attack.

    Args:
        modifications: List of packet modifications
        time_window: Time window in seconds for grouping

    Returns:
        List of modification groups
    """
    if not modifications:
        return []

    # Sort by timestamp
    sorted_mods = sorted(modifications, key=lambda m: m.timestamp)

    groups = []
    current_group = [sorted_mods[0]]

    for mod in sorted_mods[1:]:
        # Check if this modification is within time window of the last in current group
        time_diff = (mod.timestamp - current_group[-1].timestamp).total_seconds()

        if time_diff <= time_window:
            current_group.append(mod)
        else:
            groups.append(current_group)
            current_group = [mod]

    # Add the last group
    if current_group:
        groups.append(current_group)

    return groups


def classify_attack_from_modifications(modifications: List[PacketModification]) -> Optional[str]:
    """Classify attack type based on packet modifications.

    Args:
        modifications: List of packet modifications from the same attack

    Returns:
        Detected attack type or None if unrecognized
    """
    if not modifications:
        return None

    mod_types = [mod.modification_type for mod in modifications]

    # Check for specific attack patterns
    if ModificationType.SPLIT in mod_types:
        if len([m for m in mod_types if m == ModificationType.SPLIT]) > 1:
            return "multisplit"
        else:
            return "split"

    if ModificationType.DISORDER in mod_types:
        return "disorder"

    if ModificationType.FAKE in mod_types:
        return "fake"

    if ModificationType.TTL_MODIFICATION in mod_types:
        return "ttl_modification"

    # Check for combinations
    if len(set(mod_types)) > 1:
        return f"combo_{'+'.join(sorted(set(t.value for t in mod_types)))}"

    return "unknown"
