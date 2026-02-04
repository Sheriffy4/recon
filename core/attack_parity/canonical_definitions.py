"""
Canonical Attack Definitions Registry

This module defines the universal semantics for all attack types used in the system.
Each attack has a canonical definition that specifies exactly what packet modifications
it should produce, regardless of execution mode (discovery vs service).
"""

from typing import Dict, List, Optional
from .models import (
    AttackDefinition,
    PacketModificationSpec,
    AttackCombination,
    InteractionRule,
    ModificationType,
    InteractionType,
    TimingConstraint,
    ConflictResolution,
    ModificationEffect,
    CombinationConstraint,
)


class CanonicalAttackRegistry:
    """Registry of canonical attack definitions."""

    def __init__(self):
        self._attack_definitions: Dict[str, AttackDefinition] = {}
        self._combination_definitions: Dict[str, AttackCombination] = {}
        self._initialize_core_attacks()
        self._initialize_combinations()

    def _initialize_core_attacks(self):
        """Initialize canonical definitions for core attack types."""

        # Split attack - splits packets at specified position
        self._attack_definitions["split"] = AttackDefinition(
            attack_type="split",
            description="Splits a single packet into two fragments at specified position",
            expected_packet_modifications=[
                PacketModificationSpec(
                    modification_type=ModificationType.SPLIT,
                    target_fields=["size"],  # Split typically changes packet size
                    conditions=["split_position > 0", "split_position < payload_length"],
                )
            ],
            parameter_effects={
                "split_pos": ModificationEffect(
                    parameter_name="split_pos",
                    effect_description="Position where packet is split",
                    affected_fields=["payload_fragment_1", "payload_fragment_2"],
                )
            },
            invariants=[
                "fragment_1_size + fragment_2_size == original_size",
                "fragment_1_content + fragment_2_content == original_content",
            ],
        )

        # Multisplit attack - splits packets into multiple fragments
        self._attack_definitions["multisplit"] = AttackDefinition(
            attack_type="multisplit",
            description="Splits a single packet into multiple fragments",
            expected_packet_modifications=[
                PacketModificationSpec(
                    modification_type=ModificationType.SPLIT,  # Multisplit uses SPLIT type
                    target_fields=["size"],  # Multisplit changes packet sizes
                    conditions=["split_count > 1"],
                )
            ],
            parameter_effects={
                "split_count": ModificationEffect(
                    parameter_name="split_count",
                    effect_description="Number of fragments to create",
                    affected_fields=["fragment_count"],
                )
            },
            invariants=[
                "sum(fragment_sizes) == original_size",
                "concatenated_fragments == original_content",
            ],
        )

        # Disorder attack - reorders packet fragments
        self._attack_definitions["disorder"] = AttackDefinition(
            attack_type="disorder",
            description="Reorders packet fragments to bypass DPI",
            expected_packet_modifications=[
                PacketModificationSpec(
                    modification_type=ModificationType.DISORDER,
                    target_fields=["sequence_number"],  # Disorder changes sequence numbers
                    conditions=["fragment_count > 1"],
                )
            ],
            parameter_effects={
                "disorder_pattern": ModificationEffect(
                    parameter_name="disorder_pattern",
                    effect_description="Pattern for reordering fragments",
                    affected_fields=["sequence_order"],
                )
            },
            invariants=[
                "all_fragments_present",
                "reordered_content == original_content_when_reassembled",
            ],
        )

        # Fake attack - inserts fake packets
        self._attack_definitions["fake"] = AttackDefinition(
            attack_type="fake",
            description="Inserts fake packets with invalid checksums or TTL",
            expected_packet_modifications=[
                PacketModificationSpec(
                    modification_type=ModificationType.FAKE,
                    target_fields=["ttl"],  # Fake typically modifies TTL or checksum
                    conditions=["fake_packet_inserted"],
                )
            ],
            parameter_effects={
                "fake_type": ModificationEffect(
                    parameter_name="fake_type",
                    effect_description="Type of fake packet (badsum, badttl)",
                    affected_fields=["checksum", "ttl"],
                )
            },
            invariants=[
                "fake_packets_have_invalid_checksums_or_ttl",
                "real_packets_remain_unchanged",
            ],
        )

    def _initialize_combinations(self):
        """Initialize canonical definitions for attack combinations."""

        # Smart combo: disorder + multisplit
        self._combination_definitions["smart_combo_disorder_multisplit"] = AttackCombination(
            combination_name="smart_combo_disorder_multisplit",
            attack_sequence=["multisplit", "disorder"],
            interaction_rules=[
                InteractionRule(
                    primary_attack="multisplit",
                    secondary_attack="disorder",
                    interaction_type=InteractionType.SEQUENTIAL,
                    timing_constraints=TimingConstraint(min_delay=0.0, max_delay=0.1),
                    conflict_resolution=ConflictResolution.MERGE,
                )
            ],
            connection_preservation_rules=[
                "fragments_must_be_reassemblable",
                "total_content_preserved",
                "tcp_sequence_numbers_valid",
            ],
            failure_conditions=["fragments_lost_during_reordering", "tcp_connection_reset"],
        )

        # Smart combo: fake + split
        self._combination_definitions["smart_combo_fake_split"] = AttackCombination(
            combination_name="smart_combo_fake_split",
            attack_sequence=["split", "fake"],
            interaction_rules=[
                InteractionRule(
                    primary_attack="split",
                    secondary_attack="fake",
                    interaction_type=InteractionType.PARALLEL,
                    timing_constraints=TimingConstraint(min_delay=0.0, max_delay=0.05),
                    conflict_resolution=ConflictResolution.FIRST_WINS,
                )
            ],
            connection_preservation_rules=[
                "real_fragments_maintain_connection",
                "fake_packets_ignored_by_server",
            ],
            failure_conditions=["server_processes_fake_packets", "connection_confused_by_fakes"],
        )

    def get_attack_definition(self, attack_type: str) -> Optional[AttackDefinition]:
        """Get canonical definition for an attack type."""
        return self._attack_definitions.get(attack_type)

    def get_combination_definition(self, combination_name: str) -> Optional[AttackCombination]:
        """Get canonical definition for an attack combination."""
        return self._combination_definitions.get(combination_name)

    def register_attack(self, definition: AttackDefinition):
        """Register a new attack definition."""
        self._attack_definitions[definition.attack_type] = definition

    def register_combination(self, combination: AttackCombination):
        """Register a new attack combination definition."""
        self._combination_definitions[combination.combination_name] = combination

    def list_attack_types(self) -> List[str]:
        """List all registered attack types."""
        return list(self._attack_definitions.keys())

    def list_combinations(self) -> List[str]:
        """List all registered attack combinations."""
        return list(self._combination_definitions.keys())

    def validate_attack_parameters(self, attack_type: str, parameters: Dict) -> bool:
        """Validate parameters against canonical attack definition."""
        definition = self.get_attack_definition(attack_type)
        if not definition:
            return False
        return definition.validate_parameters(parameters)


# Global registry instance
canonical_registry = CanonicalAttackRegistry()
