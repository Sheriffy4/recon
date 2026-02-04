"""
Attack combination registry from adaptive knowledge.

This module parses adaptive_knowledge.json to extract all used attack combinations
and builds canonical definitions for combinations like smart_combo_disorder_multisplit,
smart_combo_fake_split, etc., validating combination logic against connection
preservation rules.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from .models import (
    AttackCombination,
    InteractionRule,
    InteractionType,
    ConflictResolution,
    TimingConstraint,
    PacketModificationSpec,
    ModificationType,
    AttackDefinition,
)
from .canonical_definitions import canonical_registry

logger = logging.getLogger(__name__)


@dataclass
class CombinationStrategy:
    """Represents a strategy from adaptive knowledge."""

    strategy_name: str
    strategy_params: Dict[str, Any]
    success_count: int
    failure_count: int
    domains: List[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate success rate for this strategy."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def is_combination(self) -> bool:
        """Check if this is a combination attack strategy."""
        return "combo" in self.strategy_name.lower()

    def get_attack_types(self) -> List[str]:
        """Extract individual attack types from combination name."""
        if not self.is_combination:
            return [self.strategy_name]

        # Parse combination name like "smart_combo_disorder_multisplit"
        parts = self.strategy_name.lower().split("_")
        if "combo" in parts:
            combo_index = parts.index("combo")
            attack_parts = parts[combo_index + 1 :]
            return attack_parts

        return [self.strategy_name]


class AdaptiveKnowledgeParser:
    """Parser for adaptive_knowledge.json file."""

    def __init__(self, knowledge_file_path: str = "data/adaptive_knowledge.json"):
        """
        Initialize the parser.

        Args:
            knowledge_file_path: Path to adaptive_knowledge.json file
        """
        self.knowledge_file_path = Path(knowledge_file_path)
        self.logger = logging.getLogger(__name__)

    def parse_adaptive_knowledge(self) -> Dict[str, List[CombinationStrategy]]:
        """
        Parse adaptive knowledge file and extract strategies.

        Returns:
            Dictionary mapping domains to their strategies
        """
        if not self.knowledge_file_path.exists():
            self.logger.warning(f"Adaptive knowledge file not found: {self.knowledge_file_path}")
            return {}

        try:
            with open(self.knowledge_file_path, "r", encoding="utf-8") as f:
                knowledge_data = json.load(f)

            strategies_by_domain = {}

            for domain, domain_data in knowledge_data.items():
                strategies = []

                for strategy_data in domain_data.get("strategies", []):
                    strategy = CombinationStrategy(
                        strategy_name=strategy_data["strategy_name"],
                        strategy_params=strategy_data["strategy_params"],
                        success_count=strategy_data["success_count"],
                        failure_count=strategy_data["failure_count"],
                        domains=[domain],
                    )
                    strategies.append(strategy)

                strategies_by_domain[domain] = strategies

            self.logger.info(f"Parsed {len(strategies_by_domain)} domains with strategies")
            return strategies_by_domain

        except Exception as e:
            self.logger.error(f"Failed to parse adaptive knowledge: {e}")
            return {}

    def extract_unique_combinations(
        self, strategies_by_domain: Dict[str, List[CombinationStrategy]]
    ) -> Dict[str, CombinationStrategy]:
        """
        Extract unique combination strategies across all domains.

        Args:
            strategies_by_domain: Strategies grouped by domain

        Returns:
            Dictionary mapping combination names to representative strategies
        """
        unique_combinations = {}

        for domain, strategies in strategies_by_domain.items():
            for strategy in strategies:
                if strategy.is_combination:
                    combo_name = strategy.strategy_name

                    if combo_name not in unique_combinations:
                        unique_combinations[combo_name] = strategy
                    else:
                        # Merge domain information
                        existing = unique_combinations[combo_name]
                        existing.domains.append(domain)
                        existing.success_count += strategy.success_count
                        existing.failure_count += strategy.failure_count

        self.logger.info(f"Found {len(unique_combinations)} unique attack combinations")
        return unique_combinations


class AttackCombinationRegistry:
    """
    Registry for attack combinations built from adaptive knowledge.

    This class builds canonical definitions for attack combinations and validates
    combination logic against connection preservation rules.
    """

    def __init__(self, knowledge_file_path: str = "data/adaptive_knowledge.json"):
        """
        Initialize the combination registry.

        Args:
            knowledge_file_path: Path to adaptive_knowledge.json file
        """
        self.knowledge_parser = AdaptiveKnowledgeParser(knowledge_file_path)
        self.combinations: Dict[str, AttackCombination] = {}
        self.logger = logging.getLogger(__name__)

        # Connection preservation rules
        self.connection_preservation_rules = [
            "Maintain TCP sequence number continuity",
            "Preserve connection state during modifications",
            "Avoid conflicting packet modifications",
            "Ensure proper timing between attack phases",
            "Maintain protocol compliance for connection establishment",
        ]

        # Failure conditions that break connections
        self.failure_conditions = [
            "Overlapping packet modifications",
            "Conflicting TTL values",
            "Invalid sequence number progression",
            "Excessive timing delays between phases",
            "Protocol violation during handshake",
        ]

    def build_registry(self) -> Dict[str, AttackCombination]:
        """
        Build the complete attack combination registry.

        Returns:
            Dictionary mapping combination names to AttackCombination objects
        """
        self.logger.info("Building attack combination registry from adaptive knowledge")

        # Parse adaptive knowledge
        strategies_by_domain = self.knowledge_parser.parse_adaptive_knowledge()
        unique_combinations = self.knowledge_parser.extract_unique_combinations(
            strategies_by_domain
        )

        # Build canonical definitions for each combination
        for combo_name, strategy in unique_combinations.items():
            combination = self._build_combination_definition(combo_name, strategy)
            if combination:
                self.combinations[combo_name] = combination

        self.logger.info(f"Built registry with {len(self.combinations)} attack combinations")
        return self.combinations

    def get_combination(self, name: str) -> Optional[AttackCombination]:
        """Get a specific attack combination by name."""
        return self.combinations.get(name)

    def get_all_combinations(self) -> List[AttackCombination]:
        """Get all registered attack combinations."""
        return list(self.combinations.values())

    def get_combinations_by_attack_type(self, attack_type: str) -> List[AttackCombination]:
        """Get all combinations that include a specific attack type."""
        matching_combinations = []

        for combination in self.combinations.values():
            if attack_type in combination.attack_sequence:
                matching_combinations.append(combination)

        return matching_combinations

    def validate_combination_logic(self, combination: AttackCombination) -> Dict[str, Any]:
        """
        Validate combination logic against connection preservation rules.

        Args:
            combination: AttackCombination to validate

        Returns:
            Dictionary containing validation results
        """
        validation_result = {
            "is_valid": True,
            "warnings": [],
            "errors": [],
            "connection_safety": "safe",
            "recommendations": [],
        }

        # Check for conflicting attack types
        conflicts = self._check_attack_conflicts(combination.attack_sequence)
        if conflicts:
            validation_result["warnings"].extend(conflicts)
            validation_result["connection_safety"] = "risky"

        # Validate interaction rules
        interaction_issues = self._validate_interaction_rules(combination.interaction_rules)
        if interaction_issues:
            validation_result["warnings"].extend(interaction_issues)

        # Check timing constraints
        timing_issues = self._validate_timing_constraints(combination.interaction_rules)
        if timing_issues:
            validation_result["errors"].extend(timing_issues)
            validation_result["is_valid"] = False
            validation_result["connection_safety"] = "unsafe"

        # Generate recommendations
        validation_result["recommendations"] = self._generate_combination_recommendations(
            combination, validation_result
        )

        return validation_result

    def _build_combination_definition(
        self, combo_name: str, strategy: CombinationStrategy
    ) -> Optional[AttackCombination]:
        """Build canonical definition for a combination strategy."""
        try:
            # Extract attack types from combination name
            attack_types = strategy.get_attack_types()

            if len(attack_types) < 2:
                self.logger.warning(f"Combination {combo_name} has fewer than 2 attack types")
                return None

            # Build interaction rules
            interaction_rules = self._build_interaction_rules(
                attack_types, strategy.strategy_params
            )

            # Build expected modifications
            expected_modifications = self._build_expected_modifications(
                attack_types, strategy.strategy_params
            )

            # Create combination definition
            combination = AttackCombination(
                combination_name=combo_name,
                attack_sequence=attack_types,
                interaction_rules=interaction_rules,
                connection_preservation_rules=self.connection_preservation_rules.copy(),
                expected_combined_modifications=expected_modifications,
                failure_conditions=self.failure_conditions.copy(),
            )

            return combination

        except Exception as e:
            self.logger.error(f"Failed to build combination definition for {combo_name}: {e}")
            return None

    def _build_interaction_rules(
        self, attack_types: List[str], params: Dict[str, Any]
    ) -> List[InteractionRule]:
        """Build interaction rules for attack combination."""
        rules = []

        # Create sequential interaction rules for most combinations
        for i in range(len(attack_types) - 1):
            primary = attack_types[i]
            secondary = attack_types[i + 1]

            # Determine timing constraints based on attack types
            timing_constraint = self._determine_timing_constraint(primary, secondary, params)

            # Determine conflict resolution
            conflict_resolution = self._determine_conflict_resolution(primary, secondary)

            rule = InteractionRule(
                primary_attack=primary,
                secondary_attack=secondary,
                interaction_type=InteractionType.SEQUENTIAL,
                timing_constraints=timing_constraint,
                parameter_dependencies=self._extract_parameter_dependencies(params),
                conflict_resolution=conflict_resolution,
            )
            rules.append(rule)

        return rules

    def _build_expected_modifications(
        self, attack_types: List[str], params: Dict[str, Any]
    ) -> List[PacketModificationSpec]:
        """Build expected packet modifications for combination."""
        modifications = []

        for attack_type in attack_types:
            # Get canonical definition for this attack type
            canonical_def = canonical_registry.get_attack_definition(attack_type)

            if canonical_def:
                # Add expected modifications from canonical definition
                modifications.extend(canonical_def.expected_packet_modifications)
            else:
                # Create basic modification spec for unknown attack types
                mod_spec = self._create_basic_modification_spec(attack_type, params)
                if mod_spec:
                    modifications.append(mod_spec)

        return modifications

    def _determine_timing_constraint(
        self, primary: str, secondary: str, params: Dict[str, Any]
    ) -> TimingConstraint:
        """Determine timing constraints between two attacks."""
        # Default timing constraints
        min_delay = 0.001  # 1ms minimum
        max_delay = 0.1  # 100ms maximum
        sync_required = False

        # Adjust based on attack types
        if "fake" in primary or "fake" in secondary:
            # Fake attacks need careful timing
            min_delay = 0.005
            max_delay = 0.05
            sync_required = True

        if "disorder" in primary or "disorder" in secondary:
            # Disorder attacks need precise timing
            min_delay = 0.001
            max_delay = 0.02
            sync_required = True

        return TimingConstraint(
            min_delay=min_delay, max_delay=max_delay, synchronization_required=sync_required
        )

    def _determine_conflict_resolution(self, primary: str, secondary: str) -> ConflictResolution:
        """Determine how to resolve conflicts between attacks."""
        # Default to first wins for most combinations
        if "fake" in primary and "split" in secondary:
            return ConflictResolution.MERGE
        elif "disorder" in primary:
            return ConflictResolution.FIRST_WINS
        else:
            return ConflictResolution.LAST_WINS

    def _extract_parameter_dependencies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Extract parameter dependencies from strategy parameters."""
        dependencies = {}

        # Common parameter mappings
        if "split_pos" in params:
            dependencies["split_position"] = params["split_pos"]

        if "split_count" in params:
            dependencies["split_count"] = params["split_count"]

        if "ttl" in params:
            dependencies["ttl_value"] = params["ttl"]

        if "fooling" in params:
            dependencies["fooling_method"] = params["fooling"]

        if "disorder_method" in params:
            dependencies["disorder_method"] = params["disorder_method"]

        return dependencies

    def _create_basic_modification_spec(
        self, attack_type: str, params: Dict[str, Any]
    ) -> Optional[PacketModificationSpec]:
        """Create basic modification spec for unknown attack types."""
        if "split" in attack_type:
            return PacketModificationSpec(
                modification_type=ModificationType.SPLIT,
                target_fields=["size", "payload"],
                conditions=["packet_size > split_position"],
            )
        elif "multisplit" in attack_type:
            return PacketModificationSpec(
                modification_type=ModificationType.MULTISPLIT,
                target_fields=["size", "payload"],
                conditions=["split_count > 1"],
            )
        elif "disorder" in attack_type:
            return PacketModificationSpec(
                modification_type=ModificationType.DISORDER,
                target_fields=["sequence_number"],
                conditions=["reorder_method specified"],
            )
        elif "fake" in attack_type:
            return PacketModificationSpec(
                modification_type=ModificationType.FAKE,
                target_fields=["ttl", "checksum"],
                conditions=["fooling_method specified"],
            )

        return None

    def _check_attack_conflicts(self, attack_sequence: List[str]) -> List[str]:
        """Check for conflicting attack types in sequence."""
        conflicts = []

        # Check for known problematic combinations
        if "fake" in attack_sequence and "disorder" in attack_sequence:
            conflicts.append("Fake and disorder attacks may conflict in timing")

        if attack_sequence.count("split") > 1 or attack_sequence.count("multisplit") > 1:
            conflicts.append("Multiple split operations may cause packet fragmentation issues")

        return conflicts

    def _validate_interaction_rules(self, rules: List[InteractionRule]) -> List[str]:
        """Validate interaction rules for consistency."""
        issues = []

        for rule in rules:
            # Check timing constraints
            if rule.timing_constraints.min_delay > rule.timing_constraints.max_delay:
                issues.append(
                    f"Invalid timing constraint: min_delay > max_delay for {rule.primary_attack}->{rule.secondary_attack}"
                )

            # Check for circular dependencies
            # This is a simplified check - in practice, you'd need more sophisticated cycle detection
            if rule.primary_attack == rule.secondary_attack:
                issues.append(f"Circular dependency detected: {rule.primary_attack}")

        return issues

    def _validate_timing_constraints(self, rules: List[InteractionRule]) -> List[str]:
        """Validate timing constraints for feasibility."""
        errors = []

        for rule in rules:
            timing = rule.timing_constraints

            # Check for unrealistic timing constraints
            if timing.min_delay < 0:
                errors.append(
                    f"Negative minimum delay for {rule.primary_attack}->{rule.secondary_attack}"
                )

            if timing.max_delay > 1.0:  # 1 second is probably too long
                errors.append(
                    f"Excessive maximum delay ({timing.max_delay}s) for {rule.primary_attack}->{rule.secondary_attack}"
                )

        return errors

    def _generate_combination_recommendations(
        self, combination: AttackCombination, validation_result: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for combination improvement."""
        recommendations = []

        if not validation_result["is_valid"]:
            recommendations.append("Fix timing constraint errors before deployment")

        if validation_result["connection_safety"] == "risky":
            recommendations.append("Test thoroughly in controlled environment")
            recommendations.append("Monitor connection success rates closely")

        if validation_result["connection_safety"] == "unsafe":
            recommendations.append("Do not use in production - high risk of connection failures")

        # Attack-specific recommendations
        if "fake" in combination.attack_sequence and "disorder" in combination.attack_sequence:
            recommendations.append(
                "Consider reducing timing constraints for fake+disorder combination"
            )

        if len(combination.attack_sequence) > 3:
            recommendations.append(
                "Complex combinations may be unreliable - consider simplification"
            )

        return recommendations


# Global registry instance
combination_registry = AttackCombinationRegistry()


def get_combination_registry() -> AttackCombinationRegistry:
    """Get the global combination registry instance."""
    return combination_registry


def build_combination_registry(
    knowledge_file_path: str = "data/adaptive_knowledge.json",
) -> Dict[str, AttackCombination]:
    """
    Build and return the attack combination registry.

    Args:
        knowledge_file_path: Path to adaptive_knowledge.json file

    Returns:
        Dictionary mapping combination names to AttackCombination objects
    """
    registry = AttackCombinationRegistry(knowledge_file_path)
    return registry.build_registry()


def validate_all_combinations(
    combinations: Dict[str, AttackCombination],
) -> Dict[str, Dict[str, Any]]:
    """
    Validate all combinations in the registry.

    Args:
        combinations: Dictionary of combinations to validate

    Returns:
        Dictionary mapping combination names to validation results
    """
    registry = get_combination_registry()
    validation_results = {}

    for name, combination in combinations.items():
        validation_results[name] = registry.validate_combination_logic(combination)

    return validation_results
