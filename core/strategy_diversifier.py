"""
StrategyDiversifier - Ensures diverse strategy generation and prevents repetitive testing.

This module implements the strategy diversity system for auto-discovery mode,
ensuring that different strategies are tested rather than applying the same strategy repeatedly.

Key Components:
- StrategyDiversifier: Main class for diversity tracking and generation
- DiversityTracker: Tracks tested combinations and calculates diversity metrics
- StrategyVariation: Represents different variations of strategies

Requirements addressed: 2.1, 2.2, 2.4, 2.5
"""

import logging
import hashlib
import json
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter
import random

LOG = logging.getLogger("strategy_diversifier")


class AttackType(Enum):
    """Types of attacks for categorization"""

    FRAGMENTATION = "fragmentation"
    DISORDER = "disorder"
    FAKE = "fake"
    TTL_MANIPULATION = "ttl_manipulation"
    FOOLING = "fooling"
    MULTISPLIT = "multisplit"
    SEQOVL = "seqovl"
    PASSTHROUGH = "passthrough"


@dataclass
class StrategyVariation:
    """Represents a strategy variation with its characteristics"""

    name: str
    attack_types: List[AttackType]
    parameters: Dict[str, Any]
    complexity_score: float = 0.0
    tested: bool = False
    test_timestamp: Optional[datetime] = None
    success_rate: Optional[float] = None

    def get_signature(self) -> str:
        """Generate a unique signature for this strategy variation"""
        # Create a deterministic signature based on attack types and key parameters
        signature_data = {
            "attack_types": sorted([at.value for at in self.attack_types]),
            "key_params": {
                k: v
                for k, v in self.parameters.items()
                if k in ["split_pos", "ttl", "fooling", "split_count", "disorder_count"]
            },
        }
        signature_str = json.dumps(signature_data, sort_keys=True)
        return hashlib.md5(signature_str.encode()).hexdigest()[:12]


@dataclass
class DiversityMetrics:
    """Metrics for tracking strategy diversity"""

    total_strategies: int = 0
    unique_combinations: int = 0
    attack_type_distribution: Dict[str, int] = field(default_factory=dict)
    parameter_variations: Dict[str, Set[Any]] = field(default_factory=lambda: defaultdict(set))
    diversity_score: float = 0.0
    untested_ratio: float = 1.0

    def calculate_diversity_score(self) -> float:
        """Calculate overall diversity score (0.0 to 1.0)"""
        if self.total_strategies == 0:
            return 0.0

        # Factor 1: Unique combination ratio
        uniqueness_factor = self.unique_combinations / max(1, self.total_strategies)

        # Factor 2: Attack type distribution evenness
        if self.attack_type_distribution:
            total_usage = sum(self.attack_type_distribution.values())
            expected_usage = total_usage / len(self.attack_type_distribution)
            variance = sum(
                (count - expected_usage) ** 2 for count in self.attack_type_distribution.values()
            )
            evenness_factor = 1.0 / (1.0 + variance / max(1, expected_usage))
        else:
            evenness_factor = 0.0

        # Factor 3: Parameter variation richness
        param_richness = len(self.parameter_variations) / max(1, len(self.parameter_variations))

        # Factor 4: Untested strategy availability
        untested_factor = self.untested_ratio

        # Weighted combination
        self.diversity_score = (
            uniqueness_factor * 0.3
            + evenness_factor * 0.25
            + param_richness * 0.2
            + untested_factor * 0.25
        )

        return self.diversity_score


class StrategyDiversifier:
    """
    Main class for ensuring strategy diversity in auto-discovery mode.

    Responsibilities:
    - Track tested strategy combinations
    - Generate diverse strategy variations
    - Prevent repetitive testing
    - Calculate diversity metrics
    - Prioritize untested strategies
    """

    def __init__(self, max_history: int = 1000):
        """
        Initialize the StrategyDiversifier.

        Args:
            max_history: Maximum number of strategies to keep in history
        """
        self.max_history = max_history
        self.tested_strategies: Dict[str, StrategyVariation] = {}
        self.attack_type_usage: Counter = Counter()
        self.parameter_variations: Dict[str, Set[Any]] = defaultdict(set)
        self.generation_history: List[Tuple[datetime, str]] = []

        # Strategy generation templates
        self.attack_templates = self._initialize_attack_templates()
        self.parameter_ranges = self._initialize_parameter_ranges()

        LOG.info("StrategyDiversifier initialized")

    def _initialize_attack_templates(self) -> Dict[AttackType, Dict[str, Any]]:
        """Initialize attack type templates with default parameters"""
        return {
            AttackType.FRAGMENTATION: {
                "base_attacks": ["split", "multisplit"],
                "default_params": {"split_pos": 3, "split_count": 2},
            },
            AttackType.DISORDER: {
                "base_attacks": ["disorder", "multidisorder"],
                "default_params": {"disorder_count": 2, "split_pos": 3},
            },
            AttackType.FAKE: {
                "base_attacks": ["fake", "fakeddisorder"],
                "default_params": {"split_pos": 76, "overlap_size": 1},
            },
            AttackType.TTL_MANIPULATION: {"base_attacks": ["ttl"], "default_params": {"ttl": 1}},
            AttackType.FOOLING: {
                "base_attacks": ["badsum", "badseq", "md5sig"],
                "default_params": {"fooling": "badsum"},
            },
            AttackType.SEQOVL: {
                "base_attacks": ["seqovl"],
                "default_params": {"split_pos": 3, "overlap_size": 1},
            },
            AttackType.PASSTHROUGH: {"base_attacks": ["passthrough"], "default_params": {}},
        }

    def _initialize_parameter_ranges(self) -> Dict[str, List[Any]]:
        """Initialize parameter variation ranges"""
        return {
            "split_pos": [1, 2, 3, 5, 10, 76, "sni", "random"],
            "ttl": [1, 2, 3, 4, 5],
            "fooling": ["badsum", "badseq", "md5sig"],
            "split_count": [2, 4, 8, 16],
            "disorder_count": [1, 2, 3, 4],
            "overlap_size": [1, 2, 3],
        }

    def generate_next_strategy(
        self,
        target_domain: Optional[str] = None,
        exclude_types: Optional[List[AttackType]] = None,
        prefer_untested: bool = True,
    ) -> Optional[StrategyVariation]:
        """
        Generate the next diverse strategy variation.

        Args:
            target_domain: Target domain for strategy adaptation
            exclude_types: Attack types to exclude from generation
            prefer_untested: Whether to prioritize untested combinations

        Returns:
            StrategyVariation or None if no diverse strategy can be generated
        """
        LOG.debug(f"Generating next strategy for domain: {target_domain}")

        exclude_types = exclude_types or []
        available_types = [at for at in AttackType if at not in exclude_types]

        if not available_types:
            LOG.warning("No available attack types for strategy generation")
            return None

        # Try to generate untested strategies first
        if prefer_untested:
            strategy = self._generate_untested_strategy(available_types, target_domain)
            if strategy:
                return strategy

        # Generate diverse strategy based on current usage patterns
        strategy = self._generate_diverse_strategy(available_types, target_domain)

        if strategy:
            LOG.info(
                f"Generated strategy: {strategy.name} with signature: {strategy.get_signature()}"
            )

        return strategy

    def _generate_untested_strategy(
        self, available_types: List[AttackType], target_domain: Optional[str]
    ) -> Optional[StrategyVariation]:
        """Generate a strategy that hasn't been tested yet"""

        # Find least used attack types
        type_usage = {at: self.attack_type_usage.get(at.value, 0) for at in available_types}
        min_usage = min(type_usage.values()) if type_usage else 0
        least_used_types = [at for at, usage in type_usage.items() if usage == min_usage]

        # CRITICAL FIX: Randomize order to ensure diverse strategy generation
        # Without this, the method always returns fragmentation first (first in enum)
        random.shuffle(least_used_types)

        # Try different combinations starting with least used types
        for primary_type in least_used_types:
            # Single attack strategy
            strategy = self._create_strategy_variation([primary_type], target_domain)
            if strategy and not self._is_strategy_tested(strategy):
                return strategy

            # Combination strategies
            for secondary_type in available_types:
                if secondary_type != primary_type and self._are_types_compatible(
                    primary_type, secondary_type
                ):
                    strategy = self._create_strategy_variation(
                        [primary_type, secondary_type], target_domain
                    )
                    if strategy and not self._is_strategy_tested(strategy):
                        return strategy

        return None

    def _generate_diverse_strategy(
        self, available_types: List[AttackType], target_domain: Optional[str]
    ) -> Optional[StrategyVariation]:
        """Generate a diverse strategy based on current patterns"""

        # Select attack types to maximize diversity
        selected_types = self._select_diverse_attack_types(available_types)

        if not selected_types:
            return None

        # Generate strategy with diverse parameters
        strategy = self._create_strategy_variation(selected_types, target_domain)

        # If this exact strategy was tested, try parameter variations
        if strategy and self._is_strategy_tested(strategy):
            strategy = self._create_parameter_variation(strategy)

        return strategy

    def _select_diverse_attack_types(self, available_types: List[AttackType]) -> List[AttackType]:
        """Select attack types to maximize diversity"""

        # Calculate selection weights (inverse of usage frequency)
        total_usage = sum(self.attack_type_usage.values()) or 1
        weights = {}

        for attack_type in available_types:
            usage = self.attack_type_usage.get(attack_type.value, 0)
            # Higher weight for less used types
            weights[attack_type] = max(0.1, 1.0 - (usage / total_usage))

        # Select 1-3 attack types based on weights
        num_types = random.choices([1, 2, 3], weights=[0.4, 0.4, 0.2])[0]

        selected = []
        remaining_types = available_types.copy()

        for _ in range(min(num_types, len(remaining_types))):
            # Weighted random selection
            type_weights = [weights[at] for at in remaining_types]
            selected_type = random.choices(remaining_types, weights=type_weights)[0]

            selected.append(selected_type)
            remaining_types.remove(selected_type)

            # Remove incompatible types
            remaining_types = [
                at for at in remaining_types if self._are_types_compatible(selected_type, at)
            ]

        return selected

    def _create_strategy_variation(
        self, attack_types: List[AttackType], target_domain: Optional[str]
    ) -> StrategyVariation:
        """Create a strategy variation from attack types"""

        # Combine parameters from all attack types
        parameters = {}
        base_attacks = []

        for attack_type in attack_types:
            template = self.attack_templates.get(attack_type, {})
            base_attacks.extend(template.get("base_attacks", []))
            parameters.update(template.get("default_params", {}))

        # Add attack list to parameters
        if base_attacks:
            parameters["attacks"] = base_attacks

        # Generate diverse parameter values
        parameters = self._diversify_parameters(parameters, attack_types)

        # Generate strategy name with parameter-based suffix for uniqueness
        type_names = [at.value for at in attack_types]
        base_name = "_".join(type_names)
        if target_domain:
            base_name += f"_{target_domain.replace('.', '_')}"

        # Add parameter-based suffix to make name unique
        # Use key parameters to differentiate strategies
        param_suffix_parts = []
        key_params = ["split_pos", "ttl", "fooling", "split_count", "disorder_count"]
        for param in key_params:
            if param in parameters:
                value = parameters[param]
                # Convert value to string representation
                if isinstance(value, list):
                    value_str = f"{len(value)}items"
                else:
                    value_str = str(value).replace(".", "_")
                param_suffix_parts.append(f"{param[:3]}{value_str}")

        if param_suffix_parts:
            strategy_name = f"{base_name}_{'_'.join(param_suffix_parts[:3])}"  # Limit to 3 params
        else:
            strategy_name = base_name

        # Calculate complexity score
        complexity = self._calculate_complexity_score(attack_types, parameters)

        return StrategyVariation(
            name=strategy_name,
            attack_types=attack_types,
            parameters=parameters,
            complexity_score=complexity,
        )

    def _diversify_parameters(
        self, base_params: Dict[str, Any], attack_types: List[AttackType]
    ) -> Dict[str, Any]:
        """Generate diverse parameter values"""

        diversified = base_params.copy()

        for param, current_value in base_params.items():
            if param in self.parameter_ranges:
                available_values = self.parameter_ranges[param]
                used_values = self.parameter_variations.get(param, set())

                # Prefer unused values
                unused_values = [v for v in available_values if v not in used_values]
                if unused_values:
                    diversified[param] = random.choice(unused_values)
                else:
                    # All values used, pick randomly
                    diversified[param] = random.choice(available_values)

        # Add attack-type specific parameter variations
        for attack_type in attack_types:
            if attack_type == AttackType.FRAGMENTATION:
                if "split_count" not in diversified:
                    diversified["split_count"] = random.choice([2, 4, 8])
            elif attack_type == AttackType.DISORDER:
                if "disorder_count" not in diversified:
                    diversified["disorder_count"] = random.choice([1, 2, 3])
            elif attack_type == AttackType.TTL_MANIPULATION:
                diversified["ttl"] = random.choice([1, 2, 3])

        return diversified

    def _create_parameter_variation(self, base_strategy: StrategyVariation) -> StrategyVariation:
        """Create a parameter variation of an existing strategy"""

        new_params = base_strategy.parameters.copy()

        # Vary one or two parameters
        param_keys = list(new_params.keys())
        if param_keys:
            vary_count = random.choice([1, 2])
            params_to_vary = random.sample(param_keys, min(vary_count, len(param_keys)))

            for param in params_to_vary:
                if param in self.parameter_ranges:
                    available_values = self.parameter_ranges[param]
                    current_value = new_params[param]
                    other_values = [v for v in available_values if v != current_value]
                    if other_values:
                        new_params[param] = random.choice(other_values)

        # Create new strategy with varied parameters
        new_strategy = StrategyVariation(
            name=f"{base_strategy.name}_var",
            attack_types=base_strategy.attack_types,
            parameters=new_params,
            complexity_score=base_strategy.complexity_score,
        )

        return new_strategy

    def _are_types_compatible(self, type1: AttackType, type2: AttackType) -> bool:
        """Check if two attack types are compatible"""

        # Define incompatible combinations
        incompatible_pairs = {
            (AttackType.FRAGMENTATION, AttackType.MULTISPLIT),
            (AttackType.DISORDER, AttackType.SEQOVL),
            (AttackType.FAKE, AttackType.PASSTHROUGH),
        }

        # Check both directions
        return (type1, type2) not in incompatible_pairs and (type2, type1) not in incompatible_pairs

    def _calculate_complexity_score(
        self, attack_types: List[AttackType], parameters: Dict[str, Any]
    ) -> float:
        """Calculate complexity score for a strategy (0.0 to 1.0)"""

        # Base complexity from number of attack types
        base_complexity = len(attack_types) * 0.2

        # Parameter complexity
        param_complexity = 0.0
        complex_params = ["split_count", "disorder_count", "overlap_size"]
        for param in complex_params:
            if param in parameters:
                value = parameters[param]
                if isinstance(value, int):
                    param_complexity += min(0.1, value * 0.02)

        # Attack type specific complexity
        type_complexity = 0.0
        complexity_weights = {
            AttackType.FRAGMENTATION: 0.1,
            AttackType.DISORDER: 0.15,
            AttackType.FAKE: 0.2,
            AttackType.SEQOVL: 0.25,
            AttackType.MULTISPLIT: 0.3,
        }

        for attack_type in attack_types:
            type_complexity += complexity_weights.get(attack_type, 0.1)

        total_complexity = base_complexity + param_complexity + type_complexity
        return min(1.0, total_complexity)

    def _is_strategy_tested(self, strategy: StrategyVariation) -> bool:
        """Check if a strategy has been tested"""
        signature = strategy.get_signature()
        return signature in self.tested_strategies

    def mark_strategy_tested(
        self, strategy: StrategyVariation, success_rate: Optional[float] = None
    ) -> None:
        """Mark a strategy as tested and update diversity metrics"""

        signature = strategy.get_signature()
        strategy.tested = True
        strategy.test_timestamp = datetime.now()
        strategy.success_rate = success_rate

        # Store in tested strategies
        self.tested_strategies[signature] = strategy

        # Update usage counters
        for attack_type in strategy.attack_types:
            self.attack_type_usage[attack_type.value] += 1

        # Update parameter variations
        for param, value in strategy.parameters.items():
            # Convert unhashable types to hashable ones
            if isinstance(value, list):
                hashable_value = tuple(value)
            elif isinstance(value, dict):
                hashable_value = tuple(sorted(value.items()))
            else:
                hashable_value = value
            self.parameter_variations[param].add(hashable_value)

        # Add to generation history
        self.generation_history.append((datetime.now(), signature))

        # Cleanup old history if needed
        if len(self.tested_strategies) > self.max_history:
            self._cleanup_old_strategies()

        LOG.info(f"Marked strategy {strategy.name} as tested (success_rate: {success_rate})")

    def _cleanup_old_strategies(self) -> None:
        """Remove old strategies to maintain history limit"""

        # Sort by test timestamp and remove oldest
        sorted_strategies = sorted(
            self.tested_strategies.items(), key=lambda x: x[1].test_timestamp or datetime.min
        )

        # Remove oldest 10% of strategies
        remove_count = len(sorted_strategies) // 10
        for i in range(remove_count):
            signature, strategy = sorted_strategies[i]
            del self.tested_strategies[signature]

            # Update counters
            for attack_type in strategy.attack_types:
                self.attack_type_usage[attack_type.value] = max(
                    0, self.attack_type_usage[attack_type.value] - 1
                )

        LOG.debug(f"Cleaned up {remove_count} old strategies from history")

    def get_diversity_metrics(self) -> DiversityMetrics:
        """Calculate and return current diversity metrics"""

        total_strategies = len(self.tested_strategies)
        unique_combinations = len(set(s.get_signature() for s in self.tested_strategies.values()))

        # Attack type distribution
        attack_distribution = dict(self.attack_type_usage)

        # Parameter variations
        param_variations = {k: v.copy() for k, v in self.parameter_variations.items()}

        # Calculate untested ratio
        # Estimate total possible combinations (simplified)
        estimated_total_combinations = len(AttackType) * 10  # Rough estimate
        untested_ratio = max(0.0, 1.0 - (total_strategies / estimated_total_combinations))

        metrics = DiversityMetrics(
            total_strategies=total_strategies,
            unique_combinations=unique_combinations,
            attack_type_distribution=attack_distribution,
            parameter_variations=param_variations,
            untested_ratio=untested_ratio,
        )

        metrics.calculate_diversity_score()

        return metrics

    def get_untested_strategy_count(self) -> int:
        """Get estimated number of untested strategy combinations"""

        # This is a simplified estimation
        total_attack_types = len(AttackType)
        avg_params_per_type = 3
        estimated_total = total_attack_types * avg_params_per_type * 2  # Single + combo strategies

        tested_count = len(self.tested_strategies)
        return max(0, estimated_total - tested_count)

    def reset_diversity_tracking(self) -> None:
        """Reset all diversity tracking data"""

        self.tested_strategies.clear()
        self.attack_type_usage.clear()
        self.parameter_variations.clear()
        self.generation_history.clear()

        LOG.info("Reset diversity tracking data")

    def export_diversity_data(self) -> Dict[str, Any]:
        """Export diversity data for analysis or persistence"""

        return {
            "tested_strategies": {
                sig: {
                    "name": strategy.name,
                    "attack_types": [at.value for at in strategy.attack_types],
                    "parameters": strategy.parameters,
                    "complexity_score": strategy.complexity_score,
                    "tested": strategy.tested,
                    "test_timestamp": (
                        strategy.test_timestamp.isoformat() if strategy.test_timestamp else None
                    ),
                    "success_rate": strategy.success_rate,
                }
                for sig, strategy in self.tested_strategies.items()
            },
            "attack_type_usage": dict(self.attack_type_usage),
            "parameter_variations": {k: list(v) for k, v in self.parameter_variations.items()},
            "generation_history": [
                (timestamp.isoformat(), signature)
                for timestamp, signature in self.generation_history
            ],
            "diversity_metrics": asdict(self.get_diversity_metrics()),
        }

    def import_diversity_data(self, data: Dict[str, Any]) -> None:
        """Import diversity data from external source"""

        # Import tested strategies
        if "tested_strategies" in data:
            for sig, strategy_data in data["tested_strategies"].items():
                attack_types = [AttackType(at) for at in strategy_data["attack_types"]]
                test_timestamp = None
                if strategy_data.get("test_timestamp"):
                    test_timestamp = datetime.fromisoformat(strategy_data["test_timestamp"])

                strategy = StrategyVariation(
                    name=strategy_data["name"],
                    attack_types=attack_types,
                    parameters=strategy_data["parameters"],
                    complexity_score=strategy_data["complexity_score"],
                    tested=strategy_data["tested"],
                    test_timestamp=test_timestamp,
                    success_rate=strategy_data.get("success_rate"),
                )

                self.tested_strategies[sig] = strategy

        # Import usage counters
        if "attack_type_usage" in data:
            self.attack_type_usage = Counter(data["attack_type_usage"])

        # Import parameter variations
        if "parameter_variations" in data:
            self.parameter_variations = {k: set(v) for k, v in data["parameter_variations"].items()}

        # Import generation history
        if "generation_history" in data:
            self.generation_history = [
                (datetime.fromisoformat(timestamp), signature)
                for timestamp, signature in data["generation_history"]
            ]

        LOG.info("Imported diversity data")


# Example usage and testing
if __name__ == "__main__":
    # Create diversifier
    diversifier = StrategyDiversifier()

    # Generate some test strategies
    print("Generating diverse strategies:")
    for i in range(10):
        strategy = diversifier.generate_next_strategy(target_domain="example.com")
        if strategy:
            print(f"  {i+1}. {strategy.name} - Types: {[at.value for at in strategy.attack_types]}")
            print(f"     Parameters: {strategy.parameters}")
            print(f"     Complexity: {strategy.complexity_score:.2f}")

            # Mark as tested with random success rate
            success_rate = random.uniform(0.0, 1.0)
            diversifier.mark_strategy_tested(strategy, success_rate)
            print(f"     Marked as tested (success: {success_rate:.2f})")
            print()

    # Show diversity metrics
    metrics = diversifier.get_diversity_metrics()
    print(f"Diversity Metrics:")
    print(f"  Total strategies: {metrics.total_strategies}")
    print(f"  Unique combinations: {metrics.unique_combinations}")
    print(f"  Diversity score: {metrics.diversity_score:.3f}")
    print(f"  Attack type distribution: {metrics.attack_type_distribution}")
    print(f"  Untested ratio: {metrics.untested_ratio:.3f}")
