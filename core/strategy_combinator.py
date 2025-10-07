"""
Strategy combination logic for creating complex DPI bypass strategies.
Combines simple attacks into more sophisticated multi-stage strategies.
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import copy

LOG = logging.getLogger('strategy_combinator')

# Import fingerprinting types if available
try:
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    FINGERPRINTING_AVAILABLE = True
except ImportError:
    LOG.warning("Advanced fingerprinting not available, using fallback types")
    FINGERPRINTING_AVAILABLE = False
    
    class DPIType(Enum):
        UNKNOWN = "unknown"
        ROSKOMNADZOR_TSPU = "roskomnadzor_tspu"
        COMMERCIAL_DPI = "commercial_dpi"


@dataclass
class AttackComponent:
    """Represents a single attack component that can be combined"""
    name: str
    attack_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    fooling_methods: List[str] = field(default_factory=list)
    priority: int = 50
    compatibility: Set[str] = field(default_factory=set)  # Compatible attack types
    conflicts: Set[str] = field(default_factory=set)      # Conflicting attack types


class StrategyCombinator:
    """
    Combines simple attack strategies into more complex multi-stage strategies.
    
    Example combinations:
    - fakeddisorder + badsum + low TTL
    - multisplit + md5sig + high TTL  
    - fake + disorder + seqovl
    """
    
    def __init__(self):
        self.attack_components = {}
        self.combination_rules = {}
        self._load_attack_components()
        self._load_combination_rules()
    
    def _load_attack_components(self):
        """Load available attack components"""
        
        components = [
            AttackComponent(
                name="fakeddisorder_base",
                attack_type="fakeddisorder",
                parameters={"split_pos": 76, "overlap_size": 1},
                compatibility={"fake", "badsum_fooling", "md5sig_fooling", "ttl_manipulation"},
                conflicts={"multisplit", "seqovl_standalone"}
            ),
            
            AttackComponent(
                name="multisplit_base", 
                attack_type="multisplit",
                parameters={"positions": [1, 3, 5]},
                compatibility={"badsum_fooling", "md5sig_fooling", "ttl_manipulation"},
                conflicts={"fakeddisorder", "seqovl"}
            ),
            
            AttackComponent(
                name="fake_base",
                attack_type="fake",
                parameters={},
                compatibility={"fakeddisorder", "badsum_fooling", "md5sig_fooling", "ttl_manipulation"},
                conflicts=set()
            ),
            
            AttackComponent(
                name="seqovl_base",
                attack_type="seqovl", 
                parameters={"split_pos": 3, "overlap_size": 1},
                compatibility={"badsum_fooling", "md5sig_fooling"},
                conflicts={"multisplit"}
            ),
            
            # Fooling methods
            AttackComponent(
                name="badsum_fooling",
                attack_type="fooling",
                fooling_methods=["badsum"],
                compatibility={"fakeddisorder", "multisplit", "fake", "seqovl"},
                conflicts=set()
            ),
            
            AttackComponent(
                name="md5sig_fooling",
                attack_type="fooling", 
                fooling_methods=["md5sig"],
                compatibility={"fakeddisorder", "multisplit", "fake", "seqovl"},
                conflicts=set()
            ),
            
            AttackComponent(
                name="badseq_fooling",
                attack_type="fooling",
                fooling_methods=["badseq"],
                compatibility={"fakeddisorder", "multisplit", "fake", "seqovl"},
                conflicts=set()
            ),
            
            # TTL manipulation
            AttackComponent(
                name="low_ttl",
                attack_type="ttl_manipulation",
                parameters={"ttl": 1},
                compatibility={"fakeddisorder", "multisplit", "fake", "seqovl"},
                conflicts={"high_ttl"}
            ),
            
            AttackComponent(
                name="high_ttl", 
                attack_type="ttl_manipulation",
                parameters={"ttl": 64},
                compatibility={"fakeddisorder", "multisplit", "fake", "seqovl"},
                conflicts={"low_ttl"}
            ),
            
            # Advanced parameters
            AttackComponent(
                name="autottl",
                attack_type="parameter",
                parameters={"autottl": 2},
                compatibility={"fakeddisorder", "multisplit", "fake"},
                conflicts=set()
            ),
            
            AttackComponent(
                name="repeats",
                attack_type="parameter", 
                parameters={"repeats": 2},
                compatibility={"fakeddisorder", "multisplit", "fake"},
                conflicts=set()
            )
        ]
        
        for comp in components:
            self.attack_components[comp.name] = comp
    
    def _load_combination_rules(self):
        """Load rules for effective attack combinations"""
        
        self.combination_rules = {
            # Roskomnadzor TSPU optimized combinations
            "roskomnadzor_aggressive": [
                "fakeddisorder_base", "badsum_fooling", "md5sig_fooling", "low_ttl", "autottl"
            ],
            
            "roskomnadzor_conservative": [
                "fakeddisorder_base", "badseq_fooling", "low_ttl"
            ],
            
            # Commercial DPI combinations
            "commercial_dpi_bypass": [
                "multisplit_base", "badsum_fooling", "high_ttl"
            ],
            
            "commercial_dpi_advanced": [
                "fakeddisorder_base", "badsum_fooling", "high_ttl", "repeats"
            ],
            
            # Generic effective combinations
            "disorder_badsum_combo": [
                "fakeddisorder_base", "badsum_fooling", "high_ttl"
            ],
            
            "disorder_md5sig_combo": [
                "fakeddisorder_base", "md5sig_fooling", "low_ttl"
            ],
            
            "multisplit_aggressive": [
                "multisplit_base", "badsum_fooling", "md5sig_fooling", "high_ttl"
            ],
            
            # Fallback combinations
            "simple_fake": [
                "fake_base", "badsum_fooling", "high_ttl"
            ],
            
            "seqovl_basic": [
                "seqovl_base", "badsum_fooling"
            ]
        }
    
    def _check_compatibility(self, components: List[str]) -> Tuple[bool, List[str]]:
        """
        Check if a list of components can be combined.
        
        Returns:
            Tuple of (is_compatible, list_of_conflicts)
        """
        
        conflicts = []
        component_types = set()
        
        for comp_name in components:
            if comp_name not in self.attack_components:
                conflicts.append(f"Unknown component: {comp_name}")
                continue
            
            comp = self.attack_components[comp_name]
            
            # Check for conflicts with other components
            for other_name in components:
                if other_name == comp_name:
                    continue
                
                if other_name not in self.attack_components:
                    continue
                
                other_comp = self.attack_components[other_name]
                
                # Check direct conflicts
                if other_comp.attack_type in comp.conflicts:
                    conflicts.append(f"{comp_name} conflicts with {other_name}")
                
                # Check for TTL conflicts specifically
                if comp.attack_type == "ttl_manipulation" and other_comp.attack_type == "ttl_manipulation":
                    if comp_name != other_name:  # Different TTL components conflict
                        conflicts.append(f"{comp_name} conflicts with {other_name} (TTL conflict)")
                
                # Check if components are compatible
                if comp.attack_type != "fooling" and comp.attack_type != "ttl_manipulation" and comp.attack_type != "parameter":
                    if other_comp.attack_type not in comp.compatibility and other_comp.attack_type not in ["fooling", "ttl_manipulation", "parameter"]:
                        conflicts.append(f"{comp_name} not compatible with {other_name}")
            
            component_types.add(comp.attack_type)
        
        # Must have at least one main attack type
        main_types = {"fakeddisorder", "multisplit", "fake", "seqovl"}
        if not component_types.intersection(main_types):
            conflicts.append("No main attack type specified")
        
        return len(conflicts) == 0, conflicts
    
    def combine_components(self, component_names: List[str]) -> Optional[Dict[str, Any]]:
        """
        Combine attack components into a single strategy.
        
        Args:
            component_names: List of component names to combine
            
        Returns:
            Combined strategy dictionary or None if incompatible
        """
        
        # Check compatibility
        is_compatible, conflicts = self._check_compatibility(component_names)
        if not is_compatible:
            LOG.warning(f"Cannot combine components: {conflicts}")
            return None
        
        # Find the main attack type
        main_attack = None
        combined_params = {}
        fooling_methods = []
        
        for comp_name in component_names:
            comp = self.attack_components[comp_name]
            
            # Identify main attack type
            if comp.attack_type in ["fakeddisorder", "multisplit", "fake", "seqovl"]:
                if main_attack is None:
                    main_attack = comp.attack_type
                    combined_params.update(comp.parameters)
                else:
                    # Multiple main attacks - this shouldn't happen if compatibility check passed
                    LOG.warning(f"Multiple main attack types: {main_attack}, {comp.attack_type}")
                    return None
            
            # Collect fooling methods
            elif comp.attack_type == "fooling":
                fooling_methods.extend(comp.fooling_methods)
            
            # Merge other parameters
            else:
                combined_params.update(comp.parameters)
        
        if main_attack is None:
            LOG.error("No main attack type found in components")
            return None
        
        # Add fooling methods if any
        if fooling_methods:
            combined_params["fooling"] = list(set(fooling_methods))  # Remove duplicates
        
        strategy = {
            "type": main_attack,
            "params": combined_params
        }
        
        LOG.info(f"Combined strategy: {strategy}")
        return strategy
    
    def get_predefined_combination(self, combination_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a predefined combination by name.
        
        Args:
            combination_name: Name of predefined combination
            
        Returns:
            Strategy dictionary or None if not found
        """
        
        if combination_name not in self.combination_rules:
            LOG.error(f"Unknown combination: {combination_name}")
            return None
        
        components = self.combination_rules[combination_name]
        return self.combine_components(components)
    
    def suggest_combinations_for_fingerprint(self, fingerprint: DPIFingerprint) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Suggest effective combinations based on DPI fingerprint.
        
        Args:
            fingerprint: DPI fingerprint
            
        Returns:
            List of (combination_name, strategy) tuples
        """
        
        suggestions = []
        
        # DPI type specific suggestions
        if fingerprint.dpi_type == DPIType.ROSKOMNADZOR_TSPU:
            suggestions.extend([
                ("roskomnadzor_aggressive", self.get_predefined_combination("roskomnadzor_aggressive")),
                ("roskomnadzor_conservative", self.get_predefined_combination("roskomnadzor_conservative")),
                ("disorder_md5sig_combo", self.get_predefined_combination("disorder_md5sig_combo"))
            ])
        
        elif fingerprint.dpi_type == DPIType.COMMERCIAL_DPI:
            suggestions.extend([
                ("commercial_dpi_bypass", self.get_predefined_combination("commercial_dpi_bypass")),
                ("commercial_dpi_advanced", self.get_predefined_combination("commercial_dpi_advanced")),
                ("multisplit_aggressive", self.get_predefined_combination("multisplit_aggressive"))
            ])
        
        # Capability-based suggestions
        if fingerprint.vulnerable_to_bad_checksum_race:
            suggestions.append(("disorder_badsum_combo", self.get_predefined_combination("disorder_badsum_combo")))
        
        if fingerprint.vulnerable_to_fragmentation:
            suggestions.append(("multisplit_aggressive", self.get_predefined_combination("multisplit_aggressive")))
        
        # Fallback suggestions
        suggestions.extend([
            ("simple_fake", self.get_predefined_combination("simple_fake")),
            ("seqovl_basic", self.get_predefined_combination("seqovl_basic"))
        ])
        
        # Filter out None results and remove duplicates
        valid_suggestions = []
        seen_strategies = set()
        
        for name, strategy in suggestions:
            if strategy is not None:
                strategy_str = str(sorted(strategy.items()))
                if strategy_str not in seen_strategies:
                    valid_suggestions.append((name, strategy))
                    seen_strategies.add(strategy_str)
        
        return valid_suggestions
    
    def suggest_combinations_from_rule_recommendations(self, rule_recommendations: List[str], 
                                                     technique_priorities: Dict[str, int],
                                                     technique_confidences: Dict[str, float]) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Create strategy combinations based on rule engine recommendations.
        
        Args:
            rule_recommendations: List of recommended techniques from rule engine
            technique_priorities: Priority scores for each technique
            technique_confidences: Confidence scores for each technique
            
        Returns:
            List of (combination_name, strategy) tuples
        """
        
        suggestions = []
        
        # Group techniques by type
        main_attacks = []
        fooling_methods = []
        ttl_methods = []
        advanced_methods = []
        
        for technique in rule_recommendations:
            if technique in ["tcp_fakeddisorder", "tcp_multisplit", "tcp_seqovl", "tcp_multidisorder"]:
                main_attacks.append(technique)
            elif "fooling" in technique or technique in ["badsum_fooling", "md5sig_fooling", "badseq_fooling"]:
                fooling_methods.append(technique)
            elif "ttl" in technique:
                ttl_methods.append(technique)
            else:
                advanced_methods.append(technique)
        
        # Create combinations based on highest priority techniques
        if main_attacks:
            primary_attack = main_attacks[0]  # Highest priority main attack
            
            # Create basic combination
            components = [f"{primary_attack.replace('tcp_', '')}_base"]
            
            # Add fooling if available
            if fooling_methods:
                fooling_method = fooling_methods[0].replace("_fooling", "")
                components.append(f"{fooling_method}_fooling")
            
            # Add TTL if available
            if ttl_methods:
                if "low_ttl" in ttl_methods[0]:
                    components.append("low_ttl")
                else:
                    components.append("high_ttl")
            
            # Create combination
            strategy = self.combine_components(components)
            if strategy:
                confidence = max([technique_confidences.get(t, 0.5) for t in rule_recommendations[:3]])
                combination_name = f"rule_based_{primary_attack}_{confidence:.2f}"
                suggestions.append((combination_name, strategy))
        
        # Create advanced combinations for high-confidence techniques
        high_confidence_techniques = [
            t for t in rule_recommendations 
            if technique_confidences.get(t, 0.0) > 0.8
        ]
        
        if len(high_confidence_techniques) >= 2:
            # Try to create a multi-technique combination
            if "tcp_multisplit" in high_confidence_techniques and "badsum_fooling" in high_confidence_techniques:
                strategy = self.get_predefined_combination("multisplit_aggressive")
                if strategy:
                    suggestions.append(("rule_multisplit_aggressive", strategy))
            
            if "tcp_fakeddisorder" in high_confidence_techniques:
                strategy = self.get_predefined_combination("disorder_badsum_combo")
                if strategy:
                    suggestions.append(("rule_fakeddisorder_combo", strategy))
        
        # Remove duplicates
        unique_suggestions = []
        seen_strategies = set()
        
        for name, strategy in suggestions:
            if strategy is not None:
                strategy_str = str(sorted(strategy.items()))
                if strategy_str not in seen_strategies:
                    unique_suggestions.append((name, strategy))
                    seen_strategies.add(strategy_str)
        
        return unique_suggestions
    
    def create_custom_combination(self, base_attack: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Create a custom combination with specified parameters.
        
        Args:
            base_attack: Base attack type (fakeddisorder, multisplit, etc.)
            **kwargs: Additional parameters like ttl, fooling, etc.
            
        Returns:
            Strategy dictionary
        """
        
        components = []
        
        # Add base attack
        base_component = f"{base_attack}_base"
        if base_component in self.attack_components:
            components.append(base_component)
        else:
            LOG.error(f"Unknown base attack: {base_attack}")
            return None
        
        # Add TTL if specified
        if "ttl" in kwargs:
            ttl_val = kwargs["ttl"]
            if ttl_val <= 5:
                components.append("low_ttl")
            else:
                components.append("high_ttl")
        
        # Add fooling methods
        if "fooling" in kwargs:
            fooling_list = kwargs["fooling"]
            if isinstance(fooling_list, str):
                fooling_list = [fooling_list]
            
            for method in fooling_list:
                if f"{method}_fooling" in self.attack_components:
                    components.append(f"{method}_fooling")
        
        # Add other parameters
        if "autottl" in kwargs:
            components.append("autottl")
        
        if "repeats" in kwargs:
            components.append("repeats")
        
        return self.combine_components(components)
    
    def list_available_combinations(self) -> List[str]:
        """List all available predefined combinations"""
        return list(self.combination_rules.keys())
    
    def list_available_components(self) -> List[str]:
        """List all available attack components"""
        return list(self.attack_components.keys())


def create_default_combinator() -> StrategyCombinator:
    """Factory function to create a combinator with default components"""
    return StrategyCombinator()


# Example usage and testing
if __name__ == "__main__":
    # Import fingerprinting if available
    if FINGERPRINTING_AVAILABLE:
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    
    # Create test fingerprint
    test_fingerprint = DPIFingerprint(
        dpi_type=DPIType.ROSKOMNADZOR_TSPU,
        allows_badsum=True,
        allows_md5sig=True,
        requires_low_ttl=True
    )
    
    # Create combinator
    combinator = create_default_combinator()
    
    # Test predefined combination
    strategy = combinator.get_predefined_combination("roskomnadzor_aggressive")
    print("Roskomnadzor aggressive strategy:", strategy)
    
    # Test suggestions
    suggestions = combinator.suggest_combinations_for_fingerprint(test_fingerprint)
    print(f"\nSuggested combinations ({len(suggestions)}):")
    for name, strat in suggestions[:3]:  # Show first 3
        print(f"  {name}: {strat}")
    
    # Test custom combination
    custom = combinator.create_custom_combination(
        "fakeddisorder", 
        ttl=64, 
        fooling=["badsum", "md5sig"]
    )
    print(f"\nCustom combination: {custom}")