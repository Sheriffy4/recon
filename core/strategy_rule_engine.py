"""
Rule-based strategy generation engine for DPI bypass.
Converts fingerprinting results into concrete strategies.
"""

import logging
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass, field
from enum import Enum

LOG = logging.getLogger('strategy_rule_engine')

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
        DEEP_PACKET_INSPECTION = "deep_packet_inspection"
    
    @dataclass
    class DPIFingerprint:
        target: str = "unknown"
        dpi_type: DPIType = DPIType.UNKNOWN
        vulnerable_to_bad_checksum_race: bool = False
        tcp_options_filtering: bool = False
        content_inspection_depth: int = 0
        connection_reset_timing: float = 0.0
        tcp_window_manipulation: bool = False
        rst_injection_detected: bool = False
        rst_ttl: Optional[int] = None
        vulnerable_to_fragmentation: bool = False
        vulnerable_to_sni_case: bool = False


@dataclass
class StrategyRule:
    """Represents a single rule for strategy generation"""
    name: str
    condition: str  # Human-readable condition description
    priority: int = 50  # Higher priority rules are applied first
    attack_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    fooling_methods: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.parameters:
            self.parameters = {}
        if not self.fooling_methods:
            self.fooling_methods = []


class StrategyRuleEngine:
    """
    Rule-based engine for generating DPI bypass strategies from fingerprints.
    
    Example usage:
        engine = StrategyRuleEngine()
        strategy = engine.generate_strategy(fingerprint)
    """
    
    def __init__(self):
        self.rules: List[StrategyRule] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default rule set for common DPI types"""
        
        # High priority rules for specific DPI types
        self.rules.extend([
            StrategyRule(
                name="roskomnadzor_tspu_optimized",
                condition="DPI type is Roskomnadzor TSPU",
                priority=90,
                attack_type="fakeddisorder",
                parameters={
                    "ttl": 1,
                    "split_pos": 76,
                    "overlap_size": 1,
                    "autottl": 2
                },
                fooling_methods=["badseq", "md5sig"]
            ),
            
            StrategyRule(
                name="commercial_dpi_bypass",
                condition="DPI type is commercial DPI",
                priority=85,
                attack_type="multisplit",
                parameters={
                    "positions": [1, 5, 10, 20],
                    "ttl": 64
                },
                fooling_methods=["badsum"]
            ),
            
            # Badsum-specific rules
            StrategyRule(
                name="badsum_fooling",
                condition="Fingerprint allows badsum",
                priority=80,
                attack_type="fakeddisorder",
                parameters={"ttl": 64},
                fooling_methods=["badsum"]
            ),
            
            StrategyRule(
                name="md5sig_fooling", 
                condition="Fingerprint allows md5sig",
                priority=75,
                attack_type="fakeddisorder",
                parameters={"ttl": 1},
                fooling_methods=["md5sig"]
            ),
            
            # Split position rules based on content inspection depth
            StrategyRule(
                name="high_split_pos",
                condition="TLS alert on split pos < 40",
                priority=70,
                attack_type="fakeddisorder",
                parameters={"split_pos": 41}
            ),
            
            StrategyRule(
                name="low_split_pos",
                condition="TLS alert on split pos >= 40",
                priority=65,
                attack_type="fakeddisorder", 
                parameters={"split_pos": 76}
            ),
            
            # TTL-based rules using RST TTL detection
            StrategyRule(
                name="low_ttl_required",
                condition="Requires low TTL",
                priority=60,
                attack_type="fakeddisorder",
                parameters={"ttl": 1}
            ),
            
            StrategyRule(
                name="high_ttl_bypass",
                condition="Does not require low TTL",
                priority=55,
                attack_type="fakeddisorder",
                parameters={"ttl": 64}
            ),
            
            # Fragmentation rules
            StrategyRule(
                name="fragmentation_support",
                condition="Supports fragmentation",
                priority=50,
                attack_type="multisplit",
                parameters={"positions": [1, 3, 5]}
            ),
            
            # Fallback rules
            StrategyRule(
                name="default_fakeddisorder",
                condition="Default fallback",
                priority=10,
                attack_type="fakeddisorder",
                parameters={
                    "ttl": 64,
                    "split_pos": 76,
                    "overlap_size": 1
                },
                fooling_methods=["badseq"]
            )
        ])
    
    def add_rule(self, rule: StrategyRule):
        """Add a custom rule to the engine"""
        self.rules.append(rule)
        # Keep rules sorted by priority (highest first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
    
    def _evaluate_rule_condition(self, rule: StrategyRule, fingerprint: DPIFingerprint) -> bool:
        """Evaluate if a rule's condition matches the fingerprint"""
        
        # DPI type conditions
        if "roskomnadzor" in rule.condition.lower():
            return fingerprint.dpi_type == DPIType.ROSKOMNADZOR_TSPU
        
        if "commercial dpi" in rule.condition.lower():
            return fingerprint.dpi_type == DPIType.COMMERCIAL_DPI
        
        # Fooling method conditions
        if "allows badsum" in rule.condition.lower():
            return fingerprint.vulnerable_to_bad_checksum_race
        
        if "allows md5sig" in rule.condition.lower():
            return fingerprint.tcp_options_filtering
        
        # Split position conditions - use content inspection depth as proxy
        if "tls alert on split pos < 40" in rule.condition.lower():
            return fingerprint.content_inspection_depth < 40
        
        if "tls alert on split pos >= 40" in rule.condition.lower():
            return fingerprint.content_inspection_depth >= 40
        
        # TTL conditions - use RST TTL as indicator
        if "requires low ttl" in rule.condition.lower():
            return fingerprint.rst_ttl is not None and fingerprint.rst_ttl <= 5
        
        if "does not require low ttl" in rule.condition.lower():
            return fingerprint.rst_ttl is None or fingerprint.rst_ttl > 5
        
        # Fragmentation conditions
        if "supports fragmentation" in rule.condition.lower():
            return fingerprint.vulnerable_to_fragmentation
        
        # Default fallback
        if "default fallback" in rule.condition.lower():
            return True
        
        return False
    
    def generate_strategy(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """
        Generate a strategy based on fingerprint using rule engine.
        
        Args:
            fingerprint: DPI fingerprint containing detected characteristics
            
        Returns:
            Dictionary containing strategy type and parameters
        """
        
        LOG.info(f"Generating strategy for DPI type: {fingerprint.dpi_type}")
        
        # Find all matching rules
        matching_rules = []
        for rule in self.rules:
            if self._evaluate_rule_condition(rule, fingerprint):
                matching_rules.append(rule)
                LOG.debug(f"Rule '{rule.name}' matches: {rule.condition}")
        
        if not matching_rules:
            LOG.warning("No rules matched fingerprint, using default")
            return {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 64,
                    "split_pos": 76,
                    "overlap_size": 1
                }
            }
        
        # Use highest priority rule as base
        base_rule = matching_rules[0]
        strategy = {
            "type": base_rule.attack_type,
            "params": base_rule.parameters.copy()
        }
        
        # Merge parameters from other matching rules
        fooling_methods = set(base_rule.fooling_methods)
        
        for rule in matching_rules[1:]:
            # Merge parameters (later rules can override)
            strategy["params"].update(rule.parameters)
            
            # Accumulate fooling methods
            fooling_methods.update(rule.fooling_methods)
        
        # Add fooling methods if any
        if fooling_methods:
            strategy["params"]["fooling"] = list(fooling_methods)
        
        LOG.info(f"Generated strategy: {strategy}")
        return strategy
    
    def generate_multiple_strategies(self, fingerprint: DPIFingerprint, count: int = 3) -> List[Dict[str, Any]]:
        """
        Generate multiple alternative strategies for A/B testing.
        
        Args:
            fingerprint: DPI fingerprint
            count: Number of strategies to generate
            
        Returns:
            List of strategy dictionaries
        """
        
        strategies = []
        
        # Primary strategy
        primary = self.generate_strategy(fingerprint)
        strategies.append(primary)
        
        if count <= 1:
            return strategies
        
        # Generate variations
        base_params = primary["params"].copy()
        
        # Variation 1: Different TTL
        if count > 1:
            var1 = {
                "type": primary["type"],
                "params": base_params.copy()
            }
            current_ttl = base_params.get("ttl", 64)
            var1["params"]["ttl"] = 1 if current_ttl > 1 else 64
            strategies.append(var1)
        
        # Variation 2: Different attack type
        if count > 2:
            var2_type = "multisplit" if primary["type"] == "fakeddisorder" else "fakeddisorder"
            var2 = {
                "type": var2_type,
                "params": base_params.copy()
            }
            if var2_type == "multisplit":
                var2["params"]["positions"] = [1, 3, 5, 10]
            strategies.append(var2)
        
        return strategies[:count]
    
    def explain_strategy(self, fingerprint: DPIFingerprint) -> str:
        """
        Generate human-readable explanation of why a strategy was chosen.
        
        Args:
            fingerprint: DPI fingerprint
            
        Returns:
            String explanation of the strategy selection
        """
        
        matching_rules = []
        for rule in self.rules:
            if self._evaluate_rule_condition(rule, fingerprint):
                matching_rules.append(rule)
        
        if not matching_rules:
            return "No specific rules matched, using default fakeddisorder strategy"
        
        explanation = f"Strategy selected based on {len(matching_rules)} matching rules:\n"
        
        for i, rule in enumerate(matching_rules[:3]):  # Show top 3 rules
            explanation += f"{i+1}. {rule.name}: {rule.condition}\n"
        
        if len(matching_rules) > 3:
            explanation += f"... and {len(matching_rules) - 3} more rules"
        
        return explanation


def create_default_rule_engine() -> StrategyRuleEngine:
    """Factory function to create a rule engine with default rules"""
    return StrategyRuleEngine()


# Example usage and testing
if __name__ == "__main__":
    # Create test fingerprint
    test_fingerprint = DPIFingerprint(
        dpi_type=DPIType.ROSKOMNADZOR_TSPU,
        allows_badsum=True,
        allows_md5sig=True,
        tls_alert_on_split_pos=30,
        requires_low_ttl=True
    )
    
    # Generate strategy
    engine = create_default_rule_engine()
    strategy = engine.generate_strategy(test_fingerprint)
    
    print("Generated strategy:", strategy)
    print("\nExplanation:")
    print(engine.explain_strategy(test_fingerprint))