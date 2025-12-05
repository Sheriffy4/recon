"""
StrategyLoader - Unified strategy loading with wildcard and parent domain matching.

This module implements the strategy loading logic with the following priority:
1. Exact domain match
2. Wildcard match (*.example.com)
3. Parent domain match (example.com for sub.example.com)
4. Default strategy fallback

Requirements: 5.1, 6.1, 6.2, 6.3, 6.4
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Strategy:
    """Represents a DPI bypass strategy."""
    type: str  # Legacy field, ignored if attacks present
    attacks: List[str]  # Source of truth for attack list
    params: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure attacks field exists and has priority over type."""
        if not self.attacks:
            # If attacks is empty but type exists, create single-element attacks list
            if self.type:
                self.attacks = [self.type]
            else:
                self.attacks = []


@dataclass
class ValidationResult:
    """Result of strategy validation."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class StrategyLoader:
    """
    Loads and manages DPI bypass strategies from domain_rules.json.
    
    Implements domain matching with the following priority:
    1. Exact match (example.com)
    2. Wildcard match (*.example.com)
    3. Parent domain match (example.com for sub.example.com)
    4. Default strategy
    """
    
    def __init__(self, rules_path: str = "domain_rules.json"):
        """
        Initialize loader with path to rules file.
        
        Args:
            rules_path: Path to domain_rules.json file
        """
        self.rules_path = Path(rules_path)
        self.rules: Dict[str, Strategy] = {}
        self.default_strategy: Optional[Strategy] = None
        self._rules_mtime: Optional[float] = None
        
    def load_rules(self) -> Dict[str, Strategy]:
        """
        Load all rules from JSON file.
        
        Returns:
            Dictionary mapping domain to Strategy
        """
        try:
            if not self.rules_path.exists():
                logger.warning(f"Rules file not found: {self.rules_path}")
                return {}
            
            # Check if file has been modified
            current_mtime = self.rules_path.stat().st_mtime
            if self._rules_mtime == current_mtime and self.rules:
                logger.debug("Rules file unchanged, using cached rules")
                return self.rules
            
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.rules = {}
            domain_rules = data.get('domain_rules', {})
            
            for domain, rule_data in domain_rules.items():
                try:
                    strategy = self._parse_strategy(rule_data)
                    self.rules[domain] = strategy
                except Exception as e:
                    logger.warning(f"Failed to parse rule for {domain}: {e}")
                    continue
            
            # Load default strategy
            if 'default_strategy' in data:
                try:
                    self.default_strategy = self._parse_strategy(data['default_strategy'])
                    logger.debug("Loaded default strategy")
                except Exception as e:
                    logger.warning(f"Failed to parse default strategy: {e}")
            
            self._rules_mtime = current_mtime
            logger.info(f"Loaded {len(self.rules)} domain rules from {self.rules_path}")
            
            return self.rules
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {self.rules_path}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error loading rules from {self.rules_path}: {e}")
            return {}
    
    def _parse_strategy(self, rule_data: Dict[str, Any]) -> Strategy:
        """
        Parse strategy from rule data.
        
        Args:
            rule_data: Dictionary containing strategy data
            
        Returns:
            Strategy object
        """
        strategy_type = rule_data.get('type', '')
        attacks = rule_data.get('attacks', [])
        params = rule_data.get('params', {})
        metadata = rule_data.get('metadata', {})
        
        return Strategy(
            type=strategy_type,
            attacks=attacks,
            params=params,
            metadata=metadata
        )
    
    def find_strategy(self, domain: str) -> Optional[Strategy]:
        """
        Find strategy for domain with fallback logic.
        
        Priority:
        1. Exact match
        2. Wildcard match (*.example.com)
        3. Parent domain match
        4. Default strategy
        
        Args:
            domain: Domain name to find strategy for
            
        Returns:
            Strategy object or None if no strategy found
        """
        # Ensure rules are loaded
        if not self.rules:
            self.load_rules()
        
        # Task 12: Log strategy loading (Requirement 1.5)
        logger.info(f"🔍 Loading strategy for domain: {domain}")
        
        # 1. Exact match
        if domain in self.rules:
            logger.info(f"✅ Found exact match for {domain}")
            strategy = self.rules[domain]
            logger.info(f"   Attacks: {strategy.attacks}")
            logger.info(f"   Params: {strategy.params}")
            return strategy
        
        # 2. Wildcard match (*.example.com)
        # Check all wildcard patterns in rules to see if any match this domain
        for pattern, strategy in self.rules.items():
            if pattern.startswith('*.'):
                # Extract the suffix (e.g., ".googlevideo.com" from "*.googlevideo.com")
                suffix = pattern[1:]  # Remove the '*'
                # Check if domain ends with this suffix
                if domain.endswith(suffix):
                    # Ensure it's a proper subdomain match (not partial match)
                    # e.g., "*.googlevideo.com" should match "rr3---sn-4pvgq-n8v6.googlevideo.com"
                    # but not "fakegooglevideo.com"
                    if len(domain) > len(suffix):  # Must have at least one character before suffix
                        logger.info(f"✅ Found wildcard match for {domain}: {pattern}")
                        logger.info(f"   Attacks: {strategy.attacks}")
                        logger.info(f"   Params: {strategy.params}")
                        return strategy
        
        # 3. Parent domain match
        # Try progressively shorter parent domains
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.rules:
                logger.info(f"✅ Found parent domain match for {domain}: {parent_domain}")
                strategy = self.rules[parent_domain]
                logger.info(f"   Attacks: {strategy.attacks}")
                logger.info(f"   Params: {strategy.params}")
                return strategy
        
        # 4. Default strategy
        if self.default_strategy:
            logger.info(f"✅ Using default strategy for {domain}")
            logger.info(f"   Attacks: {self.default_strategy.attacks}")
            logger.info(f"   Params: {self.default_strategy.params}")
            return self.default_strategy
        
        logger.warning(f"⚠️ No strategy found for {domain}")
        return None
    
    def validate_strategy(self, strategy: Strategy) -> ValidationResult:
        """
        Validate strategy syntax and parameters.
        
        Args:
            strategy: Strategy to validate
            
        Returns:
            ValidationResult with validation status and messages
        """
        errors = []
        warnings = []
        
        # Check that attacks list is not empty
        if not strategy.attacks:
            errors.append("Strategy must have at least one attack")
        
        # Check for valid attack types
        valid_attacks = {
            'fake', 'split', 'multisplit', 'disorder', 
            'fakeddisorder', 'disorder_short_ttl_decoy'
        }
        for attack in strategy.attacks:
            if attack not in valid_attacks:
                warnings.append(f"Unknown attack type: {attack}")
        
        # Validate params based on attacks
        params = strategy.params
        
        if 'fake' in strategy.attacks or 'fakeddisorder' in strategy.attacks:
            if 'ttl' not in params:
                warnings.append("fake attack should have 'ttl' parameter")
            if 'fooling' not in params:
                warnings.append("fake attack should have 'fooling' parameter")
        
        if 'split' in strategy.attacks or 'multisplit' in strategy.attacks:
            if 'split_pos' not in params:
                warnings.append("split attack should have 'split_pos' parameter")
            if 'multisplit' in strategy.attacks and 'split_count' not in params:
                warnings.append("multisplit attack should have 'split_count' parameter")
        
        if 'disorder' in strategy.attacks or 'fakeddisorder' in strategy.attacks:
            if 'disorder_method' not in params:
                warnings.append("disorder attack should have 'disorder_method' parameter")
        
        # Check for type/attacks mismatch
        if strategy.type and strategy.attacks:
            if strategy.type not in strategy.attacks and len(strategy.attacks) == 1:
                warnings.append(
                    f"type '{strategy.type}' differs from attacks {strategy.attacks}. "
                    "attacks field will be used."
                )
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def save_strategy(self, domain: str, strategy: Strategy) -> bool:
        """
        Save strategy to rules file.
        
        Args:
            domain: Domain name
            strategy: Strategy to save
            
        Returns:
            True if save was successful, False otherwise
        """
        try:
            # Load current rules
            if self.rules_path.exists():
                with open(self.rules_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                data = {
                    'version': '1.0',
                    'domain_rules': {},
                    'default_strategy': {}
                }
            
            # Update domain rule
            domain_rules = data.get('domain_rules', {})
            domain_rules[domain] = {
                'type': strategy.type,
                'attacks': strategy.attacks,
                'params': strategy.params,
                'metadata': strategy.metadata
            }
            data['domain_rules'] = domain_rules
            
            # Write back to file
            with open(self.rules_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Update cache
            self.rules[domain] = strategy
            self._rules_mtime = self.rules_path.stat().st_mtime
            
            logger.info(f"Saved strategy for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save strategy for {domain}: {e}")
            return False
