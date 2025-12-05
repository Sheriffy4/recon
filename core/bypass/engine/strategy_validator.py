#!/usr/bin/env python3
"""
Strategy Validator Component

Validates that strategies applied in production match the expected strategies
from domain_rules.json, ensuring testing-production parity.

Requirements: 1.4, 4.1, 4.2, 4.3, 4.4
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

LOG = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of strategy validation."""
    valid: bool
    reason: Optional[str] = None
    warning: Optional[str] = None
    recommendation: Optional[str] = None
    mismatches: List[str] = field(default_factory=list)


class StrategyValidator:
    """
    Validates strategy application correctness.
    
    Ensures that strategies applied in production mode match the expected
    strategies from domain_rules.json, preventing testing-production parity issues.
    """
    
    def __init__(self, domain_rules_path: str = "domain_rules.json"):
        """
        Initialize the StrategyValidator.
        
        Args:
            domain_rules_path: Path to domain_rules.json file
        """
        self.domain_rules_path = domain_rules_path
        self.domain_rules = self._load_domain_rules()
        self.validation_cache = {}
    
    def _load_domain_rules(self) -> Dict[str, Any]:
        """Load domain rules from JSON file."""
        try:
            rules_path = Path(self.domain_rules_path)
            if not rules_path.exists():
                LOG.warning(f"Domain rules file not found: {self.domain_rules_path}")
                return {}
            
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Extract rules from the structure
            if isinstance(data, dict):
                # Check for various possible keys
                if 'domain_rules' in data:
                    return data['domain_rules']
                elif 'rules' in data:
                    return data['rules']
            return data
            
        except Exception as e:
            LOG.error(f"Failed to load domain rules: {e}")
            return {}
    
    def validate_strategy_application(
        self,
        domain: str,
        applied_strategy: Dict,
        match_type: str
    ) -> ValidationResult:
        """
        Validate that the applied strategy matches the expected strategy.
        
        Args:
            domain: Domain (SNI) being accessed
            applied_strategy: Strategy that is being applied
            match_type: Type of match ('exact', 'wildcard', 'parent')
        
        Returns:
            ValidationResult with validation details
        """
        # Check if we have an expected strategy for this domain
        expected_strategy = self.domain_rules.get(domain)
        
        # If no exact match, try wildcard matching
        if not expected_strategy:
            expected_strategy = self._find_wildcard_strategy(domain)
        
        if not expected_strategy:
            return ValidationResult(
                valid=False,
                reason=f"No strategy found for {domain}",
                recommendation=f"Run 'cli.py auto {domain}' to find working strategy"
            )
        
        # Check strategy type match
        applied_type = applied_strategy.get('type')
        expected_type = expected_strategy.get('type')
        
        if applied_type != expected_type:
            return ValidationResult(
                valid=False,
                reason=f"Strategy type mismatch: applied={applied_type}, expected={expected_type}",
                recommendation=f"Check domain_rules.json for {domain}"
            )
        
        # Check parameters
        param_mismatches = self._check_parameters(
            applied_strategy.get('params', {}),
            expected_strategy.get('params', {})
        )
        
        if param_mismatches:
            return ValidationResult(
                valid=False,
                reason=f"Parameter mismatches detected",
                mismatches=param_mismatches,
                recommendation="Verify strategy parameters in domain_rules.json"
            )
        
        # Check match type - warn if using parent domain fallback
        if match_type == 'parent':
            return ValidationResult(
                valid=True,
                warning=f"Using parent domain strategy for {domain}",
                recommendation=f"Consider creating specific strategy for {domain}"
            )
        
        # All checks passed
        return ValidationResult(valid=True)
    
    def _find_wildcard_strategy(self, domain: str) -> Optional[Dict]:
        """
        Find a wildcard strategy that matches the domain.
        
        Args:
            domain: Domain to match against wildcard patterns
        
        Returns:
            Strategy dict if wildcard match found, None otherwise
        """
        # Check all wildcard patterns in rules
        for pattern, strategy in self.domain_rules.items():
            if pattern.startswith('*.'):
                # Extract the suffix (e.g., ".googlevideo.com" from "*.googlevideo.com")
                suffix = pattern[1:]  # Remove the '*'
                # Check if domain ends with this suffix
                if domain.endswith(suffix):
                    # Ensure it's a proper subdomain match (not partial match)
                    if len(domain) > len(suffix):
                        LOG.debug(f"Found wildcard match for {domain}: {pattern}")
                        return strategy
        
        return None
    
    def _check_parameters(self, applied: Dict, expected: Dict) -> List[str]:
        """
        Check that critical parameters match between applied and expected strategies.
        
        Args:
            applied: Parameters from applied strategy
            expected: Parameters from expected strategy
        
        Returns:
            List of parameter mismatch descriptions
        """
        mismatches = []
        
        # Critical parameters that must match exactly
        critical_params = [
            'split_pos',
            'split_count',
            'fooling',
            'ttl',
            'disorder_method',
            'autottl',
            'overlap_size',
            'positions'
        ]
        
        for param in critical_params:
            if param in expected:
                applied_value = applied.get(param)
                expected_value = expected[param]
                
                # Handle list comparison (e.g., fooling, positions)
                if isinstance(expected_value, list):
                    if not isinstance(applied_value, list):
                        mismatches.append(
                            f"{param}: applied={applied_value} (not a list), expected={expected_value}"
                        )
                    elif sorted(applied_value) != sorted(expected_value):
                        mismatches.append(
                            f"{param}: applied={applied_value}, expected={expected_value}"
                        )
                # Handle regular value comparison
                elif applied_value != expected_value:
                    mismatches.append(
                        f"{param}: applied={applied_value}, expected={expected_value}"
                    )
        
        return mismatches
    
    def reload_domain_rules(self):
        """Reload domain rules from file."""
        self.domain_rules = self._load_domain_rules()
        self.validation_cache.clear()
        LOG.info(f"Reloaded domain rules from {self.domain_rules_path}")
    
    def get_expected_strategy(self, domain: str) -> Optional[Dict]:
        """
        Get the expected strategy for a domain.
        
        Args:
            domain: Domain to look up
        
        Returns:
            Expected strategy dict or None if not found
        """
        return self.domain_rules.get(domain)
    
    def has_strategy_for_domain(self, domain: str) -> bool:
        """
        Check if a strategy exists for the given domain.
        
        Args:
            domain: Domain to check
        
        Returns:
            True if strategy exists, False otherwise
        """
        return domain in self.domain_rules
