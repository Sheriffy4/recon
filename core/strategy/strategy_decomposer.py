"""
Strategy Decomposition Module

This module provides functionality to decompose combo strategies into their
component attacks for proper execution and validation.

Feature: strategy-testing-production-parity
Requirements: 7.1, 7.2, 7.3
"""

import logging
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


@dataclass
class AttackExecutionTracker:
    """
    Tracks which attacks have been executed in a combo strategy.
    
    Handles duplicate attacks properly by tracking execution count per attack.
    
    Requirements: 7.3
    """
    strategy_name: str
    expected_attacks: List[str]
    executed_attacks: List[str] = field(default_factory=list)
    execution_order: List[str] = field(default_factory=list)
    
    def record_execution(self, attack_name: str) -> None:
        """
        Record that an attack was executed.
        
        Tracks each execution separately to handle duplicate attacks.
        
        Args:
            attack_name: Name of the attack that was executed
        """
        self.executed_attacks.append(attack_name)
        self.execution_order.append(attack_name)
    
    def is_complete(self) -> bool:
        """
        Check if all expected attacks have been executed.
        
        Handles duplicates by comparing counts of each attack type.
        
        Returns:
            True if all attacks executed, False otherwise
        """
        from collections import Counter
        expected_counts = Counter(self.expected_attacks)
        executed_counts = Counter(self.executed_attacks)
        
        # Check if all expected attacks have been executed the right number of times
        for attack, count in expected_counts.items():
            if executed_counts.get(attack, 0) < count:
                return False
        return True
    
    def get_missing_attacks(self) -> List[str]:
        """
        Get list of attacks that haven't been executed yet.
        
        Handles duplicates by returning the actual missing instances.
        
        Returns:
            List of missing attack names (may contain duplicates)
        """
        from collections import Counter
        expected_counts = Counter(self.expected_attacks)
        executed_counts = Counter(self.executed_attacks)
        
        missing = []
        for attack, expected_count in expected_counts.items():
            executed_count = executed_counts.get(attack, 0)
            if executed_count < expected_count:
                # Add the missing instances
                missing.extend([attack] * (expected_count - executed_count))
        
        return missing
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """
        Get summary of execution status.
        
        Returns:
            Dictionary with execution details
        """
        return {
            'strategy_name': self.strategy_name,
            'expected_attacks': self.expected_attacks,
            'executed_attacks': self.executed_attacks,
            'execution_order': self.execution_order,
            'is_complete': self.is_complete(),
            'missing_attacks': self.get_missing_attacks(),
            'expected_count': len(self.expected_attacks),
            'executed_count': len(self.executed_attacks)
        }


class StrategyDecomposer:
    """
    Decomposes combo strategies into individual attack components.
    
    Handles parsing of smart_combo_X_Y_Z format strategies and extraction
    of individual attack names for execution and validation.
    
    Requirements: 7.1, 7.2, 7.3
    """
    
    # Known attack names that can appear in combo strategies
    KNOWN_ATTACKS = {
        'fake', 'split', 'disorder', 'disorder2', 'multidisorder',
        'multisplit', 'seqovl', 'ttl', 'badseq', 'badsum',
        'fakeddisorder', 'overlap'
    }
    
    def __init__(self):
        """Initialize the strategy decomposer."""
        self.logger = LOG
        self._execution_trackers: Dict[str, AttackExecutionTracker] = {}
    
    def decompose_strategy(self, strategy_name: str) -> List[str]:
        """
        Decompose a strategy name into component attacks.
        
        Handles various formats:
        - smart_combo_X_Y_Z -> ['X', 'Y', 'Z']
        - existing_smart_combo_X_Y -> ['X', 'Y']
        - smart_combo_split -> ['split']
        - regular_attack -> ['regular_attack']
        
        Args:
            strategy_name: Name of the strategy to decompose
            
        Returns:
            List of component attack names
            
        Requirements: 7.1, 7.2
        """
        if not strategy_name or not isinstance(strategy_name, str):
            self.logger.warning(f"Invalid strategy name: {strategy_name}")
            return []
        
        # Handle smart_combo_ prefix
        if strategy_name.startswith('smart_combo_'):
            return self._parse_smart_combo(strategy_name, 'smart_combo_')
        
        # Handle existing_smart_combo_ prefix
        if strategy_name.startswith('existing_smart_combo_'):
            return self._parse_smart_combo(strategy_name, 'existing_smart_combo_')
        
        # Not a combo strategy - return as single attack
        return [strategy_name]
    
    def _parse_smart_combo(self, strategy_name: str, prefix: str) -> List[str]:
        """
        Parse smart_combo_ or existing_smart_combo_ strategy name.
        
        Args:
            strategy_name: Full strategy name
            prefix: Prefix to remove ('smart_combo_' or 'existing_smart_combo_')
            
        Returns:
            List of component attack names
        """
        # Remove prefix
        name_without_prefix = strategy_name.replace(prefix, '')
        
        if not name_without_prefix:
            self.logger.warning(f"Empty strategy name after removing prefix: {strategy_name}")
            return []
        
        # Split by underscore
        parts = name_without_prefix.split('_')
        
        # Filter to known attacks
        attacks = []
        for part in parts:
            if part in self.KNOWN_ATTACKS:
                attacks.append(part)
            else:
                # Log unknown parts but include them anyway
                self.logger.debug(f"Unknown attack component in {strategy_name}: {part}")
                attacks.append(part)
        
        if not attacks:
            # If no known attacks found, return all parts
            self.logger.warning(
                f"No known attacks found in {strategy_name}, using all parts: {parts}"
            )
            return parts
        
        self.logger.info(f"Decomposed {strategy_name} -> {attacks}")
        return attacks
    
    def is_combo_strategy(self, strategy_name: str) -> bool:
        """
        Check if a strategy name represents a combo strategy.
        
        Args:
            strategy_name: Name of the strategy
            
        Returns:
            True if this is a combo strategy, False otherwise
        """
        if not strategy_name or not isinstance(strategy_name, str):
            return False
        
        return (
            strategy_name.startswith('smart_combo_') or
            strategy_name.startswith('existing_smart_combo_')
        )
    
    def get_attack_count(self, strategy_name: str) -> int:
        """
        Get the number of component attacks in a strategy.
        
        Args:
            strategy_name: Name of the strategy
            
        Returns:
            Number of component attacks
        """
        attacks = self.decompose_strategy(strategy_name)
        return len(attacks)
    
    def create_execution_tracker(self, strategy_name: str) -> AttackExecutionTracker:
        """
        Create an execution tracker for a combo strategy.
        
        Args:
            strategy_name: Name of the strategy to track
            
        Returns:
            AttackExecutionTracker instance
            
        Requirements: 7.3
        """
        attacks = self.decompose_strategy(strategy_name)
        tracker = AttackExecutionTracker(
            strategy_name=strategy_name,
            expected_attacks=attacks
        )
        self._execution_trackers[strategy_name] = tracker
        self.logger.info(f"Created execution tracker for {strategy_name}: {attacks}")
        return tracker
    
    def get_execution_tracker(self, strategy_name: str) -> Optional[AttackExecutionTracker]:
        """
        Get the execution tracker for a strategy.
        
        Args:
            strategy_name: Name of the strategy
            
        Returns:
            AttackExecutionTracker or None if not found
        """
        return self._execution_trackers.get(strategy_name)
    
    def execute_attacks_in_sequence(
        self,
        strategy_name: str,
        attack_executor: Callable[[str, Dict[str, Any]], Any],
        params: Dict[str, Any] = None
    ) -> AttackExecutionTracker:
        """
        Execute all component attacks in a combo strategy in sequence.
        
        This method:
        1. Decomposes the strategy into component attacks
        2. Creates an execution tracker
        3. Executes each attack in order
        4. Tracks which attacks were executed
        5. Ensures all components run before returning
        
        Args:
            strategy_name: Name of the combo strategy
            attack_executor: Function to execute each attack (attack_name, params) -> result
            params: Parameters to pass to each attack
            
        Returns:
            AttackExecutionTracker with execution results
            
        Requirements: 7.3
        """
        params = params or {}
        
        # Create tracker
        tracker = self.create_execution_tracker(strategy_name)
        
        # Execute each attack in sequence
        for attack_name in tracker.expected_attacks:
            self.logger.info(f"Executing attack {attack_name} for strategy {strategy_name}")
            
            try:
                # Execute the attack
                attack_executor(attack_name, params)
                
                # Record successful execution
                tracker.record_execution(attack_name)
                self.logger.info(f"✅ Attack {attack_name} executed successfully")
                
            except Exception as e:
                self.logger.error(f"❌ Attack {attack_name} failed: {e}")
                # Continue with next attack even if one fails
        
        # Log completion status
        if tracker.is_complete():
            self.logger.info(f"✅ All attacks completed for {strategy_name}")
        else:
            missing = tracker.get_missing_attacks()
            self.logger.warning(f"⚠️ Incomplete execution for {strategy_name}: missing {missing}")
        
        return tracker
    
    def clear_execution_tracker(self, strategy_name: str) -> None:
        """
        Clear the execution tracker for a strategy.
        
        Args:
            strategy_name: Name of the strategy
        """
        if strategy_name in self._execution_trackers:
            del self._execution_trackers[strategy_name]
            self.logger.debug(f"Cleared execution tracker for {strategy_name}")
    
    def clear_all_trackers(self) -> None:
        """Clear all execution trackers."""
        count = len(self._execution_trackers)
        self._execution_trackers.clear()
        self.logger.info(f"Cleared {count} execution trackers")


# Global instance for convenience
_decomposer = None


def get_strategy_decomposer() -> StrategyDecomposer:
    """
    Get the global strategy decomposer instance.
    
    Returns:
        StrategyDecomposer instance
    """
    global _decomposer
    if _decomposer is None:
        _decomposer = StrategyDecomposer()
    return _decomposer


def decompose_strategy(strategy_name: str) -> List[str]:
    """
    Convenience function to decompose a strategy name.
    
    Args:
        strategy_name: Name of the strategy to decompose
        
    Returns:
        List of component attack names
    """
    decomposer = get_strategy_decomposer()
    return decomposer.decompose_strategy(strategy_name)
