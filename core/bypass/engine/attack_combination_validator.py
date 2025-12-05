#!/usr/bin/env python3
"""
Attack Combination Validator

Validates that attack combinations are semantically correct and don't result
in duplicate or conflicting packet transmissions.

Requirements: 1.1, 1.2, 4.1, 4.2, 4.5, 9.1, 9.2, 9.3
"""

import logging
from dataclasses import dataclass
from typing import List, Optional, Set

LOG = logging.getLogger(__name__)


@dataclass
class CombinationValidationResult:
    """Result of attack combination validation."""
    valid: bool
    reason: Optional[str] = None
    recommendation: Optional[str] = None
    conflicts: List[str] = None
    
    def __post_init__(self):
        if self.conflicts is None:
            self.conflicts = []


class AttackCombinationValidator:
    """
    Validates attack combinations to prevent semantic errors.
    
    Key validation rules:
    1. 'fake' attack already sends full payload, so it should NOT be combined with:
       - 'split' (would send payload twice: once full, once fragmented)
       - 'multisplit' (would send payload twice: once full, once fragmented)
    
    2. 'multisplit' and 'split' do the same thing (fragmentation), so they should NOT
       be combined together (would send fragments twice)
    
    3. Valid combinations:
       - 'fake' + 'disorder' → fakeddisorder (fake packet + disordered fragments)
       - 'multisplit' + 'disorder' → multidisorder (multiple fragments + disorder)
       - 'split' + 'disorder' → disorder with split_pos (2 fragments + disorder)
       - Single attacks: 'fake', 'split', 'multisplit', 'disorder'
    
    4. Invalid combinations:
       - 'fake' + 'split' (duplicate payload)
       - 'fake' + 'multisplit' (duplicate payload)
       - 'multisplit' + 'split' (duplicate fragmentation)
       - 'fake' + 'multisplit' + 'split' (triple payload!)
    """
    
    # Define attack categories
    FAKE_ATTACKS = {'fake'}
    SPLIT_ATTACKS = {'split', 'multisplit'}
    DISORDER_ATTACKS = {'disorder', 'disorder2'}
    
    # Define valid combination patterns
    VALID_COMBINATIONS = {
        # Single attacks (always valid)
        frozenset(['fake']),
        frozenset(['split']),
        frozenset(['multisplit']),
        frozenset(['disorder']),
        frozenset(['disorder2']),
        frozenset(['seqovl']),
        
        # Valid two-attack combinations
        frozenset(['fake', 'disorder']),  # fakeddisorder
        frozenset(['multisplit', 'disorder']),  # multidisorder
        frozenset(['split', 'disorder']),  # disorder with split
        
        # Note: 'fake' + 'split' is INVALID (duplicate payload)
        # Note: 'fake' + 'multisplit' is INVALID (duplicate payload)
        # Note: 'multisplit' + 'split' is INVALID (duplicate fragmentation)
    }
    
    def __init__(self):
        """Initialize the validator."""
        self.validation_cache = {}
    
    def validate_combination(self, attacks: List[str]) -> CombinationValidationResult:
        """
        Validate an attack combination.
        
        Args:
            attacks: List of attack types in the combination
            
        Returns:
            CombinationValidationResult with validation details
        """
        if not attacks:
            return CombinationValidationResult(
                valid=False,
                reason="Empty attack list",
                recommendation="Specify at least one attack"
            )
        
        # Normalize attack names (remove whitespace, lowercase)
        normalized_attacks = [a.strip().lower() for a in attacks]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_attacks = []
        for attack in normalized_attacks:
            if attack not in seen:
                seen.add(attack)
                unique_attacks.append(attack)
        
        # Check cache
        cache_key = tuple(sorted(unique_attacks))
        if cache_key in self.validation_cache:
            return self.validation_cache[cache_key]
        
        # Perform validation
        result = self._validate_attacks(unique_attacks)
        
        # Cache result
        self.validation_cache[cache_key] = result
        
        return result
    
    def _validate_attacks(self, attacks: List[str]) -> CombinationValidationResult:
        """
        Internal validation logic.
        
        Args:
            attacks: Normalized list of unique attack types
            
        Returns:
            CombinationValidationResult
        """
        attack_set = set(attacks)
        
        # --- СУЩЕСТВУЮЩИЕ ПРОВЕРКИ ---
        
        # === НОВОЕ ИСПРАВЛЕНИЕ (Task 13.3 Fix) ===
        # Блокировка тройных комбинаций, вызывающих дублирование нагрузки
        # fake отправляет полный пакет, split/multisplit отправляют фрагменты.
        # Вместе они отправляют данные 2+ раза.
        if 'fake' in attack_set and ('split' in attack_set or 'multisplit' in attack_set):
             return CombinationValidationResult(
                valid=False,
                reason="Critical Conflict: 'fake' cannot be combined with fragmentation ('split'/'multisplit')",
                recommendation="Use 'fakeddisorder' (fake+disorder) instead. Never combine fake with split.",
                conflicts=[
                    "fake sends full payload",
                    "split/multisplit sends fragmented payload",
                    "Result: Server receives duplicate data and drops connection"
                ]
            )
        
        # Rule 1: Check for 'fake' + 'split' combination (INVALID)
        if 'fake' in attack_set and 'split' in attack_set:
            return CombinationValidationResult(
                valid=False,
                reason="Invalid combination: 'fake' + 'split'",
                recommendation=(
                    "Remove 'split' from combination. "
                    "'fake' attack already sends full payload, making 'split' redundant. "
                    "Use 'fake' alone or 'fake' + 'disorder' (fakeddisorder)."
                ),
                conflicts=[
                    "'fake' sends: FAKE packet + REAL packet (full payload)",
                    "'split' sends: Fragment 1 + Fragment 2",
                    "Result: Server receives payload twice (1 full + 1 fragmented)"
                ]
            )
        
        # Rule 2: Check for 'fake' + 'multisplit' combination (INVALID)
        if 'fake' in attack_set and 'multisplit' in attack_set:
            return CombinationValidationResult(
                valid=False,
                reason="Invalid combination: 'fake' + 'multisplit'",
                recommendation=(
                    "Remove 'multisplit' from combination. "
                    "'fake' attack already sends full payload, making 'multisplit' redundant. "
                    "Use 'fake' alone or 'fake' + 'disorder' (fakeddisorder)."
                ),
                conflicts=[
                    "'fake' sends: FAKE packet + REAL packet (full payload)",
                    "'multisplit' sends: Fragment 1 + Fragment 2 + ... + Fragment N",
                    "Result: Server receives payload twice (1 full + 1 fragmented)"
                ]
            )
        
        # Rule 3: Check for 'multisplit' + 'split' combination (INVALID)
        if 'multisplit' in attack_set and 'split' in attack_set:
            return CombinationValidationResult(
                valid=False,
                reason="Invalid combination: 'multisplit' + 'split'",
                recommendation=(
                    "Remove either 'multisplit' or 'split' from combination. "
                    "Both attacks do the same thing (fragmentation). "
                    "Use 'multisplit' alone or 'multisplit' + 'disorder' (multidisorder)."
                ),
                conflicts=[
                    "'multisplit' sends: Fragment 1 + Fragment 2 + ... + Fragment N",
                    "'split' sends: Fragment 1 + Fragment 2",
                    "Result: Server receives fragments twice"
                ]
            )
        
        # Rule 4: Check for 'fake' + 'multisplit' + 'split' combination (INVALID)
        if 'fake' in attack_set and 'multisplit' in attack_set and 'split' in attack_set:
            return CombinationValidationResult(
                valid=False,
                reason="Invalid combination: 'fake' + 'multisplit' + 'split'",
                recommendation=(
                    "This combination is semantically incorrect. "
                    "Use ONE of: 'fakeddisorder', 'multidisorder', or 'fake' alone."
                ),
                conflicts=[
                    "'fake' sends: FAKE packet + REAL packet (full payload)",
                    "'multisplit' sends: Fragment 1 + Fragment 2 + ... + Fragment N",
                    "'split' sends: Fragment 1 + Fragment 2",
                    "Result: Server receives ClientHello 3 times (1 full + 2 fragmented)!"
                ]
            )
        
        # Rule 5: Check if combination matches a known valid pattern
        attack_frozenset = frozenset(attacks)
        if attack_frozenset in self.VALID_COMBINATIONS:
            return CombinationValidationResult(
                valid=True,
                reason=f"Valid combination: {', '.join(attacks)}"
            )
        
        # Rule 6: Warn about unknown combinations (but don't block them)
        # This allows for future extensibility
        LOG.warning(
            f"Unknown attack combination: {attacks}. "
            f"This may or may not work correctly."
        )
        
        return CombinationValidationResult(
            valid=True,  # Allow unknown combinations (with warning)
            reason=f"Unknown combination: {', '.join(attacks)}",
            recommendation=(
                "This combination is not in the known valid patterns. "
                "Test carefully to ensure it works as expected."
            )
        )
    
    def get_recommended_combination(self, attacks: List[str]) -> Optional[List[str]]:
        """
        Get a recommended valid combination based on invalid attacks.
        
        Args:
            attacks: List of attack types (possibly invalid)
            
        Returns:
            Recommended valid combination or None
        """
        attack_set = set(a.strip().lower() for a in attacks)
        
        # If combination includes 'fake' + 'split' or 'fake' + 'multisplit'
        if 'fake' in attack_set and ('split' in attack_set or 'multisplit' in attack_set):
            # Recommend 'fake' + 'disorder' (fakeddisorder)
            if 'disorder' in attack_set:
                return ['fake', 'disorder']
            else:
                return ['fake']
        
        # If combination includes 'multisplit' + 'split'
        if 'multisplit' in attack_set and 'split' in attack_set:
            # Recommend 'multisplit' + 'disorder' if disorder is present
            if 'disorder' in attack_set:
                return ['multisplit', 'disorder']
            else:
                return ['multisplit']
        
        return None
    
    def clear_cache(self):
        """Clear validation cache."""
        self.validation_cache.clear()
        LOG.debug("Validation cache cleared")
