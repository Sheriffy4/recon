"""
ParameterNormalizer - Normalize and validate strategy parameters.

This module implements parameter normalization, validation, and conflict
detection for DPI bypass strategies. It ensures that parameters are in
the correct format and values before being passed to attack executors.

Requirements: 6.1, 6.2, 6.3, 6.5, 7.1, 7.2, 7.3, 7.4, 7.5
"""

import logging
from typing import Any, Dict, List, Optional

from .exceptions import ValidationError, ImplementationError

logger = logging.getLogger(__name__)


class ParameterNormalizer:
    """
    Normalizes and validates strategy parameters.
    
    This class is responsible for:
    1. Resolving parameter aliases (fooling → fooling_methods)
    2. Converting types (string → list for fooling_methods)
    3. Validating parameter values (TTL range, fooling methods)
    4. Detecting configuration conflicts (split_pos + split_count)
    5. Logging all transformations for debugging
    
    Requirements:
    - 6.1: Preserve all specified parameter values
    - 6.2: Resolve aliases without losing values
    - 6.3: Don't override explicitly configured values
    - 6.5: Reject invalid parameter values
    - 7.1-7.4: Detect configuration conflicts
    """
    
    # Valid values for parameters
    VALID_FOOLING_METHODS = {'badsum', 'badseq', 'md5sig', 'none'}
    VALID_DISORDER_METHODS = {'reverse', 'random', 'swap'}
    VALID_FAKE_MODES = {'single', 'per_fragment', 'per_signature', 'smart'}
    
    def __init__(self):
        """Initialize ParameterNormalizer."""
        self.logger = logger
        self.logger.debug("✅ ParameterNormalizer initialized")
    
    def normalize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize strategy parameters.
        
        This method:
        1. Resolves parameter aliases
        2. Converts types to canonical forms
        3. Preserves original values
        4. Logs all transformations
        
        Args:
            params: Raw parameter dictionary from strategy configuration
            
        Returns:
            Normalized parameter dictionary
            
        Raises:
            ValidationError: If parameter values are invalid
        """
        self.logger.info("🔧 Normalizing strategy parameters")
        self.logger.debug(f"   Input params: {params}")
        
        # Create a copy to avoid modifying original
        normalized = params.copy()
        
        # Track transformations for logging
        transformations = []
        
        # 1. Resolve fooling parameter alias
        if 'fooling' in normalized and 'fooling_methods' not in normalized:
            fooling_value = normalized['fooling']
            
            # Convert to list if it's a string
            if isinstance(fooling_value, str):
                fooling_methods = [fooling_value]
                transformations.append(
                    f"fooling='{fooling_value}' → fooling_methods={fooling_methods}"
                )
            elif isinstance(fooling_value, list):
                fooling_methods = fooling_value
                transformations.append(
                    f"fooling={fooling_value} → fooling_methods={fooling_methods}"
                )
            else:
                # Invalid type, will be caught by validation
                fooling_methods = [str(fooling_value)]
                transformations.append(
                    f"fooling={fooling_value} (invalid type) → fooling_methods={fooling_methods}"
                )
            
            normalized['fooling_methods'] = fooling_methods
            # Keep original fooling for backward compatibility
            # Don't delete it - some code may still reference it
        
        # 2. Resolve fake_ttl alias to ttl
        if 'fake_ttl' in normalized and 'ttl' not in normalized:
            normalized['ttl'] = normalized['fake_ttl']
            transformations.append(
                f"fake_ttl={normalized['fake_ttl']} → ttl={normalized['ttl']}"
            )
        
        # 3. Ensure fooling_methods is a list
        if 'fooling_methods' in normalized:
            if isinstance(normalized['fooling_methods'], str):
                old_value = normalized['fooling_methods']
                normalized['fooling_methods'] = [old_value]
                transformations.append(
                    f"fooling_methods='{old_value}' → fooling_methods={normalized['fooling_methods']}"
                )
        
        # 4. Apply defaults ONLY if parameter is missing (not if it's None)
        # This ensures explicit values are never overwritten
        if 'fooling_methods' not in normalized and 'fooling' not in normalized:
            # No fooling specified at all - use default
            normalized['fooling_methods'] = ['badsum']
            transformations.append(
                "fooling_methods not specified → fooling_methods=['badsum'] (default)"
            )
        
        if 'fake_mode' not in normalized:
            # No fake_mode specified - use default
            normalized['fake_mode'] = 'single'
            transformations.append(
                "fake_mode not specified → fake_mode='single' (default)"
            )
        
        if 'disorder_method' not in normalized:
            # No disorder_method specified - use default
            normalized['disorder_method'] = 'reverse'
            transformations.append(
                "disorder_method not specified → disorder_method='reverse' (default)"
            )
        
        # Log all transformations
        if transformations:
            self.logger.info("📝 Parameter transformations:")
            for transformation in transformations:
                self.logger.info(f"   {transformation}")
        else:
            self.logger.info("   No transformations needed")
        
        self.logger.debug(f"   Output params: {normalized}")
        
        return normalized
    
    def validate(self, params: Dict[str, Any]) -> None:
        """
        Validate parameter values.
        
        This method checks that all parameter values are within valid ranges
        and raises ValidationError if any are invalid.
        
        Args:
            params: Normalized parameter dictionary
            
        Raises:
            ValidationError: If any parameter value is invalid
        """
        self.logger.info("✅ Validating strategy parameters")
        
        errors = []
        
        # Validate TTL range (1-255)
        if 'ttl' in params:
            ttl = params['ttl']
            if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
                errors.append(
                    ValidationError(
                        f"TTL must be an integer between 1 and 255",
                        parameter_name='ttl',
                        expected='1-255',
                        actual=ttl
                    )
                )
        
        # Validate fooling methods
        if 'fooling_methods' in params:
            fooling_methods = params['fooling_methods']
            if not isinstance(fooling_methods, list):
                errors.append(
                    ValidationError(
                        f"fooling_methods must be a list",
                        parameter_name='fooling_methods',
                        expected='list',
                        actual=type(fooling_methods).__name__
                    )
                )
            else:
                invalid_methods = set(fooling_methods) - self.VALID_FOOLING_METHODS
                if invalid_methods:
                    errors.append(
                        ValidationError(
                            f"Invalid fooling methods: {invalid_methods}",
                            parameter_name='fooling_methods',
                            expected=f"one of {self.VALID_FOOLING_METHODS}",
                            actual=fooling_methods
                        )
                    )
        
        # Validate split_pos > 0
        if 'split_pos' in params:
            split_pos = params['split_pos']
            # split_pos can be 'sni' string or positive integer
            if isinstance(split_pos, int) and split_pos <= 0:
                errors.append(
                    ValidationError(
                        f"split_pos must be greater than 0",
                        parameter_name='split_pos',
                        expected='> 0',
                        actual=split_pos
                    )
                )
            elif not isinstance(split_pos, (int, str)):
                errors.append(
                    ValidationError(
                        f"split_pos must be an integer or 'sni'",
                        parameter_name='split_pos',
                        expected='int or "sni"',
                        actual=type(split_pos).__name__
                    )
                )
        
        # Validate split_count >= 2
        if 'split_count' in params:
            split_count = params['split_count']
            if not isinstance(split_count, int) or split_count < 2:
                errors.append(
                    ValidationError(
                        f"split_count must be an integer >= 2",
                        parameter_name='split_count',
                        expected='>= 2',
                        actual=split_count
                    )
                )
        
        # Validate disorder_method
        if 'disorder_method' in params:
            disorder_method = params['disorder_method']
            if disorder_method not in self.VALID_DISORDER_METHODS:
                errors.append(
                    ValidationError(
                        f"Invalid disorder_method",
                        parameter_name='disorder_method',
                        expected=f"one of {self.VALID_DISORDER_METHODS}",
                        actual=disorder_method
                    )
                )
        
        # Validate fake_mode
        if 'fake_mode' in params:
            fake_mode = params['fake_mode']
            if fake_mode not in self.VALID_FAKE_MODES:
                errors.append(
                    ValidationError(
                        f"Invalid fake_mode",
                        parameter_name='fake_mode',
                        expected=f"one of {self.VALID_FAKE_MODES}",
                        actual=fake_mode
                    )
                )
        
        # If there are validation errors, raise the first one
        if errors:
            self.logger.error(f"❌ Validation failed with {len(errors)} error(s)")
            for error in errors:
                self.logger.error(f"   {error}")
            raise errors[0]
        
        self.logger.info("   All parameters valid")
    
    def detect_conflicts(
        self,
        params: Dict[str, Any],
        attacks: List[str]
    ) -> List[str]:
        """
        Detect configuration conflicts.
        
        This method checks for conflicting parameter combinations and
        returns a list of warning messages.
        
        Args:
            params: Normalized parameter dictionary
            attacks: List of attack types in the strategy
            
        Returns:
            List of warning messages (empty if no conflicts)
        """
        self.logger.info("🔍 Detecting parameter conflicts")
        
        warnings = []
        
        # Conflict 1: split_pos + split_count
        if 'split_pos' in params and 'split_count' in params:
            warnings.append(
                f"⚠️ Both split_pos and split_count specified. "
                f"split_count will take priority and split_pos will be ignored."
            )
        
        # Conflict 2: fake_mode without split
        fake_mode = params.get('fake_mode', 'single')
        has_split = any(attack in attacks for attack in ['split', 'multisplit'])
        if fake_mode in ('per_fragment', 'per_signature', 'smart') and not has_split:
            warnings.append(
                f"⚠️ fake_mode='{fake_mode}' requires split attack, "
                f"but no split/multisplit in attacks list. "
                f"Will fall back to single fake mode."
            )
        
        # Conflict 3: disorder_method without disorder in attacks
        if 'disorder_method' in params:
            has_disorder = any('disorder' in attack for attack in attacks)
            if not has_disorder:
                warnings.append(
                    f"⚠️ disorder_method specified but 'disorder' not in attacks list. "
                    f"Disorder will not be applied."
                )
        
        # Conflict 4: Unimplemented attacks
        implemented_attacks = {
            'fake', 'split', 'multisplit', 'disorder',
            'fakeddisorder', 'disorder_short_ttl_decoy'
        }
        unimplemented = set(attacks) - implemented_attacks
        if unimplemented:
            warnings.append(
                f"⚠️ Unimplemented attacks will be skipped: {unimplemented}"
            )
        
        # Log all warnings
        if warnings:
            self.logger.warning(f"Found {len(warnings)} conflict(s):")
            for warning in warnings:
                self.logger.warning(f"   {warning}")
        else:
            self.logger.info("   No conflicts detected")
        
        return warnings
