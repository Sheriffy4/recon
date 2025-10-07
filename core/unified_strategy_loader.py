#!/usr/bin/env python3
"""
Unified Strategy Loader - Single strategy loading interface for all modes

This module provides a unified interface for loading and normalizing strategies
across both testing mode and service mode, ensuring identical behavior.

Key Features:
1. Loads strategies from various formats (JSON, Zapret-style, function-style)
2. Normalizes strategy parameters to consistent format
3. Creates forced override configurations by default
4. Validates strategy parameters before application
5. Provides error handling and logging

Critical Design:
- ALWAYS creates forced override (no_fallbacks=True)
- Matches testing mode behavior exactly
- Single source of truth for strategy loading
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

# All parsing logic is now consolidated in this module
# No external parser dependencies needed


class StrategyLoadError(Exception):
    """Raised when strategy loading fails."""
    pass


class StrategyValidationError(Exception):
    """Raised when strategy validation fails."""
    pass


@dataclass
class NormalizedStrategy:
    """Normalized strategy configuration."""
    type: str  # Attack type (fakeddisorder, multisplit, etc.)
    params: Dict[str, Any]  # Strategy parameters
    no_fallbacks: bool = True  # CRITICAL: Always True for forced override
    forced: bool = True  # Forced override flag
    raw_string: str = ""  # Original strategy string
    source_format: str = ""  # Original format (zapret, function, json)
    
    def to_engine_format(self) -> Dict[str, Any]:
        """Convert to format expected by BypassEngine."""
        return {
            'type': self.type,
            'params': self.params,
            'no_fallbacks': self.no_fallbacks,
            'forced': self.forced
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return asdict(self)


class UnifiedStrategyLoader:
    """
    Unified strategy loader for all modes.
    
    Ensures identical strategy loading and application across:
    - Testing mode (enhanced_find_rst_triggers.py)
    - Service mode (recon_service.py)
    - Any other mode that needs strategy loading
    """
    
    def __init__(self, debug: bool = False):
        self.logger = logging.getLogger(__name__)
        self.debug = debug
        
        # All parsing is now handled internally
        
        # Known attack types for validation
        self.known_attacks = {
            'fake', 'split', 'disorder', 'disorder2', 'multisplit', 
            'multidisorder', 'fakeddisorder', 'seqovl'
        }
        
        # Required parameters for each attack type
        self.required_params = {
            'fakeddisorder': [],  # Can work with defaults
            'multisplit': ['split_pos'],
            'multidisorder': [],
            'fake': ['ttl'],
            'split': ['split_pos'],
            'disorder': [],
            'seqovl': ['overlap_size']
        }
        
        if self.debug:
            self.logger.setLevel(logging.DEBUG)
    
    def _normalize_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize parameters to consistent format.
        
        Handles various parameter formats and ensures consistency.
        """
        normalized = params.copy()
        
        # Convert single-item lists to strings for certain parameters
        string_params = ['fooling', 'fake_sni']
        for param in string_params:
            if param in normalized and isinstance(normalized[param], list):
                if len(normalized[param]) == 1:
                    normalized[param] = normalized[param][0]
                elif len(normalized[param]) > 1:
                    # Keep as list if multiple values
                    pass
                else:
                    # Empty list, remove parameter
                    del normalized[param]
        
        return normalized
    
    def load_strategy(self, strategy_input: Union[str, Dict[str, Any]]) -> NormalizedStrategy:
        """
        Load and normalize a strategy from various input formats.
        
        Args:
            strategy_input: Strategy in string format (Zapret/function style) or dict
            
        Returns:
            NormalizedStrategy: Normalized strategy with forced override
            
        Raises:
            StrategyLoadError: If strategy cannot be loaded
            StrategyValidationError: If strategy validation fails
        """
        try:
            if isinstance(strategy_input, dict):
                return self._load_from_dict(strategy_input)
            elif isinstance(strategy_input, str):
                return self._load_from_string(strategy_input)
            else:
                raise StrategyLoadError(f"Unsupported strategy input type: {type(strategy_input)}")
                
        except Exception as e:
            self.logger.error(f"Failed to load strategy: {e}")
            raise StrategyLoadError(f"Strategy loading failed: {e}") from e
    
    def _load_from_string(self, strategy_string: str) -> NormalizedStrategy:
        """Load strategy from string format (Zapret or function style)."""
        strategy_string = strategy_string.strip()
        
        if not strategy_string:
            raise StrategyLoadError("Empty strategy string")
        
        # Parse using consolidated parsing logic
        if self._is_zapret_style(strategy_string):
            return self._parse_zapret_style(strategy_string)
        elif self._is_function_style(strategy_string):
            return self._parse_function_style(strategy_string)
        else:
            raise StrategyLoadError(f"Unknown strategy format: {strategy_string}")
    
    def _load_from_dict(self, strategy_dict: Dict[str, Any]) -> NormalizedStrategy:
        """Load strategy from dictionary format."""
        if 'type' not in strategy_dict:
            raise StrategyLoadError("Strategy dict missing 'type' field")
        
        return NormalizedStrategy(
            type=strategy_dict['type'],
            params=strategy_dict.get('params', {}),
            no_fallbacks=True,  # CRITICAL: Always forced override
            forced=True,
            raw_string=str(strategy_dict),
            source_format='dict'
        )
    
    def _is_zapret_style(self, strategy: str) -> bool:
        """Check if strategy is in Zapret command-line style."""
        return '--dpi-desync' in strategy
    
    def _is_function_style(self, strategy: str) -> bool:
        """Check if strategy is in function call style."""
        return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*$', strategy))
    
    def _parse_zapret_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse Zapret command-line style strategy with comprehensive parameter support."""
        params = {}
        attack_type = "fakeddisorder"  # Default
        
        # Extract desync method
        desync_match = re.search(r'--dpi-desync=([^\s]+)', strategy_string)
        if desync_match:
            desync_methods = desync_match.group(1).split(',')
            # Determine attack type from methods
            if 'fake' in desync_methods and 'disorder' in desync_methods:
                attack_type = 'fakeddisorder'
            elif 'multidisorder' in desync_methods:
                attack_type = 'multidisorder'
            elif 'multisplit' in desync_methods:
                attack_type = 'multisplit'
            elif len(desync_methods) == 1:
                attack_type = desync_methods[0]
            else:
                attack_type = desync_methods[0]  # Use first method
        
        # Extract integer parameters
        int_params = {
            'ttl': 'dpi_desync_ttl',
            'autottl': 'dpi_desync_autottl', 
            'split-pos': 'split_pos',
            'split-count': 'split_count',
            'split-seqovl': 'overlap_size',
            'repeats': 'dpi_desync_repeats',
            'badseq-increment': 'badseq_increment'
        }
        
        for param_name, param_key in int_params.items():
            pattern = rf'--dpi-desync-{param_name}=([-\d]+|midsld)'
            match = re.search(pattern, strategy_string)
            if match:
                value_str = match.group(1)
                if value_str == 'midsld':
                    params[param_key.replace('dpi_desync_', '')] = 'midsld'
                else:
                    try:
                        params[param_key.replace('dpi_desync_', '')] = int(value_str)
                    except ValueError:
                        self.logger.warning(f"Could not parse integer for {param_name}: {value_str}")
        
        # Extract string parameters
        string_params = {
            'fooling': 'fooling',
            'fake-sni': 'fake_sni'
        }
        
        for param_name, param_key in string_params.items():
            pattern = rf'--dpi-desync-{param_name}=([^\s]+)'
            match = re.search(pattern, strategy_string)
            if match:
                value = match.group(1)
                if param_name == 'fooling':
                    # Handle comma-separated fooling methods
                    params[param_key] = value.split(',') if ',' in value else value
                else:
                    params[param_key] = value
        
        # Extract flag parameters (can be with or without value)
        flag_params = {
            'fake-tls': 'fake_tls',
            'fake-http': 'fake_http', 
            'fake-syndata': 'fake_syndata'
        }
        
        for param_name, param_key in flag_params.items():
            pattern = rf'--dpi-desync-{param_name}(?:=([^\s]+))?'
            match = re.search(pattern, strategy_string)
            if match:
                value = match.group(1)
                if value is not None:
                    try:
                        params[param_key] = int(value)
                    except ValueError:
                        params[param_key] = value
                else:
                    params[param_key] = True
        
        # Handle special autottl flag without value (defaults to 2)
        if '--dpi-desync-autottl' in strategy_string and 'autottl' not in params:
            params['autottl'] = 2
        
        # Validate mutual exclusivity of ttl and autottl
        if 'ttl' in params and 'autottl' in params:
            raise StrategyLoadError(
                f"Cannot specify both --dpi-desync-ttl and --dpi-desync-autottl in the same strategy. "
                f"These parameters are mutually exclusive. Strategy: {strategy_string}"
            )
        
        # Set default for repeats if not specified
        if 'repeats' not in params:
            params['repeats'] = 1
        
        # Normalize parameters
        normalized_params = self._normalize_params(params)
        
        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            no_fallbacks=True,  # CRITICAL: Always forced override
            forced=True,
            raw_string=strategy_string,
            source_format='zapret'
        )
    
    def _parse_function_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse function call style strategy with comprehensive parameter support."""
        match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*$', strategy_string)
        if not match:
            raise StrategyLoadError(f"Invalid function syntax: {strategy_string}")
        
        attack_type = match.group(1).lower().strip()
        params_str = match.group(2).strip()
        
        # Validate attack type
        if attack_type not in self.known_attacks:
            self.logger.warning(f"Unknown attack type '{attack_type}'")
        
        params = {}
        if params_str:
            # Advanced parameter parsing with support for lists and nested structures
            param_parts = self._smart_split(params_str, ',')
            
            for part in param_parts:
                part = part.strip()
                if not part or '=' not in part:
                    continue
                
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key:
                    params[key] = self._parse_value(value)
        
        # Normalize parameters
        normalized_params = self._normalize_params(params)
        
        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            no_fallbacks=True,  # CRITICAL: Always forced override
            forced=True,
            raw_string=strategy_string,
            source_format='function'
        )
    
    def _smart_split(self, text: str, delimiter: str) -> List[str]:
        """
        Split text by delimiter while respecting quotes and brackets.
        
        This handles complex parameter strings like:
        fooling=['badsum', 'badseq'], split_pos=76
        """
        parts = []
        current = []
        depth = 0
        in_quote = None
        
        for char in text:
            if char in ('"', "'"):
                if in_quote is None:
                    in_quote = char
                elif in_quote == char:
                    in_quote = None
                current.append(char)
            elif char in ('[', '(', '{') and in_quote is None:
                depth += 1
                current.append(char)
            elif char in (']', ')', '}') and in_quote is None:
                depth -= 1
                current.append(char)
            elif char == delimiter and depth == 0 and in_quote is None:
                parts.append(''.join(current))
                current = []
            else:
                current.append(char)
        
        if current:
            parts.append(''.join(current))
        
        return parts
    
    def _parse_value(self, value_str: str) -> Any:
        """
        Parse a parameter value string to appropriate Python type.
        
        Supports: int, float, bool, None, string, list
        """
        value_str = value_str.strip()
        if not value_str:
            return None
        
        # Handle lists
        if value_str.startswith('[') and value_str.endswith(']'):
            return self._parse_list(value_str)
        
        # Handle quoted strings
        if ((value_str.startswith("'") and value_str.endswith("'")) or 
            (value_str.startswith('"') and value_str.endswith('"'))):
            return value_str[1:-1]
        
        # Handle boolean values
        if value_str.lower() == 'true':
            return True
        if value_str.lower() == 'false':
            return False
        
        # Handle None/null
        if value_str.lower() in ('none', 'null'):
            return None
        
        # Handle special string values
        if value_str == 'midsld':
            return 'midsld'
        
        # Try to parse as number
        try:
            if '.' not in value_str and 'e' not in value_str.lower():
                return int(value_str)
            return float(value_str)
        except ValueError:
            pass
        
        # Return as string
        return value_str
    
    def _parse_list(self, list_str: str) -> List[Any]:
        """Parse a list string like ['item1', 'item2'] to Python list."""
        content = list_str[1:-1].strip()
        if not content:
            return []
        
        items = self._smart_split(content, ',')
        return [self._parse_value(item.strip()) for item in items]
    
    def create_forced_override(self, strategy: Union[NormalizedStrategy, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create a forced override configuration from a strategy.
        
        This method ensures the strategy is applied with forced override,
        matching the behavior of testing mode exactly.
        
        Args:
            strategy: Strategy to create forced override for
            
        Returns:
            Dict with forced override configuration
        """
        if isinstance(strategy, NormalizedStrategy):
            base_config = strategy.to_engine_format()
        elif isinstance(strategy, dict):
            base_config = strategy.copy()
        else:
            raise StrategyLoadError(f"Invalid strategy type for forced override: {type(strategy)}")
        
        # CRITICAL: Ensure forced override parameters
        forced_config = {
            'type': base_config.get('type', 'fakeddisorder'),
            'params': base_config.get('params', {}),
            'no_fallbacks': True,  # CRITICAL: Always True
            'forced': True,        # CRITICAL: Always True
            'override_mode': True  # Additional flag for clarity
        }
        
        if self.debug:
            self.logger.debug(f"Created forced override: {forced_config}")
        
        return forced_config
    
    def validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """
        Validate strategy parameters and configuration.
        
        Args:
            strategy: Strategy to validate
            
        Returns:
            True if valid
            
        Raises:
            StrategyValidationError: If validation fails
        """
        # Check attack type
        if strategy.type not in self.known_attacks:
            self.logger.warning(f"Unknown attack type: {strategy.type}")
            # Don't fail for unknown types, just warn
        
        # Check required parameters
        required = self.required_params.get(strategy.type, [])
        missing = []
        
        for param in required:
            if param not in strategy.params:
                missing.append(param)
        
        if missing:
            raise StrategyValidationError(
                f"Strategy '{strategy.type}' missing required parameters: {missing}"
            )
        
        # Validate parameter types and ranges
        self._validate_parameter_values(strategy)
        
        # CRITICAL: Ensure forced override is set
        if not strategy.no_fallbacks:
            self.logger.warning("Strategy does not have no_fallbacks=True, this may cause issues")
        
        if not strategy.forced:
            self.logger.warning("Strategy does not have forced=True, this may cause issues")
        
        return True
    
    def _validate_parameter_values(self, strategy: NormalizedStrategy) -> None:
        """Validate individual parameter values."""
        params = strategy.params
        
        # Validate TTL values
        if 'ttl' in params:
            ttl = params['ttl']
            if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
                raise StrategyValidationError(f"Invalid TTL value: {ttl} (must be 1-255)")
        
        # Validate autottl values
        if 'autottl' in params:
            autottl = params['autottl']
            if not isinstance(autottl, int) or autottl < 1 or autottl > 10:
                raise StrategyValidationError(f"Invalid autottl value: {autottl} (must be 1-10)")
        
        # Validate split position
        if 'split_pos' in params:
            split_pos = params['split_pos']
            if not isinstance(split_pos, int) or split_pos < 1:
                raise StrategyValidationError(f"Invalid split_pos value: {split_pos} (must be >= 1)")
        
        # Validate overlap size
        if 'overlap_size' in params:
            overlap_size = params['overlap_size']
            if not isinstance(overlap_size, int) or overlap_size < 0:
                raise StrategyValidationError(f"Invalid overlap_size value: {overlap_size} (must be >= 0)")
        
        # Validate repeats
        if 'repeats' in params:
            repeats = params['repeats']
            if not isinstance(repeats, int) or repeats < 1 or repeats > 10:
                raise StrategyValidationError(f"Invalid repeats value: {repeats} (must be 1-10)")
        
        # Validate fooling method
        if 'fooling' in params:
            fooling = params['fooling']
            valid_fooling = {'badseq', 'badsum', 'md5sig', 'none'}
            if fooling not in valid_fooling:
                raise StrategyValidationError(f"Invalid fooling method: {fooling} (must be one of {valid_fooling})")
    
    def load_strategies_from_file(self, file_path: Union[str, Path]) -> Dict[str, NormalizedStrategy]:
        """
        Load multiple strategies from a JSON file.
        
        Args:
            file_path: Path to JSON file containing strategies
            
        Returns:
            Dict mapping domain/key to normalized strategy
            
        Raises:
            StrategyLoadError: If file cannot be loaded
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise StrategyLoadError(f"Strategy file not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            raise StrategyLoadError(f"Failed to read strategy file {file_path}: {e}")
        
        strategies = {}
        
        # Handle different JSON formats
        if isinstance(data, dict):
            for key, value in data.items():
                try:
                    if isinstance(value, str):
                        # String strategy
                        strategies[key] = self.load_strategy(value)
                    elif isinstance(value, dict):
                        # Dict strategy or nested structure
                        if 'strategy' in value:
                            # Nested format: {"domain": {"strategy": "..."}}
                            strategies[key] = self.load_strategy(value['strategy'])
                        else:
                            # Direct dict format
                            strategies[key] = self.load_strategy(value)
                    else:
                        self.logger.warning(f"Skipping invalid strategy for {key}: {value}")
                except Exception as e:
                    self.logger.error(f"Failed to load strategy for {key}: {e}")
                    # Continue loading other strategies
        
        if self.debug:
            self.logger.debug(f"Loaded {len(strategies)} strategies from {file_path}")
        
        return strategies
    
    def normalize_strategy_dict(self, strategy_dict: Dict[str, Any]) -> NormalizedStrategy:
        """
        Normalize a strategy dictionary to standard format.
        
        This method handles various dictionary formats and ensures
        they are normalized to the standard NormalizedStrategy format.
        """
        # Handle different dict formats
        if 'attack_type' in strategy_dict:
            # ParsedStrategy-like format
            return NormalizedStrategy(
                type=strategy_dict['attack_type'],
                params=strategy_dict.get('params', {}),
                no_fallbacks=True,
                forced=True,
                raw_string=strategy_dict.get('raw_string', ''),
                source_format=strategy_dict.get('syntax_type', 'dict')
            )
        elif 'type' in strategy_dict:
            # Direct format
            return NormalizedStrategy(
                type=strategy_dict['type'],
                params=strategy_dict.get('params', {}),
                no_fallbacks=True,
                forced=True,
                raw_string=str(strategy_dict),
                source_format='dict'
            )
        else:
            raise StrategyLoadError(f"Invalid strategy dict format: {strategy_dict}")


# Convenience functions for backward compatibility
def load_strategy(strategy_input: Union[str, Dict[str, Any]], debug: bool = False) -> NormalizedStrategy:
    """Convenience function to load a single strategy."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.load_strategy(strategy_input)


def create_forced_override(strategy: Union[NormalizedStrategy, Dict[str, Any]], debug: bool = False) -> Dict[str, Any]:
    """Convenience function to create forced override."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.create_forced_override(strategy)


def load_strategies_from_file(file_path: Union[str, Path], debug: bool = False) -> Dict[str, NormalizedStrategy]:
    """Convenience function to load strategies from file."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.load_strategies_from_file(file_path)