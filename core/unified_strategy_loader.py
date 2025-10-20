# Файл: core/unified_strategy_loader.py
"""
Unified Strategy Loader - Single strategy loading interface for all modes

This module provides a unified interface for loading and normalizing strategies
across both testing mode and service mode, ensuring identical behavior.
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path


class StrategyLoadError(Exception):
    """Raised when strategy loading fails."""
    pass


class StrategyValidationError(Exception):
    """Raised when strategy validation fails."""
    pass


@dataclass
class NormalizedStrategy:
    """Normalized strategy configuration."""
    type: str
    params: Dict[str, Any]
    no_fallbacks: bool = True
    forced: bool = True
    raw_string: str = ""
    source_format: str = ""
    
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
    """
    
    def __init__(self, debug: bool = False):
        self.logger = logging.getLogger(__name__)
        self.debug = debug
        self._attack_registry = None
        
        # Initialize with comprehensive known attacks from AttackRegistry
        self.known_attacks = {
            # Core attack types from AttackRegistry
            'fakeddisorder', 'seqovl', 'multidisorder', 'disorder', 'disorder2',
            'multisplit', 'split', 'fake',
            
            # Aliases from AttackRegistry
            'fake_disorder', 'fakedisorder', 'seq_overlap', 'overlap',
            'multi_disorder', 'simple_disorder', 'disorder_ack',
            'multi_split', 'simple_split', 'fake_race', 'race',
            
            # Legacy compatibility types
            'fragment-tls', 'fake-sni-random', 'tls13-only',
            
            # Additional common variations
            'fake_packet_race', 'sequence_overlap', 'packet_split',
            'packet_disorder', 'multi_packet_split'
        }
        
        self.required_params = {
            # Core attack types with their required parameters (matching AttackRegistry)
            'fakeddisorder': ['split_pos'],
            'seqovl': ['split_pos', 'overlap_size'],
            'multidisorder': [],  # No required params, handler will handle defaults
            'disorder': ['split_pos'],
            'disorder2': ['split_pos'],
            'multisplit': ['positions'],
            'split': ['split_pos'],
            'fake': ['ttl'],
            
            # Aliases mapping to same requirements as main types (from AttackRegistry)
            'fake_disorder': ['split_pos'],  # alias for fakeddisorder
            'fakedisorder': ['split_pos'],   # alias for fakeddisorder
            'seq_overlap': ['split_pos', 'overlap_size'],  # alias for seqovl
            'overlap': ['split_pos', 'overlap_size'],      # alias for seqovl
            'multi_disorder': [],            # alias for multidisorder
            'simple_disorder': ['split_pos'], # alias for disorder
            'disorder_ack': ['split_pos'],   # alias for disorder2
            'multi_split': ['positions'],    # alias for multisplit
            'simple_split': ['split_pos'],   # alias for split
            'fake_race': ['ttl'],           # alias for fake
            'race': ['ttl'],                # alias for fake
            
            # Legacy compatibility types
            'fragment-tls': [],
            'fake-sni-random': [],
            'tls13-only': [],
            
            # Additional variations for backward compatibility
            'fake_packet_race': ['ttl'],
            'sequence_overlap': ['split_pos', 'overlap_size'],
            'packet_split': ['split_pos'],
            'packet_disorder': ['split_pos'],
            'multi_packet_split': ['positions']
        }
        
        # Try to enhance with AttackRegistry data
        self._enhance_with_registry()
        
        if self.debug:
            self.logger.setLevel(logging.DEBUG)
    
    def _enhance_with_registry(self):
        """Enhance known_attacks and required_params with AttackRegistry data."""
        try:
            from core.bypass.attacks.attack_registry import get_attack_registry
            
            registry = get_attack_registry()
            
            # Get all registered attacks from the registry
            registered_attacks = registry.list_attacks()
            
            # Clear existing known_attacks and required_params to avoid conflicts
            # Keep only the basic legacy attacks that might not be in registry
            legacy_attacks = {
                'fragment-tls', 'fake-sni-random', 'tls13-only'
            }
            
            # Reset to only legacy attacks
            self.known_attacks = legacy_attacks.copy()
            legacy_required_params = {
                'fragment-tls': [],
                'fake-sni-random': [],
                'tls13-only': []
            }
            
            # Add all registered attacks from AttackRegistry
            for attack_type in registered_attacks:
                self.known_attacks.add(attack_type)
                
                metadata = registry.get_attack_metadata(attack_type)
                if metadata:
                    self.required_params[attack_type] = metadata.required_params
                    
                    # Also add aliases
                    for alias in metadata.aliases:
                        self.known_attacks.add(alias)
                        self.required_params[alias] = metadata.required_params
                else:
                    # Fallback for attacks without metadata
                    self.required_params[attack_type] = []
            
            # Add legacy required params back
            self.required_params.update(legacy_required_params)
            
            # Store registry reference for later use
            self._attack_registry = registry
            
            if self.debug:
                self.logger.debug(f"Enhanced with {len(registered_attacks)} attacks from AttackRegistry")
                self.logger.debug(f"Total known attacks: {len(self.known_attacks)}")
                self.logger.debug(f"Total required params entries: {len(self.required_params)}")
                
        except Exception as e:
            self.logger.warning(f"Failed to enhance with AttackRegistry: {e}")
            # Continue with basic configuration - restore original hardcoded values
            self._attack_registry = None
            self._restore_hardcoded_attacks()
    
    def _restore_hardcoded_attacks(self):
        """Restore hardcoded attack definitions as fallback."""
        self.known_attacks = {
            # Core attack types from AttackRegistry
            'fakeddisorder', 'seqovl', 'multidisorder', 'disorder', 'disorder2',
            'multisplit', 'split', 'fake',
            
            # Aliases from AttackRegistry
            'fake_disorder', 'fakedisorder', 'seq_overlap', 'overlap',
            'multi_disorder', 'simple_disorder', 'disorder_ack',
            'multi_split', 'simple_split', 'fake_race', 'race',
            
            # Legacy compatibility types
            'fragment-tls', 'fake-sni-random', 'tls13-only',
            
            # Additional common variations
            'fake_packet_race', 'sequence_overlap', 'packet_split',
            'packet_disorder', 'multi_packet_split'
        }
        
        self.required_params = {
            # Core attack types with their required parameters (matching AttackRegistry)
            'fakeddisorder': ['split_pos'],
            'seqovl': ['split_pos', 'overlap_size'],
            'multidisorder': [],  # No required params, handler will handle defaults
            'disorder': ['split_pos'],
            'disorder2': ['split_pos'],
            'multisplit': ['positions'],
            'split': ['split_pos'],
            'fake': ['ttl'],
            
            # Aliases mapping to same requirements as main types (from AttackRegistry)
            'fake_disorder': ['split_pos'],  # alias for fakeddisorder
            'fakedisorder': ['split_pos'],   # alias for fakeddisorder
            'seq_overlap': ['split_pos', 'overlap_size'],  # alias for seqovl
            'overlap': ['split_pos', 'overlap_size'],      # alias for seqovl
            'multi_disorder': [],            # alias for multidisorder
            'simple_disorder': ['split_pos'], # alias for disorder
            'disorder_ack': ['split_pos'],   # alias for disorder2
            'multi_split': ['positions'],    # alias for multisplit
            'simple_split': ['split_pos'],   # alias for split
            'fake_race': ['ttl'],           # alias for fake
            'race': ['ttl'],                # alias for fake
            
            # Legacy compatibility types
            'fragment-tls': [],
            'fake-sni-random': [],
            'tls13-only': [],
            
            # Additional variations for backward compatibility
            'fake_packet_race': ['ttl'],
            'sequence_overlap': ['split_pos', 'overlap_size'],
            'packet_split': ['split_pos'],
            'packet_disorder': ['split_pos'],
            'multi_packet_split': ['positions']
        }
    
    def _normalize_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize parameters to consistent format."""
        normalized = params.copy()
        
        if 'fake_sni' in normalized and isinstance(normalized['fake_sni'], list):
            if len(normalized['fake_sni']) >= 1:
                normalized['fake_sni'] = normalized['fake_sni'][0]
            else:
                del normalized['fake_sni']
        
        if 'fooling' in normalized:
            fooling_val = normalized['fooling']
            fooling_list = []
            if isinstance(fooling_val, str):
                fooling_list = [f.strip() for f in fooling_val.split(',') if f.strip()]
            elif isinstance(fooling_val, list):
                fooling_list = [str(f).strip() for f in fooling_val if str(f).strip()]
            elif fooling_val is not None:
                fooling_list = [str(fooling_val)]
            
            if fooling_list:
                normalized['fooling'] = list(dict.fromkeys(fooling_list))
            else:
                del normalized['fooling']

        return normalized
    
    def _normalize_params_with_registry(self, attack_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize parameters using AttackRegistry metadata."""
        try:
            # Use stored registry reference if available, otherwise get it
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            metadata = registry.get_attack_metadata(attack_type)
            
            if metadata:
                # Start with normalized params
                normalized = self._normalize_params(params)
                
                # Add missing optional parameters with their defaults
                for param_name, default_value in metadata.optional_params.items():
                    if param_name not in normalized:
                        normalized[param_name] = default_value
                
                # Normalize special parameters
                normalized = self._normalize_special_parameters(normalized)
                
                return normalized
            else:
                # Fall back to basic normalization if no metadata found
                return self._normalize_special_parameters(self._normalize_params(params))
                
        except Exception as e:
            self.logger.warning(f"Failed to normalize params with registry for {attack_type}: {e}")
            return self._normalize_special_parameters(self._normalize_params(params))
    
    def _normalize_special_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize special parameters to ensure consistency."""
        normalized = params.copy()
        
        # Import special parameter constants
        try:
            from core.bypass.attacks.metadata import SpecialParameterValues
        except ImportError:
            # Fallback constants
            class SpecialParameterValues:
                CIPHER = "cipher"
                SNI = "sni"
                MIDSLD = "midsld"
                ALL = ["cipher", "sni", "midsld"]
        
        # Normalize split_pos special values
        if 'split_pos' in normalized and normalized['split_pos'] is not None:
            split_pos = normalized['split_pos']
            
            if isinstance(split_pos, str):
                # Normalize case and whitespace
                normalized_value = split_pos.lower().strip()
                if normalized_value in SpecialParameterValues.ALL:
                    normalized['split_pos'] = normalized_value
                else:
                    # Try to convert to int if it's not a special value
                    try:
                        normalized['split_pos'] = int(split_pos)
                    except ValueError:
                        # Keep as string, validation will catch invalid values
                        pass
            elif isinstance(split_pos, list):
                # Normalize each position in the list
                normalized_positions = []
                for pos in split_pos:
                    if isinstance(pos, str):
                        normalized_value = pos.lower().strip()
                        if normalized_value in SpecialParameterValues.ALL:
                            normalized_positions.append(normalized_value)
                        else:
                            try:
                                normalized_positions.append(int(pos))
                            except ValueError:
                                normalized_positions.append(pos)  # Keep for validation
                    else:
                        normalized_positions.append(pos)
                normalized['split_pos'] = normalized_positions
        
        # Normalize positions special values
        if 'positions' in normalized and normalized['positions'] is not None:
            positions = normalized['positions']
            
            # Handle string format (comma-separated values)
            if isinstance(positions, str):
                try:
                    # Convert comma-separated string to list
                    positions = [pos.strip() for pos in positions.split(',') if pos.strip()]
                    normalized['positions'] = positions
                except Exception:
                    # Keep as string if conversion fails
                    pass
            
            if isinstance(positions, list):
                normalized_positions = []
                for pos in positions:
                    if isinstance(pos, str):
                        normalized_value = pos.lower().strip()
                        if normalized_value in SpecialParameterValues.ALL:
                            normalized_positions.append(normalized_value)
                        else:
                            try:
                                normalized_positions.append(int(pos))
                            except ValueError:
                                normalized_positions.append(pos)  # Keep for validation
                    else:
                        normalized_positions.append(pos)
                normalized['positions'] = normalized_positions
        
        # Normalize TTL parameters
        ttl_params = ['ttl', 'fake_ttl']
        for ttl_param in ttl_params:
            if ttl_param in normalized and normalized[ttl_param] is not None:
                ttl_value = normalized[ttl_param]
                if isinstance(ttl_value, str):
                    try:
                        normalized[ttl_param] = int(ttl_value)
                    except ValueError:
                        # Keep as string, validation will catch invalid values
                        pass
        
        # Normalize boolean parameters
        boolean_params = ['ack_first', 'fake_tls', 'fake_http', 'fake_syndata']
        for bool_param in boolean_params:
            if bool_param in normalized and normalized[bool_param] is not None:
                bool_value = normalized[bool_param]
                if isinstance(bool_value, str):
                    lower_value = bool_value.lower().strip()
                    if lower_value in ('true', '1', 'yes', 'on'):
                        normalized[bool_param] = True
                    elif lower_value in ('false', '0', 'no', 'off'):
                        normalized[bool_param] = False
                elif isinstance(bool_value, int):
                    normalized[bool_param] = bool(bool_value)
        
        # Normalize integer parameters
        int_params = ['overlap_size', 'repeats', 'autottl', 'badseq_increment']
        for int_param in int_params:
            if int_param in normalized and normalized[int_param] is not None:
                int_value = normalized[int_param]
                if isinstance(int_value, str):
                    try:
                        normalized[int_param] = int(int_value)
                    except ValueError:
                        # Keep as string, validation will catch invalid values
                        pass
        
        # Normalize fooling methods
        fooling_params = ['fooling', 'fooling_methods']
        for fooling_param in fooling_params:
            if fooling_param in normalized and normalized[fooling_param] is not None:
                fooling_value = normalized[fooling_param]
                if isinstance(fooling_value, str):
                    # Split comma-separated values
                    fooling_list = [method.strip().lower() for method in fooling_value.split(',') if method.strip()]
                    normalized[fooling_param] = fooling_list
                elif isinstance(fooling_value, list):
                    # Normalize each method in the list
                    normalized[fooling_param] = [str(method).strip().lower() for method in fooling_value if str(method).strip()]
        
        return normalized
    
    def load_strategy(self, strategy_input: Union[str, Dict[str, Any]]) -> NormalizedStrategy:
        """Load and normalize a strategy from various input formats."""
        try:
            if isinstance(strategy_input, dict):
                strategy = self._load_from_dict(strategy_input)
            elif isinstance(strategy_input, str):
                strategy = self._load_from_string(strategy_input)
            else:
                raise StrategyLoadError(f"Unsupported strategy input type: {type(strategy_input)}")
            
            self.validate_strategy(strategy)
            return strategy

        except (StrategyLoadError, StrategyValidationError) as e:
            self.logger.error(f"Failed to load and validate strategy: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during strategy loading: {e}")
            raise StrategyLoadError(f"Strategy loading failed unexpectedly: {e}") from e
    
    def _load_from_string(self, strategy_string: str) -> NormalizedStrategy:
        """Load strategy from string format."""
        strategy_string = strategy_string.strip()
        if not strategy_string:
            raise StrategyLoadError("Empty strategy string")
        
        if self._is_zapret_style(strategy_string):
            return self._parse_zapret_style(strategy_string)
        elif self._is_function_style(strategy_string):
            return self._parse_function_style(strategy_string)
        # NEW: Handle new advanced formats that are not zapret-style
        elif strategy_string.startswith('--'):
             return self._parse_generic_cli_style(strategy_string)
        else:
            raise StrategyLoadError(f"Unknown strategy format: {strategy_string}")

    def _parse_generic_cli_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parses generic --key=value style strategies."""
        parts = strategy_string.split()
        attack_type = parts[0].lstrip('-')
        params = {}
        for part in parts[1:]:
            if '=' in part:
                key, value = part.lstrip('-').split('=', 1)
                params[key.replace('-', '_')] = self._parse_value(value)
            else:
                params[part.lstrip('-').replace('-', '_')] = True
        
        return NormalizedStrategy(
            type=attack_type,
            params=self._normalize_params(params),
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format='generic_cli'
        )

    def _load_from_dict(self, strategy_dict: Dict[str, Any]) -> NormalizedStrategy:
        """Load strategy from dictionary format."""
        if 'type' not in strategy_dict:
            raise StrategyLoadError("Strategy dict missing 'type' field")
        
        attack_type = strategy_dict['type']
        normalized_params = self._normalize_params_with_registry(attack_type, strategy_dict.get('params', {}))

        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            no_fallbacks=True,
            forced=True,
            raw_string=str(strategy_dict),
            source_format='dict'
        )
    
    def _is_zapret_style(self, strategy: str) -> bool:
        return '--dpi-desync' in strategy
    
    def _is_function_style(self, strategy: str) -> bool:
        return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*$', strategy))
    
    def _parse_zapret_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse Zapret command-line style strategy."""
        params = {}
        attack_type = "fakeddisorder"

        desync_match = re.search(r'--dpi-desync=([^\s]+)', strategy_string)
        if desync_match:
            desync_methods = [m.strip() for m in desync_match.group(1).split(',')]
            if 'fake' in desync_methods and ('disorder' in desync_methods or 'multidisorder' in desync_methods):
                attack_type = 'fakeddisorder'
            else:
                priority_order = ['multidisorder', 'fakeddisorder', 'multisplit', 'disorder2', 'seqovl', 'disorder', 'split', 'fake']
                found_type = next((method for method in priority_order if method in desync_methods), None)
                if found_type:
                    attack_type = found_type
                elif desync_methods:
                    attack_type = desync_methods[0]
           
        split_pos_match = re.search(r'--dpi-desync-split-pos=([^\s]+)', strategy_string)
        if split_pos_match:
            split_pos_str = split_pos_match.group(1)
            special_values = ['midsld', 'cipher', 'sni']
            if split_pos_str in special_values:
                params['split_pos'] = split_pos_str
            elif ',' in split_pos_str:
                parts = [p.strip() for p in split_pos_str.split(',') if p.strip()]
                parsed_parts = [int(p) if p.isdigit() else p for p in parts if p.isdigit() or p in special_values]
                if parsed_parts: params['split_pos'] = parsed_parts
            else:
                try:
                    params['split_pos'] = int(split_pos_str)
                except ValueError:
                    self.logger.warning(f"Could not parse split-pos: {split_pos_str}")
        
        int_params = {'ttl': 'dpi_desync_ttl', 'autottl': 'dpi_desync_autottl', 'split-count': 'split_count', 'split-seqovl': 'overlap_size', 'repeats': 'dpi_desync_repeats', 'badseq-increment': 'badseq_increment'}
        for param_name, param_key in int_params.items():
            match = re.search(rf'--dpi-desync-{param_name}=([-\d]+|midsld)', strategy_string)
            if match:
                value_str = match.group(1)
                if value_str == 'midsld':
                    params[param_key.replace('dpi_desync_', '')] = 'midsld'
                else:
                    try:
                        params[param_key.replace('dpi_desync_', '')] = int(value_str)
                    except ValueError:
                        self.logger.warning(f"Could not parse integer for {param_name}: {value_str}")
        
        string_params = {'fooling': 'fooling', 'fake-sni': 'fake_sni'}
        for param_name, param_key in string_params.items():
            match = re.search(rf'--dpi-desync-{param_name}=([^\s]+)', strategy_string)
            if match:
                params[param_key] = match.group(1)
        
        flag_params = {'fake-tls': 'fake_tls', 'fake-http': 'fake_http', 'fake-syndata': 'fake_syndata'}
        for param_name, param_key in flag_params.items():
            match = re.search(rf'--dpi-desync-{param_name}(?:=([^\s]+))?', strategy_string)
            if match:
                value = match.group(1)
                params[param_key] = int(value) if value and value.isdigit() else (value or True)
        
        if '--dpi-desync-autottl' in strategy_string and 'autottl' not in params:
            params['autottl'] = 2
        if 'repeats' not in params:
            params['repeats'] = 1
        
        # Handle backward compatibility: convert split_count to positions for multisplit
        if attack_type == 'multisplit' and 'split_count' in params and 'positions' not in params:
            split_count = params.get('split_count', 3)
            split_pos = params.get('split_pos', 1)
            
            # Generate positions based on split_count and split_pos
            if isinstance(split_pos, int):
                positions = []
                base_pos = split_pos
                gap = max(6, split_pos * 2)  # Reasonable gap between positions
                
                for i in range(split_count):
                    positions.append(base_pos + (i * gap))
                
                params['positions'] = positions
            else:
                # If split_pos is special value, keep split_count for later processing
                pass
        
        # Handle backward compatibility: convert split_pos to positions for multidisorder if needed
        if attack_type == 'multidisorder' and 'split_pos' in params and 'positions' not in params:
            split_pos = params.get('split_pos')
            if isinstance(split_pos, int):
                # For multidisorder, create multiple positions around the split_pos
                positions = [split_pos, split_pos + 5, split_pos + 10]
                params['positions'] = positions
        
        # Handle backward compatibility: convert split_pos to positions for multisplit if needed
        if attack_type == 'multisplit' and 'split_pos' in params and 'positions' not in params:
            split_pos = params.get('split_pos')
            if isinstance(split_pos, int):
                # For multisplit, create multiple positions based on split_pos
                positions = [split_pos, split_pos + 8, split_pos + 16]
                params['positions'] = positions
        
        normalized_params = self._normalize_params_with_registry(attack_type, params)
        
        return NormalizedStrategy(
            type=attack_type, params=normalized_params, no_fallbacks=True, forced=True,
            raw_string=strategy_string, source_format='zapret'
        )
    
    def _parse_function_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse function call style strategy."""
        match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*$', strategy_string)
        if not match:
            raise StrategyLoadError(f"Invalid function syntax: {strategy_string}")
        
        attack_type = match.group(1).lower().strip()
        params_str = match.group(2).strip()
        
        params = {}
        if params_str:
            param_parts = self._smart_split(params_str, ',')
            for part in param_parts:
                part = part.strip()
                if not part or '=' not in part: continue
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key: params[key] = self._parse_value(value)
        
        normalized_params = self._normalize_params_with_registry(attack_type, params)
        
        return NormalizedStrategy(
            type=attack_type, params=normalized_params, no_fallbacks=True, forced=True,
            raw_string=strategy_string, source_format='function'
        )
    
    def _smart_split(self, text: str, delimiter: str) -> List[str]:
        """Split text by delimiter while respecting quotes and brackets."""
        parts, current, depth, in_quote = [], [], 0, None
        for char in text:
            if char in ('"', "'"):
                if in_quote is None: in_quote = char
                elif in_quote == char: in_quote = None
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
        if current: parts.append(''.join(current))
        return parts
    
    def _parse_value(self, value_str: str) -> Any:
        """Parse a parameter value string to appropriate Python type."""
        value_str = value_str.strip()
        if not value_str: return None
        if value_str.startswith('[') and value_str.endswith(']'): return self._parse_list(value_str)
        if (value_str.startswith("'") and value_str.endswith("'")) or (value_str.startswith('"') and value_str.endswith('"')): return value_str[1:-1]
        if value_str.lower() == 'true': return True
        if value_str.lower() == 'false': return False
        if value_str.lower() in ('none', 'null'): return None
        if value_str == 'midsld': return 'midsld'
        try:
            if '.' not in value_str and 'e' not in value_str.lower(): return int(value_str)
            return float(value_str)
        except ValueError: pass
        return value_str
    
    def _parse_list(self, list_str: str) -> List[Any]:
        """Parse a list string like ['item1', 'item2'] to Python list."""
        content = list_str[1:-1].strip()
        if not content: return []
        return [self._parse_value(item.strip()) for item in self._smart_split(content, ',')]
    
    def create_forced_override(self, strategy: Union[NormalizedStrategy, Dict[str, Any]]) -> Dict[str, Any]:
        """Create a forced override configuration from a strategy."""
        if isinstance(strategy, NormalizedStrategy):
            base_config = strategy.to_engine_format()
        elif isinstance(strategy, dict):
            base_config = strategy.copy()
        else:
            raise StrategyLoadError(f"Invalid strategy type for forced override: {type(strategy)}")
        
        forced_config = {
            'type': base_config.get('type', 'fakeddisorder'),
            'params': base_config.get('params', {}),
            'no_fallbacks': True,
            'forced': True,
            'override_mode': True
        }
        if self.debug: self.logger.debug(f"Created forced override: {forced_config}")
        return forced_config
    
    def validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """Validate strategy parameters and configuration using AttackRegistry."""
        try:
            # Use stored registry reference if available, otherwise get it
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            # Validate parameters using the registry (includes special parameter validation)
            validation_result = registry.validate_parameters(strategy.type, strategy.params)
            
            if not validation_result.is_valid:
                raise StrategyValidationError(f"AttackRegistry validation failed for '{strategy.type}': {validation_result.error_message}")
            
            # Log warnings from AttackRegistry validation
            if validation_result.has_warnings():
                for warning in validation_result.warnings:
                    self.logger.warning(f"Strategy '{strategy.type}' validation warning: {warning}")
            
            # Additional UnifiedStrategyLoader-specific validation
            self._validate_parameter_values(strategy)
            
            # Additional validation for strategy configuration
            if not strategy.no_fallbacks or not strategy.forced:
                self.logger.warning("Strategy is not configured for forced override.")
            
            # Validate special parameter combinations
            self._validate_parameter_combinations(strategy)
            
            return True
            
        except ImportError:
            # Fall back to legacy validation if AttackRegistry is not available
            self.logger.warning("AttackRegistry not available, using legacy validation")
            return self._legacy_validate_strategy(strategy)
        except Exception as e:
            # Fall back to legacy validation on any error
            self.logger.warning(f"AttackRegistry validation failed, using legacy validation: {e}")
            return self._legacy_validate_strategy(strategy)
    
    def _legacy_validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """Legacy strategy validation for backward compatibility."""
        if strategy.type not in self.known_attacks:
            self.logger.warning(f"Unknown attack type: {strategy.type}")
        
        required = self.required_params.get(strategy.type, [])
        
        # Handle backward compatibility for multisplit
        if strategy.type == 'multisplit' and 'positions' in required:
            # If we have split_count, split_pos, or positions, we can generate positions, so positions is not required
            if ('split_count' in strategy.params or 
                'split_pos' in strategy.params or 
                'positions' in strategy.params):
                required = [param for param in required if param != 'positions']
        
        # Handle backward compatibility for multidisorder  
        if strategy.type == 'multidisorder' and 'positions' in required:
            # If we have split_pos or positions, we can generate positions, so positions is not required
            if 'split_pos' in strategy.params or 'positions' in strategy.params:
                required = [param for param in required if param != 'positions']
        
        missing = [param for param in required if param not in strategy.params]
        if missing:
            raise StrategyValidationError(f"Strategy '{strategy.type}' missing required parameters: {missing}")
        
        self._validate_parameter_values(strategy)
        
        if not strategy.no_fallbacks or not strategy.forced:
            self.logger.warning("Strategy is not configured for forced override.")
        
        return True
    
    def _validate_parameter_values(self, strategy: NormalizedStrategy) -> None:
        """Validate individual parameter values including special parameters."""
        params = strategy.params
        
        # Import special parameter constants
        try:
            from core.bypass.attacks.metadata import SpecialParameterValues, FoolingMethods
        except ImportError:
            # Fallback to local constants if metadata module is not available
            class SpecialParameterValues:
                CIPHER = "cipher"
                SNI = "sni"
                MIDSLD = "midsld"
                ALL = ["cipher", "sni", "midsld"]
            
            class FoolingMethods:
                ALL = ["badseq", "badsum", "md5sig", "none", "hopbyhop", "badack", "datanoack"]
        
        # TTL validation
        if 'ttl' in params and params.get('ttl') is not None and 'autottl' in params and params.get('autottl') is not None:
            raise StrategyValidationError("Cannot specify both ttl and autottl.")
        
        if 'ttl' in params and params['ttl'] is not None:
            ttl = params['ttl']
            if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                raise StrategyValidationError(f"Invalid TTL value: {ttl}. Must be integer between 1 and 255.")
        
        if 'fake_ttl' in params and params['fake_ttl'] is not None:
            fake_ttl = params['fake_ttl']
            if not isinstance(fake_ttl, int) or not (1 <= fake_ttl <= 255):
                raise StrategyValidationError(f"Invalid fake_ttl value: {fake_ttl}. Must be integer between 1 and 255.")
        
        if 'autottl' in params and params['autottl'] is not None:
            autottl = params['autottl']
            if not isinstance(autottl, int) or not (-10 <= autottl <= 10):
                raise StrategyValidationError(f"Invalid autottl value: {autottl}. Must be integer between -10 and 10.")
        
        # Special parameter validation for split_pos
        if 'split_pos' in params and params['split_pos'] is not None:
            split_pos = params['split_pos']
            
            if isinstance(split_pos, list):
                # Validate each position in the list
                for i, pos in enumerate(split_pos):
                    self._validate_single_position(pos, f"split_pos[{i}]", SpecialParameterValues.ALL)
            else:
                # Validate single position
                self._validate_single_position(split_pos, "split_pos", SpecialParameterValues.ALL)
        
        # Special parameter validation for positions (multisplit/multidisorder)
        if 'positions' in params and params['positions'] is not None:
            positions = params['positions']
            
            # Handle backward compatibility: convert string to list
            if isinstance(positions, str):
                # Convert comma-separated string to list of integers
                try:
                    positions = [int(pos.strip()) for pos in positions.split(',') if pos.strip()]
                    params['positions'] = positions
                except ValueError:
                    raise StrategyValidationError(f"Invalid positions string: {params['positions']}. Must be comma-separated integers.")
            
            if not isinstance(positions, list):
                raise StrategyValidationError(f"Invalid positions parameter: must be a list, got {type(positions).__name__}")
            
            if len(positions) == 0:
                raise StrategyValidationError("positions list cannot be empty")
            
            for i, pos in enumerate(positions):
                self._validate_single_position(pos, f"positions[{i}]", SpecialParameterValues.ALL)
        
        # Overlap size validation
        if 'overlap_size' in params and params['overlap_size'] is not None:
            overlap_size = params['overlap_size']
            if not isinstance(overlap_size, int) or overlap_size < 0:
                raise StrategyValidationError(f"Invalid overlap_size value: {overlap_size}. Must be non-negative integer.")
            
            # Additional validation: overlap_size should be reasonable
            if overlap_size > 1000:
                raise StrategyValidationError(f"overlap_size too large: {overlap_size}. Maximum allowed is 1000.")
        
        # Repeats validation
        if 'repeats' in params and params['repeats'] is not None:
            repeats = params['repeats']
            if not isinstance(repeats, int) or not (1 <= repeats <= 10):
                raise StrategyValidationError(f"Invalid repeats value: {repeats}. Must be integer between 1 and 10.")
        
        # Fooling methods validation
        if 'fooling' in params and params['fooling'] is not None:
            fooling = params['fooling']
            if not isinstance(fooling, list):
                raise StrategyValidationError(f"Invalid fooling parameter: must be a list, got {type(fooling).__name__}")
            
            # Validate each fooling method
            for method in fooling:
                if not isinstance(method, str):
                    raise StrategyValidationError(f"Invalid fooling method: must be string, got {type(method).__name__}")
                
                if method not in FoolingMethods.ALL:
                    raise StrategyValidationError(f"Invalid fooling method '{method}'. Valid methods: {FoolingMethods.ALL}")
        
        # Fooling methods validation (alternative parameter name)
        if 'fooling_methods' in params and params['fooling_methods'] is not None:
            fooling_methods = params['fooling_methods']
            if not isinstance(fooling_methods, list):
                raise StrategyValidationError(f"Invalid fooling_methods parameter: must be a list, got {type(fooling_methods).__name__}")
            
            for method in fooling_methods:
                if not isinstance(method, str):
                    raise StrategyValidationError(f"Invalid fooling method: must be string, got {type(method).__name__}")
                
                if method not in FoolingMethods.ALL:
                    raise StrategyValidationError(f"Invalid fooling method '{method}'. Valid methods: {FoolingMethods.ALL}")
        
        # Boolean flags validation (with special handling for fake_tls)
        boolean_params = ['ack_first', 'fake_http', 'fake_syndata']
        for param_name in boolean_params:
            if param_name in params and params[param_name] is not None:
                param_value = params[param_name]
                if not isinstance(param_value, bool):
                    # Try to convert common values
                    if isinstance(param_value, (int, str)):
                        if str(param_value).lower() in ('true', '1', 'yes', 'on'):
                            params[param_name] = True
                        elif str(param_value).lower() in ('false', '0', 'no', 'off'):
                            params[param_name] = False
                        else:
                            raise StrategyValidationError(f"Invalid {param_name} value: {param_value}. Must be boolean or convertible to boolean.")
                    else:
                        raise StrategyValidationError(f"Invalid {param_name} value: {param_value}. Must be boolean.")
        
        # Special handling for fake_tls (can be boolean or hex string for backward compatibility)
        if 'fake_tls' in params and params['fake_tls'] is not None:
            fake_tls = params['fake_tls']
            if isinstance(fake_tls, bool):
                # Already boolean, keep as is
                pass
            elif isinstance(fake_tls, (int, str)):
                str_value = str(fake_tls).lower()
                if str_value in ('true', '1', 'yes', 'on'):
                    params['fake_tls'] = True
                elif str_value in ('false', '0', 'no', 'off'):
                    params['fake_tls'] = False
                elif str_value.startswith('0x') or str_value.isdigit():
                    # Hex value or numeric - keep as string for backward compatibility
                    params['fake_tls'] = str(fake_tls)
                else:
                    # Unknown string value - keep as is for backward compatibility
                    params['fake_tls'] = str(fake_tls)
            else:
                # Keep as is for backward compatibility
                pass
        
        # Custom data validation
        if 'fake_data' in params and params['fake_data'] is not None:
            fake_data = params['fake_data']
            if not isinstance(fake_data, (str, bytes)):
                raise StrategyValidationError(f"Invalid fake_data: must be string or bytes, got {type(fake_data).__name__}")
        
        if 'fake_sni' in params and params['fake_sni'] is not None:
            fake_sni = params['fake_sni']
            if not isinstance(fake_sni, str):
                raise StrategyValidationError(f"Invalid fake_sni: must be string, got {type(fake_sni).__name__}")
            
            # Basic domain name validation
            if not self._is_valid_domain_name(fake_sni):
                raise StrategyValidationError(f"Invalid fake_sni domain name: {fake_sni}")
    
    def _validate_single_position(self, position: Any, param_name: str, special_values: List[str]) -> None:
        """Validate a single position parameter (can be int or special string value)."""
        if isinstance(position, int):
            if position < 1:
                raise StrategyValidationError(f"Invalid {param_name}: {position}. Position must be >= 1.")
            
            # Additional validation: position should be reasonable
            if position > 65535:
                raise StrategyValidationError(f"Invalid {param_name}: {position}. Position too large (max 65535).")
                
        elif isinstance(position, str):
            # Check if it's a special value
            if position in special_values:
                # Special values are valid
                pass
            else:
                # Try to convert to int
                try:
                    int_pos = int(position)
                    if int_pos < 1:
                        raise StrategyValidationError(f"Invalid {param_name}: {position}. Position must be >= 1.")
                    if int_pos > 65535:
                        raise StrategyValidationError(f"Invalid {param_name}: {position}. Position too large (max 65535).")
                except ValueError:
                    raise StrategyValidationError(f"Invalid {param_name}: {position}. Must be integer >= 1 or one of special values: {special_values}")
        else:
            raise StrategyValidationError(f"Invalid {param_name}: {position}. Must be integer or string, got {type(position).__name__}")
    
    def _is_valid_domain_name(self, domain: str) -> bool:
        """Basic domain name validation."""
        if not domain or len(domain) > 253:
            return False
        
        # Basic regex for domain validation
        import re
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def _validate_parameter_combinations(self, strategy: NormalizedStrategy) -> None:
        """Validate special parameter combinations and dependencies."""
        params = strategy.params
        attack_type = strategy.type
        
        # Validate seqovl specific requirements
        if attack_type in ['seqovl', 'seq_overlap', 'overlap']:
            if 'overlap_size' not in params:
                raise StrategyValidationError(f"Attack type '{attack_type}' requires 'overlap_size' parameter")
            
            if 'split_pos' not in params:
                raise StrategyValidationError(f"Attack type '{attack_type}' requires 'split_pos' parameter")
            
            # Validate that overlap_size makes sense with split_pos
            overlap_size = params.get('overlap_size', 0)
            split_pos = params.get('split_pos')
            
            if isinstance(split_pos, int) and isinstance(overlap_size, int):
                if overlap_size >= split_pos:
                    raise StrategyValidationError(f"overlap_size ({overlap_size}) must be less than split_pos ({split_pos})")
        
        # Validate multisplit/multidisorder requirements
        if attack_type in ['multisplit', 'multidisorder', 'multi_split', 'multi_disorder']:
            # Either positions or split_pos should be provided
            if 'positions' not in params and 'split_pos' not in params:
                raise StrategyValidationError(f"Attack type '{attack_type}' requires either 'positions' or 'split_pos' parameter")
            
            # If both are provided, warn about potential conflict
            if 'positions' in params and 'split_pos' in params:
                self.logger.warning(f"Both 'positions' and 'split_pos' provided for '{attack_type}'. 'positions' will take precedence.")
        
        # Validate TTL parameter combinations
        if 'ttl' in params and 'autottl' in params:
            if params['ttl'] is not None and params['autottl'] is not None:
                raise StrategyValidationError("Cannot specify both 'ttl' and 'autottl' parameters")
        
        # Validate fake packet parameters
        fake_params = ['fake_tls', 'fake_http', 'fake_syndata', 'fake_sni', 'fake_data']
        has_fake_params = any(param in params and params[param] is not None for param in fake_params)
        
        if has_fake_params and attack_type not in ['fakeddisorder', 'fake_disorder', 'fakedisorder', 'fake', 'fake_race', 'race']:
            self.logger.warning(f"Fake packet parameters provided for non-fake attack type '{attack_type}'. They may be ignored.")
        
        # Validate fooling methods consistency
        if 'fooling' in params and 'fooling_methods' in params:
            if params['fooling'] is not None and params['fooling_methods'] is not None:
                self.logger.warning("Both 'fooling' and 'fooling_methods' provided. 'fooling' will take precedence.")
        
        # Validate special position values context
        special_positions = []
        
        # Check split_pos for special values
        if 'split_pos' in params:
            split_pos = params['split_pos']
            if isinstance(split_pos, str) and split_pos in ['cipher', 'sni', 'midsld']:
                special_positions.append(split_pos)
            elif isinstance(split_pos, list):
                for pos in split_pos:
                    if isinstance(pos, str) and pos in ['cipher', 'sni', 'midsld']:
                        special_positions.append(pos)
        
        # Check positions for special values
        if 'positions' in params:
            positions = params['positions']
            if isinstance(positions, list):
                for pos in positions:
                    if isinstance(pos, str) and pos in ['cipher', 'sni', 'midsld']:
                        special_positions.append(pos)
        
        # Warn about TLS-specific special values for non-TLS contexts
        tls_specific = ['cipher', 'sni']
        for special_pos in special_positions:
            if special_pos in tls_specific:
                self.logger.warning(f"Special position '{special_pos}' is TLS-specific. Ensure this strategy is used with TLS traffic.")
        
        # Validate domain-specific special values
        if 'midsld' in special_positions:
            self.logger.warning("Special position 'midsld' requires domain name extraction. Ensure this strategy is used with HTTP/HTTPS traffic.")
        
        # Validate attack type specific parameter requirements
        self._validate_attack_type_specific_requirements(attack_type, params)
    
    def _validate_attack_type_specific_requirements(self, attack_type: str, params: Dict[str, Any]) -> None:
        """Validate attack type specific parameter requirements."""
        
        # Normalize attack type for checking
        normalized_type = attack_type.lower()
        
        # Split-based attacks require position parameters
        split_attacks = ['split', 'simple_split', 'multisplit', 'multi_split']
        if normalized_type in split_attacks:
            if 'split_pos' not in params and 'positions' not in params:
                raise StrategyValidationError(f"Split attack '{attack_type}' requires position parameters ('split_pos' or 'positions')")
        
        # Disorder attacks require position parameters
        disorder_attacks = ['disorder', 'disorder2', 'simple_disorder', 'disorder_ack', 'multidisorder', 'multi_disorder']
        if normalized_type in disorder_attacks:
            if 'split_pos' not in params and 'positions' not in params:
                raise StrategyValidationError(f"Disorder attack '{attack_type}' requires position parameters ('split_pos' or 'positions')")
        
        # Fake attacks require TTL or fake-related parameters
        fake_attacks = ['fake', 'fake_race', 'race', 'fakeddisorder', 'fake_disorder', 'fakedisorder']
        if normalized_type in fake_attacks:
            has_ttl = 'ttl' in params or 'fake_ttl' in params
            has_fake_params = any(param in params for param in ['fake_tls', 'fake_http', 'fake_syndata', 'fake_sni', 'fake_data'])
            
            if not has_ttl and not has_fake_params:
                # For fake attacks, we need at least TTL
                if normalized_type in ['fake', 'fake_race', 'race']:
                    raise StrategyValidationError(f"Fake attack '{attack_type}' requires 'ttl' parameter")
                else:
                    # For fakeddisorder, TTL is optional but recommended
                    self.logger.warning(f"Fake attack '{attack_type}' should have 'ttl' or fake packet parameters for optimal effectiveness")
        
        # Overlap attacks require specific parameters
        overlap_attacks = ['seqovl', 'seq_overlap', 'overlap']
        if normalized_type in overlap_attacks:
            required_params = ['split_pos', 'overlap_size']
            missing_params = [param for param in required_params if param not in params]
            if missing_params:
                raise StrategyValidationError(f"Overlap attack '{attack_type}' missing required parameters: {missing_params}")
    
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
    
    def get_attack_metadata(self, attack_type: str) -> Optional[Any]:
        """
        Get attack metadata from AttackRegistry.
        
        Args:
            attack_type: Type of attack
            
        Returns:
            AttackMetadata object or None if not found
        """
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            return registry.get_attack_metadata(attack_type)
        except Exception as e:
            self.logger.warning(f"Failed to get metadata for attack '{attack_type}': {e}")
            return None
    
    def list_available_attacks(self, category: Optional[str] = None) -> List[str]:
        """
        List all available attacks from AttackRegistry.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of attack types
        """
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            return registry.list_attacks(category)
        except Exception as e:
            self.logger.warning(f"Failed to list attacks: {e}")
            # Fall back to known_attacks
            if category is None:
                return list(self.known_attacks)
            else:
                # Can't filter by category without registry
                return []
    
    def get_attack_aliases(self, attack_type: str) -> List[str]:
        """
        Get all aliases for an attack type.
        
        Args:
            attack_type: Type of attack
            
        Returns:
            List of aliases
        """
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            return registry.get_attack_aliases(attack_type)
        except Exception as e:
            self.logger.warning(f"Failed to get aliases for attack '{attack_type}': {e}")
            return []
    
    def validate_attack_parameters(self, attack_type: str, params: Dict[str, Any]) -> bool:
        """
        Validate parameters for a specific attack type using AttackRegistry.
        
        Args:
            attack_type: Type of attack
            params: Parameters to validate
            
        Returns:
            True if valid, raises StrategyValidationError if not
        """
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            validation_result = registry.validate_parameters(attack_type, params)
            
            if not validation_result.is_valid:
                raise StrategyValidationError(f"Parameter validation failed for '{attack_type}': {validation_result.error_message}")
            
            # Log warnings
            if validation_result.has_warnings():
                for warning in validation_result.warnings:
                    self.logger.warning(f"Parameter validation warning for '{attack_type}': {warning}")
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Failed to validate parameters for attack '{attack_type}': {e}")
            # Fall back to legacy validation
            return self._legacy_validate_attack_parameters(attack_type, params)
    
    def _legacy_validate_attack_parameters(self, attack_type: str, params: Dict[str, Any]) -> bool:
        """Legacy parameter validation for backward compatibility."""
        if attack_type not in self.known_attacks:
            raise StrategyValidationError(f"Unknown attack type: {attack_type}")
        
        required = self.required_params.get(attack_type, [])
        missing = [param for param in required if param not in params]
        if missing:
            raise StrategyValidationError(f"Attack '{attack_type}' missing required parameters: {missing}")
        
        return True
    
    def is_attack_supported(self, attack_type: str) -> bool:
        """
        Check if an attack type is supported.
        
        Args:
            attack_type: Type of attack to check
            
        Returns:
            True if supported, False otherwise
        """
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            # Check if attack is registered in AttackRegistry
            metadata = registry.get_attack_metadata(attack_type)
            return metadata is not None
            
        except Exception as e:
            self.logger.warning(f"Failed to check attack support for '{attack_type}': {e}")
            # Fall back to known_attacks check
            return attack_type in self.known_attacks
    
    def get_attack_handler(self, attack_type: str) -> Optional[Any]:
        """
        Get attack handler from AttackRegistry.
        
        Args:
            attack_type: Type of attack
            
        Returns:
            Attack handler function or None if not found
        """
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            return registry.get_attack_handler(attack_type)
        except Exception as e:
            self.logger.warning(f"Failed to get handler for attack '{attack_type}': {e}")
            return None
    
    def refresh_registry_integration(self) -> bool:
        """
        Refresh the integration with AttackRegistry.
        
        This method can be called to re-sync with AttackRegistry
        if new attacks have been registered.
        
        Returns:
            True if refresh was successful, False otherwise
        """
        try:
            # Clear cached registry reference
            self._attack_registry = None
            
            # Re-enhance with registry data
            self._enhance_with_registry()
            
            if self.debug:
                self.logger.debug("Successfully refreshed AttackRegistry integration")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to refresh AttackRegistry integration: {e}")
            return False
    
    def get_registry_status(self) -> Dict[str, Any]:
        """
        Get status information about AttackRegistry integration.
        
        Returns:
            Dictionary with status information
        """
        status = {
            'registry_available': False,
            'registry_attacks_count': 0,
            'known_attacks_count': len(self.known_attacks),
            'required_params_count': len(self.required_params),
            'integration_active': False
        }
        
        try:
            registry = getattr(self, '_attack_registry', None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            if registry:
                status['registry_available'] = True
                status['registry_attacks_count'] = len(registry.list_attacks())
                status['integration_active'] = True
                
        except Exception as e:
            self.logger.warning(f"Failed to get registry status: {e}")
        
        return status


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