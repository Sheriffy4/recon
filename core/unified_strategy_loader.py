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
    attacks: List[str] = None  # Complete attack sequence for combination attacks
    no_fallbacks: bool = True
    forced: bool = True
    raw_string: str = ""
    source_format: str = ""

    def __post_init__(self):
        """Initialize attacks field if not provided."""
        if self.attacks is None:
            # Default to single attack based on type
            self.attacks = [self.type]

    def to_engine_format(self) -> Dict[str, Any]:
        """Convert to format expected by BypassEngine."""
        return {
            "type": self.type,
            "params": self.params,
            "attacks": self.attacks,
            "no_fallbacks": self.no_fallbacks,
            "forced": self.forced,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return asdict(self)


class UnifiedStrategyLoader:
    """
    Unified strategy loader for all modes.
    """

    def __init__(self, debug: bool = False, validator=None):
        self.logger = logging.getLogger(__name__)
        self.debug = debug
        self._attack_registry = None
        self._validator = validator

        # Initialize with comprehensive known attacks from AttackRegistry
        self.known_attacks = {
            # Combination attack types - these are categories, not specific attacks
            "combo",
            "adaptive_combo",
            "dpi_response_adaptive",
            "multi_layer_combo",
            "steganography_combo",
            "tcp_http_combo",
            # Core attack types from AttackRegistry
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "disorder2",
            "multisplit",
            "split",
            "fake",
            # Aliases from AttackRegistry
            "fake_disorder",
            "fakedisorder",
            "seq_overlap",
            "overlap",
            "multi_disorder",
            "simple_disorder",
            "disorder_ack",
            "multi_split",
            "simple_split",
            "fake_race",
            "race",
            # Legacy compatibility types
            "fragment-tls",
            "fake-sni-random",
            "tls13-only",
            # Additional common variations
            "fake_packet_race",
            "sequence_overlap",
            "packet_split",
            "packet_disorder",
            "multi_packet_split",
        }

        self.required_params = {
            # Core attack types with their required parameters (matching AttackRegistry)
            "fakeddisorder": ["split_pos"],
            "seqovl": ["split_pos", "overlap_size"],
            "multidisorder": [],  # No required params, handler will handle defaults
            "disorder": [],  # No required params, handler will handle defaults for split_pos
            "disorder2": [],  # No required params, handler will handle defaults for split_pos
            "multisplit": [],  # No required params, handler will handle defaults for positions
            "split": ["split_pos"],
            "fake": ["ttl"],
            # Aliases mapping to same requirements as main types (from AttackRegistry)
            "fake_disorder": ["split_pos"],  # alias for fakeddisorder
            "fakedisorder": ["split_pos"],  # alias for fakeddisorder
            "seq_overlap": ["split_pos", "overlap_size"],  # alias for seqovl
            "overlap": ["split_pos", "overlap_size"],  # alias for seqovl
            "multi_disorder": [],  # alias for multidisorder
            "simple_disorder": [],  # alias for disorder,  # alias for disorder
            "disorder_ack": [],  # alias for disorder2,  # alias for disorder2
            "multi_split": [],  # alias for multisplit,  # alias for multisplit
            "simple_split": ["split_pos"],  # alias for split
            "fake_race": ["ttl"],  # alias for fake
            "race": ["ttl"],  # alias for fake
            # Legacy compatibility types
            "fragment-tls": [],
            "fake-sni-random": [],
            "tls13-only": [],
            # Additional variations for backward compatibility
            "fake_packet_race": ["ttl"],
            "sequence_overlap": ["split_pos", "overlap_size"],
            "packet_split": ["split_pos"],
            "packet_disorder": [],
            "multi_packet_split": [],
            # Combination attack types
            "combo": [],  # Combo attacks have flexible parameters
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
            legacy_attacks = {"fragment-tls", "fake-sni-random", "tls13-only", "combo"}

            # Reset to only legacy attacks
            self.known_attacks = legacy_attacks.copy()
            legacy_required_params = {
                "fragment-tls": [],
                "fake-sni-random": [],
                "tls13-only": [],
                "combo": [],  # Combo attacks have flexible parameters
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
                    
                # Special handling for combo attacks - they have flexible parameters
                if "combo" in attack_type or attack_type.endswith("_combo"):
                    self.required_params[attack_type] = []  # No required params for combo attacks

            # Add legacy required params back
            self.required_params.update(legacy_required_params)

            # Store registry reference for later use
            self._attack_registry = registry

            if self.debug:
                self.logger.debug(
                    f"Enhanced with {len(registered_attacks)} attacks from AttackRegistry"
                )
                self.logger.debug(f"Total known attacks: {len(self.known_attacks)}")
                self.logger.debug(
                    f"Total required params entries: {len(self.required_params)}"
                )

        except Exception as e:
            self.logger.warning(f"Failed to enhance with AttackRegistry: {e}")
            # Continue with basic configuration - restore original hardcoded values
            self._attack_registry = None
            self._restore_hardcoded_attacks()

    def _restore_hardcoded_attacks(self):
        """Restore hardcoded attack definitions as fallback."""
        self.known_attacks = {
            # Combination attack types
            "combo",
            # Core attack types from AttackRegistry
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "disorder2",
            "multisplit",
            "split",
            "fake",
            # Aliases from AttackRegistry
            "fake_disorder",
            "fakedisorder",
            "seq_overlap",
            "overlap",
            "multi_disorder",
            "simple_disorder",
            "disorder_ack",
            "multi_split",
            "simple_split",
            "fake_race",
            "race",
            # Legacy compatibility types
            "fragment-tls",
            "fake-sni-random",
            "tls13-only",
            # Additional common variations
            "fake_packet_race",
            "sequence_overlap",
            "packet_split",
            "packet_disorder",
            "multi_packet_split",
        }

        self.required_params = {
            # Core attack types with their required parameters (matching AttackRegistry)
            "fakeddisorder": ["split_pos"],
            "seqovl": ["split_pos", "overlap_size"],
            "multidisorder": [],  # No required params, handler will handle defaults
            "disorder": [],  # No required params, handler will handle defaults for split_pos
            "disorder2": [],  # No required params, handler will handle defaults for split_pos
            "multisplit": [],  # No required params, handler will handle defaults for positions
            "split": ["split_pos"],
            "fake": ["ttl"],
            # Aliases mapping to same requirements as main types (from AttackRegistry)
            "fake_disorder": ["split_pos"],  # alias for fakeddisorder
            "fakedisorder": ["split_pos"],  # alias for fakeddisorder
            "seq_overlap": ["split_pos", "overlap_size"],  # alias for seqovl
            "overlap": ["split_pos", "overlap_size"],  # alias for seqovl
            "multi_disorder": [],  # alias for multidisorder
            "simple_disorder": [],  # alias for disorder,  # alias for disorder
            "disorder_ack": [],  # alias for disorder2,  # alias for disorder2
            "multi_split": [],  # alias for multisplit,  # alias for multisplit
            "simple_split": ["split_pos"],  # alias for split
            "fake_race": ["ttl"],  # alias for fake
            "race": ["ttl"],  # alias for fake
            # Legacy compatibility types
            "fragment-tls": [],
            "fake-sni-random": [],
            "tls13-only": [],
            # Additional variations for backward compatibility
            "fake_packet_race": ["ttl"],
            "sequence_overlap": ["split_pos", "overlap_size"],
            "packet_split": ["split_pos"],
            "packet_disorder": [],
            "multi_packet_split": [],
            # Combination attack types
            "combo": [],  # Combo attacks have flexible parameters
        }

    def _normalize_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize parameters to consistent format."""
        normalized = params.copy()

        if "fake_sni" in normalized and isinstance(normalized["fake_sni"], list):
            if len(normalized["fake_sni"]) >= 1:
                normalized["fake_sni"] = normalized["fake_sni"][0]
            else:
                del normalized["fake_sni"]

        if "fooling" in normalized and "fooling_methods" in normalized:
            # Объединяем оба списка, убираем дубликаты
            fooling = normalized.get("fooling", [])
            fooling_methods = normalized.get("fooling_methods", [])
            
            if not isinstance(fooling, list):
                fooling = [fooling] if fooling else []
            if not isinstance(fooling_methods, list):
                fooling_methods = [fooling_methods] if fooling_methods else []
            
            # Объединяем и убираем дубликаты
            combined = list(dict.fromkeys(fooling + fooling_methods))
            
            # Фильтруем None
            combined = [f for f in combined if f and str(f).lower() not in ("none", "null", "")]
            
            if combined:
                normalized["fooling"] = combined
                del normalized["fooling_methods"]  # Оставляем только fooling
                self.logger.debug(f"Unified fooling: {combined}")
            else:
                # Оба пустые
                if "fooling" in normalized:
                    del normalized["fooling"]
                if "fooling_methods" in normalized:
                    del normalized["fooling_methods"]
        
        # Остальная нормализация fooling
        if "fooling" in normalized:
            fooling_val = normalized["fooling"]
            fooling_list = []
            if isinstance(fooling_val, str):
                # Игнорируем 'None' и 'none' как строки
                if fooling_val.lower() not in ("none", "null", ""):
                    fooling_list = [
                        f.strip()
                        for f in fooling_val.split(",")
                        if f.strip() and f.strip().lower() not in ("none", "null")
                    ]
            elif isinstance(fooling_val, list):
                # Фильтруем None и 'None' из списка
                fooling_list = [
                    str(f).strip()
                    for f in fooling_val
                    if f is not None
                    and str(f).strip().lower() not in ("none", "null", "")
                ]
            elif fooling_val is not None:
                # Только если это не None и не строка 'None'
                val_str = str(fooling_val).strip().lower()
                if val_str not in ("none", "null", ""):
                    fooling_list = [str(fooling_val)]

            if fooling_list:
                normalized["fooling"] = list(dict.fromkeys(fooling_list))
            else:
                del normalized["fooling"]

        return normalized

    def _normalize_params_with_registry(
        self, attack_type: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize parameters using AttackRegistry metadata."""
        try:
            # Use stored registry reference if available, otherwise get it
            registry = getattr(self, "_attack_registry", None)
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
                        # Специальная логика для fooling/fooling_methods - не добавляем дубликаты
                        if param_name == "fooling_methods" and "fooling" in normalized:
                            continue  # Пропускаем fooling_methods если уже есть fooling
                        if param_name == "fooling" and "fooling_methods" in normalized:
                            continue  # Пропускаем fooling если уже есть fooling_methods
                        normalized[param_name] = default_value

                # Apply attack-specific transformations BEFORE special parameter normalization
                normalized = self._apply_attack_specific_transformations(
                    attack_type, normalized
                )

                # Normalize special parameters
                normalized = self._normalize_special_parameters(normalized)

                return normalized
            else:
                # Fall back to basic normalization if no metadata found
                normalized = self._normalize_params(params)
                normalized = self._apply_attack_specific_transformations(
                    attack_type, normalized
                )
                return self._normalize_special_parameters(normalized)

        except Exception as e:
            self.logger.warning(
                f"Failed to normalize params with registry for {attack_type}: {e}"
            )
            normalized = self._normalize_params(params)
            normalized = self._apply_attack_specific_transformations(
                attack_type, normalized
            )
            return self._normalize_special_parameters(normalized)

    def _apply_attack_specific_transformations(
        self, attack_type: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply attack-specific parameter transformations."""
        params = params.copy()

        # ✅ ИСПРАВЛЕНИЕ: Генерируем positions если он None или отсутствует
        if attack_type == "multisplit":
            # Если positions None или отсутствует, генерируем из split_count/split_pos
            if params.get("positions") is None or "positions" not in params:
                split_count = params.get("split_count", 3)
                split_pos = params.get("split_pos", 1)

                if isinstance(split_pos, int):
                    positions = []
                    base_pos = split_pos
                    gap = max(6, split_pos * 2)

                    for i in range(split_count):
                        positions.append(base_pos + (i * gap))

                    params["positions"] = positions
                    self.logger.debug(
                        f"Generated positions {positions} from split_count={split_count}, split_pos={split_pos}"
                    )
                # Если split_pos не int (например, 'sni'), оставляем split_count
        
        # ✅ ИСПРАВЛЕНИЕ: Аналогично для multidisorder
        if attack_type == "multidisorder":
            if params.get("positions") is None or "positions" not in params:
                split_pos = params.get("split_pos")
                split_count = params.get("split_count")
                
                if isinstance(split_pos, int):
                    # Use split_count if provided
                    if split_count and isinstance(split_count, int) and split_count > 1:
                        gap = 5  # Smaller gap for multidisorder
                        positions = [split_pos + (i * gap) for i in range(split_count)]
                    else:
                        # Fallback: create 3 positions
                        positions = [split_pos, split_pos + 5, split_pos + 10]
                    params["positions"] = positions
                    self.logger.debug(
                        f"Generated positions {positions} from split_pos={split_pos}, split_count={split_count} for multidisorder"
                    )

        return params

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
        if "split_pos" in normalized and normalized["split_pos"] is not None:
            split_pos = normalized["split_pos"]

            if isinstance(split_pos, str):
                # Normalize case and whitespace
                normalized_value = split_pos.lower().strip()
                if normalized_value in SpecialParameterValues.ALL:
                    normalized["split_pos"] = normalized_value
                else:
                    # Try to convert to int if it's not a special value
                    try:
                        normalized["split_pos"] = int(split_pos)
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
                normalized["split_pos"] = normalized_positions

        # Normalize positions special values
        if "positions" in normalized and normalized["positions"] is not None:
            positions = normalized["positions"]

            # Handle string format (comma-separated values)
            if isinstance(positions, str):
                try:
                    # Convert comma-separated string to list
                    positions = [
                        pos.strip() for pos in positions.split(",") if pos.strip()
                    ]
                    normalized["positions"] = positions
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
                normalized["positions"] = normalized_positions

        # Normalize TTL parameters
        ttl_params = ["ttl", "fake_ttl"]
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
        boolean_params = ["ack_first", "fake_tls", "fake_http", "fake_syndata"]
        for bool_param in boolean_params:
            if bool_param in normalized and normalized[bool_param] is not None:
                bool_value = normalized[bool_param]
                if isinstance(bool_value, str):
                    lower_value = bool_value.lower().strip()
                    if lower_value in ("true", "1", "yes", "on"):
                        normalized[bool_param] = True
                    elif lower_value in ("false", "0", "no", "off"):
                        normalized[bool_param] = False
                elif isinstance(bool_value, int):
                    normalized[bool_param] = bool(bool_value)

        # Normalize integer parameters
        int_params = ["overlap_size", "repeats", "autottl", "badseq_increment"]
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
        fooling_params = ["fooling", "fooling_methods"]
        for fooling_param in fooling_params:
            if fooling_param in normalized and normalized[fooling_param] is not None:
                fooling_value = normalized[fooling_param]
                if isinstance(fooling_value, str):
                    # Split comma-separated values
                    fooling_list = [
                        method.strip().lower()
                        for method in fooling_value.split(",")
                        if method.strip()
                    ]
                    normalized[fooling_param] = fooling_list
                elif isinstance(fooling_value, list):
                    # Normalize each method in the list
                    normalized[fooling_param] = [
                        str(method).strip().lower()
                        for method in fooling_value
                        if str(method).strip()
                    ]

        return normalized

    def _sanitize_strategy_name(self, name: str) -> str:
        """
        Remove 'existing_' prefix from strategy name.
        
        This is a defensive measure to prevent corrupted strategy names
        from causing errors in the attack dispatcher.
        """
        if isinstance(name, str):
            # Keep removing 'existing_' prefix until there are no more
            while name.startswith('existing_'):
                name = name.replace('existing_', '', 1)
                if self.debug:
                    self.logger.warning(f"Removed 'existing_' prefix from strategy name: {name}")
        return name

    def load_strategy(
        self, strategy_input: Union[str, Dict[str, Any]]
    ) -> NormalizedStrategy:
        """Load and normalize a strategy from various input formats."""
        try:
            # Sanitize strategy input to remove 'existing_' prefix
            if isinstance(strategy_input, str):
                strategy_input = self._sanitize_strategy_name(strategy_input)
            elif isinstance(strategy_input, dict):
                # Sanitize all strategy name fields
                if 'type' in strategy_input:
                    strategy_input['type'] = self._sanitize_strategy_name(strategy_input['type'])
                if 'attack_name' in strategy_input:
                    strategy_input['attack_name'] = self._sanitize_strategy_name(strategy_input['attack_name'])
                if 'attack_type' in strategy_input:
                    strategy_input['attack_type'] = self._sanitize_strategy_name(strategy_input['attack_type'])
                if 'strategy_name' in strategy_input:
                    strategy_input['strategy_name'] = self._sanitize_strategy_name(strategy_input['strategy_name'])
                if 'attacks' in strategy_input and isinstance(strategy_input['attacks'], list):
                    strategy_input['attacks'] = [
                        self._sanitize_strategy_name(a) if isinstance(a, str) else a
                        for a in strategy_input['attacks']
                    ]
            
            if isinstance(strategy_input, dict):
                strategy = self._load_from_dict(strategy_input)
            elif isinstance(strategy_input, str):
                strategy = self._load_from_string(strategy_input)
            else:
                raise StrategyLoadError(
                    f"Unsupported strategy input type: {type(strategy_input)}"
                )

            self.validate_strategy(strategy)
            return strategy

        except (StrategyLoadError, StrategyValidationError) as e:
            self.logger.error(f"Failed to load and validate strategy: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during strategy loading: {e}")
            raise StrategyLoadError(f"Strategy loading failed unexpectedly: {e}") from e

    def _load_from_string(self, strategy_string: str) -> NormalizedStrategy:
        strategy_string = strategy_string.strip()
        if not strategy_string:
            raise StrategyLoadError("Empty strategy string")

        if self._is_zapret_style(strategy_string):
            return self._parse_zapret_style(strategy_string)
        elif self._is_function_style(strategy_string):
            return self._parse_function_style(strategy_string)
        elif self._is_colon_style(strategy_string):
            return self._parse_colon_style(strategy_string)
        elif strategy_string.startswith("--"):
            return self._parse_generic_cli_style(strategy_string)
        elif self._is_semicolon_combo_style(strategy_string):
            return self._parse_semicolon_combo_style(strategy_string)
        elif self._is_simple_attack_name(strategy_string):
            # Простое имя атаки без параметров (например, "smart_combo_split_fake")
            return self._parse_simple_attack_name(strategy_string)
        else:
            raise StrategyLoadError(f"Unknown strategy format: {strategy_string}")

    def _is_semicolon_combo_style(self, s: str) -> bool:
        # Формат: "attack1,attack2; k=v; k=v" ИЛИ "attack; k=v"
        if "--" in s or ":" in s or "(" in s or ")" in s:
            return False
        if ";" not in s:
            return False
        head = s.split(";", 1)[0].strip()
        # head — список атак через запятую или одиночная атака без '='
        return head and "=" not in head

    def _is_simple_attack_name(self, s: str) -> bool:
        """Check if string is a simple attack name without parameters."""
        # Простое имя: только буквы, цифры, подчеркивания
        # Без специальных символов: --:;=(),
        if any(char in s for char in ["--", ":", ";", "=", "(", ")", ","]):
            return False
        # Должно содержать только допустимые символы
        return s.replace("_", "").replace("-", "").isalnum()

    def _parse_simple_attack_name(self, strategy_string: str) -> NormalizedStrategy:
        """Parse simple attack name without parameters."""
        attack_type = strategy_string.lower().strip()
        
        # Проверяем, является ли это smart_combo стратегией
        if attack_type.startswith("smart_combo_"):
            # Извлекаем атаки из имени: smart_combo_split_fake -> [split, fake]
            parts = attack_type.replace("smart_combo_", "").split("_")
            attacks = []
            
            # Распознаем известные атаки
            known_attack_names = {
                "fake", "split", "disorder", "disorder2", "multidisorder",
                "multisplit", "seqovl", "ttl", "badseq", "badsum",
                "fakeddisorder", "overlap"
            }
            
            for part in parts:
                if part in known_attack_names:
                    attacks.append(part)
            
            if not attacks:
                # Если не смогли распознать, используем все части
                attacks = parts
            
            if self.debug:
                self.logger.debug(f"Parsed smart_combo: {attack_type} -> attacks={attacks}")
        else:
            # Для обычных атак используем имя как тип и как единственную атаку
            attacks = [attack_type]
        
        # Получаем параметры по умолчанию из реестра для каждой атаки
        params = {}
        try:
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry
                registry = get_attack_registry()
            
            # Собираем параметры по умолчанию для всех атак в комбинации
            for attack in attacks:
                metadata = registry.get_attack_metadata(attack)
                if metadata:
                    # Объединяем параметры, не перезаписывая существующие
                    for param_name, default_value in metadata.optional_params.items():
                        if param_name not in params:
                            params[param_name] = default_value
            
            if self.debug and params:
                self.logger.debug(
                    f"Using default params from registry for {attack_type}: {params}"
                )
        except Exception as e:
            if self.debug:
                self.logger.debug(f"Could not get default params for {attack_type}: {e}")
        
        return NormalizedStrategy(
            type=attack_type,
            attacks=attacks,
            params=params,
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format="simple_name",
        )

    def _parse_semicolon_combo_style(self, strategy_string: str) -> NormalizedStrategy:
        # Пример: "fake,split; ttl=1; fooling=badseq; split_pos=3; split_count=2"
        parts = [p.strip() for p in strategy_string.split(";") if p.strip()]
        head = parts[0]
        attacks = [a.strip().lower() for a in head.split(",") if a.strip()]

        params: Dict[str, Any] = {}
        for token in parts[1:] if "=" not in head else parts:
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            params[k.strip().replace("-", "_")] = self._parse_value(v.strip())

        # Выбор attack_type из комбинации (исправленная логика)
        disorder_variants = {"disorder", "disorder2", "multidisorder", "fakeddisorder"}
        att_set = set(attacks)

        # Проверяем комбинации в правильном порядке приоритета
        if "multisplit" in att_set:
            attack_type = "multisplit"
        elif "fake" in att_set and (att_set & disorder_variants):
            # Комбинация fake + disorder (с или без split) -> fakeddisorder
            # fakeddisorder может обрабатывать split через параметры split_pos/split_count
            attack_type = "fakeddisorder"
        elif "split" in att_set and ("split_count" in params or "positions" in params):
            # Если есть split_count/positions, но это не явный multisplit, остается split
            attack_type = "split"
        elif "multidisorder" in att_set:
            attack_type = "multidisorder"
        elif att_set & {"seqovl", "seq_overlap", "overlap"}:
            attack_type = "seqovl"
        elif "disorder2" in att_set:
            attack_type = "disorder2"
        elif "disorder" in att_set:
            attack_type = "disorder"
        elif "split" in att_set:
            attack_type = "split"
        elif "fake" in att_set:
            attack_type = "fake"
        else:
            # Фолбэк на первый атаковый токен
            attack_type = attacks[0] if attacks else "fake"

        normalized_params = self._normalize_params_with_registry(attack_type, params)

        # CRITICAL FIX: Include ALL attacks for combination strategies
        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            attacks=attacks,  # CRITICAL: Include all attacks, not just type
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format="semicolon_combo",
        )
    
    def _parse_generic_cli_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parses generic --key=value style strategies."""
        parts = strategy_string.split()
        
        # Handle --attack=<attack_type> format specifically
        first_part = parts[0].lstrip("-")
        if first_part.startswith("attack="):
            attack_type = first_part[7:]  # Remove "attack=" prefix
        else:
            attack_type = first_part
            
        params = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.lstrip("-").split("=", 1)
                params[key.replace("-", "_")] = self._parse_value(value)
            else:
                params[part.lstrip("-").replace("-", "_")] = True

        return NormalizedStrategy(
            type=attack_type,
            params=self._normalize_params(params),
            attacks=[attack_type],  # Single attack for generic CLI style
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format="generic_cli",
        )

    def _load_from_dict(self, strategy_dict: Dict[str, Any]) -> NormalizedStrategy:
        """Load strategy from dictionary format."""
        if "type" not in strategy_dict:
            raise StrategyLoadError("Strategy dict missing 'type' field")

        attack_type = strategy_dict["type"]
        params = strategy_dict.get("params", {})
        
        # DEBUG: Log incoming params
        if self.debug:
            self.logger.debug(f"📥 _load_from_dict: type={attack_type}, incoming params={params}")
        
        # Extract attacks field from strategy dictionary
        attacks = strategy_dict.get("attacks", [])
        
        # ИСПРАВЛЕНИЕ: Если это smart_combo стратегия, парсим её через _parse_simple_attack_name
        if attack_type.startswith("smart_combo_") and (not attacks or attacks == [attack_type]) and not params:
            if self.debug:
                self.logger.debug(f"📋 Detected smart_combo without params, parsing: {attack_type}")
            # Используем парсер для извлечения атак и параметров
            parsed = self._parse_simple_attack_name(attack_type)
            attacks = parsed.attacks
            params = parsed.params
            if self.debug:
                self.logger.debug(f"📋 Parsed smart_combo: attacks={attacks}, params={params}")
        elif not attacks:
            # Fall back to single attack if attacks field missing (backward compatibility)
            attacks = [attack_type]
            if self.debug:
                self.logger.debug(
                    f"Strategy for {attack_type} missing 'attacks' field, "
                    f"assuming single attack"
                )
        
        # Log the loaded attack combination
        if self.debug:
            self.logger.debug(
                f"Loading strategy: type={attack_type}, attacks={attacks}"
            )
        
        # Validate attack combination before normalizing parameters
        self._validate_attack_combination(attacks, params)
        
        normalized_params = self._normalize_params_with_registry(
            attack_type, params
        )
        
        # DEBUG: Log normalized params
        if self.debug:
            self.logger.debug(f"📤 _load_from_dict: type={attack_type}, normalized params={normalized_params}")

        return NormalizedStrategy(
            type=attack_type,
            attacks=attacks,
            params=normalized_params,
            no_fallbacks=True,
            forced=True,
            raw_string=str(strategy_dict),
            source_format="dict",
        )

    def _validate_attack_combination(
        self, attacks: List[str], params: Dict[str, Any]
    ) -> None:
        """
        Validate that attack combination is complete and consistent.
        
        This method ensures that attack combinations have all required parameters
        and logs comprehensive warnings for missing or invalid configurations.
        
        Args:
            attacks: List of attack types in the combination
            params: Strategy parameters
            
        Raises:
            StrategyValidationError: If validation fails critically
        """
        if not attacks:
            self.logger.error("❌ Validation failed: Empty attacks list")
            raise StrategyValidationError("Empty attacks list")
        
        validation_warnings = []
        validation_errors = []
        
        # Check each attack is known/registered
        unknown_attacks = []
        for attack in attacks:
            # Skip validation for combo attack names (e.g., "smart_combo_fake_multisplit_disorder")
            # These are dynamically generated strategy names, not individual attack types
            if "combo" in attack.lower() and "_" in attack:
                continue
            
            if attack not in self.known_attacks:
                unknown_attacks.append(attack)
        
        if unknown_attacks:
            # Log warning but don't fail - might be a new attack type
            warning_msg = (
                f"Unknown attack type(s) in combination: {unknown_attacks}. "
                f"Known attacks include: {sorted(list(self.known_attacks)[:10])}..."
            )
            validation_warnings.append(warning_msg)
            self.logger.warning(f"⚠️ {warning_msg}")
        
        # Check combination-specific parameter requirements
        
        # Validate disorder combinations have disorder_method
        disorder_variants = ["disorder", "disorder2", "multidisorder", "fakeddisorder"]
        has_disorder = any(variant in attacks for variant in disorder_variants)
        
        if has_disorder:
            if "disorder_method" not in params:
                # Set default disorder_method to 'reverse'
                params["disorder_method"] = "reverse"
                warning_msg = (
                    f"Disorder attack ({[a for a in attacks if a in disorder_variants]}) "
                    "in combination but 'disorder_method' parameter missing. "
                    "Defaulting to 'reverse'. Expected values: 'reverse', 'random'."
                )
                validation_warnings.append(warning_msg)
                self.logger.warning(f"⚠️ {warning_msg}")
            else:
                # Validate disorder_method value
                disorder_method = params["disorder_method"]
                valid_methods = ["reverse", "random"]
                if disorder_method not in valid_methods:
                    warning_msg = (
                        f"Invalid disorder_method '{disorder_method}'. "
                        f"Valid values: {valid_methods}"
                    )
                    validation_warnings.append(warning_msg)
                    self.logger.warning(f"⚠️ {warning_msg}")
                else:
                    if self.debug:
                        self.logger.debug(
                            f"✅ Disorder attack validated with method: {disorder_method}"
                        )
        
        # Validate multisplit combinations have split_count or positions
        if "multisplit" in attacks:
            has_split_count = "split_count" in params and params["split_count"] is not None
            has_positions = "positions" in params and params["positions"] is not None
            has_split_pos = "split_pos" in params and params["split_pos"] is not None
            
            if not has_split_count and not has_positions and not has_split_pos:
                warning_msg = (
                    "Multisplit attack missing required parameters. "
                    "Expected: 'split_count' (int), 'positions' (list of ints), or 'split_pos' (int). "
                    "Attack handler will use defaults which may not be optimal."
                )
                validation_warnings.append(warning_msg)
                self.logger.warning(f"⚠️ {warning_msg}")
            else:
                # Validate parameter values
                if has_split_count:
                    split_count = params["split_count"]
                    if not isinstance(split_count, int) or split_count < 2:
                        warning_msg = (
                            f"Invalid split_count value: {split_count}. "
                            "Expected: integer >= 2"
                        )
                        validation_warnings.append(warning_msg)
                        self.logger.warning(f"⚠️ {warning_msg}")
                    elif self.debug:
                        self.logger.debug(
                            f"✅ Multisplit validated with split_count: {split_count}"
                        )
                
                if has_positions:
                    positions = params["positions"]
                    if not isinstance(positions, list) or len(positions) < 2:
                        warning_msg = (
                            f"Invalid positions value: {positions}. "
                            "Expected: list with at least 2 positions"
                        )
                        validation_warnings.append(warning_msg)
                        self.logger.warning(f"⚠️ {warning_msg}")
                    elif self.debug:
                        self.logger.debug(
                            f"✅ Multisplit validated with positions: {positions}"
                        )
        
        # Validate fake attack has ttl parameter
        if "fake" in attacks or "fakeddisorder" in attacks:
            has_ttl = "ttl" in params and params["ttl"] is not None
            has_fake_ttl = "fake_ttl" in params and params["fake_ttl"] is not None
            has_autottl = "autottl" in params and params["autottl"] is not None
            
            if not has_ttl and not has_fake_ttl and not has_autottl:
                warning_msg = (
                    f"Fake attack ({[a for a in attacks if 'fake' in a]}) "
                    "in combination but no TTL parameter found. "
                    "Expected: 'ttl' (1-255), 'fake_ttl' (1-255), or 'autottl' (-10 to 10). "
                    "Attack handler will use default TTL which may not be optimal."
                )
                validation_warnings.append(warning_msg)
                self.logger.warning(f"⚠️ {warning_msg}")
            else:
                # Validate TTL values
                if has_ttl:
                    ttl = params["ttl"]
                    if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                        warning_msg = f"Invalid ttl value: {ttl}. Expected: integer 1-255"
                        validation_warnings.append(warning_msg)
                        self.logger.warning(f"⚠️ {warning_msg}")
                    elif self.debug:
                        self.logger.debug(f"✅ Fake attack validated with ttl: {ttl}")
                
                if has_autottl:
                    autottl = params["autottl"]
                    if not isinstance(autottl, int) or not (-10 <= autottl <= 10):
                        warning_msg = (
                            f"Invalid autottl value: {autottl}. Expected: integer -10 to 10"
                        )
                        validation_warnings.append(warning_msg)
                        self.logger.warning(f"⚠️ {warning_msg}")
                    elif self.debug:
                        self.logger.debug(f"✅ Fake attack validated with autottl: {autottl}")
        
        # Validate seqovl attack has required parameters
        seqovl_variants = ["seqovl", "seq_overlap", "overlap"]
        has_seqovl = any(variant in attacks for variant in seqovl_variants)
        
        if has_seqovl:
            missing_params = []
            
            if "overlap_size" not in params or params["overlap_size"] is None:
                missing_params.append("overlap_size (int, bytes to overlap)")
            
            if "split_pos" not in params or params["split_pos"] is None:
                missing_params.append("split_pos (int or 'sni'/'cipher'/'midsld')")
            
            if missing_params:
                warning_msg = (
                    f"Sequence overlap attack ({[a for a in attacks if a in seqovl_variants]}) "
                    f"missing required parameters: {', '.join(missing_params)}. "
                    "Attack handler will use defaults which may not work correctly."
                )
                validation_warnings.append(warning_msg)
                self.logger.warning(f"⚠️ {warning_msg}")
            else:
                # Validate parameter values
                overlap_size = params["overlap_size"]
                if not isinstance(overlap_size, int) or overlap_size < 1:
                    warning_msg = (
                        f"Invalid overlap_size value: {overlap_size}. Expected: integer >= 1"
                    )
                    validation_warnings.append(warning_msg)
                    self.logger.warning(f"⚠️ {warning_msg}")
                elif self.debug:
                    self.logger.debug(
                        f"✅ Sequence overlap validated with overlap_size: {overlap_size}"
                    )
        
        # Validate split attack has split_pos
        if "split" in attacks:
            if "split_pos" not in params or params["split_pos"] is None:
                warning_msg = (
                    "Split attack missing 'split_pos' parameter. "
                    "Expected: integer >= 1 or special value ('sni', 'cipher', 'midsld'). "
                    "Attack handler will use default."
                )
                validation_warnings.append(warning_msg)
                self.logger.warning(f"⚠️ {warning_msg}")
            elif self.debug:
                self.logger.debug(
                    f"✅ Split attack validated with split_pos: {params['split_pos']}"
                )
        
        # Log validation summary
        if validation_errors:
            error_summary = "; ".join(validation_errors)
            self.logger.error(
                f"❌ Attack combination validation failed: {error_summary}"
            )
            raise StrategyValidationError(
                f"Attack combination validation failed: {error_summary}"
            )
        
        if validation_warnings:
            self.logger.warning(
                f"⚠️ Attack combination validation completed with {len(validation_warnings)} warning(s)"
            )
            if self.debug:
                for i, warning in enumerate(validation_warnings, 1):
                    self.logger.debug(f"  Warning {i}: {warning}")
        else:
            if self.debug:
                self.logger.debug(
                    f"✅ Attack combination validated successfully: {attacks} "
                    f"with {len(params)} parameters"
                )

    def _is_zapret_style(self, strategy: str) -> bool:
        return "--dpi-desync" in strategy

    def _is_function_style(self, strategy: str) -> bool:
        return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*$", strategy))

    def _is_colon_style(self, strategy: str) -> bool:
        """Check if strategy is in colon-separated format: attack:param1=value1,param2=value2"""
        return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*:[^:]+$", strategy))

    def _parse_zapret_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse Zapret command-line style strategy."""
        params = {}
        attack_type = "fakeddisorder"

        desync_match = re.search(r"--dpi-desync=([^\s]+)", strategy_string)
        if desync_match:
            desync_methods = [m.strip() for m in desync_match.group(1).split(",")]

            # FIXED: Check for fake + any disorder variant -> fakeddisorder
            if "fake" in desync_methods:
                # Check for any disorder variant (disorder, disorder2, multidisorder, fakeddisorder)
                disorder_variants = [
                    "disorder",
                    "disorder2",
                    "multidisorder",
                    "fakeddisorder",
                ]
                has_disorder = any(
                    variant in desync_methods for variant in disorder_variants
                )

                if has_disorder:
                    attack_type = "fakeddisorder"
                else:
                    # fake without disorder -> just fake
                    attack_type = "fake"
            else:
                # No fake, use priority order
                priority_order = [
                    "multidisorder",
                    "fakeddisorder",
                    "multisplit",
                    "disorder2",
                    "seqovl",
                    "disorder",
                    "split",
                ]
                found_type = next(
                    (method for method in priority_order if method in desync_methods),
                    None,
                )
                if found_type:
                    attack_type = found_type
                elif desync_methods:
                    attack_type = desync_methods[0]

        split_pos_match = re.search(r"--dpi-desync-split-pos=([^\s]+)", strategy_string)
        if split_pos_match:
            split_pos_str = split_pos_match.group(1)
            special_values = ["midsld", "cipher", "sni"]
            if split_pos_str in special_values:
                params["split_pos"] = split_pos_str
            elif "," in split_pos_str:
                parts = [p.strip() for p in split_pos_str.split(",") if p.strip()]
                parsed_parts = [
                    int(p) if p.isdigit() else p
                    for p in parts
                    if p.isdigit() or p in special_values
                ]
                if parsed_parts:
                    params["split_pos"] = parsed_parts
            else:
                try:
                    params["split_pos"] = int(split_pos_str)
                except ValueError:
                    self.logger.warning(f"Could not parse split-pos: {split_pos_str}")

        # Parse TTL parameters with priority: autottl > ttl
        ttl_match = re.search(r"--dpi-desync-ttl=([-\d]+)", strategy_string)
        autottl_match = re.search(
            r"--dpi-desync-autottl=([-\d]+|midsld)", strategy_string
        )

        if autottl_match:
            # autottl has priority over ttl
            value_str = autottl_match.group(1)
            if value_str == "midsld":
                params["autottl"] = "midsld"
            else:
                try:
                    params["autottl"] = int(value_str)
                except ValueError:
                    self.logger.warning(f"Could not parse autottl: {value_str}")
        elif ttl_match:
            # Only use ttl if autottl is not present
            try:
                params["ttl"] = int(ttl_match.group(1))
            except ValueError:
                self.logger.warning(f"Could not parse ttl: {ttl_match.group(1)}")

        # Parse other integer parameters
        other_int_params = {
            "split-count": "split_count",
            "split-seqovl": "overlap_size",
            "repeats": "repeats",
            "badseq-increment": "badseq_increment",
        }
        for param_name, param_key in other_int_params.items():
            match = re.search(
                rf"--dpi-desync-{param_name}=([-\d]+|midsld)", strategy_string
            )
            if match:
                value_str = match.group(1)
                if value_str == "midsld":
                    params[param_key] = "midsld"
                else:
                    try:
                        params[param_key] = int(value_str)
                    except ValueError:
                        self.logger.warning(
                            f"Could not parse integer for {param_name}: {value_str}"
                        )

        string_params = {"fooling": "fooling", "fake-sni": "fake_sni"}
        for param_name, param_key in string_params.items():
            match = re.search(rf"--dpi-desync-{param_name}=([^\s]+)", strategy_string)
            if match:
                params[param_key] = match.group(1)

        flag_params = {
            "fake-tls": "fake_tls",
            "fake-http": "fake_http",
            "fake-syndata": "fake_syndata",
        }
        for param_name, param_key in flag_params.items():
            match = re.search(
                rf"--dpi-desync-{param_name}(?:=([^\s]+))?", strategy_string
            )
            if match:
                value = match.group(1)
                params[param_key] = (
                    int(value) if value and value.isdigit() else (value or True)
                )

        if "--dpi-desync-autottl" in strategy_string and "autottl" not in params:
            params["autottl"] = 2
        if "repeats" not in params:
            params["repeats"] = 1

        # Handle backward compatibility: convert split_count to positions for multisplit
        if (
            attack_type == "multisplit"
            and "split_count" in params
            and "positions" not in params
        ):
            split_count = params.get("split_count", 3)
            split_pos = params.get("split_pos", 1)

            # Generate positions based on split_count and split_pos
            if isinstance(split_pos, int):
                positions = []
                base_pos = split_pos
                gap = max(6, split_pos * 2)  # Reasonable gap between positions

                for i in range(split_count):
                    positions.append(base_pos + (i * gap))

                params["positions"] = positions
            else:
                # If split_pos is special value, keep split_count for later processing
                pass

        # Handle backward compatibility: convert split_pos to positions for multidisorder if needed
        if (
            attack_type == "multidisorder"
            and "split_pos" in params
            and "positions" not in params
        ):
            split_pos = params.get("split_pos")
            if isinstance(split_pos, int):
                # For multidisorder, create multiple positions around the split_pos
                positions = [split_pos, split_pos + 5, split_pos + 10]
                params["positions"] = positions

        # Handle backward compatibility: convert split_pos to positions for multisplit if needed
        if (
            attack_type == "multisplit"
            and "split_pos" in params
            and "positions" not in params
        ):
            split_pos = params.get("split_pos")
            split_count = params.get("split_count")
            
            if isinstance(split_pos, int):
                # For multisplit, create multiple positions based on split_pos and split_count
                if split_count and isinstance(split_count, int) and split_count > 1:
                    # Use split_count to generate positions with gap of 6 bytes
                    gap = 6
                    positions = [split_pos + (i * gap) for i in range(split_count)]
                else:
                    # Fallback: create 3 positions if split_count not specified
                    positions = [split_pos, split_pos + 8, split_pos + 16]
                params["positions"] = positions

        normalized_params = self._normalize_params_with_registry(attack_type, params)

        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            attacks=[attack_type],  # Single attack for zapret style
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format="zapret",
        )

    def _parse_function_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse function call style strategy."""
        match = re.match(
            r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*$", strategy_string
        )
        if not match:
            raise StrategyLoadError(f"Invalid function syntax: {strategy_string}")

        attack_type = match.group(1).lower().strip()
        params_str = match.group(2).strip()

        params = {}
        if params_str:
            param_parts = self._smart_split(params_str, ",")
            for part in param_parts:
                part = part.strip()
                if not part or "=" not in part:
                    continue
                key, value = part.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key:
                    params[key] = self._parse_value(value)

        normalized_params = self._normalize_params_with_registry(attack_type, params)

        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            attacks=[attack_type],  # Single attack for function style
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format="function",
        )

    def _parse_colon_style(self, strategy_string: str) -> NormalizedStrategy:
        """Parse colon-separated style strategy: attack:param1=value1,param2=value2 or attack:value"""
        parts = strategy_string.split(":", 1)
        if len(parts) != 2:
            raise StrategyLoadError(f"Invalid colon-style syntax: {strategy_string}")

        attack_type = parts[0].strip().lower()
        params_str = parts[1].strip()

        params = {}
        if params_str:
            # Check if it's a shorthand format (single value without '=')
            if "=" not in params_str and "," not in params_str:
                # Shorthand format: attack:value
                # Interpret as split_pos for split/disorder attacks, or ttl for fake
                value = self._parse_value(params_str)

                # Determine parameter name based on attack type
                if attack_type in [
                    "split",
                    "disorder",
                    "disorder2",
                    "fakeddisorder",
                    "seqovl",
                ]:
                    params["split_pos"] = value
                elif attack_type in ["fake"]:
                    params["ttl"] = value
                elif attack_type in ["multisplit", "multidisorder"]:
                    # For multi-attacks, single value is ambiguous, use split_pos
                    params["split_pos"] = value
                else:
                    # Default to split_pos for unknown attacks
                    params["split_pos"] = value
            else:
                # Full format: attack:param1=value1,param2=value2
                param_parts = self._smart_split(params_str, ",")
                for part in param_parts:
                    part = part.strip()
                    if not part:
                        continue
                    if "=" not in part:
                        # Skip parts without '='
                        continue
                    key, value = part.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if key:
                        params[key] = self._parse_value(value)

        normalized_params = self._normalize_params_with_registry(attack_type, params)

        return NormalizedStrategy(
            type=attack_type,
            params=normalized_params,
            attacks=[attack_type],  # Single attack for colon style
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_string,
            source_format="colon",
        )

    def _smart_split(self, text: str, delimiter: str) -> List[str]:
        """Split text by delimiter while respecting quotes and brackets."""
        parts, current, depth, in_quote = [], [], 0, None
        for char in text:
            if char in ('"', "'"):
                if in_quote is None:
                    in_quote = char
                elif in_quote == char:
                    in_quote = None
                current.append(char)
            elif char in ("[", "(", "{") and in_quote is None:
                depth += 1
                current.append(char)
            elif char in ("]", ")", "}") and in_quote is None:
                depth -= 1
                current.append(char)
            elif char == delimiter and depth == 0 and in_quote is None:
                parts.append("".join(current))
                current = []
            else:
                current.append(char)
        if current:
            parts.append("".join(current))
        return parts

    def _parse_value(self, value_str: str) -> Any:
        """Parse a parameter value string to appropriate Python type."""
        value_str = value_str.strip()
        if not value_str:
            return None
        if value_str.startswith("[") and value_str.endswith("]"):
            return self._parse_list(value_str)
        if (value_str.startswith("'") and value_str.endswith("'")) or (
            value_str.startswith('"') and value_str.endswith('"')
        ):
            return value_str[1:-1]
        if value_str.lower() == "true":
            return True
        if value_str.lower() == "false":
            return False
        if value_str.lower() in ("none", "null"):
            return None
        if value_str == "midsld":
            return "midsld"
        try:
            if "." not in value_str and "e" not in value_str.lower():
                return int(value_str)
            return float(value_str)
        except ValueError:
            pass
        return value_str

    def _parse_list(self, list_str: str) -> List[Any]:
        """Parse a list string like ['item1', 'item2'] to Python list."""
        content = list_str[1:-1].strip()
        if not content:
            return []
        return [
            self._parse_value(item.strip()) for item in self._smart_split(content, ",")
        ]

    def create_forced_override(
        self, strategy: Union[NormalizedStrategy, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a forced override configuration from a strategy."""
        if isinstance(strategy, NormalizedStrategy):
            base_config = strategy.to_engine_format()
        elif isinstance(strategy, dict):
            base_config = strategy.copy()
        else:
            raise StrategyLoadError(
                f"Invalid strategy type for forced override: {type(strategy)}"
            )

        forced_config = {
            "type": base_config.get("type", "fakeddisorder"),
            "params": base_config.get("params", {}),
            "no_fallbacks": True,
            "forced": True,
            "override_mode": True,
        }
        
        # CRITICAL FIX: Include 'attacks' field for combination attacks
        # This ensures testing-production parity for combo strategies
        if "attacks" in base_config:
            forced_config["attacks"] = base_config["attacks"]
            if self.debug:
                self.logger.debug(f"Included attacks field in forced override: {base_config['attacks']}")
        
        if self.debug:
            self.logger.debug(f"Created forced override: {forced_config}")
        return forced_config

    def validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """Validate strategy parameters and configuration using AttackRegistry."""
        try:
            # Special handling for combo attacks - they are valid but flexible
            if strategy.type == "combo" or strategy.type.endswith("_combo") or "combo" in strategy.type:
                self.logger.debug(f"Combo attack type detected: {strategy.type}, using flexible validation")
                # Combo attacks are always valid with flexible parameters
                # Just do basic parameter validation
                self._validate_parameter_values(strategy)
                return True
            
            # Use stored registry reference if available, otherwise get it
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            # Validate parameters using the registry (includes special parameter validation)
            validation_result = registry.validate_parameters(
                strategy.type, strategy.params
            )

            if not validation_result.is_valid:
                raise StrategyValidationError(
                    f"AttackRegistry validation failed for '{strategy.type}': {validation_result.error_message}"
                )

            # Log warnings from AttackRegistry validation
            if validation_result.has_warnings():
                for warning in validation_result.warnings:
                    self.logger.warning(
                        f"Strategy '{strategy.type}' validation warning: {warning}"
                    )

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
            self.logger.warning(
                f"AttackRegistry validation failed, using legacy validation: {e}"
            )
            return self._legacy_validate_strategy(strategy)

    def _legacy_validate_strategy(self, strategy: NormalizedStrategy) -> bool:
        """Legacy strategy validation for backward compatibility."""
        # Special handling for combo attacks - they are valid but flexible
        if strategy.type == "combo" or strategy.type.endswith("_combo") or "combo" in strategy.type:
            self.logger.debug(f"Combo attack type detected: {strategy.type}")
            # Combo attacks are always valid with flexible parameters
            return True
            
        if strategy.type not in self.known_attacks:
            self.logger.warning(f"Unknown attack type: {strategy.type}")

        required = self.required_params.get(strategy.type, [])

        # Handle backward compatibility for multisplit
        if strategy.type == "multisplit" and "positions" in required:
            # If we have split_count, split_pos, or positions, we can generate positions, so positions is not required
            if (
                "split_count" in strategy.params
                or "split_pos" in strategy.params
                or "positions" in strategy.params
            ):
                required = [param for param in required if param != "positions"]

        # Handle backward compatibility for multidisorder
        if strategy.type == "multidisorder" and "positions" in required:
            # If we have split_pos or positions, we can generate positions, so positions is not required
            if "split_pos" in strategy.params or "positions" in strategy.params:
                required = [param for param in required if param != "positions"]

        # Handle disorder attacks - they can work with default split_pos if not provided
        if strategy.type in ["disorder", "disorder2"] and "split_pos" in required:
            # These attacks can work with default split_pos, so it's not strictly required
            # The handler will set a default value if needed
            required = [param for param in required if param != "split_pos"]

        # Check for missing parameters, but ignore None values (they will be handled by normalizer)
        missing = []
        for param in required:
            if param not in strategy.params:
                missing.append(param)
            elif strategy.params[param] is None:
                # None values are acceptable - they will be handled by parameter normalizer or attack handler
                continue
        if missing:
            raise StrategyValidationError(
                f"Strategy '{strategy.type}' missing required parameters: {missing}"
            )

        self._validate_parameter_values(strategy)

        if not strategy.no_fallbacks or not strategy.forced:
            self.logger.warning("Strategy is not configured for forced override.")

        return True

    def _validate_parameter_values(self, strategy: NormalizedStrategy) -> None:
        """Validate individual parameter values including special parameters."""
        params = strategy.params

        # Import special parameter constants
        try:
            from core.bypass.attacks.metadata import (
                SpecialParameterValues,
                FoolingMethods,
            )
        except ImportError:
            # Fallback to local constants if metadata module is not available
            class SpecialParameterValues:
                CIPHER = "cipher"
                SNI = "sni"
                MIDSLD = "midsld"
                ALL = ["cipher", "sni", "midsld"]

            class FoolingMethods:
                ALL = [
                    "badseq",
                    "badsum",
                    "md5sig",
                    "none",
                    "hopbyhop",
                    "badack",
                    "datanoack",
                ]

        # TTL validation with auto-resolution
        if (
            "ttl" in params
            and params.get("ttl") is not None
            and "autottl" in params
            and params.get("autottl") is not None
        ):
            # Auto-resolve conflict: autottl has priority over ttl
            self.logger.warning(
                "Both ttl and autottl specified. Using autottl and removing ttl."
            )
            del params["ttl"]

        if "ttl" in params and params["ttl"] is not None:
            ttl = params["ttl"]
            if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                raise StrategyValidationError(
                    f"Invalid TTL value: {ttl}. Must be integer between 1 and 255."
                )

        if "fake_ttl" in params and params["fake_ttl"] is not None:
            fake_ttl = params["fake_ttl"]
            if not isinstance(fake_ttl, int) or not (1 <= fake_ttl <= 255):
                raise StrategyValidationError(
                    f"Invalid fake_ttl value: {fake_ttl}. Must be integer between 1 and 255."
                )

        if "autottl" in params and params["autottl"] is not None:
            autottl = params["autottl"]
            if not isinstance(autottl, int) or not (-10 <= autottl <= 10):
                raise StrategyValidationError(
                    f"Invalid autottl value: {autottl}. Must be integer between -10 and 10."
                )

        # Special parameter validation for split_pos
        if "split_pos" in params and params["split_pos"] is not None:
            split_pos = params["split_pos"]

            if isinstance(split_pos, list):
                # Validate each position in the list
                for i, pos in enumerate(split_pos):
                    self._validate_single_position(
                        pos, f"split_pos[{i}]", SpecialParameterValues.ALL
                    )
            else:
                # Validate single position
                self._validate_single_position(
                    split_pos, "split_pos", SpecialParameterValues.ALL
                )

        # Special parameter validation for positions (multisplit/multidisorder)
        if "positions" in params and params["positions"] is not None:
            positions = params["positions"]

            # Handle backward compatibility: convert string to list
            if isinstance(positions, str):
                # Convert comma-separated string to list of integers
                try:
                    positions = [
                        int(pos.strip()) for pos in positions.split(",") if pos.strip()
                    ]
                    params["positions"] = positions
                except ValueError:
                    raise StrategyValidationError(
                        f"Invalid positions string: {params['positions']}. Must be comma-separated integers."
                    )

            if not isinstance(positions, list):
                raise StrategyValidationError(
                    f"Invalid positions parameter: must be a list, got {type(positions).__name__}"
                )

            if len(positions) == 0:
                raise StrategyValidationError("positions list cannot be empty")

            for i, pos in enumerate(positions):
                self._validate_single_position(
                    pos, f"positions[{i}]", SpecialParameterValues.ALL
                )

        # Overlap size validation
        if "overlap_size" in params and params["overlap_size"] is not None:
            overlap_size = params["overlap_size"]
            if not isinstance(overlap_size, int) or overlap_size < 0:
                raise StrategyValidationError(
                    f"Invalid overlap_size value: {overlap_size}. Must be non-negative integer."
                )

            # Additional validation: overlap_size should be reasonable
            if overlap_size > 1000:
                raise StrategyValidationError(
                    f"overlap_size too large: {overlap_size}. Maximum allowed is 1000."
                )

        # Repeats validation
        if "repeats" in params and params["repeats"] is not None:
            repeats = params["repeats"]
            if not isinstance(repeats, int) or not (1 <= repeats <= 10):
                raise StrategyValidationError(
                    f"Invalid repeats value: {repeats}. Must be integer between 1 and 10."
                )

        # Fooling methods validation
        if "fooling" in params and params["fooling"] is not None:
            fooling = params["fooling"]
            if not isinstance(fooling, list):
                raise StrategyValidationError(
                    f"Invalid fooling parameter: must be a list, got {type(fooling).__name__}"
                )

            # Validate each fooling method
            for method in fooling:
                if not isinstance(method, str):
                    raise StrategyValidationError(
                        f"Invalid fooling method: must be string, got {type(method).__name__}"
                    )

                if method not in FoolingMethods.ALL:
                    raise StrategyValidationError(
                        f"Invalid fooling method '{method}'. Valid methods: {FoolingMethods.ALL}"
                    )

        # Fooling methods validation (alternative parameter name)
        if "fooling_methods" in params and params["fooling_methods"] is not None:
            fooling_methods = params["fooling_methods"]
            if not isinstance(fooling_methods, list):
                raise StrategyValidationError(
                    f"Invalid fooling_methods parameter: must be a list, got {type(fooling_methods).__name__}"
                )

            for method in fooling_methods:
                if not isinstance(method, str):
                    raise StrategyValidationError(
                        f"Invalid fooling method: must be string, got {type(method).__name__}"
                    )

                if method not in FoolingMethods.ALL:
                    raise StrategyValidationError(
                        f"Invalid fooling method '{method}'. Valid methods: {FoolingMethods.ALL}"
                    )

        # Boolean flags validation (with special handling for fake_tls)
        boolean_params = ["ack_first", "fake_http", "fake_syndata"]
        for param_name in boolean_params:
            if param_name in params and params[param_name] is not None:
                param_value = params[param_name]
                if not isinstance(param_value, bool):
                    # Try to convert common values
                    if isinstance(param_value, (int, str)):
                        if str(param_value).lower() in ("true", "1", "yes", "on"):
                            params[param_name] = True
                        elif str(param_value).lower() in ("false", "0", "no", "off"):
                            params[param_name] = False
                        else:
                            raise StrategyValidationError(
                                f"Invalid {param_name} value: {param_value}. Must be boolean or convertible to boolean."
                            )
                    else:
                        raise StrategyValidationError(
                            f"Invalid {param_name} value: {param_value}. Must be boolean."
                        )

        # Special handling for fake_tls (can be boolean or hex string for backward compatibility)
        if "fake_tls" in params and params["fake_tls"] is not None:
            fake_tls = params["fake_tls"]
            if isinstance(fake_tls, bool):
                # Already boolean, keep as is
                pass
            elif isinstance(fake_tls, (int, str)):
                str_value = str(fake_tls).lower()
                if str_value in ("true", "1", "yes", "on"):
                    params["fake_tls"] = True
                elif str_value in ("false", "0", "no", "off"):
                    params["fake_tls"] = False
                elif str_value.startswith("0x") or str_value.isdigit():
                    # Hex value or numeric - keep as string for backward compatibility
                    params["fake_tls"] = str(fake_tls)
                else:
                    # Unknown string value - keep as is for backward compatibility
                    params["fake_tls"] = str(fake_tls)
            else:
                # Keep as is for backward compatibility
                pass

        # Custom data validation
        if "fake_data" in params and params["fake_data"] is not None:
            fake_data = params["fake_data"]
            if not isinstance(fake_data, (str, bytes)):
                raise StrategyValidationError(
                    f"Invalid fake_data: must be string or bytes, got {type(fake_data).__name__}"
                )

        if "fake_sni" in params and params["fake_sni"] is not None:
            fake_sni = params["fake_sni"]
            if not isinstance(fake_sni, str):
                raise StrategyValidationError(
                    f"Invalid fake_sni: must be string, got {type(fake_sni).__name__}"
                )

            # Basic domain name validation
            if not self._is_valid_domain_name(fake_sni):
                raise StrategyValidationError(
                    f"Invalid fake_sni domain name: {fake_sni}"
                )

    def _validate_single_position(
        self, position: Any, param_name: str, special_values: List[str]
    ) -> None:
        """Validate a single position parameter (can be int or special string value)."""
        if isinstance(position, int):
            if position < 1:
                raise StrategyValidationError(
                    f"Invalid {param_name}: {position}. Position must be >= 1."
                )

            # Additional validation: position should be reasonable
            if position > 65535:
                raise StrategyValidationError(
                    f"Invalid {param_name}: {position}. Position too large (max 65535)."
                )

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
                        raise StrategyValidationError(
                            f"Invalid {param_name}: {position}. Position must be >= 1."
                        )
                    if int_pos > 65535:
                        raise StrategyValidationError(
                            f"Invalid {param_name}: {position}. Position too large (max 65535)."
                        )
                except ValueError:
                    raise StrategyValidationError(
                        f"Invalid {param_name}: {position}. Must be integer >= 1 or one of special values: {special_values}"
                    )
        else:
            raise StrategyValidationError(
                f"Invalid {param_name}: {position}. Must be integer or string, got {type(position).__name__}"
            )

    def _is_valid_domain_name(self, domain: str) -> bool:
        """Basic domain name validation."""
        if not domain or len(domain) > 253:
            return False

        # Basic regex for domain validation
        import re

        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )

        return bool(domain_pattern.match(domain))

    def _validate_parameter_combinations(self, strategy: NormalizedStrategy) -> None:
        """Validate special parameter combinations and dependencies."""
        params = strategy.params
        attack_type = strategy.type

        # Validate seqovl specific requirements
        if attack_type in ["seqovl", "seq_overlap", "overlap"]:
            if "overlap_size" not in params:
                raise StrategyValidationError(
                    f"Attack type '{attack_type}' requires 'overlap_size' parameter"
                )

            if "split_pos" not in params:
                raise StrategyValidationError(
                    f"Attack type '{attack_type}' requires 'split_pos' parameter"
                )

            # Validate that overlap_size makes sense with split_pos
            overlap_size = params.get("overlap_size", 0)
            split_pos = params.get("split_pos")

            if isinstance(split_pos, int) and isinstance(overlap_size, int):
                if overlap_size >= split_pos:
                    raise StrategyValidationError(
                        f"overlap_size ({overlap_size}) must be less than split_pos ({split_pos})"
                    )

        # Validate multisplit/multidisorder requirements
        if attack_type in [
            "multisplit",
            "multidisorder",
            "multi_split",
            "multi_disorder",
        ]:
            # Either positions or split_pos should be provided
            if "positions" not in params and "split_pos" not in params:
                raise StrategyValidationError(
                    f"Attack type '{attack_type}' requires either 'positions' or 'split_pos' parameter"
                )

            # If both are provided, warn about potential conflict
            if "positions" in params and "split_pos" in params:
                self.logger.warning(
                    f"Both 'positions' and 'split_pos' provided for '{attack_type}'. 'positions' will take precedence."
                )

        # Validate TTL parameter combinations
        if "ttl" in params and "autottl" in params:
            if params["ttl"] is not None and params["autottl"] is not None:
                raise StrategyValidationError(
                    "Cannot specify both 'ttl' and 'autottl' parameters"
                )

        # Validate fake packet parameters
        fake_params = ["fake_tls", "fake_http", "fake_syndata", "fake_sni", "fake_data"]
        has_fake_params = any(
            param in params and params[param] is not None for param in fake_params
        )

        if has_fake_params and attack_type not in [
            "fakeddisorder",
            "fake_disorder",
            "fakedisorder",
            "fake",
            "fake_race",
            "race",
        ]:
            self.logger.warning(
                f"Fake packet parameters provided for non-fake attack type '{attack_type}'. They may be ignored."
            )

        # Validate fooling methods consistency
        if "fooling" in params and "fooling_methods" in params:
            if params["fooling"] is not None and params["fooling_methods"] is not None:
                self.logger.warning(
                    "Both 'fooling' and 'fooling_methods' provided. 'fooling' will take precedence."
                )

        # Validate special position values context
        special_positions = []

        # Check split_pos for special values
        if "split_pos" in params:
            split_pos = params["split_pos"]
            if isinstance(split_pos, str) and split_pos in ["cipher", "sni", "midsld"]:
                special_positions.append(split_pos)
            elif isinstance(split_pos, list):
                for pos in split_pos:
                    if isinstance(pos, str) and pos in ["cipher", "sni", "midsld"]:
                        special_positions.append(pos)

        # Check positions for special values
        if "positions" in params:
            positions = params["positions"]
            if isinstance(positions, list):
                for pos in positions:
                    if isinstance(pos, str) and pos in ["cipher", "sni", "midsld"]:
                        special_positions.append(pos)

        # Warn about TLS-specific special values for non-TLS contexts
        tls_specific = ["cipher", "sni"]
        for special_pos in special_positions:
            if special_pos in tls_specific:
                self.logger.warning(
                    f"Special position '{special_pos}' is TLS-specific. Ensure this strategy is used with TLS traffic."
                )

        # Validate domain-specific special values
        if "midsld" in special_positions:
            self.logger.warning(
                "Special position 'midsld' requires domain name extraction. Ensure this strategy is used with HTTP/HTTPS traffic."
            )

        # Validate attack type specific parameter requirements
        self._validate_attack_type_specific_requirements(attack_type, params)

    def _validate_attack_type_specific_requirements(
        self, attack_type: str, params: Dict[str, Any]
    ) -> None:
        """Validate attack type specific parameter requirements."""

        # Normalize attack type for checking
        normalized_type = attack_type.lower()

        # Split-based attacks require position parameters
        split_attacks = ["split", "simple_split", "multisplit", "multi_split"]
        if normalized_type in split_attacks:
            if "split_pos" not in params and "positions" not in params:
                raise StrategyValidationError(
                    f"Split attack '{attack_type}' requires position parameters ('split_pos' or 'positions')"
                )

        # Disorder attacks require position parameters
        disorder_attacks = [
            "disorder",
            "disorder2",
            "simple_disorder",
            "disorder_ack",
            "multidisorder",
            "multi_disorder",
        ]
        if normalized_type in disorder_attacks:
            if "split_pos" not in params and "positions" not in params:
                raise StrategyValidationError(
                    f"Disorder attack '{attack_type}' requires position parameters ('split_pos' or 'positions')"
                )

        # Fake attacks require TTL or fake-related parameters
        fake_attacks = [
            "fake",
            "fake_race",
            "race",
            "fakeddisorder",
            "fake_disorder",
            "fakedisorder",
        ]
        if normalized_type in fake_attacks:
            has_ttl = "ttl" in params or "fake_ttl" in params
            has_fake_params = any(
                param in params
                for param in [
                    "fake_tls",
                    "fake_http",
                    "fake_syndata",
                    "fake_sni",
                    "fake_data",
                ]
            )

            if not has_ttl and not has_fake_params:
                # For fake attacks, we need at least TTL
                if normalized_type in ["fake", "fake_race", "race"]:
                    raise StrategyValidationError(
                        f"Fake attack '{attack_type}' requires 'ttl' parameter"
                    )
                else:
                    # For fakeddisorder, TTL is optional but recommended
                    self.logger.warning(
                        f"Fake attack '{attack_type}' should have 'ttl' or fake packet parameters for optimal effectiveness"
                    )

        # Overlap attacks require specific parameters
        overlap_attacks = ["seqovl", "seq_overlap", "overlap"]
        if normalized_type in overlap_attacks:
            required_params = ["split_pos", "overlap_size"]
            missing_params = [param for param in required_params if param not in params]
            if missing_params:
                raise StrategyValidationError(
                    f"Overlap attack '{attack_type}' missing required parameters: {missing_params}"
                )

    def load_strategies_from_file(
        self, file_path: Union[str, Path]
    ) -> Dict[str, NormalizedStrategy]:
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
            with open(file_path, "r", encoding="utf-8") as f:
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
                        if "strategy" in value:
                            # Nested format: {"domain": {"strategy": "..."}}
                            strategies[key] = self.load_strategy(value["strategy"])
                        else:
                            # Direct dict format
                            strategies[key] = self.load_strategy(value)
                    else:
                        self.logger.warning(
                            f"Skipping invalid strategy for {key}: {value}"
                        )
                except Exception as e:
                    self.logger.error(f"Failed to load strategy for {key}: {e}")
                    # Continue loading other strategies

        if self.debug:
            self.logger.debug(f"Loaded {len(strategies)} strategies from {file_path}")

        return strategies

    def normalize_strategy_dict(
        self, strategy_dict: Dict[str, Any]
    ) -> NormalizedStrategy:
        """
        Normalize a strategy dictionary to standard format.

        This method handles various dictionary formats and ensures
        they are normalized to the standard NormalizedStrategy format.
        """
        # Handle different dict formats
        if "attack_type" in strategy_dict:
            # ParsedStrategy-like format
            attack_type = strategy_dict["attack_type"]
            attacks = strategy_dict.get("attacks", [attack_type])  # Preserve attacks or default to single
            return NormalizedStrategy(
                type=attack_type,
                params=strategy_dict.get("params", {}),
                attacks=attacks,  # Include attacks field
                no_fallbacks=True,
                forced=True,
                raw_string=strategy_dict.get("raw_string", ""),
                source_format=strategy_dict.get("syntax_type", "dict"),
            )
        elif "type" in strategy_dict:
            # Direct format
            attack_type = strategy_dict["type"]
            attacks = strategy_dict.get("attacks", [attack_type])  # Preserve attacks or default to single
            return NormalizedStrategy(
                type=attack_type,
                params=strategy_dict.get("params", {}),
                attacks=attacks,  # Include attacks field
                no_fallbacks=True,
                forced=True,
                raw_string=str(strategy_dict),
                source_format="dict",
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
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            return registry.get_attack_metadata(attack_type)
        except Exception as e:
            self.logger.warning(
                f"Failed to get metadata for attack '{attack_type}': {e}"
            )
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
            registry = getattr(self, "_attack_registry", None)
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
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            return registry.get_attack_aliases(attack_type)
        except Exception as e:
            self.logger.warning(
                f"Failed to get aliases for attack '{attack_type}': {e}"
            )
            return []

    def validate_attack_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> bool:
        """
        Validate parameters for a specific attack type using AttackRegistry.

        Args:
            attack_type: Type of attack
            params: Parameters to validate

        Returns:
            True if valid, raises StrategyValidationError if not
        """
        try:
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            validation_result = registry.validate_parameters(attack_type, params)

            if not validation_result.is_valid:
                raise StrategyValidationError(
                    f"Parameter validation failed for '{attack_type}': {validation_result.error_message}"
                )

            # Log warnings
            if validation_result.has_warnings():
                for warning in validation_result.warnings:
                    self.logger.warning(
                        f"Parameter validation warning for '{attack_type}': {warning}"
                    )

            return True

        except Exception as e:
            self.logger.warning(
                f"Failed to validate parameters for attack '{attack_type}': {e}"
            )
            # Fall back to legacy validation
            return self._legacy_validate_attack_parameters(attack_type, params)

    def _legacy_validate_attack_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> bool:
        """Legacy parameter validation for backward compatibility."""
        if attack_type not in self.known_attacks:
            raise StrategyValidationError(f"Unknown attack type: {attack_type}")

        required = self.required_params.get(attack_type, [])
        missing = [param for param in required if param not in params]
        if missing:
            raise StrategyValidationError(
                f"Attack '{attack_type}' missing required parameters: {missing}"
            )

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
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            # Check if attack is registered in AttackRegistry
            metadata = registry.get_attack_metadata(attack_type)
            return metadata is not None

        except Exception as e:
            self.logger.warning(
                f"Failed to check attack support for '{attack_type}': {e}"
            )
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
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            return registry.get_attack_handler(attack_type)
        except Exception as e:
            self.logger.warning(
                f"Failed to get handler for attack '{attack_type}': {e}"
            )
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
            "registry_available": False,
            "registry_attacks_count": 0,
            "known_attacks_count": len(self.known_attacks),
            "required_params_count": len(self.required_params),
            "integration_active": False,
        }

        try:
            registry = getattr(self, "_attack_registry", None)
            if registry is None:
                from core.bypass.attacks.attack_registry import get_attack_registry

                registry = get_attack_registry()

            if registry:
                status["registry_available"] = True
                status["registry_attacks_count"] = len(registry.list_attacks())
                status["integration_active"] = True

        except Exception as e:
            self.logger.warning(f"Failed to get registry status: {e}")

        return status

    def load_all_strategies(
        self, file_path: str = "domain_strategies.json"
    ) -> Dict[str, NormalizedStrategy]:
        """
        Load all strategies from domain_strategies.json file.

        Args:
            file_path: Path to the strategies JSON file (default: domain_strategies.json)

        Returns:
            Dict mapping domain to normalized strategy

        Raises:
            StrategyLoadError: If file cannot be loaded or parsed
        """
        file_path = Path(file_path)

        if not file_path.exists():
            self.logger.warning(f"Strategy file not found: {file_path}")
            return {}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise StrategyLoadError(f"Failed to read strategy file {file_path}: {e}")

        strategies = {}

        # Handle domain_strategies.json format
        if "domain_strategies" in data:
            # New format with metadata
            domain_strategies = data["domain_strategies"]
            for domain, strategy_data in domain_strategies.items():
                try:
                    if isinstance(strategy_data, dict) and "strategy" in strategy_data:
                        # Extract strategy string from nested structure
                        strategy_str = strategy_data["strategy"]
                        strategies[domain] = self.load_strategy(strategy_str)
                    elif isinstance(strategy_data, str):
                        # Direct strategy string
                        strategies[domain] = self.load_strategy(strategy_data)
                    elif isinstance(strategy_data, dict):
                        # Dict format strategy
                        strategies[domain] = self.load_strategy(strategy_data)
                    else:
                        self.logger.warning(
                            f"Skipping invalid strategy for {domain}: {strategy_data}"
                        )
                except Exception as e:
                    self.logger.error(f"Failed to load strategy for {domain}: {e}")
                    # Continue loading other strategies
        else:
            # Legacy format - direct domain to strategy mapping
            for domain, strategy_data in data.items():
                # Skip metadata fields
                if domain in ["version", "last_updated"]:
                    continue

                try:
                    if isinstance(strategy_data, str):
                        strategies[domain] = self.load_strategy(strategy_data)
                    elif isinstance(strategy_data, dict):
                        if "strategy" in strategy_data:
                            strategies[domain] = self.load_strategy(
                                strategy_data["strategy"]
                            )
                        else:
                            strategies[domain] = self.load_strategy(strategy_data)
                    else:
                        self.logger.warning(
                            f"Skipping invalid strategy for {domain}: {strategy_data}"
                        )
                except Exception as e:
                    self.logger.error(f"Failed to load strategy for {domain}: {e}")
                    # Continue loading other strategies

        if self.debug:
            self.logger.debug(
                f"Loaded {len(strategies)} strategies from {file_path}"
            )

        return strategies

    def save_strategy(
        self,
        domain: str,
        strategy: Union[str, Dict[str, Any], NormalizedStrategy],
        file_path: str = "domain_strategies.json",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Save a strategy for a domain to domain_strategies.json file.

        Args:
            domain: Domain name
            strategy: Strategy to save (string, dict, or NormalizedStrategy)
            file_path: Path to the strategies JSON file (default: domain_strategies.json)
            metadata: Optional metadata to save with the strategy (success_rate, latency, etc.)

        Raises:
            StrategyLoadError: If file cannot be written
        """
        from datetime import datetime

        file_path = Path(file_path)

        # Load existing strategies
        existing_data = {}
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
            except Exception as e:
                self.logger.warning(
                    f"Failed to read existing strategies from {file_path}: {e}"
                )
                existing_data = {}

        # Ensure domain_strategies structure exists
        if "domain_strategies" not in existing_data:
            existing_data["domain_strategies"] = {}

        # Normalize the strategy
        if isinstance(strategy, NormalizedStrategy):
            strategy_str = strategy.raw_string
        elif isinstance(strategy, dict):
            # Convert dict to string format
            normalized = self.load_strategy(strategy)
            strategy_str = normalized.raw_string
        elif isinstance(strategy, str):
            # Validate the strategy string
            normalized = self.load_strategy(strategy)
            strategy_str = strategy
        else:
            raise StrategyLoadError(
                f"Invalid strategy type: {type(strategy)}. Must be str, dict, or NormalizedStrategy"
            )

        # Create strategy entry
        strategy_entry = {
            "domain": domain,
            "strategy": strategy_str,
            "last_tested": datetime.now().isoformat(),
        }

        # Add metadata if provided
        if metadata:
            strategy_entry.update(metadata)

        # Update domain_strategies
        existing_data["domain_strategies"][domain] = strategy_entry

        # Update file metadata
        existing_data["last_updated"] = datetime.now().isoformat()
        if "version" not in existing_data:
            existing_data["version"] = "2.0"

        # Write to file
        try:
            # Create parent directory if it doesn't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)

            if self.debug:
                self.logger.debug(
                    f"Saved strategy for {domain} to {file_path}: {strategy_str}"
                )
        except Exception as e:
            raise StrategyLoadError(f"Failed to write strategy file {file_path}: {e}")

    def save_all_strategies(
        self,
        strategies: Dict[str, Union[str, Dict[str, Any], NormalizedStrategy]],
        file_path: str = "domain_strategies.json",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Save multiple strategies to domain_strategies.json file.

        Args:
            strategies: Dict mapping domain to strategy
            file_path: Path to the strategies JSON file (default: domain_strategies.json)
            metadata: Optional global metadata

        Raises:
            StrategyLoadError: If file cannot be written
        """
        from datetime import datetime

        file_path = Path(file_path)

        # Load existing data to preserve metadata
        existing_data = {}
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
            except Exception as e:
                self.logger.warning(
                    f"Failed to read existing strategies from {file_path}: {e}"
                )
                existing_data = {}

        # Ensure structure
        if "domain_strategies" not in existing_data:
            existing_data["domain_strategies"] = {}

        # Process each strategy
        for domain, strategy in strategies.items():
            try:
                # Normalize the strategy
                if isinstance(strategy, NormalizedStrategy):
                    strategy_str = strategy.raw_string
                elif isinstance(strategy, dict):
                    if "strategy" in strategy:
                        # Already in correct format
                        existing_data["domain_strategies"][domain] = strategy
                        continue
                    else:
                        # Convert dict to string format
                        normalized = self.load_strategy(strategy)
                        strategy_str = normalized.raw_string
                elif isinstance(strategy, str):
                    # Validate the strategy string
                    normalized = self.load_strategy(strategy)
                    strategy_str = strategy
                else:
                    self.logger.warning(
                        f"Skipping invalid strategy for {domain}: {type(strategy)}"
                    )
                    continue

                # Create strategy entry
                strategy_entry = {
                    "domain": domain,
                    "strategy": strategy_str,
                    "last_tested": datetime.now().isoformat(),
                }

                # Add per-domain metadata if available
                if metadata and domain in metadata:
                    strategy_entry.update(metadata[domain])

                existing_data["domain_strategies"][domain] = strategy_entry

            except Exception as e:
                self.logger.error(f"Failed to process strategy for {domain}: {e}")
                # Continue with other strategies

        # Update file metadata
        existing_data["last_updated"] = datetime.now().isoformat()
        if "version" not in existing_data:
            existing_data["version"] = "2.0"

        # Write to file
        try:
            # Create parent directory if it doesn't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)

            if self.debug:
                self.logger.debug(
                    f"Saved {len(strategies)} strategies to {file_path}"
                )
        except Exception as e:
            raise StrategyLoadError(f"Failed to write strategy file {file_path}: {e}")


# Convenience functions for backward compatibility
def load_strategy(
    strategy_input: Union[str, Dict[str, Any]], debug: bool = False
) -> NormalizedStrategy:
    """Convenience function to load a single strategy."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.load_strategy(strategy_input)


def create_forced_override(
    strategy: Union[NormalizedStrategy, Dict[str, Any]], debug: bool = False
) -> Dict[str, Any]:
    """Convenience function to create forced override."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.create_forced_override(strategy)


def load_strategies_from_file(
    file_path: Union[str, Path], debug: bool = False
) -> Dict[str, NormalizedStrategy]:
    """Convenience function to load strategies from file."""
    loader = UnifiedStrategyLoader(debug=debug)
    return loader.load_strategies_from_file(file_path)

