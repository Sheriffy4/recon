"""
Strategy Parsers Module

Parsers for different strategy string formats.
"""

import re
import logging
from typing import Dict, Any, Optional, TYPE_CHECKING

from .parsing_utils import parse_value, smart_split

# Use TYPE_CHECKING to avoid circular imports at runtime
if TYPE_CHECKING:
    from core.unified_strategy_loader import NormalizedStrategy, StrategyLoadError
else:
    # At runtime, we'll get these from the calling module
    NormalizedStrategy = None
    StrategyLoadError = None


def _get_normalized_strategy_class():
    """Get NormalizedStrategy class at runtime to avoid circular imports."""
    global NormalizedStrategy
    if NormalizedStrategy is None:
        from core.unified_strategy_loader import NormalizedStrategy as NS

        NormalizedStrategy = NS
    return NormalizedStrategy


def _get_strategy_load_error_class():
    """Get StrategyLoadError class at runtime to avoid circular imports."""
    global StrategyLoadError
    if StrategyLoadError is None:
        from core.unified_strategy_loader import StrategyLoadError as SLE

        StrategyLoadError = SLE
    return StrategyLoadError


def parse_comma_separated_combo(strategy_string: str):
    """Parse comma-separated combo attack (e.g., 'disorder,multisplit')."""
    NormalizedStrategy = _get_normalized_strategy_class()
    attacks = [attack.strip().lower() for attack in strategy_string.split(",")]

    # Use the first attack as the primary type, but include all attacks
    attack_type = attacks[0]

    # Create a combo type name
    combo_type = ",".join(attacks)

    NormalizedStrategy = _get_normalized_strategy_class()
    return NormalizedStrategy(
        type=combo_type,
        params={},
        attacks=attacks,
        no_fallbacks=True,
        forced=True,
        raw_string=strategy_string,
        source_format="comma_separated_combo",
    )


def parse_simple_attack_name(
    strategy_string: str,
    attack_registry: Any = None,
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
):
    """
    Parse simple attack name without parameters.

    Args:
        strategy_string: Strategy string to parse
        attack_registry: Optional attack registry for default parameters
        debug: Enable debug logging
        logger: Optional logger

    Returns:
        Normalized strategy
    """
    NormalizedStrategy = _get_normalized_strategy_class()
    if logger is None:
        logger = logging.getLogger(__name__)

    attack_type = strategy_string.lower().strip()

    # Проверяем, является ли это smart_combo стратегией
    if attack_type.startswith("smart_combo_"):
        # Извлекаем атаки из имени: smart_combo_split_fake -> [split, fake]
        parts = attack_type.replace("smart_combo_", "").split("_")
        attacks = []

        # Распознаем известные атаки
        known_attack_names = {
            "fake",
            "split",
            "disorder",
            "disorder2",
            "multidisorder",
            "multisplit",
            "seqovl",
            "ttl",
            "badseq",
            "badsum",
            "fakeddisorder",
            "overlap",
        }

        for part in parts:
            if part in known_attack_names:
                attacks.append(part)

        if not attacks:
            # Если не смогли распознать, используем все части
            attacks = parts

        if debug:
            logger.debug(f"Parsed smart_combo: {attack_type} -> attacks={attacks}")
    else:
        # Для обычных атак используем имя как тип и как единственную атаку
        attacks = [attack_type]

    # Получаем параметры по умолчанию из реестра для каждой атаки
    params = {}
    if attack_registry:
        try:
            # Собираем параметры по умолчанию для всех атак в комбинации
            for attack in attacks:
                metadata = attack_registry.get_attack_metadata(attack)
                if metadata:
                    # Объединяем параметры, не перезаписывая существующие
                    for param_name, default_value in metadata.optional_params.items():
                        if param_name not in params:
                            params[param_name] = default_value

            if debug and params:
                logger.debug(f"Using default params from registry for {attack_type}: {params}")
        except Exception as e:
            if debug:
                logger.debug(f"Could not get default params for {attack_type}: {e}")

    return NormalizedStrategy(
        type=attack_type,
        attacks=attacks,
        params=params,
        no_fallbacks=True,
        forced=True,
        raw_string=strategy_string,
        source_format="simple_name",
    )


def parse_semicolon_combo_style(
    strategy_string: str,
    normalize_params_func: callable,
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
):
    """
    Parse semicolon combo style strategy.

    Format: "fake,split; ttl=1; fooling=badseq; split_pos=3; split_count=2"

    Args:
        strategy_string: Strategy string to parse
        normalize_params_func: Function to normalize parameters
        debug: Enable debug logging
        logger: Optional logger

    Returns:
        Normalized strategy
    """
    NormalizedStrategy = _get_normalized_strategy_class()
    if logger is None:
        logger = logging.getLogger(__name__)

    # Пример: "fake,split; ttl=1; fooling=badseq; split_pos=3; split_count=2"
    parts = [p.strip() for p in strategy_string.split(";") if p.strip()]
    head = parts[0]
    attacks = [a.strip().lower() for a in head.split(",") if a.strip()]

    params: Dict[str, Any] = {}
    for token in parts[1:] if "=" not in head else parts:
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        params[k.strip().replace("-", "_")] = parse_value(v.strip())

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

    normalized_params = normalize_params_func(attack_type, params)

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


def parse_generic_cli_style(
    strategy_string: str,
    normalize_params_func: callable,
):
    """
    Parse generic --key=value style strategies.

    Args:
        strategy_string: Strategy string to parse
        normalize_params_func: Function to normalize parameters

    Returns:
        Normalized strategy
    """
    NormalizedStrategy = _get_normalized_strategy_class()
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
            params[key.replace("-", "_")] = parse_value(value)
        else:
            params[part.lstrip("-").replace("-", "_")] = True

    # Use basic normalize_params (not with registry) for generic CLI
    from core.strategy_loader.param_normalizer import normalize_params

    normalized_params = normalize_params(params)

    return NormalizedStrategy(
        type=attack_type,
        params=normalized_params,
        attacks=[attack_type],  # Single attack for generic CLI style
        no_fallbacks=True,
        forced=True,
        raw_string=strategy_string,
        source_format="generic_cli",
    )


def parse_zapret_style(
    strategy_string: str,
    normalize_params_func: callable,
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
):
    """
    Parse Zapret command-line style strategy.

    Args:
        strategy_string: Strategy string to parse
        normalize_params_func: Function to normalize parameters
        debug: Enable debug logging
        logger: Optional logger

    Returns:
        Normalized strategy
    """
    NormalizedStrategy = _get_normalized_strategy_class()
    if logger is None:
        logger = logging.getLogger(__name__)

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
            has_disorder = any(variant in desync_methods for variant in disorder_variants)

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
                int(p) if p.isdigit() else p for p in parts if p.isdigit() or p in special_values
            ]
            if parsed_parts:
                params["split_pos"] = parsed_parts
        else:
            try:
                params["split_pos"] = int(split_pos_str)
            except ValueError:
                logger.warning(f"Could not parse split-pos: {split_pos_str}")

    # Parse TTL parameters with priority: autottl > ttl
    ttl_match = re.search(r"--dpi-desync-ttl=([-\d]+)", strategy_string)
    autottl_match = re.search(r"--dpi-desync-autottl=([-\d]+|midsld)", strategy_string)

    if autottl_match:
        # autottl has priority over ttl
        value_str = autottl_match.group(1)
        if value_str == "midsld":
            params["autottl"] = "midsld"
        else:
            try:
                params["autottl"] = int(value_str)
            except ValueError:
                logger.warning(f"Could not parse autottl: {value_str}")
    elif ttl_match:
        # Only use ttl if autottl is not present
        try:
            params["ttl"] = int(ttl_match.group(1))
        except ValueError:
            logger.warning(f"Could not parse ttl: {ttl_match.group(1)}")

    # Parse other integer parameters
    other_int_params = {
        "split-count": "split_count",
        "split-seqovl": "overlap_size",
        "repeats": "repeats",
        "badseq-increment": "badseq_increment",
    }
    for param_name, param_key in other_int_params.items():
        match = re.search(rf"--dpi-desync-{param_name}=([-\d]+|midsld)", strategy_string)
        if match:
            value_str = match.group(1)
            if value_str == "midsld":
                params[param_key] = "midsld"
            else:
                try:
                    params[param_key] = int(value_str)
                except ValueError:
                    logger.warning(f"Could not parse integer for {param_name}: {value_str}")

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
        match = re.search(rf"--dpi-desync-{param_name}(?:=([^\s]+))?", strategy_string)
        if match:
            value = match.group(1)
            params[param_key] = int(value) if value and value.isdigit() else (value or True)

    if "--dpi-desync-autottl" in strategy_string and "autottl" not in params:
        params["autottl"] = 2
    if "repeats" not in params:
        params["repeats"] = 1

    # Handle backward compatibility: convert split_count to positions for multisplit
    if attack_type == "multisplit" and "split_count" in params and "positions" not in params:
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
    if attack_type == "multidisorder" and "split_pos" in params and "positions" not in params:
        split_pos = params.get("split_pos")
        if isinstance(split_pos, int):
            # For multidisorder, create multiple positions around the split_pos
            positions = [split_pos, split_pos + 5, split_pos + 10]
            params["positions"] = positions

    # Handle backward compatibility: convert split_pos to positions for multisplit if needed
    if attack_type == "multisplit" and "split_pos" in params and "positions" not in params:
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

    normalized_params = normalize_params_func(attack_type, params)

    return NormalizedStrategy(
        type=attack_type,
        params=normalized_params,
        attacks=[attack_type],  # Single attack for zapret style
        no_fallbacks=True,
        forced=True,
        raw_string=strategy_string,
        source_format="zapret",
    )


def parse_function_style(
    strategy_string: str,
    normalize_params_func: callable,
):
    """
    Parse function call style strategy.

    Format: attack(param1=value1, param2=value2)

    Args:
        strategy_string: Strategy string to parse
        normalize_params_func: Function to normalize parameters

    Returns:
        Normalized strategy
    """
    NormalizedStrategy = _get_normalized_strategy_class()
    StrategyLoadError = _get_strategy_load_error_class()
    match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*$", strategy_string)
    if not match:
        raise StrategyLoadError(f"Invalid function syntax: {strategy_string}")

    attack_type = match.group(1).lower().strip()
    params_str = match.group(2).strip()

    params = {}
    if params_str:
        param_parts = smart_split(params_str, ",")
        for part in param_parts:
            part = part.strip()
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key:
                params[key] = parse_value(value)

    normalized_params = normalize_params_func(attack_type, params)

    return NormalizedStrategy(
        type=attack_type,
        params=normalized_params,
        attacks=[attack_type],  # Single attack for function style
        no_fallbacks=True,
        forced=True,
        raw_string=strategy_string,
        source_format="function",
    )


def parse_colon_style(
    strategy_string: str,
    normalize_params_func: callable,
):
    """
    Parse colon-separated style strategy.

    Format: attack:param1=value1,param2=value2 or attack:value

    Args:
        strategy_string: Strategy string to parse
        normalize_params_func: Function to normalize parameters

    Returns:
        Normalized strategy
    """
    NormalizedStrategy = _get_normalized_strategy_class()
    StrategyLoadError = _get_strategy_load_error_class()
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
            value = parse_value(params_str)

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
            param_parts = smart_split(params_str, ",")
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
                    params[key] = parse_value(value)

    normalized_params = normalize_params_func(attack_type, params)

    return NormalizedStrategy(
        type=attack_type,
        params=normalized_params,
        attacks=[attack_type],  # Single attack for colon style
        no_fallbacks=True,
        forced=True,
        raw_string=strategy_string,
        source_format="colon",
    )
