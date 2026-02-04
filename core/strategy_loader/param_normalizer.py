"""
Parameter Normalization Module

Handles normalization and transformation of strategy parameters.
"""

import logging
from typing import Dict, Any, Optional


def normalize_params(
    params: Dict[str, Any], logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Normalize parameters to consistent format.

    Args:
        params: Raw parameters dictionary
        logger: Optional logger for debug output

    Returns:
        Normalized parameters dictionary
    """
    if logger is None:
        logger = logging.getLogger(__name__)

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
            logger.debug(f"Unified fooling: {combined}")
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
                if f is not None and str(f).strip().lower() not in ("none", "null", "")
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


def normalize_position_value(pos: Any, special_values: list) -> Any:
    """
    Normalize a single position value.

    Args:
        pos: Position value (string, int, or other)
        special_values: List of valid special string values

    Returns:
        Normalized position value
    """
    if isinstance(pos, str):
        normalized_value = pos.lower().strip()
        if normalized_value in special_values:
            return normalized_value
        else:
            try:
                return int(pos)
            except ValueError:
                return pos  # Keep for validation
    else:
        return pos


def normalize_special_parameters(
    params: Dict[str, Any], logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Normalize special parameters to ensure consistency.

    Args:
        params: Parameters dictionary
        logger: Optional logger for debug output

    Returns:
        Normalized parameters dictionary
    """
    if logger is None:
        logger = logging.getLogger(__name__)

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
                normalized_positions.append(
                    normalize_position_value(pos, SpecialParameterValues.ALL)
                )
            normalized["split_pos"] = normalized_positions

    # Normalize positions special values
    if "positions" in normalized and normalized["positions"] is not None:
        positions = normalized["positions"]

        # Handle string format (comma-separated values)
        if isinstance(positions, str):
            try:
                # Convert comma-separated string to list
                positions = [pos.strip() for pos in positions.split(",") if pos.strip()]
                normalized["positions"] = positions
            except ValueError:
                # Keep as string if conversion fails
                pass

        if isinstance(positions, list):
            normalized_positions = []
            for pos in positions:
                normalized_positions.append(
                    normalize_position_value(pos, SpecialParameterValues.ALL)
                )
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
                    method.strip().lower() for method in fooling_value.split(",") if method.strip()
                ]
                normalized[fooling_param] = fooling_list
            elif isinstance(fooling_value, list):
                # Normalize each method in the list
                normalized[fooling_param] = [
                    str(method).strip().lower() for method in fooling_value if str(method).strip()
                ]

    return normalized


def add_missing_attack_parameters(
    attack_type: str,
    params: Dict[str, Any],
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """
    Add missing parameters with sensible defaults for specific attack types.

    Args:
        attack_type: Type of attack
        params: Current parameters
        debug: Enable debug logging
        logger: Optional logger

    Returns:
        Parameters with defaults added
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    params = params.copy()

    # Add disorder_method for disorder-based attacks
    if any(
        disorder_attack in attack_type.lower() for disorder_attack in ["disorder", "fakeddisorder"]
    ):
        if "disorder_method" not in params:
            params["disorder_method"] = "reverse"  # Default to reverse
            if debug:
                logger.debug(f"Added default disorder_method='reverse' for {attack_type}")

    # Add TTL parameters for fake-based attacks
    if any(fake_attack in attack_type.lower() for fake_attack in ["fake", "fakeddisorder"]):
        if "ttl" not in params and "fake_ttl" not in params and "autottl" not in params:
            params["ttl"] = 3  # Default TTL
            if debug:
                logger.debug(f"Added default ttl=3 for {attack_type}")

    # Add split_pos for attacks that need it (if not already present)
    if any(split_attack in attack_type.lower() for split_attack in ["split", "disorder", "fake"]):
        if "split_pos" not in params:
            params["split_pos"] = 3  # Default split position
            if debug:
                logger.debug(f"Added default split_pos=3 for {attack_type}")

    # Add overlap_size for seqovl attacks
    if "seqovl" in attack_type.lower():
        if "overlap_size" not in params:
            params["overlap_size"] = 2  # Default overlap
            if debug:
                logger.debug(f"Added default overlap_size=2 for {attack_type}")

    return params


def apply_attack_specific_transformations(
    attack_type: str,
    params: Dict[str, Any],
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """
    Apply attack-specific parameter transformations.

    Args:
        attack_type: Type of attack
        params: Current parameters
        debug: Enable debug logging
        logger: Optional logger

    Returns:
        Transformed parameters
    """
    if logger is None:
        logger = logging.getLogger(__name__)

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
                if debug:
                    logger.debug(
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
                if debug:
                    logger.debug(
                        f"Generated positions {positions} from split_pos={split_pos}, split_count={split_count} for multidisorder"
                    )

    # Add missing parameters with defaults
    params = add_missing_attack_parameters(attack_type, params, debug, logger)

    return params
