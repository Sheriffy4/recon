"""
Format Detection Module

Detects the format of strategy strings for appropriate parsing.
"""

import re
from typing import Set


def is_zapret_style(strategy: str) -> bool:
    """Check if strategy is in Zapret command-line format."""
    return "--dpi-desync" in strategy


def is_function_style(strategy: str) -> bool:
    """Check if strategy is in function call format: attack(param1=value1, param2=value2)."""
    return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*$", strategy))


def is_colon_style(strategy: str) -> bool:
    """Check if strategy is in colon-separated format: attack:param1=value1,param2=value2."""
    return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*:[^:]+$", strategy))


def is_semicolon_combo_style(strategy: str) -> bool:
    """
    Check if strategy is in semicolon combo format.

    Format: "attack1,attack2; k=v; k=v" OR "attack; k=v"
    """
    if "--" in strategy or ":" in strategy or "(" in strategy or ")" in strategy:
        return False
    if ";" not in strategy:
        return False
    head = strategy.split(";", 1)[0].strip()
    # head — список атак через запятую или одиночная атака без '='
    return head and "=" not in head


def is_comma_separated_combo(strategy: str) -> bool:
    """Check if string is a comma-separated combo attack (e.g., 'disorder,multisplit')."""
    # Must contain comma and no other special characters
    if "," not in strategy:
        return False
    if any(char in strategy for char in [":", ";", "(", ")", "=", "--"]):
        return False

    # Split by comma and check if all parts are valid attack names
    parts = [part.strip() for part in strategy.split(",")]
    if len(parts) < 2:
        return False

    # Check if all parts look like attack names (alphanumeric + underscore)
    for part in parts:
        if not part or not part.replace("_", "").replace("-", "").isalnum():
            return False

    return True


def is_simple_attack_name(strategy: str, known_attacks: Set[str] = None) -> bool:
    """
    Check if string is a simple attack name without parameters.

    Args:
        strategy: Strategy string to check
        known_attacks: Optional set of known attack names for validation
    """
    # Простое имя: только буквы, цифры, подчеркивания
    # Без специальных символов: --:;=(),
    if any(char in strategy for char in ["--", ":", ";", "=", "(", ")", ","]):
        return False
    # Должно содержать только допустимые символы
    return strategy.replace("_", "").replace("-", "").isalnum()
