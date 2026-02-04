"""
Parsing Utilities Module

Common utilities for parsing strategy strings and values.
"""

from typing import Any, List


def smart_split(text: str, delimiter: str) -> List[str]:
    """
    Split by delimiter, ignoring delimiters inside quotes and nested brackets/parens/braces.

    Args:
        text: Text to split
        delimiter: Delimiter character

    Returns:
        List of split parts
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


def parse_value(value_str: str) -> Any:
    """
    Parse a parameter value string to appropriate Python type.

    Args:
        value_str: String value to parse

    Returns:
        Parsed value (int, float, bool, str, list, or None)
    """
    value_str = value_str.strip()
    if not value_str:
        return None
    if value_str.startswith("[") and value_str.endswith("]"):
        return parse_list(value_str)
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


def parse_list(list_str: str) -> List[Any]:
    """
    Parse a list string like ['item1', 'item2'] to Python list.

    Args:
        list_str: String representation of a list

    Returns:
        Parsed list
    """
    content = list_str[1:-1].strip()
    if not content:
        return []
    return [parse_value(item.strip()) for item in smart_split(content, ",")]
