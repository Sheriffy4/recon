"""
Zapret Command Building Utilities

Shared utilities for building and manipulating zapret commands.
Provides deduplication, technique mapping, and command combination logic.
"""

from typing import List, Dict, Any


# Technique name to zapret command mapping
TECHNIQUE_MAP = {
    "tcp_segmentation": "--dpi-desync=disorder --dpi-desync-split-pos=3",
    "ip_fragmentation": "--dpi-desync=ipfrag2 --dpi-desync-split-pos=24",
    "tls_record_split": "--tlsrec=5",
    "http_header_case": "--hostcase",
    "badsum_fooling": "--dpi-desync=fake --dpi-desync-fooling=badsum",
    "ttl_manipulation": "--dpi-desync=fake --dpi-desync-ttl=5",
    "tcp_http_combo": "--dpi-desync=disorder --dpi-desync-split-pos=3 --hostcase",
    "badsum_race": "--dpi-desync=fake --dpi-desync-fooling=badsum",
    "quic_fragmentation": "--quic-frag=100",
    "tls13_0rtt_tunnel": "--tlsrec=5",
    "early_data_smuggling": "--dpi-desync=fake --dpi-desync-fake-tls=!",
    "md5sig_fooling": "--dpi-desync=fake --dpi-desync-fooling=md5sig",
}


# Base technique commands for steganography
BASE_TECHNIQUE_COMMANDS = {
    "tcp_segmentation": "--dpi-desync=disorder --dpi-desync-split-pos=3",
    "ip_fragmentation": "--dpi-desync=ipfrag2 --dpi-desync-split-pos=24",
    "tls_record_split": "--tlsrec=5",
}


def deduplicate_params(command_parts: List[str]) -> str:
    """
    Deduplicate zapret parameters while preserving order.

    Args:
        command_parts: List of command strings or single command string

    Returns:
        Deduplicated command string with parameters in original order

    Example:
        >>> deduplicate_params(["--hostcase", "--hostcase --tlsrec=5"])
        "--hostcase --tlsrec=5"
    """
    if not command_parts:
        return ""

    # Join all parts and split into individual parameters
    all_params = " ".join(command_parts).split()

    # Remove duplicates while preserving order
    unique_parts = []
    seen = set()
    for part in all_params:
        if part not in seen:
            unique_parts.append(part)
            seen.add(part)

    return " ".join(unique_parts)


def get_technique_command(technique: str, params: Dict[str, Any] = None) -> str:
    """
    Map technique name to zapret command with optional parameters.

    Args:
        technique: Name of the technique (e.g., "tcp_segmentation")
        params: Optional parameters to customize the command

    Returns:
        Zapret command string or empty string if technique not found

    Example:
        >>> get_technique_command("tcp_segmentation", {"segment_size": 5})
        "--dpi-desync=disorder --dpi-desync-split-pos=5"
    """
    if params is None:
        params = {}

    # Handle special cases with parameters
    if technique == "tcp_segmentation" and "segment_size" in params:
        size = params["segment_size"]
        return f"--dpi-desync=disorder --dpi-desync-split-pos={size}"

    # Return standard mapping
    return TECHNIQUE_MAP.get(technique, "")


def combine_commands(commands: List[str], deduplicate: bool = True) -> str:
    """
    Combine multiple zapret commands into a single command.

    Args:
        commands: List of command strings to combine
        deduplicate: Whether to remove duplicate parameters (default: True)

    Returns:
        Combined command string

    Example:
        >>> combine_commands(["--hostcase", "--tlsrec=5", "--hostcase"])
        "--hostcase --tlsrec=5"
    """
    if not commands:
        return ""

    # Filter out empty commands
    valid_commands = [cmd for cmd in commands if cmd and cmd.strip()]

    if not valid_commands:
        return ""

    if deduplicate:
        return deduplicate_params(valid_commands)
    else:
        return " ".join(valid_commands)


def has_parameter(command: str, param: str) -> bool:
    """
    Check if a command string contains a specific parameter.

    Args:
        command: Command string to check
        param: Parameter to look for (e.g., "--hostcase" or "hostcase")

    Returns:
        True if parameter is present, False otherwise

    Example:
        >>> has_parameter("--hostcase --tlsrec=5", "--hostcase")
        True
    """
    if not command or not param:
        return False

    # Normalize parameter (add -- if missing)
    normalized_param = param if param.startswith("--") else f"--{param}"

    return normalized_param in command.split()
