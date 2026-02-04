"""
Strategy configuration converter for bypass engine.

This module converts high-level strategy configurations into detailed
strategy task dictionaries used by the bypass engine.
Extracted from base_engine.py to reduce god class complexity.
"""

from typing import Dict, List, Any


def build_multisplit_positions(split_count: int, overlap: int = 20) -> List[int]:
    """
    Build position list for multisplit strategy.

    For multisplit attacks, this function generates a list of byte positions
    where the packet should be split. The positions are calculated to ensure
    effective DPI evasion while maintaining packet integrity.

    Args:
        split_count: Number of splits to create (must be > 0)
        overlap: Overlap size between segments (default: 20 bytes)

    Returns:
        List of byte positions for splitting. For example:
        - split_count=1: [6]
        - split_count=2: [6, 12]
        - split_count=3: [6, 12, 18]
        - split_count=4: [6, 14, 26, 46]

    Examples:
        >>> build_multisplit_positions(3)
        [6, 12, 18]
        >>> build_multisplit_positions(5)
        [6, 14, 26, 46, 70]
    """
    if split_count <= 0:
        return []

    # For small split counts (1-3), use simple fixed positions
    if split_count <= 3:
        return [6, 12, 18][:split_count]

    # For larger split counts, use progressive gaps
    positions = []
    base_offset = 6
    gaps = [8, 12, 16, 20, 24]  # Progressive gap sizes
    last_pos = base_offset

    for i in range(split_count):
        positions.append(last_pos)
        # Use gap from list, or repeat last gap if we run out
        gap = gaps[i] if i < len(gaps) else gaps[-1]
        last_pos += gap

    return positions


def config_to_strategy_task(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert strategy configuration to strategy task dictionary.

    This function transforms a high-level strategy configuration (typically
    from domain rules or user input) into a detailed strategy task that can
    be executed by the bypass engine.

    Supported desync methods:
    - multisplit: Split packet into multiple segments
    - fake: Send fake packet before real one
    - fakeddisorder: Send fake packet with disorder
    - seqovl: Sequence overlap attack

    Supported fooling methods:
    - badsum: Bad checksum in fake packet
    - md5sig: MD5 signature manipulation
    - badseq: Bad sequence number

    Args:
        config: Strategy configuration dictionary with keys:
            - desync_method: Method to use (default: "fake")
            - fooling: Fooling technique (default: "badsum")
            - ttl: Time-to-live value (default: 3)
            - split_pos: Position to split packet (default: 3)
            - split_count: Number of splits for multisplit (default: 3)
            - overlap_size: Overlap size for seqovl (default: 20)

    Returns:
        Strategy task dictionary with:
        - type: Strategy type identifier
        - params: Strategy parameters
        - no_fallbacks: Whether to disable fallback strategies
        - forced: Whether to force this strategy

    Examples:
        >>> config = {"desync_method": "multisplit", "split_count": 3}
        >>> task = config_to_strategy_task(config)
        >>> task['type']
        'multisplit'
        >>> len(task['params']['positions'])
        3
    """
    # Extract configuration parameters with defaults
    desync_method = config.get("desync_method", "fake")
    fooling = config.get("fooling", "badsum")
    fooling_explicit = "fooling" in config  # Track if fooling was explicitly set
    ttl = config.get("ttl", 3)
    split_pos = config.get("split_pos", 3)

    # Handle multisplit strategy
    if desync_method == "multisplit":
        split_count = config.get("split_count", 3)
        overlap = config.get("overlap_size", 20)

        # Build position list for splits
        positions = build_multisplit_positions(split_count, overlap)

        return {
            "type": "multisplit",
            "params": {
                "ttl": ttl,
                "split_pos": split_pos,
                "positions": positions,
                "overlap_size": overlap,
                "fooling": fooling,
                "window_div": 2,  # TCP window divisor
                "tcp_flags": {
                    "psh": True,  # Push flag
                    "ack": True,  # Acknowledgment flag
                    "no_fallbacks": True,
                    "forced": True,
                },
                "ipid_step": 2048,  # IP ID increment step
                "delay_ms": 5,  # Delay between packets in milliseconds
            },
        }

    # Handle fake/fakeddisorder/seqovl strategies
    elif desync_method in ("fake", "fakeddisorder", "seqovl"):
        # Base parameters common to all these strategies
        base_params = {
            "ttl": ttl,
            "split_pos": split_pos,
            "window_div": 8,  # TCP window divisor
            "tcp_flags": {"psh": True, "ack": True},
            "ipid_step": 2048,
        }

        # Determine task type based on desync_method and fooling
        # Priority: seqovl > fakeddisorder > fooling methods (if explicit)
        if desync_method == "seqovl":
            task_type = "seqovl"
            base_params["overlap_size"] = config.get("overlap_size", 20)
        elif desync_method == "fakeddisorder":
            task_type = "fakeddisorder"
        elif fooling_explicit and fooling in ("badsum", "md5sig", "badseq"):
            # IMPORTANT: do not invent attack types like "badsum_race" / "md5sig_race".
            # Encode this as a normal 'fake' attack with fooling + ttl.
            task_type = "fake"
            base_params["fooling"] = fooling
            # Keep previous "tuning" as optional params (may be ignored by some handlers).
            if fooling == "badsum":
                base_params["extra_ttl"] = ttl + 1
                base_params["delay_ms"] = 5
            elif fooling == "md5sig":
                base_params["extra_ttl"] = ttl + 2
                base_params["delay_ms"] = 7
        else:
            # Default to fakeddisorder for fake method or when fooling not explicit
            task_type = "fakeddisorder"

        return {
            "type": task_type,
            "params": base_params,
            "no_fallbacks": True,
            "forced": True,
        }

    # Default fallback strategy
    return {
        "type": "fakeddisorder",
        "params": {
            "ttl": ttl,
            "split_pos": split_pos,
            "window_div": 8,
            "tcp_flags": {
                "psh": True,
                "ack": True,
                "no_fallbacks": True,
                "forced": True,
            },
            "ipid_step": 2048,
        },
    }
