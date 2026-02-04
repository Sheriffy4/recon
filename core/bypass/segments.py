"""
Canonical segment normalization and utilities.

Provides unified handling of various segment tuple formats used across the codebase.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

Segment = Tuple[bytes, int, Dict[str, Any]]


def delay_only_segment(
    delay_ms: Union[int, float],
    *,
    seq_offset: int = 0,
    options: Optional[Dict[str, Any]] = None,
    **extra: Any,
) -> Segment:
    """
    Create a segment that only schedules a delay (no packet should be sent).
    Consumer must treat payload==b"" and delay_only==True as "sleep only".

    Args:
        delay_ms: Delay in milliseconds
        seq_offset: Sequence offset (default 0)
        options: Additional options dict
        **extra: Extra options to merge

    Returns:
        Canonical segment tuple (b"", seq_offset, options)
    """
    opts = dict(options or {})
    opts.update(extra)
    opts["delay_ms"] = float(delay_ms or 0.0)
    opts["delay_only"] = True
    return (b"", int(seq_offset or 0), opts)


def normalize_segments(
    segments: Sequence[Any],
    *,
    resequence: bool = False,
    start_seq_offset: int = 0,
    legacy_2tuple_second_is_delay: bool = False,
) -> List[Segment]:
    """
    Normalize many segment-like forms into canonical:
      (payload: bytes, rel_seq: int, options: dict)

    Supported formats:
      - bytes
      - (data,)
      - (data, rel_seq)
      - (data, options_dict)
      - (data, rel_seq, options_dict)
      - (data, rel_seq, delay_ms)
      - (data, rel_seq, delay_ms, options_dict)

    Args:
        segments: Sequence of segment-like objects
        resequence: If True, rewrite rel_seq cumulatively in current list order.
                   DO NOT use for disorder/overlap recipes where rel_seq is meaningful.
        start_seq_offset: Starting sequence offset for resequencing
        legacy_2tuple_second_is_delay: If True, interpret (data, X) as
                                      (data, 0, {"delay_ms": X}) for timing encoders

    Returns:
        List of canonical segment tuples
    """
    out: List[Segment] = []
    cur = int(start_seq_offset or 0) & 0xFFFFFFFF

    for seg in segments or []:
        n = _normalize_one(seg, legacy_2tuple_second_is_delay=legacy_2tuple_second_is_delay)
        if n is None:
            continue
        data, rel, opts = n
        if resequence:
            rel = cur
            cur = (cur + len(data)) & 0xFFFFFFFF
        _normalize_delay_keys(opts)
        out.append((data, int(rel) & 0xFFFFFFFF, opts))
    return out


def _normalize_one(seg: Any, *, legacy_2tuple_second_is_delay: bool) -> Optional[Segment]:
    """Normalize a single segment to canonical form."""
    if isinstance(seg, (bytes, bytearray, memoryview)):
        return (bytes(seg), 0, {})

    if not isinstance(seg, tuple) or len(seg) == 0:
        return None

    data = seg[0]
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    data_b = bytes(data)

    if len(seg) == 1:
        return (data_b, 0, {})

    if len(seg) == 2:
        second = seg[1]
        if isinstance(second, dict):
            opts = dict(second)
            rel = int(opts.get("rel_seq", opts.get("seq_offset", 0)) or 0)
            return (data_b, rel, opts)
        if legacy_2tuple_second_is_delay:
            try:
                d = float(second or 0.0)
            except Exception:
                d = 0.0
            return (data_b, 0, {"delay_ms": d})
        try:
            return (data_b, int(second or 0), {})
        except Exception:
            return (data_b, 0, {})

    # 3+ tuple
    second = seg[1]
    third = seg[2]

    if isinstance(third, dict):
        try:
            rel = int(second or 0)
        except Exception:
            rel = 0
        return (data_b, rel, dict(third))

    # tolerate (data, rel_seq, delay_ms)
    try:
        rel = int(second or 0)
    except Exception:
        rel = 0
    try:
        d = float(third or 0.0)
    except Exception:
        d = 0.0
    opts: Dict[str, Any] = {"delay_ms": d}

    if len(seg) >= 4 and isinstance(seg[3], dict):
        opts.update(dict(seg[3]))

    return (data_b, rel, opts)


def _normalize_delay_keys(opts: Dict[str, Any]) -> None:
    """
    Normalize delay-related keys in options dict.

    Converts delay_ms and delay_ms_after to float.
    Mirrors delay_ms into delay_ms_after if not present (since sending logic
    treats delay as "after-send" in PacketSender).
    """
    # Convert to float where possible
    if "delay_ms" in opts:
        try:
            opts["delay_ms"] = float(opts["delay_ms"] or 0.0)
        except Exception:
            opts["delay_ms"] = 0.0
    if "delay_ms_after" in opts:
        try:
            opts["delay_ms_after"] = float(opts["delay_ms_after"] or 0.0)
        except Exception:
            opts["delay_ms_after"] = 0.0

    # Your sending logic treats delay as "after-send" (PacketSender sleeps after).
    # So if only delay_ms is provided, mirror it into delay_ms_after.
    if "delay_ms_after" not in opts and "delay_ms" in opts:
        opts["delay_ms_after"] = opts["delay_ms"]
