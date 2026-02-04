"""
Segment Schema Utilities (v1)

This module defines a unified SegmentTuple contract used by obfuscation attacks.

SegmentTuple format:
    (payload_bytes: bytes, seq_offset: int, options: Dict[str, Any])

Key rule:
    Delay must be encoded only in options["delay_ms"] (non-negative int).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Tuple, Optional, List, Sequence


SegmentTuple = Tuple[bytes, int, Dict[str, Any]]

LOG = logging.getLogger(__name__)

# Strict canonical values (normalized by make_segment()).
ALLOWED_DIRECTIONS = {"c2s", "s2c", "unknown"}
ALLOWED_SEGMENT_KINDS = {
    "handshake",
    "data",
    "control",
    "padding",
    "fake",
    "gap",
    "encrypted_data",
    "covert",
    "unknown",
}

# Normalization aliases from older/other modules.
DIRECTION_ALIASES = {
    "client_to_server": "c2s",
    "server_to_client": "s2c",
    "outbound": "c2s",
    "inbound": "s2c",
    "unknown": "unknown",
    "c2s": "c2s",
    "s2c": "s2c",
}

SEGMENT_KIND_ALIASES = {
    "handshake": "handshake",
    "data": "data",
    "control": "control",
    "padding": "padding",
    "fake": "fake",
    "gap": "gap",
    "encrypted": "encrypted_data",
    "encrypted_data": "encrypted_data",
    "covert": "covert",
    "unknown": "unknown",
}


def _as_nonneg_int(value: Any, default: int = 0) -> int:
    try:
        iv = int(value)
    except (TypeError, ValueError):
        return int(default)
    return iv if iv >= 0 else 0


def _normalize_direction(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, str):
        v = value.strip().lower()
        return DIRECTION_ALIASES.get(v, "unknown")
    return "unknown"


def _normalize_segment_kind(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, str):
        v = value.strip().lower()
        return SEGMENT_KIND_ALIASES.get(v, "unknown")
    return "unknown"


def make_segment(
    payload: bytes,
    seq_offset: int,
    *,
    delay_ms: Any = 0,
    protocol: Optional[str] = None,
    attack: Optional[str] = None,
    segment_index: Optional[int] = None,
    segment_kind: Optional[str] = None,
    direction: Optional[str] = None,
    **options: Any,
) -> SegmentTuple:
    """
    Build a segment in unified engine-compatible format.

    Args:
        payload: bytes to send
        seq_offset: stream offset (TCP-like). For UDP/ICMP can be 0 or virtual.
        delay_ms: optional delay before sending this segment (ms)
        protocol/attack/segment_index/segment_kind/direction: standard metadata
        **options: additional metadata
    """
    opts: Dict[str, Any] = dict(options or {})
    if protocol is not None:
        opts.setdefault("protocol", protocol)
    if attack is not None:
        opts.setdefault("attack", attack)
    if segment_index is not None:
        opts.setdefault("segment_index", segment_index)
    if segment_kind is not None:
        opts.setdefault("segment_kind", segment_kind)
    if direction is not None:
        opts.setdefault("direction", direction)

    # Single source of truth for delay:
    # If legacy "delay" exists, treat it as delay_ms unless delay_ms already set.
    if "delay_ms" not in opts and "delay" in opts:
        opts["delay_ms"] = opts.get("delay")
    opts["delay_ms"] = _as_nonneg_int(opts.get("delay_ms", delay_ms), 0)

    # Enforce canonical direction / kind.
    opts["direction"] = _normalize_direction(opts.get("direction"))
    opts["segment_kind"] = _normalize_segment_kind(opts.get("segment_kind"))

    try:
        seq = int(seq_offset) & 0xFFFFFFFF
    except (TypeError, ValueError):
        seq = 0

    return (payload or b"", seq, opts)


def next_seq_offset(seq_offset: int, payload_len: int) -> int:
    """Helper to update seq_offset in 32-bit wraparound space."""
    try:
        return (int(seq_offset) + int(payload_len)) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return 0


def normalize_segment(
    seg: Any,
    *,
    seq_offset_fallback: int = 0,
    treat_second_as: str = "seq_offset",
    protocol: Optional[str] = None,
    attack: Optional[str] = None,
    segment_index: Optional[int] = None,
) -> SegmentTuple:
    """
    Normalize a possibly-legacy segment into SegmentTuple v1.

    Legacy formats seen in the codebase:
      - (payload, delay_ms, meta)  # WRONG for engines that expect seq_offset
      - (payload, seq_offset, meta)  # correct

    Args:
        seg: incoming segment-like object
        seq_offset_fallback: used when treat_second_as == "delay"
        treat_second_as: "seq_offset" (default) or "delay"
        protocol/attack/segment_index: optionally enrich metadata
    """
    if not (isinstance(seg, tuple) and len(seg) == 3):
        return make_segment(
            b"",
            0,
            delay_ms=0,
            protocol=protocol,
            attack=attack,
            segment_index=segment_index,
            segment_kind="unknown",
            direction="unknown",
        )

    payload, second, meta = seg
    if not isinstance(payload, (bytes, bytearray)):
        payload = b""
    payload = bytes(payload)
    if not isinstance(meta, dict):
        meta = {}

    if treat_second_as == "delay":
        delay_ms = meta.get("delay_ms", second)
        seq_offset = seq_offset_fallback
    else:
        seq_offset = second
        delay_ms = meta.get("delay_ms", meta.get("delay", 0))

    # Keep all meta keys, but enforce single source of truth for delay_ms.
    return make_segment(
        payload,
        seq_offset,
        delay_ms=delay_ms,
        protocol=protocol,
        attack=attack,
        segment_index=segment_index,
        **meta,
    )


def normalize_segments(
    segments: Any,
    *,
    treat_second_as: str = "seq_offset",
    protocol: Optional[str] = None,
    attack: Optional[str] = None,
) -> List[SegmentTuple]:
    """Normalize a list of segments; best-effort safe conversion."""
    if not segments:
        return []
    out: List[SegmentTuple] = []
    seq_offset = 0
    for idx, seg in enumerate(segments):
        normalized = normalize_segment(
            seg,
            seq_offset_fallback=seq_offset,
            treat_second_as=treat_second_as,
            protocol=protocol,
            attack=attack,
            segment_index=idx,
        )
        out.append(normalized)
        seq_offset = next_seq_offset(seq_offset, len(normalized[0]))
    return out


def validate_segment(
    seg: Any, *, strict: bool = False, logger: Optional[logging.Logger] = None
) -> bool:
    """
    Validate SegmentTuple v1.
    - tuple of len==3
    - payload is bytes
    - seq_offset is int
    - options is dict and contains delay_ms>=0, direction in allowed, segment_kind in allowed
    """
    log = logger or LOG
    ok = True

    if not (isinstance(seg, tuple) and len(seg) == 3):
        ok = False
        msg = f"Invalid segment shape: expected tuple(payload, seq_offset, options), got={type(seg)} value={seg!r}"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)
        return False

    payload, seq_offset, options = seg
    if not isinstance(payload, (bytes, bytearray)):
        ok = False
        msg = f"Invalid segment payload type: {type(payload)}"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)
    if not isinstance(seq_offset, int):
        ok = False
        msg = f"Invalid segment seq_offset type: {type(seq_offset)}"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)
    if not isinstance(options, dict):
        ok = False
        msg = f"Invalid segment options type: {type(options)}"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)
        return False

    delay_ms = options.get("delay_ms", 0)
    if not isinstance(delay_ms, int) or delay_ms < 0:
        ok = False
        msg = f"Invalid delay_ms: {delay_ms!r}"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)

    direction = options.get("direction", "unknown")
    if direction not in ALLOWED_DIRECTIONS:
        ok = False
        msg = f"Invalid direction: {direction!r} (allowed={sorted(ALLOWED_DIRECTIONS)})"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)

    kind = options.get("segment_kind", "unknown")
    if kind not in ALLOWED_SEGMENT_KINDS:
        ok = False
        msg = f"Invalid segment_kind: {kind!r} (allowed={sorted(ALLOWED_SEGMENT_KINDS)})"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)

    return ok


def validate_segments(
    segments: Any,
    *,
    strict: bool = False,
    logger: Optional[logging.Logger] = None,
    max_warnings: int = 5,
) -> bool:
    """Validate a sequence of segments; logs up to max_warnings problems."""
    log = logger or LOG
    if segments is None:
        return True
    if not isinstance(segments, list):
        msg = f"segments must be a list, got {type(segments)}"
        if strict:
            raise AssertionError(msg)
        log.warning(msg)
        return False

    ok = True
    warned = 0
    for idx, seg in enumerate(segments):
        try:
            if not validate_segment(seg, strict=strict, logger=log):
                ok = False
                warned += 1
                if warned >= max_warnings and not strict:
                    log.warning("Too many segment validation issues; suppressing further warnings.")
                    break
        except AssertionError:
            raise
        except Exception as e:
            ok = False
            warned += 1
            msg = f"Segment validation exception at index={idx}: {e}"
            if strict:
                raise AssertionError(msg)
            log.warning(msg)
            if warned >= max_warnings:
                break
    return ok


def _guess_second_field_meaning(segments: Sequence[Any]) -> str:
    """
    Heuristic:
      - seq_offset should approximately equal cumulative sum of previous payload lengths
      - delay_ms usually looks like small-ish numbers and not equal to that cumulative sum
    Returns: "seq_offset" or "delay"
    """
    if not segments:
        return "seq_offset"
    if not isinstance(segments, list):
        return "seq_offset"

    expected = 0
    matches = 0
    comparable = 0
    small_second = 0
    for seg in segments[:50]:
        if not (isinstance(seg, tuple) and len(seg) == 3):
            continue
        payload, second, meta = seg
        if not isinstance(payload, (bytes, bytearray)):
            continue
        if not isinstance(second, int):
            try:
                second = int(second)
            except Exception:
                continue
        comparable += 1
        if second == expected:
            matches += 1
        if second >= 0 and second <= 5000:
            small_second += 1
        expected = next_seq_offset(expected, len(payload))

    if comparable == 0:
        return "seq_offset"
    match_ratio = matches / comparable
    small_ratio = small_second / comparable

    # If offsets rarely match expected cumulative progression but "second" is mostly small, treat as delay.
    if match_ratio < 0.3 and small_ratio > 0.7:
        return "delay"
    return "seq_offset"


def repair_segments(
    segments: Any,
    *,
    protocol: Optional[str] = None,
    attack: Optional[str] = None,
    treat_second_as: str = "auto",
    logger: Optional[logging.Logger] = None,
) -> List[SegmentTuple]:
    """
    Repair/enrich segments:
      - normalize tuple shape
      - ensure delay_ms is present and non-negative
      - normalize direction and segment_kind
      - add protocol/attack if missing
      - if treat_second_as == "auto", guess legacy (payload, delay, meta) vs (payload, seq, meta)
    """
    log = logger or LOG
    if segments is None:
        return []
    if not isinstance(segments, list):
        # Can't repair unknown container; return empty safe value.
        log.warning("repair_segments expected list, got %s", type(segments))
        return []

    if treat_second_as == "auto":
        mode = _guess_second_field_meaning(segments)
    else:
        mode = treat_second_as

    fixed = normalize_segments(segments, treat_second_as=mode, protocol=protocol, attack=attack)
    return fixed


def set_and_validate_segments(
    metadata: Dict[str, Any],
    segments: Any,
    *,
    logger: Optional[logging.Logger] = None,
    strict: bool = False,
    repair: bool = False,
    treat_second_as: str = "auto",
    protocol: Optional[str] = None,
    attack: Optional[str] = None,
) -> Any:
    """
    Set metadata['segments'] and validate immediately (assert/log).
    Returns the same segments reference.

    If repair=True, attempts to auto-repair invalid segments before validation.
    """
    log = logger or LOG

    def _set(value: Any) -> Any:
        metadata["segments"] = value
        return value

    _set(segments)

    ok = validate_segments(segments, strict=strict, logger=log)
    if ok or not repair or segments is None:
        return segments

    # Best-effort auto-repair: normalize legacy segments and enrich metadata.
    try:
        fixed = repair_segments(
            segments,
            protocol=protocol,
            attack=attack,
            treat_second_as=treat_second_as,
            logger=log,
        )
        _set(fixed)
        validate_segments(fixed, strict=strict, logger=log)
        return fixed
    except Exception as e:
        # Keep original segments; already logged validation issues.
        log.warning("Failed to repair segments: %s", e)
        return segments
