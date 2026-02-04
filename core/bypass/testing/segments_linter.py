"""
Segments linter for AttackResult.metadata["segments"].

Engine canonical format:
    (data: bytes, seq_offset: int, options: dict)

Important:
  - PacketProcessingEngine interprets tuple[1] strictly as seq_offset.
  - Delay must be placed in options["delay_ms"].
  - Legacy formats are accepted by engine, but are easy to misuse:
        (data, delay)  -> engine treats "delay" as seq_offset (BUG).

Use this module in unit tests to validate/lock the format early.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Union

BytesLike = Union[bytes, bytearray, memoryview]


@dataclass(frozen=True)
class SegmentIssue:
    index: int
    level: str  # "ERROR" | "WARN"
    message: str


def lint_segments(
    segments: Any,
    *,
    strict: bool = True,
    require_delay_ms: bool = False,
    max_delay_ms: int = 600_000,
    allow_empty_payload: bool = True,
) -> List[SegmentIssue]:
    """
    Validate 'segments' structure.

    strict=True:
      - only allows 3-tuples: (bytes, int, dict)
      - forbids raw-bytes segments and 2-tuples

    strict=False:
      - allows engine-legacy formats, but emits warnings for suspicious ones.
    """
    issues: List[SegmentIssue] = []

    if segments is None:
        return issues

    if not isinstance(segments, (list, tuple)):
        return [
            SegmentIssue(
                index=-1,
                level="ERROR",
                message=f"segments must be list/tuple, got {type(segments).__name__}",
            )
        ]

    for i, seg in enumerate(segments):
        # bytes-like segment
        if isinstance(seg, (bytes, bytearray, memoryview)):
            if strict:
                issues.append(
                    SegmentIssue(
                        i,
                        "ERROR",
                        "segment must be 3-tuple (data, seq_offset, options), got bytes-like",
                    )
                )
            else:
                data = bytes(seg)
                if not allow_empty_payload and len(data) == 0:
                    issues.append(SegmentIssue(i, "ERROR", "empty payload segment"))
            continue

        if not isinstance(seg, tuple):
            issues.append(
                SegmentIssue(i, "ERROR", f"segment must be tuple/bytes, got {type(seg).__name__}")
            )
            continue

        if len(seg) == 0:
            issues.append(SegmentIssue(i, "ERROR", "empty tuple segment"))
            continue

        if strict and len(seg) != 3:
            issues.append(
                SegmentIssue(i, "ERROR", f"segment tuple length must be 3, got {len(seg)}")
            )

        # data
        data = seg[0]
        if not isinstance(data, (bytes, bytearray, memoryview)):
            issues.append(
                SegmentIssue(
                    i, "ERROR", f"segment[0] must be bytes-like, got {type(data).__name__}"
                )
            )
        else:
            if not allow_empty_payload and len(bytes(data)) == 0:
                issues.append(SegmentIssue(i, "ERROR", "segment payload is empty"))

        # seq_offset (or legacy ambiguous delay)
        if len(seg) >= 2:
            if not isinstance(seg[1], int):
                try:
                    int(seg[1])
                except Exception:
                    issues.append(
                        SegmentIssue(
                            i,
                            "ERROR",
                            f"segment[1] must be int (seq_offset), got {type(seg[1]).__name__}",
                        )
                    )

        # options
        if len(seg) >= 3:
            opts = seg[2]
            if not isinstance(opts, dict):
                issues.append(
                    SegmentIssue(
                        i, "ERROR", f"segment[2] must be dict options, got {type(opts).__name__}"
                    )
                )
                continue

            if require_delay_ms and "delay_ms" not in opts:
                issues.append(SegmentIssue(i, "ERROR", 'options missing required key "delay_ms"'))

            if "delay_ms" in opts:
                dm = opts.get("delay_ms", 0)
                try:
                    dm_i = int(dm)
                except Exception:
                    issues.append(
                        SegmentIssue(
                            i,
                            "ERROR",
                            f'options["delay_ms"] must be int, got {type(dm).__name__}',
                        )
                    )
                else:
                    if dm_i < 0:
                        issues.append(
                            SegmentIssue(i, "ERROR", f"delay_ms must be >= 0, got {dm_i}")
                        )
                    if dm_i > max_delay_ms:
                        issues.append(
                            SegmentIssue(i, "ERROR", f"delay_ms too large: {dm_i} > {max_delay_ms}")
                        )

            # heuristic: common bug (data, delay, options) -> delay accidentally in seg[1]
            if not strict:
                if (
                    "delay_ms" not in opts
                    and isinstance(seg[1], int)
                    and 0 < seg[1] <= max_delay_ms
                ):
                    issues.append(
                        SegmentIssue(
                            i,
                            "WARN",
                            "suspicious segment: looks like (data, delay, options) but delay_ms is missing; "
                            "engine will treat tuple[1] as seq_offset",
                        )
                    )

        # legacy 2-tuple (data, int) is ambiguous and risky
        if (
            not strict
            and len(seg) == 2
            and isinstance(seg[0], (bytes, bytearray, memoryview))
            and isinstance(seg[1], int)
        ):
            issues.append(
                SegmentIssue(
                    i,
                    "WARN",
                    "legacy 2-tuple (data, int) is ambiguous: engine treats int as seq_offset; "
                    "if it was a delay, it is a bug. Prefer 3-tuple with options['delay_ms']",
                )
            )

    return issues


def assert_segments_valid(segments: Any, **kwargs: Any) -> None:
    issues = lint_segments(segments, **kwargs)
    errors = [x for x in issues if x.level != "WARN"]
    if errors:
        lines = ["segments lint failed:"]
        for iss in issues:
            lines.append(f"- [{iss.level}] #{iss.index}: {iss.message}")
        raise AssertionError("\n".join(lines))


def assert_attack_result_segments_valid(result: Any, **kwargs: Any) -> None:
    metadata = getattr(result, "metadata", None) or {}
    assert_segments_valid(metadata.get("segments"), **kwargs)
