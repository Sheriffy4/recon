"""
Recipe to TCP segment specification converter.

This module converts attack recipes (list of payload chunks with options)
into TCP segment specifications ready for packet building. Extracted from
base_engine.py to reduce god class complexity.
"""

import logging
from typing import List, Tuple, Dict, Optional, Any
from core.bypass.packet.types import TCPSegmentSpec


def recipe_to_tcp_specs(
    recipe: List[Tuple[bytes, int, dict]],
    payload: bytes,
    strategy_task: Optional[Dict],
    logger: logging.Logger,
    debug: bool = False,
) -> List[TCPSegmentSpec]:
    """
    Convert attack recipe to TCP segment specifications.

    Args:
        recipe: List of (payload_chunk, offset, options) tuples
        payload: Original full payload
        strategy_task: Strategy configuration dict
        logger: Logger instance
        debug: Enable debug logging

    Returns:
        List of TCPSegmentSpec objects ready for packet building
    """
    if not recipe or not isinstance(recipe, (list, tuple)):
        logger.error(f"Invalid recipe type: {type(recipe)}")
        return []

    # Canonicalize recipe items
    from core.bypass.segments import normalize_segments

    canon = normalize_segments(recipe, resequence=False, legacy_2tuple_second_is_delay=False)

    specs: List[TCPSegmentSpec] = []
    total_items = len(canon)

    for i, recipe_item in enumerate(canon):
        try:
            seg_payload, offset, opts = recipe_item

            if not isinstance(offset, int):
                logger.error(f"Offset in item #{i} is not a number. Skipping.")
                continue
            if not isinstance(opts, dict):
                logger.error(f"Options in item #{i} is not a dict. Skipping.")
                continue

            is_fake = bool(opts.get("is_fake", False))
            is_delay_only = bool(opts.get("delay_only") or opts.get("is_session_gap"))
            ttl = None
            if opts.get("ttl") is not None:
                try:
                    ttl = int(opts["ttl"])
                except (TypeError, ValueError):
                    logger.warning("Invalid ttl=%r in recipe item #%d; ignoring ttl", opts.get("ttl"), i)
                    ttl = None

            # Parse TCP flags
            tcp_flags = _parse_tcp_flags(opts, logger)

            # Sanitize FIN flag
            if tcp_flags & 0x01:
                if not opts.get("allow_fin", False):
                    logger.warning(f"🛡️ FIN-Sanitizer: Removed FIN flag in segment #{i}.")
                    tcp_flags &= ~0x01

            # Normalize flags for real segments
            valid_real_flags = [0x10, 0x18]
            if not is_fake and tcp_flags not in valid_real_flags:
                logger.warning(
                    f"🛡️ Flag-Normalizer: Non-standard TCP flags 0x{tcp_flags:02X} "
                    f"in real segment #{i}, normalizing to PSH+ACK (0x18)."
                )
                tcp_flags = 0x18

            # Validate rel_seq
            payload_len = len(payload or b"")
            if not is_fake and not is_delay_only and payload_len > 0:
                if offset >= payload_len:
                    logger.error(
                        f"❌ INVALID rel_seq in REAL segment #{i}: rel_seq={offset} >= "
                        f"payload_len={payload_len}. Segment will be skipped."
                    )
                    continue

            if debug:
                logger.debug(
                    f"✅ rel_seq validation passed for segment #{i}: "
                    f"rel_seq={offset}, payload_len={payload_len}, is_fake={is_fake}"
                )

            # Determine sequence offset
            final_seq_offset, final_seq_extra = _determine_seq_offset(opts)

            spec = TCPSegmentSpec(
                rel_seq=offset,
                payload=seg_payload,
                flags=tcp_flags,
                ttl=ttl,
                corrupt_tcp_checksum=bool(opts.get("corrupt_tcp_checksum", False)),
                add_md5sig_option=bool(opts.get("add_md5sig_option", False)),
                seq_offset=final_seq_offset,
                seq_extra=final_seq_extra,
                fooling_sni=opts.get("fooling_sni"),
                is_fake=is_fake,
                delay_ms_after=(
                    int(opts.get("delay_ms_after", opts.get("delay_ms", 0)) or 0)
                    if (i < total_items - 1 or is_delay_only)
                    else 0
                ),
                preserve_window_size=bool(opts.get("preserve_window_size", not is_fake)),
            )
            specs.append(spec)

        except Exception as e:
            logger.error(f"Error processing recipe item #{i}: {e}", exc_info=debug)
            continue

    if not specs:
        logger.error("Failed to generate any valid segments from recipe.")
        return []

    # Validate payload coverage
    _validate_payload_coverage(specs, payload, strategy_task, logger, debug)

    logger.debug(f"Successfully generated {len(specs)} segment specifications.")
    return specs


def _parse_tcp_flags(opts: Dict, logger: logging.Logger) -> int:
    """Parse TCP flags from options dict."""
    tcp_flags_raw = opts.get("tcp_flags", opts.get("flags", 0x18))

    if isinstance(tcp_flags_raw, int):
        return tcp_flags_raw
    elif isinstance(tcp_flags_raw, str):
        # Handle TCP flag strings like 'PA', 'PSH', 'ACK', etc.
        flag_map = {
            "PA": 0x18,
            "PSH+ACK": 0x18,
            "AP": 0x18,
            "A": 0x10,
            "ACK": 0x10,
            "S": 0x02,
            "SYN": 0x02,
            "SA": 0x12,
            "SYN+ACK": 0x12,
            "AS": 0x12,
            "F": 0x01,
            "FIN": 0x01,
            "R": 0x04,
            "RST": 0x04,
            "P": 0x08,
            "PSH": 0x08,
        }
        tcp_flags = flag_map.get(tcp_flags_raw.upper())
        if tcp_flags is None:
            try:
                tcp_flags = int(tcp_flags_raw, 0)
            except ValueError:
                logger.warning(f"Unknown tcp_flags format: {tcp_flags_raw}, using default 0x18")
                tcp_flags = 0x18
        return tcp_flags
    else:
        return 0x18


def _determine_seq_offset(opts: Dict) -> Tuple[int, Optional[int]]:
    """Determine sequence offset from options."""
    seq_offset_value = opts.get("seq_offset", None)
    seq_extra_value = opts.get("seq_extra", None)

    if seq_offset_value is not None:
        # New approach: use seq_offset
        return int(seq_offset_value), None
    elif seq_extra_value is not None:
        # Legacy approach: use seq_extra
        return 0, int(seq_extra_value)
    else:
        # Default: no offset, or -1 if corrupt_sequence is set
        return 0, -1 if opts.get("corrupt_sequence") else None


def _validate_payload_coverage(
    specs: List[TCPSegmentSpec],
    payload: bytes,
    strategy_task: Optional[Dict],
    logger: logging.Logger,
    debug: bool,
):
    """Validate that real segments cover the entire payload."""
    try:
        L = len(payload or b"")
        if L == 0:
            return

        # Create coverage array
        covered = [False] * L
        segment_coverage = []

        for idx, s in enumerate(specs):
            if getattr(s, "is_fake", False):
                continue

            off, data_len = int(s.rel_seq), len(s.payload or b"")
            segment_start = max(0, off)
            segment_end = min(L, off + data_len)

            # Mark covered bytes
            for j in range(segment_start, segment_end):
                covered[j] = True

            segment_coverage.append(
                {
                    "segment_idx": idx,
                    "rel_seq": off,
                    "length": data_len,
                    "covers": f"[{segment_start}:{segment_end}]",
                }
            )
            logger.debug(
                f"📊 Segment {idx}: rel_seq={off}, len={data_len}, "
                f"covers bytes [{segment_start}:{segment_end}]"
            )

        # Find holes
        holes = []
        hole_start = None
        for idx, is_covered in enumerate(covered):
            if not is_covered:
                if hole_start is None:
                    hole_start = idx
            else:
                if hole_start is not None:
                    holes.append((hole_start, idx))
                    hole_start = None
        if hole_start is not None:
            holes.append((hole_start, L))

        if holes:
            total_hole_bytes = sum(end - start for start, end in holes)
            strategy_name = strategy_task.get("type", "") if isinstance(strategy_task, dict) else ""

            # For seqovl attacks, validate overlap size
            if strategy_name == "seqovl":
                params = strategy_task.get("params", {}) if isinstance(strategy_task, dict) else {}
                expected_overlap = params.get("overlap_size", 0)

                if expected_overlap > 0:
                    min_expected = int(expected_overlap * 0.8)
                    max_expected = int(expected_overlap * 1.2)

                    if total_hole_bytes < min_expected:
                        logger.warning(
                            f"⚠️ Seqovl overlap too small: {total_hole_bytes} bytes < "
                            f"expected {expected_overlap} bytes. Hole ranges: {holes[:5]}"
                        )
                    elif total_hole_bytes > max_expected:
                        logger.warning(
                            f"⚠️ Seqovl overlap too large: {total_hole_bytes} bytes > "
                            f"expected {expected_overlap} bytes. Hole ranges: {holes[:5]}"
                        )
                    else:
                        logger.debug(
                            f"✅ Seqovl overlap validated: {total_hole_bytes} bytes "
                            f"matches expected {expected_overlap} bytes."
                        )
                else:
                    if total_hole_bytes <= 20:
                        logger.warning(
                            f"⚠️ Seqovl overlap: {total_hole_bytes} bytes not covered "
                            f"(normal for overlap). Hole ranges: {holes[:5]}"
                        )
                    else:
                        logger.error(
                            f"‼️ Seqovl overlap too large: {total_hole_bytes} bytes "
                            f"without overlap_size parameter. Hole ranges: {holes[:10]}"
                        )
            else:
                # Non-seqovl attacks should not have holes
                logger.error(
                    f"‼️ CRITICAL PAYLOAD COVERAGE ERROR! "
                    f"Real segments have {len(holes)} hole(s) totaling {total_hole_bytes} bytes. "
                    f"Payload length: {L} bytes"
                )
                logger.error(f"Hole ranges: {holes[:10]}")
                logger.error(f"Segment coverage: {segment_coverage}")

                if debug:
                    raise ValueError(
                        f"TCP stream has {len(holes)} holes totaling {total_hole_bytes} bytes "
                        f"at ranges: {holes[:10]}"
                    )
        else:
            real_count = len([s for s in specs if not getattr(s, "is_fake", False)])
            logger.debug(
                f"✅ Payload coverage validation passed: all {L} bytes covered by "
                f"{real_count} real segments"
            )

    except Exception as e:
        logger.debug(f"Error during payload coverage validation: {e}")
