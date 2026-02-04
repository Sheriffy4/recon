"""
Timing Obfuscation Strategies

Various timing patterns for evading timing-based fingerprinting through
jitter injection, exponential delays, burst patterns, and rhythm breaking.
"""

import random
from typing import List, Dict, Any, Tuple
from core.bypass.attacks.obfuscation.segment_schema import make_segment, next_seq_offset


class TimingStrategy:
    """Base class for timing obfuscation strategies."""

    @staticmethod
    def _safe_base_delay(base_delay: int) -> int:
        try:
            return max(1, int(base_delay))
        except (TypeError, ValueError):
            return 1

    @staticmethod
    def _safe_jitter_range(jitter_range: int) -> int:
        try:
            return max(0, int(jitter_range))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    async def apply_jitter_timing(
        payload: bytes, base_delay: int, jitter_range: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Apply jitter-based timing obfuscation.

        Args:
            payload: Data to obfuscate
            base_delay: Base delay in milliseconds
            jitter_range: Range of jitter to apply (+/-)

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        if not payload:
            return []
        segments = []
        seq_offset = 0
        base_delay = TimingStrategy._safe_base_delay(base_delay)
        jitter_range = TimingStrategy._safe_jitter_range(jitter_range)
        chunk_size = random.randint(100, 300)

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            jitter = random.randint(-jitter_range, jitter_range)
            delay = max(1, base_delay + jitter)
            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    timing_model="jitter",
                    timing_type="jitter",
                    base_delay=base_delay,
                    jitter=jitter,
                    final_delay=delay,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments

    @staticmethod
    async def apply_exponential_timing(
        payload: bytes, base_delay: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Apply exponential timing distribution.

        Args:
            payload: Data to obfuscate
            base_delay: Base delay in milliseconds

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        if not payload:
            return []
        segments = []
        seq_offset = 0
        base_delay = TimingStrategy._safe_base_delay(base_delay)
        chunk_size = random.randint(150, 400)

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            delay = int(random.expovariate(1.0 / base_delay))
            delay = max(1, min(delay, base_delay * 5))
            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    timing_model="exponential",
                    timing_type="exponential",
                    base_delay=base_delay,
                    calculated_delay=delay,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments

    @staticmethod
    async def apply_burst_timing(
        payload: bytes, base_delay: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Apply burst timing patterns.

        Args:
            payload: Data to obfuscate
            base_delay: Base delay in milliseconds

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        if not payload:
            return []
        segments = []
        seq_offset = 0
        base_delay = TimingStrategy._safe_base_delay(base_delay)
        burst_size = random.randint(3, 6)
        burst_delay = base_delay * 3
        # Ensure step is never 0
        chunk_size = max(
            1, (len(payload) // burst_size) if len(payload) > burst_size else len(payload)
        )

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            burst_index = i // chunk_size

            if burst_index % burst_size == 0:
                delay = burst_delay + random.randint(-10, 10)
            else:
                delay = random.randint(5, 15)

            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    timing_model="burst",
                    timing_type="burst",
                    burst_index=burst_index,
                    burst_size=burst_size,
                    is_burst_start=(burst_index % burst_size == 0),
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments

    @staticmethod
    async def apply_rhythm_breaking(
        payload: bytes, base_delay: int, jitter_range: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Apply rhythm-breaking timing patterns.

        Args:
            payload: Data to obfuscate
            base_delay: Base delay in milliseconds
            jitter_range: Range of jitter to apply

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        if not payload:
            return []
        segments = []
        seq_offset = 0
        base_delay = TimingStrategy._safe_base_delay(base_delay)
        jitter_range = TimingStrategy._safe_jitter_range(jitter_range)
        chunk_size = random.randint(80, 250)
        rhythm_pattern = [1.0, 0.5, 2.0, 0.3, 1.5, 0.8, 2.5]

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            pattern_index = i // chunk_size % len(rhythm_pattern)
            rhythm_multiplier = rhythm_pattern[pattern_index]
            jitter = random.randint(-jitter_range // 2, jitter_range // 2)
            delay = max(1, int(base_delay * rhythm_multiplier) + jitter)

            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    timing_model="rhythm_break",
                    timing_type="rhythm_break",
                    pattern_index=pattern_index,
                    rhythm_multiplier=rhythm_multiplier,
                    jitter=jitter,
                    final_delay=delay,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments
