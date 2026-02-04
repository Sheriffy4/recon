# path: core/bypass/techniques/advanced_techniques.py
"""
Advanced DPI bypass techniques.

This module contains advanced attack methods extracted from FakedDisorderAttack
to reduce complexity and improve maintainability.

Techniques:
    - Window manipulation: TCP window size manipulation for flow control
    - TCP options modification: Modifying TCP options to evade detection
    - Advanced timing control: Precise timing control for segment transmission
"""

import struct
import time
import random
import logging
from typing import List, Tuple, Dict, Optional, Any

# Import utilities for segment creation
from .primitives_utils import split_payload_with_pos, create_segment_options


class AdvancedTechniques:
    """
    Advanced DPI bypass techniques.

    This class provides static methods for advanced attack techniques
    that manipulate TCP behavior beyond basic fragmentation.
    """

    @staticmethod
    def apply_window_manipulation(
        payload: bytes,
        window_size: int = 1,
        delay_ms: float = 50.0,
        fragment_count: int = 5,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        TCP window manipulation attack.

        Manipulates TCP window size to force small segments and control flow.
        This technique can bypass DPI systems that rely on window size analysis.

        Args:
            payload: Original data to fragment
            window_size: TCP window size override (small values force fragmentation)
            delay_ms: Delay between fragments in milliseconds
            fragment_count: Number of fragments to create
            fooling_methods: Optional DPI fooling methods

        Returns:
            Recipe with fragments using window size manipulation

        Example:
            >>> segments = AdvancedTechniques.apply_window_manipulation(
            ...     payload, window_size=1, fragment_count=5
            ... )
        """
        log = logging.getLogger("AdvancedTechniques")

        if len(payload) < 2:
            return [(payload, 0, create_segment_options(is_fake=False))]

        # Calculate fragment positions
        fragment_size = len(payload) // fragment_count
        if fragment_size < 1:
            fragment_size = 1
            fragment_count = len(payload)

        positions = []
        for i in range(1, fragment_count):
            pos = i * fragment_size
            if pos < len(payload):
                positions.append(pos)

        # Create fragments
        segments = []
        all_positions = [0] + positions + [len(payload)]

        for i in range(len(all_positions) - 1):
            start_pos = all_positions[i]
            end_pos = all_positions[i + 1]
            fragment_data = payload[start_pos:end_pos]

            # Create segment options with window manipulation
            options = create_segment_options(
                is_fake=False,
                tcp_flags=0x18,  # PSH+ACK
                delay_ms_after=delay_ms if i < len(all_positions) - 2 else None,
                window_size_override=window_size,
            )

            # Apply badseq to first segment if requested
            if i == 0 and fooling_methods:
                for method in fooling_methods:
                    if method == "badseq":
                        options["seq_offset"] = 0x10000000

            segments.append((fragment_data, start_pos, options))

        # Add fake packet with badsum if requested
        if fooling_methods and "badsum" in fooling_methods and segments:
            log.info("Window manipulation with badsum race enabled")
            first_segment_data = segments[0][0]
            fake_opts = create_segment_options(
                is_fake=True,
                tcp_flags=0x18,
                delay_ms_after=1,
                window_size_override=window_size,
            )
            fake_opts["corrupt_tcp_checksum"] = True
            fake_opts["ttl"] = 1
            segments.insert(0, (first_segment_data, 0, fake_opts))

        log.info(
            f"Window manipulation: {len(segments)} fragments, "
            f"window_size={window_size}, delay={delay_ms}ms"
        )
        return segments

    @staticmethod
    def apply_tcp_options_modification(
        payload: bytes,
        split_pos: int = 5,
        options_type: str = "mss",
        bad_checksum: bool = False,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        TCP options modification attack.

        Modifies TCP options to evade DPI detection while fragmenting.
        Different option types can confuse DPI systems that analyze TCP headers.

        Args:
            payload: Original data to split
            split_pos: Position to split the payload
            options_type: Type of TCP options to add
                ("mss", "window_scale", "timestamp", "sack_permitted",
                 "md5_signature", "custom")
            bad_checksum: Whether to corrupt TCP checksum
            fooling_methods: Optional DPI fooling methods

        Returns:
            Recipe with TCP options modification

        Example:
            >>> segments = AdvancedTechniques.apply_tcp_options_modification(
            ...     payload, options_type="mss", bad_checksum=True
            ... )
        """
        log = logging.getLogger("AdvancedTechniques")

        if len(payload) < 2:
            return [(payload, 0, create_segment_options(is_fake=False))]

        # Split payload (keep offset consistent with the effective split position)
        part1, part2, sp = split_payload_with_pos(payload, split_pos, validate=True)

        # Create TCP options based on type
        tcp_options = AdvancedTechniques.create_tcp_options(options_type)

        # Create segment options
        # IMPORTANT:
        # - Do NOT apply "badsum" to real segments (it breaks delivery).
        # - Applying "badseq" to real segments is also dangerous; keep it out here.
        safe_real_fooling = None
        if fooling_methods:
            safe_real_fooling = [m for m in fooling_methods if m in ("md5sig", "fakesni")]

        opts1 = create_segment_options(
            is_fake=False,
            tcp_flags=0x18,  # PSH+ACK
            fooling_methods=safe_real_fooling,
            tcp_options=tcp_options,
        )

        opts2 = create_segment_options(
            is_fake=False,
            tcp_flags=0x18,  # PSH+ACK
        )

        segments = []

        # Add fake packet with bad checksum if requested
        if bad_checksum:
            log.info("TCP options modification with badsum race enabled")
            fake_opts = create_segment_options(
                is_fake=True,
                tcp_flags=0x18,
                delay_ms_after=1,
                tcp_options=tcp_options,
            )
            fake_opts["corrupt_tcp_checksum"] = True
            fake_opts["ttl"] = 1
            segments.append((part1, 0, fake_opts))

        # Add real segments with correct checksums
        segments.append((part1, 0, opts1))
        segments.append((part2, sp, opts2))

        log.info(f"TCP options modification: {options_type}, bad_checksum={bad_checksum}")
        return segments

    @staticmethod
    def create_tcp_options(options_type: str) -> bytes:
        """
        Create TCP options based on specified type.

        Args:
            options_type: Type of TCP options to create
                - "mss": Maximum Segment Size
                - "window_scale": Window Scale
                - "timestamp": Timestamp
                - "sack_permitted": SACK Permitted
                - "md5_signature": MD5 Signature (fake)
                - "custom": Custom experimental option
                - default: No-op padding

        Returns:
            Raw TCP options bytes

        Example:
            >>> options = AdvancedTechniques.create_tcp_options("mss")
        """
        if options_type == "mss":
            # Maximum Segment Size option
            return struct.pack("!BBH", 2, 4, 1460)  # MSS = 1460

        elif options_type == "window_scale":
            # Window Scale option
            return struct.pack("!BBB", 3, 3, 7)  # Scale factor = 7

        elif options_type == "timestamp":
            # Timestamp option
            return struct.pack("!BBII", 8, 10, int(time.time()), 0)

        elif options_type == "sack_permitted":
            # SACK Permitted option
            return struct.pack("!BB", 4, 2)

        elif options_type == "md5_signature":
            # MD5 Signature option (fake)
            fake_signature = b"\xde\xad\xbe\xef" * 4  # 16 bytes
            return struct.pack("!BB", 19, 18) + fake_signature

        elif options_type == "custom":
            # Custom option for evasion
            return struct.pack("!BB", 254, 4) + b"\x00\x00"  # Experimental option

        else:
            # Default: No-op padding
            return b"\x01\x01\x01\x01"  # 4 bytes of NOP

    @staticmethod
    def apply_advanced_timing_control(
        payload: bytes,
        split_pos: int = 3,
        delays: Optional[List[float]] = None,
        jitter: bool = False,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Advanced timing control for segment transmission.

        Provides precise control over timing between segments to evade
        temporal analysis by DPI systems.

        Args:
            payload: Original data to split
            split_pos: Position to split the payload
            delays: List of delays in milliseconds for each segment
            jitter: Whether to add random jitter to delays
            fooling_methods: Optional DPI fooling methods

        Returns:
            Recipe with advanced timing control

        Example:
            >>> segments = AdvancedTechniques.apply_advanced_timing_control(
            ...     payload, delays=[1.0, 2.0], jitter=True
            ... )
        """
        log = logging.getLogger("AdvancedTechniques")

        if len(payload) < 2:
            return [(payload, 0, create_segment_options(is_fake=False))]

        # Split payload (keep offset consistent with the effective split position)
        part1, part2, sp = split_payload_with_pos(payload, split_pos, validate=True)

        # Default delays if not provided
        if delays is None:
            delays = [1.0, 2.0]  # Default delays in milliseconds

        # Add jitter if requested
        if jitter:
            delays = [d + random.uniform(-0.5, 0.5) for d in delays]

        # Create segments with timing control
        segments = []
        parts = [part1, part2]
        offsets = [0, sp]

        for i, (part, offset) in enumerate(zip(parts, offsets)):
            delay = delays[i] if i < len(delays) else 0.0

            options = create_segment_options(
                is_fake=False,
                tcp_flags=0x18,  # PSH+ACK
                # Safety: avoid applying checksum corruption to real segments
                fooling_methods=(
                    [m for m in (fooling_methods or []) if m in ("md5sig", "fakesni")]
                    if i == 0
                    else None
                ),
                delay_ms_after=delay if i < len(parts) - 1 else None,
            )

            segments.append((part, offset, options))

        log.info(f"Advanced timing control: delays={delays}, jitter={jitter}")
        return segments
