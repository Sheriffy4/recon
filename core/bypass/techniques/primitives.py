# path: core/bypass/techniques/primitives.py
# ULTIMATE CORRECTED VERSION - Best of both approaches
# REFACTORED: Utilities extracted to primitives_utils.py (Step 1)
# REFACTORED: Fooling methods deduplicated (Step 2)
# REFACTORED: Payload generators extracted to payload_generators.py (Step 3)
# REFACTORED: Factory methods extracted to attack_factories.py (Step 4)
# REFACTORED: Core logic extracted to faked_disorder_core.py (Step 5)
# REFACTORED: Advanced techniques extracted to advanced_techniques.py (Step 6)

import struct
import logging
from typing import List, Tuple, Dict, Optional, Any, Callable

# Import utilities from new modules
from .primitives_utils import (
    gen_fake_sni,
    split_payload,
    create_segment_options,
    normalize_positions,
    handle_small_payload,
    split_payload_with_pos,
)
from .payload_generators import PayloadGeneratorFactory
from .attack_factories import FakedDisorderFactory
from .faked_disorder_core import FakedDisorderCore, create_core_from_attack
from .advanced_techniques import AdvancedTechniques
from .bypass_helpers import (
    log_attack_execution,
    validate_payload_size,
    create_fallback_segment,
    validate_and_adjust_split_position,
    build_segment_metadata,
    calculate_fragment_delays,
    optimize_fragment_positions,
    create_fragment_list,
)


# Backward compatibility: keep module-level function
# Note: gen_fake_sni is now imported from primitives_utils


class BypassTechniques:
    """
    Library of primitive DPI bypass techniques in zapret style.

    This class provides low-level building blocks for DPI bypass attacks.
    For high-level usage, prefer specialized attack classes like FakedDisorderAttack.

    Core Principles:
    - Generates "recipes" - sequences of TCP segments to send
    - Each recipe is a list of tuples: (data, seq_offset, options)
    - Supports various DPI fooling methods
    - Compatible with zapret parameters and logic

    Attack Types:
    1. Fake packets (fake*): Send decoy data with low TTL
    2. Splitting (split/multisplit): Divide packet into parts
    3. Disorder: Send parts in wrong order
    4. Sequence overlap (seqovl): Overlap TCP sequences
    5. Race conditions: Race between fake and real packets

    Fooling Methods:
    - badsum: Incorrect TCP checksum
    - badseq: Incorrect sequence number
    - md5sig: TCP MD5 signature option
    - fakesni: Fake Server Name Indication

    Recipe Format:
    List[Tuple[bytes, int, Dict]] where:
    - bytes: Segment data
    - int: Offset in original payload (rel_seq)
    - Dict: Segment options (is_fake, ttl, tcp_flags, etc.)

    Examples:
        >>> # Simple disorder attack
        >>> payload = b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        >>> recipe = BypassTechniques.apply_disorder(payload, split_pos=10)
        >>> # Returns: [(part2, 10, opts), (part1, 0, opts)]

        >>> # Fakeddisorder with custom TTL
        >>> recipe = BypassTechniques.apply_fakeddisorder(
        ...     payload, split_pos=20, fake_ttl=3, fooling_methods=["badsum"]
        ... )
        >>> # Returns: [(fake, 0, opts), (part2, 20, opts), (part1, 0, opts)]

        >>> # For advanced usage, use FakedDisorderAttack class
        >>> attack = FakedDisorderAttack.create_zapret_compatible()
        >>> segments = attack.execute(payload)

    Note:
        This is a primitive implementation for backward compatibility.
        Advanced attacks are in core/bypass/attacks/.
    """

    # API version marker for diagnostics
    API_VER = "primitives ULTIMATE-2025-10-17-refactored"

    @staticmethod
    def _split_payload(
        payload: bytes, split_pos: int, validate: bool = True
    ) -> Tuple[bytes, bytes]:
        """
        Shared payload splitting logic for all disorder family attacks.

        REFACTORED: This is now a thin wrapper around primitives_utils.split_payload().
        Kept for backward compatibility with existing code.

        This helper function provides consistent payload splitting with validation
        for disorder, disorder2, multidisorder, fakeddisorder, and related attacks.

        Args:
            payload: The original payload to split
            split_pos: Position to split at (1-based, must be < len(payload))
            validate: Whether to validate and adjust split_pos if needed

        Returns:
            Tuple of (part1, part2) where:
            - part1: payload[:split_pos]
            - part2: payload[split_pos:]

        Raises:
            ValueError: If split_pos is invalid and validate=False

        Examples:
            >>> payload = b"Hello World"
            >>> part1, part2 = BypassTechniques._split_payload(payload, 5)
            >>> part1  # b"Hello"
            >>> part2  # b" World"
        """
        return split_payload(payload, split_pos, validate)

    @staticmethod
    def _create_segment_options(
        is_fake: bool,
        ttl: Optional[int] = None,
        fooling_methods: Optional[List[str]] = None,
        tcp_flags: int = 0x18,
        delay_ms_after: Optional[int] = None,
        window_size_override: Optional[int] = None,
        tcp_options: Optional[bytes] = None,
        custom_sni: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Shared segment options builder for all attacks.

        REFACTORED: This is now a thin wrapper around primitives_utils.create_segment_options().
        Kept for backward compatibility with existing code.

        This helper function provides consistent segment option creation
        with standardized fooling method handling across all attack types.

        Args:
            is_fake: Whether this is a fake segment (with low TTL)
            ttl: Time-to-live for the segment (required for fake segments)
            fooling_methods: List of DPI fooling methods to apply
            tcp_flags: TCP flags for the segment (default: PSH+ACK = 0x18)
            delay_ms_after: Milliseconds to delay after sending this segment
            window_size_override: TCP window size override for flow control
            tcp_options: Raw TCP options bytes to include
            **kwargs: Additional options to include in the segment

        Returns:
            Dictionary of segment options ready for use in attack recipes

        Fooling Methods:
            - "badsum": Corrupt TCP checksum
            - "badseq": Use far-future sequence offset (0x10000000) to avoid overlap
            - "md5sig": Add TCP MD5 signature option
            - "fakesni": Generate fake SNI (stored in fooling_sni field)

        Examples:
            >>> # Fake segment with badsum fooling
            >>> opts = BypassTechniques._create_segment_options(
            ...     is_fake=True, ttl=3, fooling_methods=["badsum"]
            ... )
            >>> opts["corrupt_tcp_checksum"]  # True

            >>> # Real segment with window manipulation
            >>> opts = BypassTechniques._create_segment_options(
            ...     is_fake=False, window_size_override=1
            ... )
            >>> opts["window_size_override"]  # 1
        """
        opts = create_segment_options(
            is_fake=is_fake,
            ttl=ttl,
            fooling_methods=fooling_methods,
            tcp_flags=tcp_flags,
            delay_ms_after=delay_ms_after,
            window_size_override=window_size_override,
            tcp_options=tcp_options,
            custom_sni=custom_sni,
            **kwargs,
        )
        # Back-compat + consistency:
        # - many engines historically only looked at delay_ms
        # - keep delay_ms_after for "after-send" semantics, but mirror to delay_ms if not provided
        if isinstance(opts, dict) and "delay_ms_after" in opts and "delay_ms" not in opts:
            try:
                opts["delay_ms"] = float(opts.get("delay_ms_after") or 0.0)
            except Exception:
                opts["delay_ms"] = 0.0
        return opts

    @staticmethod
    def _normalize_positions(positions: Any, payload_len: int, validate: bool = True) -> List[int]:
        """
        Convert various position formats to List[int] and handle special values.

        REFACTORED: This is now a thin wrapper around primitives_utils.normalize_positions().
        Kept for backward compatibility with existing code.

        This helper function provides consistent position normalization
        for multisplit, multidisorder, and other position-based attacks.

        Args:
            positions: Position specification in various formats:
                - int: Single position (converted to [position])
                - List[int]: Multiple positions (validated and sorted)
                - str: Special values ("sni", "cipher", "midsld")
                - List[str/int]: Mixed list (each element processed)
            payload_len: Length of payload for validation and special value resolution
            validate: Whether to validate positions are within payload bounds

        Returns:
            List of valid integer positions, sorted and deduplicated

        Special Values:
            - "sni": Position 43 (TLS SNI extension start)
            - "cipher": Position 11 (TLS cipher suites start)
            - "midsld": Middle of payload (payload_len // 2)

        Examples:
            >>> # Single position
            >>> BypassTechniques._normalize_positions(5, 100)  # [5]

            >>> # Multiple positions
            >>> BypassTechniques._normalize_positions([1, 5, 3], 100)  # [1, 3, 5]

            >>> # Special value
            >>> BypassTechniques._normalize_positions("sni", 100)  # [43]

            >>> # Mixed list
            >>> BypassTechniques._normalize_positions([1, "sni", 5], 100)  # [1, 5, 43]
        """
        return normalize_positions(positions, payload_len, validate)

    @staticmethod
    def apply_fake_packet_race(
        payload: bytes, ttl: int = 3, fooling: List[str] = None, **kwargs
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Создает race-атаку: фейковый пакет + оригинал.
        """
        if fooling is None:
            fooling = ["badsum"]

        # Use shared helper for segment options, passing through kwargs for custom SNI
        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True, ttl=ttl, fooling_methods=fooling, delay_ms_after=5, **kwargs
        )
        opts_real = BypassTechniques._create_segment_options(is_fake=False)

        return [(payload, 0, opts_fake), (payload, 0, opts_real)]

    # --- START OF FIX: UNIFIED AND CORRECTED fakeddisorder LOGIC ---
    @staticmethod
    def apply_fakeddisorder(
        payload: bytes,
        split_pos: int,
        fake_ttl: int,
        fooling_methods: Optional[List[str]] = None,
        **kwargs,  # Принимаем и игнорируем лишние параметры, такие как overlap_size
    ) -> List[Tuple[bytes, int, dict]]:
        """
        LOW-LEVEL PRIMITIVE: Basic fakeddisorder implementation.

        ⚠️  NOTE: This is a low-level primitive function for building blocks.
        ⚠️  For high-level usage, use FakedDisorderAttack class instead.
        ⚠️  The FakedDisorderAttack class provides enhanced features:
        ⚠️  - Zapret-compatible fake payload generation
        ⚠️  - AutoTTL testing with comprehensive range testing
        ⚠️  - Special position resolution (sni, cipher, midsld)
        ⚠️  - Parameter validation and optimization
        ⚠️  - X.COM TTL fix for maximum effectiveness
        ⚠️  - Multiple fake payload types (TLS, HTTP, QUIC, etc.)
        ⚠️  - Advanced monitoring and result validation
        ⚠️  - Repeats functionality with minimal delays
        ⚠️
        ⚠️  Example usage of enhanced class:
        ⚠️    attack = FakedDisorderAttack.create_zapret_compatible()
        ⚠️    segments = attack.execute(payload)
        ⚠️
        ⚠️  Or for X.COM optimization:
        ⚠️    attack = FakedDisorderAttack.create_x_com_optimized()
        ⚠️    segments = attack.execute(payload)

        This primitive provides the core fakeddisorder logic:
        1. Fake packet with full payload and low TTL
           - Reaches DPI but expires before server (TTL expires)
           - DPI sees "correct" packet and allows connection

        2. Real parts in reverse order (disorder)
           - Part 2 (from split_pos to end) sent first
           - Part 1 (from start to split_pos) sent second
           - Server correctly reassembles packet, DPI sees "garbage"

        Key to success:
        - Fake packet contains FULL payload (not just part)
        - Critical for x.com and other complex sites
        - overlap_size intentionally ignored (that's for seqovl)

        Fooling methods:
        - badsum: Incorrect TCP checksum in fake packet
        - badseq: Incorrect sequence number
        - md5sig: TCP MD5 signature option

        Args:
            payload: Original packet data (usually TLS ClientHello)
            split_pos: Split position for disorder parts
            fake_ttl: TTL for fake packet (usually 1-3)
            fooling_methods: DPI fooling methods for fake packet
            **kwargs: Additional parameters (ignored for compatibility)

        Returns:
            Recipe with 3 segments:
            1. Fake packet (full payload, TTL=fake_ttl)
            2. Real part 2 (from split_pos to end)
            3. Real part 1 (from start to split_pos)
        """
        log = logging.getLogger("BypassTechniques")

        # Use helper for payload validation (Step 10: consolidate duplicate)
        if not validate_payload_size(payload, min_size=2):
            return create_fallback_segment(payload)

        # Use shared helper for payload splitting
        part1, part2, sp = split_payload_with_pos(payload, split_pos, validate=True)

        # Use shared helper for segment options
        fool = fooling_methods if fooling_methods is not None else ["badsum"]
        if not fool:
            fool = ["badsum"]

        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True, ttl=fake_ttl, fooling_methods=fool, delay_ms_after=5, **kwargs
        )
        opts_real = BypassTechniques._create_segment_options(is_fake=False)

        # --- ЕДИНСТВЕННАЯ ПРАВИЛЬНАЯ ЛОГИКА ДЛЯ FAKEDDISORDER ---
        # Ключ к успеху для x.com: фейковый пакет содержит ВЕСЬ ClientHello.
        fake_payload = payload

        log.info(
            f"✅ UNIFIED fakeddisorder: "
            f"fake_full_payload={len(fake_payload)}b@0 (ttl={fake_ttl}), "
            f"real_part2={len(part2)}b@{sp}, "
            f"real_part1={len(part1)}b@0"
        )

        return [
            (fake_payload, 0, opts_fake),
            (part2, sp, opts_real),
            (part1, 0, opts_real),
        ]

    # --- END OF FIX ---

    @staticmethod
    def apply_seqovl(
        payload: bytes,
        split_pos: int,
        overlap_size: int,
        fake_ttl: int,
        fooling_methods: Optional[List[str]] = None,
        **kwargs,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Sequence Overlap (seqovl) attack - TCP sequence overlap with fixed calculation.

        Key improvements:
        1. Fixed sequence overlap calculation to ensure proper overlap
        2. Real packet remains intact (full payload)
        3. Added validation for overlap_size parameter
        4. Optimized for common use cases

        Attack principle:
        1. Fake packet with overlapping data and low TTL
           - Contains overlapping portion that conflicts with real packet
           - Reaches DPI but expires before server (low TTL)
           - DPI sees conflicting sequences and may allow connection

        2. Real full packet
           - Contains complete original data
           - Server receives correct data
           - Sent with normal TTL to reach destination

        FIXED overlap calculation:
        - Validates overlap_size is within bounds (1 to split_pos)
        - start_offset = max(0, split_pos - overlap_size)
        - overlap_part = payload[start_offset:split_pos + overlap_size]
        - Real packet always contains full payload (CRITICAL)

        Args:
            payload: Original packet data
            split_pos: Position for overlap calculation
            overlap_size: Size of overlap in bytes (must be > 0 and <= split_pos)
            fake_ttl: TTL for fake packet (typically 1-3)
            fooling_methods: DPI fooling methods for fake packet

        Returns:
            Recipe with 2 segments:
            1. Fake overlapping packet (partial data, low TTL)
            2. Real full packet (complete data, normal TTL)
        """
        log = logging.getLogger("BypassTechniques")

        # Use helper for payload validation (Step 10: consolidate duplicate)
        if not validate_payload_size(payload, min_size=2):
            return create_fallback_segment(payload)

        # FIXED: Validate and adjust parameters with proper bounds checking
        # Handle special string values that should have been resolved earlier
        if isinstance(split_pos, str):
            if split_pos.lower() == "random":
                import random

                split_pos = random.randint(1, max(1, len(payload) - 1))
                log.warning(
                    f"split_pos='random' was not resolved earlier, resolving now to {split_pos}"
                )
            else:
                try:
                    split_pos = int(split_pos)
                except ValueError:
                    log.warning(f"Invalid split_pos '{split_pos}', using default position")
                    split_pos = len(payload) // 2

        sp = max(1, min(int(split_pos), len(payload) - 1))

        # FIXED: Validate overlap_size is reasonable and within bounds
        # Cap at 1000 bytes for sanity
        max_overlap = min(sp, len(payload) - sp, 1000)
        ovl = max(1, min(int(overlap_size), max_overlap))

        if ovl != overlap_size:
            log.warning(
                f"Adjusted overlap_size from {overlap_size} to {ovl} (max allowed: {max_overlap})"
            )

        # Use shared helper for segment options
        fool = fooling_methods if fooling_methods is not None else ["badsum"]

        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True, ttl=fake_ttl, fooling_methods=fool, delay_ms_after=5, **kwargs
        )
        opts_real = BypassTechniques._create_segment_options(is_fake=False)

        # FIXED: Correct overlap calculation that ensures proper sequence
        # conflict
        start_offset = max(0, sp - ovl)
        end_offset = min(len(payload), sp + ovl)

        # Fake packet contains overlapping portion
        overlap_part = payload[start_offset:end_offset]

        # CRITICAL: Real packet ALWAYS contains full payload (requirement 11.3)
        real_full = payload

        # Validate that we have actual overlap
        if len(overlap_part) == 0:
            log.warning("No overlap generated, falling back to simple fake packet")
            overlap_part = payload[: min(len(payload), 64)]  # Small fake packet
            start_offset = 0

        log.info(
            f"✅ FIXED Seqovl: "
            f"fake_overlap={len(overlap_part)}b@{start_offset} (ttl={fake_ttl}), "
            f"real_full={len(real_full)}b@0, "
            f"overlap_size={ovl}, split_pos={sp}"
        )

        return [
            (overlap_part, start_offset, opts_fake),
            (real_full, 0, opts_real),
        ]

    @staticmethod
    def apply_multidisorder(
        payload: bytes,
        positions: List[int],
        fooling: Optional[List[str]] = None,
        fake_ttl: int = 3,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Multiple Disorder attack - optimized multi-fragment reordering.

        REFACTORED: Uses bypass_helpers for common patterns (Step 7).

        "Maximum chaos" strategy:
        1. Small "poisoning" fake packet
        2. Multiple real data fragmentation
        3. Reverse order transmission (disorder)

        Args:
            payload: Original data to fragment and reorder
            positions: List of split positions (will be sorted and optimized)
            fooling: DPI fooling methods for fake packet
            fake_ttl: TTL for fake packet

        Returns:
            Recipe with segments: fake packet + real fragments in reverse order
        """
        log = logging.getLogger("BypassTechniques")

        # Validate payload size
        if not validate_payload_size(payload, min_size=2):
            return create_fallback_segment(payload)

        # Normalize fooling methods
        if fooling is None:
            fooling = ["badsum", "badseq"]
        elif fooling == "none" or fooling == ["none"]:
            fooling = []
        elif isinstance(fooling, list) and "none" in fooling:
            fooling = []
        elif not isinstance(fooling, list):
            fooling = [fooling] if fooling else []

        log.debug(f"Fooling methods: {fooling}")

        # Normalize and optimize positions
        normalized_positions = BypassTechniques._normalize_positions(
            positions, len(payload), validate=True
        )

        if not normalized_positions:
            log.warning("No valid positions, falling back to fakeddisorder")
            return BypassTechniques.apply_fakeddisorder(
                payload, len(payload) // 2, fake_ttl, fooling
            )

        # Optimize positions for reasonable fragment sizes
        optimized_positions = optimize_fragment_positions(
            normalized_positions, len(payload), min_fragment_size=3, max_fragments=8
        )

        # Create fake packet
        fake_size = max(1, min(min(optimized_positions), 64))
        fake_payload = payload[:fake_size]

        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True,
            ttl=fake_ttl,
            fooling_methods=fooling,
            delay_ms_after=2,
        )
        segments = [(fake_payload, 0, opts_fake)]

        # Create real fragments
        real_fragments = create_fragment_list(payload, optimized_positions)

        if len(real_fragments) <= 1:
            log.warning("Only one fragment, falling back to simple disorder")
            return BypassTechniques.apply_disorder(payload, len(payload) // 2)

        # Add fragments in reverse order
        opts_real = BypassTechniques._create_segment_options(is_fake=False, delay_ms_after=1)

        for i, (data, offset) in enumerate(reversed(real_fragments)):
            fragment_opts = opts_real.copy()
            fragment_opts.update(
                build_segment_metadata(
                    len(real_fragments) - i - 1, len(real_fragments), "multidisorder_optimized"
                )
            )
            segments.append((data, offset, fragment_opts))

        log_attack_execution(
            "Multidisorder",
            len(payload),
            segments,
            positions=optimized_positions,
            fragments=len(real_fragments),
        )

        return segments

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int], fooling: Optional[List[str]] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Multiple Split attack - optimized multi-fragment transmission.

        REFACTORED: Uses bypass_helpers for common patterns (Step 7).

        Clean fragmentation approach without disorder.

        Args:
            payload: Original data to fragment
            positions: List of split positions (will be optimized)
            fooling: Fooling methods (supports badsum for race condition)

        Returns:
            Recipe with segments in correct order with optional delays
        """
        log = logging.getLogger("BypassTechniques")

        # Validate payload size
        if not validate_payload_size(payload, min_size=2):
            return create_fallback_segment(payload)

        # Normalize positions
        normalized_positions = BypassTechniques._normalize_positions(
            positions, len(payload), validate=True
        )

        if not normalized_positions:
            return create_fallback_segment(payload)

        fooling = fooling or []

        # OPTIMIZATION: Handle single position case efficiently
        if len(normalized_positions) == 1:
            split_pos = normalized_positions[0]
            log.debug(f"Single position multisplit optimized: split_pos={split_pos}")

            part1, part2, sp = split_payload_with_pos(payload, split_pos, validate=True)

            opts1 = BypassTechniques._create_segment_options(
                is_fake=False, tcp_flags=0x10, delay_ms_after=1
            )
            opts2 = BypassTechniques._create_segment_options(is_fake=False, tcp_flags=0x18)

            segments = []

            # Add fake packet if badsum requested
            if "badsum" in fooling:
                log.info("Adding FAKE packet with corrupted checksum before real segments")
                fake_opts = BypassTechniques._create_segment_options(
                    is_fake=True, tcp_flags=0x18, delay_ms_after=1
                )
                fake_opts["corrupt_tcp_checksum"] = True
                fake_opts["ttl"] = 3
                segments.append((part1, 0, fake_opts))

            segments.extend([(part1, 0, opts1), (part2, sp, opts2)])
            return segments

        # Multi-position case with enhanced validation
        flags_pattern = [0x10, 0x18]
        segments = []
        all_positions = [0] + normalized_positions + [len(payload)]

        # Validate fragment sizes
        valid_fragments = []
        for i in range(len(all_positions) - 1):
            start_pos, end_pos = all_positions[i], all_positions[i + 1]
            if end_pos - start_pos >= 1:
                valid_fragments.append((start_pos, end_pos))

        if not valid_fragments:
            log.warning("No valid fragments after validation, using single segment")
            return create_fallback_segment(payload)

        # Create segments with optimized timing
        delays = calculate_fragment_delays(len(valid_fragments), base_delay_ms=1, max_delay_ms=5)

        for i, (start_pos, end_pos) in enumerate(valid_fragments):
            segment_data = payload[start_pos:end_pos]
            tcp_flags = flags_pattern[i % len(flags_pattern)]

            opts = BypassTechniques._create_segment_options(
                is_fake=False, tcp_flags=tcp_flags, delay_ms_after=delays[i]
            )
            opts.update(build_segment_metadata(i, len(valid_fragments), "multisplit_optimized"))

            segments.append((segment_data, start_pos, opts))

        # Add fake packet if badsum requested
        if "badsum" in fooling and segments:
            log.info("Adding FAKE packet with corrupted checksum before real segments")
            first_segment_data = segments[0][0]
            fake_opts = BypassTechniques._create_segment_options(
                is_fake=True, tcp_flags=0x18, delay_ms_after=1
            )
            fake_opts["corrupt_tcp_checksum"] = True
            fake_opts["ttl"] = 1
            fake_opts["badsum_race"] = True
            segments.insert(0, (first_segment_data, 0, fake_opts))

        log_attack_execution(
            "Multisplit",
            len(payload),
            segments,
            positions=normalized_positions,
            badsum_race="badsum" in fooling,
        )

        return segments

    @staticmethod
    def apply_disorder(
        payload: bytes, split_pos: int, ack_first: bool = False
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Simple Disorder attack - reorder segments without fake packets.

        REFACTORED: Uses bypass_helpers for common patterns (Step 7).

        Minimalist approach: split payload and send in reverse order.

        Args:
            payload: Original data to split and reorder
            split_pos: Split position (1 <= pos < len(payload))
            ack_first: Use ACK-only flag in first segment (disorder2 variant)

        Returns:
            Recipe with 2 real segments in reverse order
        """
        log = logging.getLogger("BypassTechniques")

        # Validate payload size
        if not validate_payload_size(payload, min_size=2):
            return create_fallback_segment(payload)

        # Split payload
        part1, part2, sp = split_payload_with_pos(payload, split_pos, validate=True)

        # Skip disorder if one part is empty
        if len(part1) == 0 or len(part2) == 0:
            log.warning(
                f"Disorder skipped: one part empty (part1={len(part1)}, part2={len(part2)})"
            )
            return create_fallback_segment(payload)

        # Determine TCP flags
        if len(part2) < 3:
            log.debug(f"Small part2 ({len(part2)}b), using conservative flags")
            first_flags = 0x18  # Always use PSH+ACK for small parts
        else:
            first_flags = 0x10 if ack_first else 0x18

        # Create segment options
        opts_first = BypassTechniques._create_segment_options(
            is_fake=False, tcp_flags=first_flags, delay_ms_after=0
        )
        opts_first.update(build_segment_metadata(0, 2, "disorder", is_first_segment=True))

        opts_second = BypassTechniques._create_segment_options(is_fake=False, delay_ms_after=1)
        opts_second.update(build_segment_metadata(1, 2, "disorder", is_second_segment=True))

        log_attack_execution(
            "Disorder",
            len(payload),
            [(part2, sp, opts_first), (part1, 0, opts_second)],
            split_pos=split_pos,
            ack_first=ack_first,
        )

        return [
            (part2, sp, opts_first),
            (part1, 0, opts_second),
        ]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        """
        Split TLS record into two records at specified position.

        This method splits a TLS record's content into two separate TLS records,
        which can help bypass DPI systems that analyze TLS record boundaries.

        Args:
            payload: TLS record payload to split
            split_pos: Position to split the record content (default: 5)

        Returns:
            Modified payload with split TLS records, or original payload if splitting fails

        Note:
            This method has robust error handling to ensure it never crashes,
            returning the original payload if any error occurs during processing.
        """
        log = logging.getLogger("BypassTechniques")

        try:
            # Validate payload size
            if not payload or len(payload) < 5:
                log.debug("Payload too small for TLS record split")
                return payload

            # Validate TLS record header
            if (
                payload[0] != 0x16  # TLS Handshake
                or payload[1] != 0x03  # TLS version major
                or payload[2] not in (0x00, 0x01, 0x02, 0x03)  # TLS version minor
            ):
                log.debug("Not a valid TLS handshake record")
                return payload

            # Parse TLS record
            rec_len = int.from_bytes(payload[3:5], "big")
            content = payload[5 : 5 + rec_len] if 5 + rec_len <= len(payload) else payload[5:]
            tail = payload[5 + rec_len :] if 5 + rec_len <= len(payload) else b""

            # Validate split position
            if split_pos < 1 or split_pos >= len(content):
                log.debug(f"Invalid split position {split_pos} for content length {len(content)}")
                return payload

            # Split content
            part1, part2 = content[:split_pos], content[split_pos:]
            ver = payload[1:3]

            # Create two TLS records
            rec1 = bytes([0x16]) + ver + len(part1).to_bytes(2, "big") + part1
            rec2 = bytes([0x16]) + ver + len(part2).to_bytes(2, "big") + part2

            log.debug(
                f"TLS record split: {len(payload)}b → {len(rec1)}b + {len(rec2)}b + {len(tail)}b"
            )
            return rec1 + rec2 + tail

        except (ValueError, IndexError, TypeError) as e:
            # Specific exceptions for parsing/indexing errors
            log.warning(f"TLS record split failed (parsing error): {e}")
            return payload
        except OverflowError as e:
            # Handle integer overflow in to_bytes
            log.warning(f"TLS record split failed (overflow): {e}")
            return payload
        except Exception as e:
            # Catch-all for unexpected errors (should be rare)
            log.error(f"Unexpected error in TLS record split: {type(e).__name__}: {e}")
            return payload

    @staticmethod
    def apply_wssize_limit(payload: bytes, window_size: int = 1) -> List[Tuple[bytes, int, dict]]:
        segments, pos = ([], 0)
        opts = {"is_fake": False, "tcp_flags": 0x18}

        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos : pos + chunk_size]
            segments.append((chunk, pos, opts))
            pos += chunk_size

        return segments

    @staticmethod
    def _validate_promotion_inputs(
        attack_name: str, new_handler: Callable[..., Any], reason: str, log: logging.Logger
    ) -> bool:
        """Validate promotion inputs. Returns True if valid."""
        if not attack_name or not isinstance(attack_name, str):
            log.error(f"Invalid attack_name: {attack_name}")
            return False
        if not callable(new_handler):
            log.error(f"new_handler is not callable: {type(new_handler)}")
            return False
        if not reason or not isinstance(reason, str):
            log.error(f"Invalid reason: {reason}")
            return False
        return True

    @staticmethod
    def _validate_performance_data(
        performance_data: Optional[Dict[str, Any]], log: logging.Logger
    ) -> Dict[str, Any]:
        """Validate and normalize performance data."""
        if not performance_data:
            return {}
        if not isinstance(performance_data, dict):
            log.warning("performance_data should be a dictionary")
            return {}

        recommended_keys = ["improvement_percent", "test_cases", "success_rate"]
        missing_keys = [k for k in recommended_keys if k not in performance_data]
        if missing_keys:
            log.warning(f"Missing recommended performance metrics: {missing_keys}")
        return performance_data

    @staticmethod
    def _validate_handler_signature(new_handler: Callable[..., Any], log: logging.Logger) -> None:
        """Validate new handler signature."""
        import inspect

        try:
            sig = inspect.signature(new_handler)
            param_names = list(sig.parameters.keys())
            if not param_names:
                log.warning("New handler has no parameters - may not be proper attack handler")
            else:
                log.debug(f"New handler signature: {param_names}")
        except (ValueError, TypeError, AttributeError) as e:
            log.warning(f"Could not inspect handler signature: {type(e).__name__}: {e}")

    @staticmethod
    def _log_promotion_success(
        attack_name: str, reason: str, performance_data: Dict[str, Any], log: logging.Logger
    ) -> None:
        """Log successful promotion details."""
        log.info(f"✅ Successfully promoted '{attack_name}' implementation")
        log.info(f"   Reason: {reason}")
        if performance_data:
            if improvement := performance_data.get("improvement_percent"):
                log.info(f"   Performance improvement: {improvement}%")
            if success_rate := performance_data.get("success_rate"):
                log.info("   New success rate: %.1f%%", float(success_rate) * 100.0)
            if test_cases := performance_data.get("test_cases"):
                log.info(f"   Tested on {test_cases} cases")

    @staticmethod
    def promote_implementation(
        attack_name: str,
        new_handler: Callable[..., Any],
        reason: str,
        performance_data: Optional[Dict[str, Any]] = None,
        require_confirmation: bool = True,
    ) -> bool:
        """
        Allows promoting a more advanced implementation from an external module
        to become the canonical handler for a core attack type.

        REFACTORED: Extracted validation and logging to helper methods.

        This method integrates with the AttackRegistry promotion mechanism to
        replace existing attack implementations with more effective versions.

        Args:
            attack_name: Name of the attack to promote (e.g., "fakeddisorder", "seqovl")
            new_handler: New handler function to use
            reason: Justification for promotion
            performance_data: Optional performance metrics (improvement_percent, test_cases, etc.)
            require_confirmation: Whether to require explicit confirmation for CORE attacks

        Returns:
            True if promotion successful, False otherwise

        Examples:
            >>> success = BypassTechniques.promote_implementation(
            ...     "fakeddisorder",
            ...     my_improved_handler,
            ...     "Improved success rate on x.com from 85% to 95%",
            ...     {"improvement_percent": 11.8, "test_cases": 1000}
            ... )
        """
        log = logging.getLogger("BypassTechniques")

        # Validate inputs
        if not BypassTechniques._validate_promotion_inputs(attack_name, new_handler, reason, log):
            return False

        # Validate performance data
        performance_data = BypassTechniques._validate_performance_data(performance_data, log)

        try:
            # Import registry (lazy import to avoid circular dependencies)
            from ..attacks.attack_registry import get_attack_registry
            from ..attacks.metadata import AttackMetadata

            registry = get_attack_registry()

            # Validate that the attack exists
            existing_metadata = registry.get_attack_metadata(attack_name)
            if not existing_metadata:
                log.error(f"Attack '{attack_name}' not found in registry")
                return False

            # Create enhanced metadata for the promoted implementation
            new_metadata = AttackMetadata(
                name=f"{existing_metadata.name} (Promoted)",
                description=f"{existing_metadata.description}\n\nPromoted: {reason}",
                required_params=existing_metadata.required_params,
                optional_params=existing_metadata.optional_params,
                aliases=existing_metadata.aliases,
                category=existing_metadata.category,
            )

            # Validate the new handler signature
            BypassTechniques._validate_handler_signature(new_handler, log)

            # Attempt the promotion through the registry
            result = registry.promote_implementation(
                attack_type=attack_name,
                new_handler=new_handler,
                new_metadata=new_metadata,
                reason=reason,
                performance_data=performance_data,
                require_confirmation=require_confirmation,
            )

            if result.success:
                BypassTechniques._log_promotion_success(attack_name, reason, performance_data, log)
                # Log promotion history for audit trail
                if history := registry.get_promotion_history(attack_name):
                    log.debug(
                        "Promotion history for '%s': %s promotions", attack_name, len(history)
                    )
                return True
            else:
                log.error("❌ Failed to promote '%s': %s", attack_name, result.message)
                if result.conflicts:
                    for conflict in result.conflicts:
                        log.error(f"   Conflict: {conflict}")
                return False

        except ImportError as e:
            log.error(f"Failed to import AttackRegistry: {e}")
            log.error("Make sure core.bypass.attacks.attack_registry is available")
            return False
        except AttributeError as e:
            log.error(f"AttackRegistry API error: {e}")
            log.error("Registry API may have changed - check compatibility")
            return False
        except Exception as e:
            log.error(
                f"Unexpected error during promotion of '{attack_name}': {type(e).__name__}: {e}"
            )
            log.exception("Full traceback:")
            return False

    @staticmethod
    def apply_checksum_fooling(packet_data: bytearray, checksum_value: int = 0xDEAD) -> bytearray:
        """
        Apply checksum fooling to packet data.

        REFACTORED: Unified implementation replacing apply_badsum_fooling and apply_md5sig_fooling.

        Args:
            packet_data: Packet data to modify
            checksum_value: Checksum value to use (default: 0xDEAD for badsum, 0xBEEF for md5sig)

        Returns:
            Modified packet data with corrupted checksum
        """
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", checksum_value)
        return packet_data

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        """
        Apply bad checksum fooling (0xDEAD).

        DEPRECATED: This is now a thin wrapper around apply_checksum_fooling().
        Kept for backward compatibility.
        """
        return BypassTechniques.apply_checksum_fooling(packet_data, checksum_value=0xDEAD)

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        """
        Apply MD5 signature fooling (0xBEEF).

        DEPRECATED: This is now a thin wrapper around apply_checksum_fooling().
        Kept for backward compatibility.
        """
        return BypassTechniques.apply_checksum_fooling(packet_data, checksum_value=0xBEEF)


class FakedDisorderAttack:
    """
    Unified FakedDisorderAttack - the canonical fakeddisorder implementation.

    This class consolidates the best features from multiple variants:
    - Zapret-compatible defaults and algorithm
    - X.COM TTL fix for maximum effectiveness
    - Special position resolution (sni, cipher, midsld)
    - Multiple fake payload types (TLS, HTTP, QUIC, etc.)
    - Repeats functionality for stubborn DPI

    Key Features:
    - **Zapret defaults**: split_pos=76, split_seqovl=336, ttl=1
    - **X.COM TTL fix**: TTL limited to 3 for effectiveness
    - **Special positions**: "sni" (43), "cipher" (11), "midsld" (middle)
    - **Fake payloads**: TLS, HTTP, QUIC, WireGuard, DHT, custom
    - **Repeats**: Multiple attempts with minimal delays

    Architecture:
    - Lightweight facade pattern
    - Core logic delegated to FakedDisorderCore
    - Payload generation delegated to PayloadGeneratorFactory
    - Maintains backward compatibility

    Examples:
        >>> # Zapret-compatible instance
        >>> attack = FakedDisorderAttack.create_zapret_compatible()
        >>> segments = attack.execute(tls_clienthello)
        >>> # Returns: [(fake, 0, opts), (part2, seq, opts), (part1, 0, opts)]

        >>> # X.COM optimized (with repeats=2)
        >>> attack = FakedDisorderAttack.create_x_com_optimized()
        >>> segments = attack.execute(tls_clienthello)
        >>> # Returns 6 segments (3 original + 3 repeats)

        >>> # Custom configuration
        >>> attack = FakedDisorderAttack(
        ...     split_pos="sni",
        ...     ttl=2,
        ...     fooling_methods=["badsum", "badseq"],
        ...     fake_payload_type="PAYLOADTLS"
        ... )
        >>> segments = attack.execute(payload)

    Factory Methods:
    - create_zapret_compatible(): Exact zapret defaults
    - create_x_com_optimized(): Tuned for X.COM (Twitter)
    - create_instagram_optimized(): Tuned for Instagram

    See Also:
    - FakedDisorderCore: Core execution logic
    - PayloadGeneratorFactory: Fake payload generation
    - FakedDisorderFactory: Factory methods
    """

    def __init__(
        self,
        split_pos: Any = 76,
        split_seqovl: int = 336,
        ttl: int = 1,
        autottl: Optional[int] = None,
        repeats: int = 1,
        fooling_methods: Optional[List[str]] = None,
        fake_payload_type: str = "PAYLOADTLS",
        custom_fake_payload: Optional[bytes] = None,
        enable_monitoring: bool = False,
        enable_injection: bool = False,
        **kwargs,
    ):
        """
        Initialize unified FakedDisorderAttack.

        REFACTORED: Core logic delegated to FakedDisorderCore.
        This class is now a lightweight facade for backward compatibility.

        Args:
            split_pos: Split position (int or "sni"/"cipher"/"midsld")
            split_seqovl: Sequence overlap size (zapret: 336)
            ttl: TTL for fake packets (zapret: 1)
            autottl: AutoTTL range testing (1 to autottl)
            repeats: Number of attack attempts
            fooling_methods: DPI fooling methods ["badsum", "badseq", "md5sig"]
            fake_payload_type: Fake payload type ("PAYLOADTLS", "HTTP", "QUIC", etc.)
            custom_fake_payload: Custom fake payload bytes
            enable_monitoring: Enable monitoring (deprecated)
            enable_injection: Enable injection (deprecated)
            **kwargs: Additional parameters
        """
        # Store configuration
        self.split_pos = split_pos
        self.split_seqovl = split_seqovl
        self.ttl = ttl
        self.autottl = autottl
        self.repeats = repeats
        self.fooling_methods = fooling_methods or ["badsum", "badseq"]
        self.fake_payload_type = fake_payload_type
        self.custom_fake_payload = custom_fake_payload
        self.enable_monitoring = enable_monitoring
        self.enable_injection = enable_injection
        self.kwargs = kwargs

        # Initialize logger and core
        self.logger = logging.getLogger("FakedDisorderAttack")
        self._core = create_core_from_attack(self)
        self._core.validate_config()

        # Log initialization
        self.logger.info("🔧 Initialized FakedDisorderAttack")
        self.logger.info(f"   pos={self.split_pos}, overlap={self.split_seqovl}, ttl={self.ttl}")

    def _validate_config(self) -> None:
        """Validate configuration (delegates to core)."""
        self._core.validate_config()

    def execute(self, payload: bytes, **context: Any) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Execute fakeddisorder attack.

        REFACTORED: Delegates to FakedDisorderCore.

        Args:
            payload: Original packet data (usually TLS ClientHello)
            **context: Additional context (dst_ip, dst_port, etc.)

        Returns:
            List of segments: [(data, seq_offset, options), ...]
        """
        return self._core.execute(
            payload,
            generate_fake_payload_func=self._generate_fake_payload,
            create_segments_func=self._create_unified_segments,
            apply_repeats_func=self._apply_repeats if self.repeats > 1 else None,
            **context,
        )

    def _resolve_split_position(self, payload: bytes) -> int:
        """Resolve split position (delegates to core)."""
        return self._core.resolve_split_position(payload)

    def _generate_fake_payload(self, original_payload: bytes, **context: Any) -> bytes:
        """Generate fake payload (delegates to PayloadGeneratorFactory)."""
        return PayloadGeneratorFactory.generate(
            payload_type=self.fake_payload_type,
            original_payload=original_payload,
            custom_payload=self.custom_fake_payload,
            **context,
        )

    def _calculate_effective_ttl(self) -> int:
        """Calculate effective TTL (delegates to core)."""
        return self._core.calculate_effective_ttl()

    # === DEPRECATED WRAPPER METHODS (one-liners for backward compatibility) ===
    def _generate_enhanced_tls_payload(self) -> bytes:
        return PayloadGeneratorFactory.generate_enhanced_tls_payload()

    def _generate_enhanced_http_payload(self) -> bytes:
        return PayloadGeneratorFactory.generate_enhanced_http_payload()

    def _generate_quic_payload(self) -> bytes:
        return PayloadGeneratorFactory.generate_quic_payload()

    def _generate_wireguard_payload(self) -> bytes:
        return PayloadGeneratorFactory.generate_wireguard_payload()

    def _generate_dht_payload(self) -> bytes:
        return PayloadGeneratorFactory.generate_dht_payload()

    def _detect_tls(self, payload: bytes) -> bool:
        return PayloadGeneratorFactory.detect_tls(payload)

    def _detect_http(self, payload: bytes) -> bool:
        return PayloadGeneratorFactory.detect_http(payload)

    def _create_unified_segments(
        self, payload: bytes, fake_payload: bytes, split_pos: int, ttl: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create segments with zapret-compatible algorithm."""
        segments = []
        part1, part2, sp = split_payload_with_pos(payload, split_pos, validate=True)

        # Fake packet
        fake_opts = BypassTechniques._create_segment_options(
            is_fake=True, ttl=ttl, fooling_methods=self.fooling_methods, delay_ms_after=0
        )
        segments.append((fake_payload, 0, fake_opts))

        # Real segments with optional overlap
        if self.split_seqovl > 0 and len(part1) > 0 and len(part2) > 0:
            overlap = min(self.split_seqovl, len(part1), len(part2))
            overlap_seq = sp - overlap
            self.logger.debug(f"🔄 Overlap: {overlap}b @ {overlap_seq}")

            part2_opts = BypassTechniques._create_segment_options(is_fake=False, delay_ms_after=1)
            part1_opts = BypassTechniques._create_segment_options(is_fake=False, delay_ms_after=0)
            segments.extend([(part2, overlap_seq, part2_opts), (part1, 0, part1_opts)])
        else:
            part2_opts = BypassTechniques._create_segment_options(is_fake=False, delay_ms_after=1)
            part1_opts = BypassTechniques._create_segment_options(is_fake=False)
            segments.extend([(part2, sp, part2_opts), (part1, 0, part1_opts)])

        return segments

    def _apply_repeats(
        self, segments: List[Tuple[bytes, int, Dict[str, Any]]]
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply repeats with minimal delays."""
        if self.repeats <= 1:
            return segments

        repeated = segments.copy()
        for repeat_num in range(1, self.repeats):
            for payload, seq_offset, options in segments:
                opts = options.copy()
                opts["delay_ms_after"] = options.get("delay_ms_after", 0) + repeat_num * 1.0
                opts["repeat_num"] = repeat_num
                opts["is_repeat"] = True
                repeated.append((payload, seq_offset, opts))

        self.logger.debug(f"Applied {self.repeats} repeats")
        return repeated

    @classmethod
    def create_zapret_compatible(
        cls,
        split_seqovl: int = 336,
        autottl: int = 2,
        ttl: int = 1,
        split_pos: int = 76,
        **kwargs,
    ) -> "FakedDisorderAttack":
        """
        Factory method to create zapret-compatible instance.

        REFACTORED: This now delegates to FakedDisorderFactory.
        Kept as classmethod for backward compatibility.

        Uses exact zapret defaults for maximum compatibility.
        """
        return FakedDisorderFactory.create_zapret_compatible(
            split_seqovl=split_seqovl,
            autottl=autottl,
            ttl=ttl,
            split_pos=split_pos,
            **kwargs,
        )

    @classmethod
    def create_x_com_optimized(cls, **kwargs) -> "FakedDisorderAttack":
        """
        Factory method optimized for X.COM (critical failing domain).

        REFACTORED: This now delegates to FakedDisorderFactory.
        Kept as classmethod for backward compatibility.

        Uses parameters specifically tuned for X.COM effectiveness.
        """
        return FakedDisorderFactory.create_x_com_optimized(**kwargs)

    @classmethod
    def create_instagram_optimized(cls, **kwargs) -> "FakedDisorderAttack":
        """
        Factory method optimized for Instagram.

        REFACTORED: This now delegates to FakedDisorderFactory.
        Kept as classmethod for backward compatibility.
        """
        return FakedDisorderFactory.create_instagram_optimized(**kwargs)

    # === TCP WINDOW MANIPULATION TECHNIQUES ===
    # Migrated from tcp_fragmentation.py

    @staticmethod
    def apply_window_manipulation(
        payload: bytes,
        window_size: int = 1,
        delay_ms: float = 50.0,
        fragment_count: int = 5,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        TCP window manipulation attack.

        REFACTORED: Delegates to AdvancedTechniques.
        Kept as static method for backward compatibility.

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
        """
        return AdvancedTechniques.apply_window_manipulation(
            payload, window_size, delay_ms, fragment_count, fooling_methods
        )

    @staticmethod
    def apply_tcp_options_modification(
        payload: bytes,
        split_pos: int = 5,
        options_type: str = "mss",
        bad_checksum: bool = False,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        TCP options modification attack.

        REFACTORED: Delegates to AdvancedTechniques.
        Kept as static method for backward compatibility.

        Modifies TCP options to evade DPI detection while fragmenting.
        Different option types can confuse DPI systems that analyze TCP headers.

        Args:
            payload: Original data to split
            split_pos: Position to split the payload
            options_type: Type of TCP options to add ("mss", "window_scale", "timestamp", etc.)
            bad_checksum: Whether to corrupt TCP checksum
            fooling_methods: Optional DPI fooling methods

        Returns:
            Recipe with TCP options modification
        """
        return AdvancedTechniques.apply_tcp_options_modification(
            payload, split_pos, options_type, bad_checksum, fooling_methods
        )

    @staticmethod
    def _create_tcp_options(options_type: str) -> bytes:
        """
        Create TCP options based on specified type.

        REFACTORED: Delegates to AdvancedTechniques.
        Kept as static method for backward compatibility.

        Args:
            options_type: Type of TCP options to create

        Returns:
            Raw TCP options bytes
        """
        return AdvancedTechniques.create_tcp_options(options_type)

    @staticmethod
    def apply_advanced_timing_control(
        payload: bytes,
        split_pos: int = 3,
        delays: Optional[List[float]] = None,
        jitter: bool = False,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Advanced timing control for segment transmission.

        REFACTORED: Delegates to AdvancedTechniques.
        Kept as static method for backward compatibility.

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
        """
        return AdvancedTechniques.apply_advanced_timing_control(
            payload, split_pos, delays, jitter, fooling_methods
        )


# ===== MODULE-LEVEL CONVENIENCE ALIASES =====
# These provide convenient module-level access to commonly used methods
# that are otherwise only available as class methods

# Fooling methods (for backward compatibility and convenience)
apply_checksum_fooling = BypassTechniques.apply_checksum_fooling
apply_badsum_fooling = BypassTechniques.apply_badsum_fooling
apply_md5sig_fooling = BypassTechniques.apply_md5sig_fooling


# Public API exports for backward compatibility and advanced usage
__all__ = [
    # ===== MAIN CLASSES (STABLE API) =====
    "BypassTechniques",  # Main bypass techniques class
    "FakedDisorderAttack",  # Advanced fakeddisorder attack class
    # ===== UTILITY FUNCTIONS (STABLE API) =====
    # From primitives_utils.py (Step 1)
    "gen_fake_sni",  # Generate fake SNI
    "split_payload",  # Split payload at position
    "create_segment_options",  # Create segment options dict
    "normalize_positions",  # Normalize position specifications
    "handle_small_payload",  # Handle small payload edge case
    # ===== FOOLING METHODS (STABLE API) =====
    # Unified method (Step 2)
    "apply_checksum_fooling",  # Unified checksum fooling
    # Legacy wrappers (DEPRECATED but kept for compatibility)
    "apply_badsum_fooling",  # DEPRECATED: Use apply_checksum_fooling(data, 0xDEAD)
    "apply_md5sig_fooling",  # DEPRECATED: Use apply_checksum_fooling(data, 0xBEEF)
    # ===== ADVANCED COMPONENTS (FOR POWER USERS) =====
    # From payload_generators.py (Step 3)
    "PayloadGeneratorFactory",  # Factory for generating fake payloads
    # From attack_factories.py (Step 4)
    "FakedDisorderFactory",  # Factory for creating FakedDisorderAttack instances
    # From faked_disorder_core.py (Step 5)
    "FakedDisorderCore",  # Core logic for FakedDisorderAttack
    "create_core_from_attack",  # Helper to create core from attack instance
    # From advanced_techniques.py (Step 6)
    "AdvancedTechniques",  # Advanced attack techniques
    # From bypass_helpers.py (Step 7)
    "validate_payload_size",  # Validate payload size
    "create_fallback_segment",  # Create fallback segment
    "validate_and_adjust_split_position",  # Validate split position
    "build_segment_metadata",  # Build segment metadata
    "calculate_fragment_delays",  # Calculate fragment delays
    "optimize_fragment_positions",  # Optimize fragment positions
    "create_fragment_list",  # Create fragment list
    "log_attack_execution",  # Log attack execution
]

# ===== DEPRECATION NOTICES =====
# The following deprecated methods have been removed in this version:
# - _gen_fake_sni: Use gen_fake_sni() from primitives_utils instead
# - _calculate_effective_ttl: Delegated to FakedDisorderCore
# - _generate_enhanced_*_payload: Use PayloadGeneratorFactory methods instead
# - _detect_tls, _detect_http: Use PayloadGeneratorFactory methods instead
# - _execute_with_autottl: Removed (use dedicated AutoTTL strategy)
# - _evaluate_ttl_effectiveness: Removed (use proper network testing)
# - _monitor_attack_results: Removed (use dedicated monitoring system)
#
# Still deprecated but kept for backward compatibility:
# - apply_badsum_fooling: Use apply_checksum_fooling(data, 0xDEAD) instead
# - apply_md5sig_fooling: Use apply_checksum_fooling(data, 0xBEEF) instead

# ===== MODULE ORGANIZATION =====
# This module has been refactored into multiple specialized modules:
# - primitives.py: Main facade with backward compatibility
# - primitives_utils.py: Shared utility functions
# - payload_generators.py: Fake payload generation
# - attack_factories.py: Attack factory methods
# - faked_disorder_core.py: Core FakedDisorderAttack logic
# - advanced_techniques.py: Advanced attack techniques
# - bypass_helpers.py: Common helper functions
#
# All modules are accessible through this main module for convenience.
# Advanced users can import directly from submodules if needed.
