# path: core/bypass/techniques/primitives.py
# Canonical primitives for DPI bypass attacks.

import struct
import random
import string
import logging
from typing import List, Tuple, Dict, Optional


def _gen_fake_sni(original: Optional[str] = None) -> str:
    """Generate fake SNI in zapret style."""
    label = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 14))
    )
    tld = random.choice(["edu", "com", "net", "org"])
    return f"{label}.{tld}"


class BypassTechniques:
    """
    Библиотека примитивных техник обхода DPI в стиле zapret.
    Основные принципы:
    - Генерация "рецептов" - последовательностей TCP сегментов для отправки
    - Каждый рецепт - список кортежей (данные, смещение, опции)
    - Поддержка различных методов обмана DPI (fooling methods)
    - Совместимость с zapret параметрами и логикой
    Типы атак:
    1. Фейковые пакеты (fake*): Отправка ложных данных с низким TTL
    2. Разделение (split/multisplit): Деление пакета на части
    3. Изменение порядка (disorder): Отправка частей в неправильном порядке
    4. Перекрытие (seqovl): Перекрытие TCP последовательностей
    5. Race conditions: Гонка между фейковыми и реальными пакетами
    Методы обмана DPI:
    - badsum: Неправильная TCP контрольная сумма
    - badseq: Неправильный sequence number
    - md5sig: TCP MD5 signature option
    - fakesni: Поддельное Server Name Indication
    Формат рецепта:
    List[Tuple[bytes, int, Dict]] где:
    - bytes: Данные сегмента
    - int: Смещение в исходном payload (rel_seq)
    - Dict: Опции сегмента (is_fake, ttl, tcp_flags, etc.)
    Note:
        Это примитивная реализация для обратной совместимости.
        Продвинутые атаки находятся в core/bypass/attacks/.
    """

    # Маркер версии для диагностики
    API_VER = "primitives CANONICAL-2025-10-24"

    @staticmethod
    def _split_payload(
        payload: bytes, split_pos: int, validate: bool = True
    ) -> Tuple[bytes, bytes]:
        """
        Shared payload splitting logic for all disorder family attacks.
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
        log = logging.getLogger("BypassTechniques")
        payload_len = len(payload)

        # Handle edge cases
        if payload_len < 2:
            if validate:
                log.warning(
                    f"Payload too small ({payload_len} bytes), returning as single part"
                )
                return payload, b""
            else:
                raise ValueError(
                    f"Payload too small for splitting: {payload_len} bytes"
                )

        # Validate and adjust split position
        if validate:
            if split_pos <= 0:
                log.warning(f"split_pos {split_pos} <= 0, adjusting to 1")
                split_pos = 1
            elif split_pos >= payload_len:
                log.warning(
                    f"split_pos {split_pos} >= payload size {payload_len}, adjusting to {payload_len - 1}"
                )
                split_pos = payload_len - 1
        else:
            if split_pos <= 0 or split_pos >= payload_len:
                raise ValueError(
                    f"Invalid split_pos {split_pos} for payload of length {payload_len}"
                )

        # Perform the split
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]

        log.debug(f"Split payload: {payload_len}b → part1={len(part1)}b, part2={len(part2)}b at pos={split_pos}")

        return part1, part2

    @staticmethod
    def _create_segment_options(
        is_fake: bool,
        ttl: Optional[int] = None,
        fooling_methods: Optional[List[str]] = None,
        tcp_flags: int = 0x18,
        delay_ms_after: Optional[int] = None,
        window_size_override: Optional[int] = None,
        tcp_options: Optional[bytes] = None,
        **kwargs,
    ) -> Dict[str, any]:
        """
        Shared segment options builder for all attacks.
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
            - "badseq": Add -1 to sequence number
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
        # Start with base options
        options = {"is_fake": is_fake, "tcp_flags": tcp_flags}

        # Add TTL for fake segments
        if is_fake and ttl is not None:
            options["ttl"] = int(ttl)

        # Add delay if specified
        if delay_ms_after is not None:
            options["delay_ms_after"] = int(delay_ms_after)

        # Add window size override if specified
        if window_size_override is not None:
            options["window_size_override"] = int(window_size_override)

        # Add TCP options if specified
        if tcp_options is not None:
            options["tcp_options"] = tcp_options

        # Process fooling methods
        if fooling_methods:
            for method in fooling_methods:
                if method == "badsum":
                    options["corrupt_tcp_checksum"] = True
                elif method == "badseq":
                    options["seq_extra"] = -1
                elif method == "md5sig":
                    options["add_md5sig_option"] = True
                elif method == "fakesni":
                    options["fooling_sni"] = _gen_fake_sni()

        # Add any additional options
        options.update(kwargs)

        return options

    @staticmethod
    def _normalize_positions(
        positions: any, payload_len: int, validate: bool = True
    ) -> List[int]:
        """
        Convert various position formats to List[int] and handle special values.
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
        log = logging.getLogger("BypassTechniques")

        # Handle None or empty input
        if positions is None:
            return []

        # Convert to list if single value
        if not isinstance(positions, (list, tuple)):
            positions = [positions]

        normalized = []

        for pos in positions:
            if isinstance(pos, int):
                normalized.append(pos)
            elif isinstance(pos, str):
                # Handle special values
                if pos == "sni":
                    # TLS SNI extension typically starts at byte 43 in
                    # ClientHello
                    special_pos = 43
                    if validate and special_pos >= payload_len:
                        log.warning(
                            f"SNI position {special_pos} >= payload length {payload_len}, using middle"
                        )
                        special_pos = payload_len // 2
                    normalized.append(special_pos)
                elif pos == "cipher":
                    # TLS cipher suites typically start around byte 11 in
                    # ClientHello
                    special_pos = 11
                    if validate and special_pos >= payload_len:
                        log.warning(
                            f"Cipher position {special_pos} >= payload length {payload_len}, using middle"
                        )
                        special_pos = payload_len // 2
                    normalized.append(special_pos)
                elif pos == "midsld":
                    # Middle of payload
                    special_pos = payload_len // 2
                    normalized.append(special_pos)
                else:
                    log.warning(f"Unknown special position value: {pos}, ignoring")
            else:
                try:
                    # Try to convert to int
                    normalized.append(int(pos))
                except (ValueError, TypeError):
                    log.warning(f"Cannot convert position to int: {pos}, ignoring")

        # Remove duplicates and sort
        normalized = sorted(list(set(normalized)))

        # Validate positions are within bounds
        if validate:
            valid_positions = []
            for pos in normalized:
                if pos <= 0:
                    log.warning(f"Position {pos} <= 0, adjusting to 1")
                    pos = 1
                elif pos >= payload_len:
                    log.warning(f"Position {pos} >= payload length {payload_len}, adjusting to {payload_len - 1}")
                    pos = payload_len - 1

                # Only add if it's a valid split position
                if 0 < pos < payload_len:
                    valid_positions.append(pos)

            normalized = sorted(list(set(valid_positions)))

        log.debug(
            f"Normalized positions: {positions} → {normalized} (payload_len={payload_len})"
        )

        return normalized

    @staticmethod
    def apply_fake_packet_race(
        payload: bytes, ttl: int = 3, fooling: List[str] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Создает race-атаку: фейковый пакет + оригинал.
        """
        if fooling is None:
            fooling = ["badsum"]

        # Use shared helper for segment options
        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True, ttl=ttl, fooling_methods=fooling, delay_ms_after=5
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
        **kwargs, # Принимаем и игнорируем лишние параметры
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

        if len(payload) < 2:
            return [
                (payload, 0, BypassTechniques._create_segment_options(is_fake=False))
            ]

        # Use shared helper for payload splitting
        part1, part2 = BypassTechniques._split_payload(
            payload, split_pos, validate=True
        )

        # Use shared helper for segment options
        fool = fooling_methods if fooling_methods is not None else ["badsum"]
        if not fool:
            fool = ["badsum"]

        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True, ttl=fake_ttl, fooling_methods=fool, delay_ms_after=5
        )
        opts_real = BypassTechniques._create_segment_options(is_fake=False)

        # --- ЕДИНСТВЕННАЯ ПРАВИЛЬНАЯ ЛОГИКА ДЛЯ FAKEDDISORDER ---
        # Ключ к успеху для x.com: фейковый пакет содержит ВЕСЬ ClientHello.
        fake_payload = payload

        log.info(
            f"✅ fakeddisorder: fake_full={len(fake_payload)}b@0 ttl={fake_ttl}, real_p2={len(part2)}b@{split_pos}, real_p1={len(part1)}b@0"
        )

        return [
            (fake_payload, 0, opts_fake),
            (part2, split_pos, opts_real),
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

        if len(payload) < 2:
            return [
                (payload, 0, BypassTechniques._create_segment_options(is_fake=False))
            ]

        # FIXED: Validate and adjust parameters with proper bounds checking
        sp = max(1, min(int(split_pos), len(payload) - 1))

        # FIXED: Validate overlap_size is reasonable and within bounds
        # Cap at 1000 bytes for sanity
        max_overlap = min(sp, len(payload) - sp, 1000)
        ovl = max(1, min(int(overlap_size), max_overlap))

        if ovl != overlap_size:
            log.warning(f"Adjusted overlap_size from {overlap_size} to {ovl} (max allowed: {max_overlap})")

        # Use shared helper for segment options
        fool = fooling_methods if fooling_methods is not None else ["badsum"]

        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True, ttl=fake_ttl, fooling_methods=fool, delay_ms_after=5
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
            overlap_part = payload[: min(len(payload), 64)] # Small fake packet
            start_offset = 0

        log.info(f"✅ seqovl: fake_overlap={len(overlap_part)}b@{start_offset} ttl={fake_ttl}, real_full={len(real_full)}b@0, overlap_size={ovl}, split_pos={sp}")

        return [
            (overlap_part, start_offset, opts_fake),
            (real_full, 0, opts_real),
        ]

    @staticmethod
    def apply_multidisorder(
        payload: bytes,
        positions: List[int],
        fooling: Optional[List[str]] = None,
        fake_ttl: int = 1,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Multiple Disorder attack - optimized multi-fragment reordering.
        Optimizations:
        1. Uses shared helpers for consistent behavior
        2. Optimized position generation for common cases
        3. Enhanced fragment size validation
        4. Improved performance for large payloads
        "Maximum chaos" strategy:
        1. Small "poisoning" fake packet
           - Contains only initial portion of data
           - Size = minimum position from list
           - Goal: make DPI think this is the complete packet
        2. Multiple real data fragmentation
           - Payload split into fragments at positions
           - Each fragment sent as separate TCP segment
           - Positions automatically deduplicated and sorted
        3. Reverse order transmission (disorder)
           - Fragments sent in reverse order
           - Creates maximum confusion for DPI
           - Server correctly reassembles using sequence numbers
        OPTIMIZED position generation:
        - Automatic position optimization for small payloads
        - Fragment size validation (min 3 bytes per fragment)
        - Intelligent fallback for edge cases
        Advantages over simple disorder:
        - More fragments = more DPI confusion
        - Flexible position selection
        - Effective against advanced DPI systems
        Args:
            payload: Original data to fragment and reorder
            positions: List of split positions (will be sorted and optimized)
            fooling: DPI fooling methods for fake packet
            fake_ttl: TTL for fake packet
        Returns:
            Recipe with segments:
            1. Small fake packet
            2-N. Real fragments in reverse order
        """
        log = logging.getLogger("BypassTechniques")
        fooling = fooling if fooling is not None else ["badsum", "badseq"]

        # Use shared helper to normalize positions with optimization
        normalized_positions = BypassTechniques._normalize_positions(
            positions, len(payload), validate=True
        )

        if not normalized_positions or len(payload) < 2:
            log.warning(
                "Multidisorder called with no valid positions, falling back to fakeddisorder."
            )
            return BypassTechniques.apply_fakeddisorder(
                payload, len(payload) // 2, fake_ttl, fooling
            )

        # OPTIMIZATION: Filter positions to ensure reasonable fragment sizes
        optimized_positions = []
        min_fragment_size = 3  # Minimum bytes per fragment

        for pos in sorted(normalized_positions):
            if (
                not optimized_positions
                or pos - optimized_positions[-1] >= min_fragment_size
            ):
                optimized_positions.append(pos)

        # Ensure we have at least one position
        if not optimized_positions:
            optimized_positions = [len(payload) // 2]
            log.debug("No valid positions after optimization, using middle split")

        # OPTIMIZATION: Limit number of fragments for performance
        max_fragments = 8  # Reasonable limit for most cases
        if len(optimized_positions) > max_fragments:
            # Keep evenly distributed positions
            step = len(optimized_positions) // max_fragments
            optimized_positions = optimized_positions[::step][:max_fragments]
            log.debug(f"Limited to {max_fragments} fragments for performance")

        # 1. Create "poisoning" fake packet (optimized size)
        fake_size = min(optimized_positions) if optimized_positions else 1
        fake_size = max(1, min(fake_size, 64))  # Cap fake packet size
        fake_payload = payload[:fake_size]

        # Use shared helper for segment options
        opts_fake = BypassTechniques._create_segment_options(
            is_fake=True,
            ttl=fake_ttl,
            fooling_methods=fooling,
            delay_ms_after=2,  # Reduced delay for better performance
        )
        segments = [(fake_payload, 0, opts_fake)]

        # 2. OPTIMIZED: Create real fragments with validation
        all_splits = sorted(list(set([0] + optimized_positions + [len(payload)])))
        real_fragments = []

        for i in range(len(all_splits) - 1):
            start, end = all_splits[i], all_splits[i + 1]
            if start < end and end - start >= 1:  # Ensure non-empty fragments
                fragment_data = payload[start:end]
                real_fragments.append((fragment_data, start))

        # OPTIMIZATION: Skip multidisorder if we only have one fragment
        if len(real_fragments) <= 1:
            log.debug("Only one fragment, falling back to simple disorder")
            return BypassTechniques.apply_disorder(payload, len(payload) // 2)

        # 3. Add real fragments in REVERSE order with optimized timing
        opts_real = BypassTechniques._create_segment_options(
            is_fake=False, delay_ms_after=1  # Minimal delay between fragments
        )

        for i, (data, offset) in enumerate(reversed(real_fragments)):
            # Add metadata for debugging
            fragment_opts = opts_real.copy()
            fragment_opts["fragment_index"] = len(real_fragments) - i - 1
            fragment_opts["total_fragments"] = len(real_fragments)
            fragment_opts["multidisorder_type"] = "optimized"

            segments.append((data, offset, fragment_opts))

        log.info(
            f"✅ OPTIMIZED Multidisorder: "
            f"fake_part={len(fake_payload)}b, "
            f"{len(real_fragments)} fragments (positions={optimized_positions}), "
            f"reverse_order=True"
        )

        return segments

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int], fooling: Optional[List[str]] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Multiple Split attack - optimized multi-fragment transmission.
        Optimizations:
        1. Uses shared helpers for consistent behavior
        2. Optimized for single position case (most common)
        3. Enhanced fragment validation and timing
        4. Improved badsum race condition handling
        Clean fragmentation approach:
        1. Split payload into fragments at specified positions
        2. Send fragments in correct order (no disorder)
        3. Each fragment as separate TCP segment with correct sequence number
        4. Optional delays between segments for temporal separation
        OPTIMIZED single position case:
        - When only one position provided, uses simple two-segment split
        - Reduced overhead and improved performance
        - Maintains compatibility with existing code
        Enhanced features:
        - Automatic deduplication and sorting of positions
        - Alternating TCP flags (ACK/PSH+ACK) for variety
        - Optimized delays (1-5ms instead of 5-15ms)
        - Enhanced "fragmented race" with badsum
        Fragmented race (badsum):
        - If fooling=["badsum"] specified
        - First segment sent with incorrect checksum
        - Creates race condition between corrupted and correct segments
        - DPI may allow connection due to confusion
        Differences from multidisorder:
        - NO segment reordering
        - NO fake packets
        - Focus on temporal and structural separation
        - Less aggressive approach, better compatibility
        Args:
            payload: Original data to fragment
            positions: List of split positions (will be optimized)
            fooling: Fooling methods (supports badsum for race condition)
        Returns:
            Recipe with segments in correct order with optional delays
        """
        log = logging.getLogger("BypassTechniques")

        # Use shared helper to normalize positions with optimization
        normalized_positions = BypassTechniques._normalize_positions(
            positions, len(payload), validate=True
        )

        if not normalized_positions:
            return [
                (payload, 0, BypassTechniques._create_segment_options(is_fake=False))
            ]

        fooling = fooling or []

        # OPTIMIZATION: Handle single position case efficiently
        if len(normalized_positions) == 1:
            split_pos = normalized_positions[0]
            log.debug(f"Single position multisplit optimized: split_pos={split_pos}")

            # Use shared helper for payload splitting
            part1, part2 = BypassTechniques._split_payload(
                payload, split_pos, validate=True
            )

            # Create optimized two-segment split
            opts1 = BypassTechniques._create_segment_options(
                is_fake=False,
                tcp_flags=0x10,  # ACK only for first segment
                delay_ms_after=1,  # Minimal delay
            )
            opts2 = BypassTechniques._create_segment_options(
                is_fake=False, tcp_flags=0x18  # PSH+ACK for second segment
            )

            # Apply badsum to first segment if requested
            if "badsum" in fooling:
                opts1["corrupt_tcp_checksum"] = True
                log.info("🔥 Single-position multisplit with badsum race enabled")

            return [(part1, 0, opts1), (part2, split_pos, opts2)]

        # OPTIMIZATION: Multi-position case with enhanced validation
        flags_pattern = [0x10, 0x18]  # Alternate between ACK and PSH+ACK
        segments = []
        all_positions = [0] + normalized_positions + [len(payload)]

        # Validate fragment sizes
        min_fragment_size = 1
        valid_fragments = []

        for i in range(len(all_positions) - 1):
            start_pos = all_positions[i]
            end_pos = all_positions[i + 1]

            if end_pos - start_pos >= min_fragment_size:
                valid_fragments.append((start_pos, end_pos))

        if not valid_fragments:
            log.warning("No valid fragments after validation, using single segment")
            return [
                (payload, 0, BypassTechniques._create_segment_options(is_fake=False))
            ]

        # Create segments with optimized timing
        for i, (start_pos, end_pos) in enumerate(valid_fragments):
            segment_data = payload[start_pos:end_pos]
            tcp_flags = flags_pattern[i % len(flags_pattern)]

            # Build segment options using shared helper with optimized delays
            opts = BypassTechniques._create_segment_options(
                is_fake=False, tcp_flags=tcp_flags
            )

            # OPTIMIZATION: Reduced delays for better performance (1-5ms
            # instead of 5-15ms)
            if i < len(valid_fragments) - 1:  # Not the last segment
                opts["delay_ms_after"] = random.randint(1, 5)

            # Add metadata for debugging
            opts["fragment_index"] = i
            opts["total_fragments"] = len(valid_fragments)
            opts["multisplit_type"] = "optimized"

            # Apply badsum to first segment if requested (enhanced race
            # condition)
            if i == 0 and "badsum" in fooling:
                opts["corrupt_tcp_checksum"] = True
                opts["badsum_race"] = True
                log.info("🔥 Multi-position multisplit with badsum race enabled")

            segments.append((segment_data, start_pos, opts))

        log.info(
            f"✅ OPTIMIZED Multisplit: "
            f"{len(segments)} fragments, "
            f"positions={normalized_positions}, "
            f"badsum_race={'badsum' in fooling}"
        )

        return segments

    @staticmethod
    def apply_disorder(
        payload: bytes, split_pos: int, ack_first: bool = False
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Simple Disorder attack - reorder segments without fake packets.
        Optimizations:
        1. Uses shared helpers for consistent behavior
        2. Optimized for common use cases (small payloads, typical split positions)
        3. Enhanced validation and error handling
        4. Improved logging for debugging
        Minimalist approach to DPI bypass:
        1. Split payload into two parts at split_pos
        2. Send part 2 (from split_pos to end) first
        3. Send part 1 (from start to split_pos) second
        4. Server reassembles correct order using sequence numbers
        Differences from fakeddisorder:
        - NO fake packet with low TTL
        - Only real data in wrong order
        - Less traffic, but may be less effective
        - Suitable for simple DPI systems
        TCP flags optimization:
        - ack_first=False: First segment with PSH+ACK (0x18) - standard approach
        - ack_first=True: First segment with ACK only (0x10) - for flag-sensitive DPI
        - Second segment always PSH+ACK (0x18)
        Common use cases:
        - HTTP requests: split_pos=3-10 works well
        - TLS ClientHello: split_pos=5-20 recommended
        - Small payloads (<100 bytes): split_pos=payload_len//3
        Args:
            payload: Original data to split and reorder
            split_pos: Split position (1 <= pos < len(payload))
            ack_first: Use ACK-only flag in first segment (disorder2 variant)
        Returns:
            Recipe with 2 real segments in reverse order
        """
        log = logging.getLogger("BypassTechniques")

        if len(payload) < 2:
            return [
                (payload, 0, BypassTechniques._create_segment_options(is_fake=False))
            ]

        # Use shared helper for payload splitting with validation
        part1, part2 = BypassTechniques._split_payload(
            payload, split_pos, validate=True
        )

        # OPTIMIZATION: Skip disorder if one part is empty (edge case)
        if len(part1) == 0 or len(part2) == 0:
            log.warning(
                f"Disorder skipped: one part empty (part1={len(part1)}, part2={len(part2)})"
            )
            return [
                (payload, 0, BypassTechniques._create_segment_options(is_fake=False))
            ]

        # OPTIMIZATION: For very small second parts, use different strategy
        if len(part2) < 3:
            log.debug(f"Small part2 ({len(part2)}b), using conservative flags")
            first_flags = 0x18  # Always use PSH+ACK for small parts
        else:
            # Standard flag selection
            first_flags = 0x10 if ack_first else 0x18  # ACK or PSH+ACK

        # Use shared helper for segment options with optimized timing
        opts_real = BypassTechniques._create_segment_options(
            is_fake=False, delay_ms_after=1  # Minimal delay for second segment
        )
        opts_first = BypassTechniques._create_segment_options(
            is_fake=False,
            tcp_flags=first_flags,
            delay_ms_after=0,  # No delay for first segment
        )

        # OPTIMIZATION: Add metadata for debugging and monitoring
        opts_first["disorder_type"] = "simple"
        opts_first["is_first_segment"] = True
        opts_real["disorder_type"] = "simple"
        opts_real["is_second_segment"] = True

        log.info(f"✅ disorder: part2={len(part2)}b@{split_pos} flags=0x{first_flags:02x}, part1={len(part1)}b@0 ack_first={ack_first}")

        return [
            (part2, split_pos, opts_first),
            (part1, 0, opts_real),
        ]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        try:
            if not payload or len(payload) < 5:
                return payload
            if (
                payload[0] != 0x16
                or payload[1] != 0x03
                or payload[2] not in (0x00, 0x01, 0x02, 0x03)
            ):
                return payload

            rec_len = int.from_bytes(payload[3:5], "big")
            content = (
                payload[5 : 5 + rec_len] if 5 + rec_len <= len(payload) else payload[5:]
            )
            tail = payload[5 + rec_len :] if 5 + rec_len <= len(payload) else b""

            if split_pos < 1 or split_pos >= len(content):
                return payload

            part1, part2 = content[:split_pos], content[split_pos:]
            ver = payload[1:3]

            rec1 = bytes([0x16]) + ver + len(part1).to_bytes(2, "big") + part1
            rec2 = bytes([0x16]) + ver + len(part2).to_bytes(2, "big") + part2

            return rec1 + rec2 + tail
        except Exception:
            return payload

    @staticmethod
    def apply_wssize_limit(
        payload: bytes, window_size: int = 1
    ) -> List[Tuple[bytes, int, dict]]:
        segments, pos = ([], 0)
        opts = {"is_fake": False, "tcp_flags": 0x18}

        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos : pos + chunk_size]
            segments.append((chunk, pos, opts))
            pos += chunk_size

        return segments

    @staticmethod
    def promote_implementation(
        attack_name: str,
        new_handler: callable,
        reason: str,
        performance_data: Optional[Dict[str, any]] = None,
        require_confirmation: bool = True,
    ) -> bool:
        """
        Allows promoting a more advanced implementation from an external module
        to become the canonical handler for a core attack type.
        This method integrates with the AttackRegistry promotion mechanism to
        replace existing attack implementations with more effective versions.
        It should be used sparingly and only after thorough testing and
        validation that the new implementation is more effective.
        The promotion process:
        1. Validates the attack exists in the registry
        2. Validates the new handler is callable and properly structured
        3. Optionally validates performance improvements
        4. Creates comprehensive metadata for the new implementation
        5. Uses the registry's promote_implementation method
        6. Logs the promotion with detailed information
        Args:
            attack_name: Name of the attack to promote (e.g., "fakeddisorder", "seqovl")
            new_handler: New handler function to use. Must have signature:
                        handler(context: AttackContext) -> List[Tuple[bytes, int, Dict]]
            reason: Justification for promotion (e.g., "30% better success rate on x.com")
            performance_data: Optional performance metrics supporting the promotion.
                            Should include keys like:
                            - improvement_percent: float (e.g., 30.0 for 30% improvement)
                            - test_cases: int (number of test cases used)
                            - success_rate: float (0.0-1.0, new success rate)
                            - baseline_time_ms: float (old execution time)
                            - new_time_ms: float (new execution time)
                            - tested_domains: List[str] (domains tested against)
            require_confirmation: Whether to require explicit confirmation for CORE attacks
        Returns:
            True if promotion successful, False otherwise
        Raises:
            ImportError: If AttackRegistry cannot be imported
            ValueError: If attack_name is invalid or handler is not callable
        Examples:
            # Promote a fakeddisorder implementation with performance data
            success = BypassTechniques.promote_implementation(
                "fakeddisorder",
                my_improved_handler,
                "Improved success rate on x.com from 85% to 95%",
                {
                    "improvement_percent": 11.8,
                    "test_cases": 1000,
                    "success_rate": 0.95,
                    "baseline_time_ms": 1.2,
                    "new_time_ms": 1.1,
                    "tested_domains": ["x.com", "youtube.com", "facebook.com"]
                }
            )
            # Simple promotion without performance data
            success = BypassTechniques.promote_implementation(
                "seqovl",
                my_fixed_seqovl_handler,
                "Fixed sequence overlap calculation bug"
            )
        """
        log = logging.getLogger("BypassTechniques")

        # Validate inputs
        if not attack_name or not isinstance(attack_name, str):
            log.error(f"Invalid attack_name: {attack_name}")
            return False

        if not callable(new_handler):
            log.error(f"new_handler is not callable: {type(new_handler)}")
            return False

        if not reason or not isinstance(reason, str):
            log.error(f"Invalid reason: {reason}")
            return False

        try:
            # Import registry (lazy import to avoid circular dependencies)
            from ..attacks.attack_registry import get_attack_registry
            from ..attacks.metadata import AttackMetadata, AttackCategories
            from ..attacks.base import AttackContext

            registry = get_attack_registry()

            # Validate that the attack exists
            existing_metadata = registry.get_attack_metadata(attack_name)
            if not existing_metadata:
                log.error(f"Attack '{attack_name}' not found in registry")
                return False

            # Validate performance data if provided
            if performance_data:
                if not isinstance(performance_data, dict):
                    log.warning("performance_data should be a dictionary")
                    performance_data = {}
                else:
                    # Validate recommended metrics
                    recommended_keys = [
                        "improvement_percent",
                        "test_cases",
                        "success_rate",
                    ]
                    missing_keys = [
                        k for k in recommended_keys if k not in performance_data
                    ]
                    if missing_keys:
                        log.warning(
                            f"Missing recommended performance metrics: {missing_keys}"
                        )

            # Create enhanced metadata for the promoted implementation
            # Preserve existing metadata but mark as promoted
            new_metadata = AttackMetadata(
                name=f"{existing_metadata.name} (Promoted)",
                description=f"{existing_metadata.description}\n\nPromoted implementation: {reason}",
                required_params=existing_metadata.required_params,
                optional_params=existing_metadata.optional_params,
                aliases=existing_metadata.aliases,
                category=existing_metadata.category,
            )

            # Validate the new handler signature
            import inspect

            try:
                sig = inspect.signature(new_handler)
                # Check if it looks like a proper attack handler
                # Should accept context or similar parameters
                param_names = list(sig.parameters.keys())
                if not param_names:
                    log.warning(
                        "New handler has no parameters - this may not be a proper attack handler"
                    )
                else:
                    log.debug(f"New handler signature: {param_names}")
            except Exception as e:
                log.warning(f"Could not inspect new handler signature: {e}")

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
                log.info(f"✅ Successfully promoted '{attack_name}' implementation")
                log.info(f"   Reason: {reason}")
                if performance_data:
                    improvement = performance_data.get("improvement_percent")
                    if improvement:
                        log.info(f"   Performance improvement: {improvement}%")
                    success_rate = performance_data.get("success_rate")
                    if success_rate:
                        log.info(
                            f"   New success rate: {success_rate * 100:.1f}%"
                        )
                    test_cases = performance_data.get("test_cases")
                    if test_cases:
                        log.info(f"   Tested on {test_cases} cases")

                # Log promotion history for audit trail
                history = registry.get_promotion_history(attack_name)
                if history:
                    log.debug(
                        f"Promotion history for '{attack_name}': {len(history)} promotions"
                    )

                return True
            else:
                log.error(
                    f"❌ Failed to promote '{attack_name}': {result.message}"
                )
                if result.conflicts:
                    for conflict in result.conflicts:
                        log.error(f"   Conflict: {conflict}")
                return False

        except ImportError as e:
            log.error(f"Failed to import AttackRegistry: {e}")
            return False
        except Exception as e:
            log.error(f"Unexpected error during promotion of '{attack_name}': {e}")
            return False

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", 0xDEAD
            )
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", 0xBEEF
            )
        return packet_data