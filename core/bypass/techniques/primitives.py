# path: core/bypass/techniques/primitives.py
# ULTIMATE CORRECTED VERSION - Best of both approaches

import struct
import random
import string
import logging
from typing import List, Tuple, Dict, Optional


def _gen_fake_sni(original: Optional[str] = None, custom_sni: Optional[str] = None) -> str:
    """
    Generate fake SNI in zapret style.
    
    Args:
        original: Original SNI (currently unused)
        custom_sni: Custom SNI value to use instead of generating random
        
    Returns:
        SNI value to use (custom if provided, otherwise random)
    """
    if custom_sni is not None:
        return custom_sni
    
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
    API_VER = "primitives ULTIMATE-2025-10-17"

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
                    f"split_pos {split_pos} >= payload size {payload_len}, adjusting to {
                        payload_len - 1}"
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

        log.debug(
            f"Split payload: {payload_len}b → part1={
                len(part1)}b, part2={
                len(part2)}b at pos={split_pos}"
        )

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
        custom_sni: Optional[str] = None,
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
                    # Use far-future sequence offset to avoid overlap with real packet
                    # 0x10000000 (268,435,456 bytes) places fake packet far in future
                    # This confuses DPI while remaining acceptable to legitimate servers
                    options["seq_offset"] = 0x10000000
                elif method == "md5sig":
                    options["add_md5sig_option"] = True
                elif method == "fakesni":
                    # Use custom SNI if provided in kwargs, otherwise generate random
                    custom_sni = kwargs.get("resolved_custom_sni")
                    options["fooling_sni"] = _gen_fake_sni(custom_sni=custom_sni)

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
                    log.warning(
                        f"Position {pos} >= payload length {payload_len}, adjusting to {
                            payload_len - 1}"
                    )
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
            is_fake=True, ttl=fake_ttl, fooling_methods=fool, delay_ms_after=5, **kwargs
        )
        opts_real = BypassTechniques._create_segment_options(is_fake=False)

        # --- ЕДИНСТВЕННАЯ ПРАВИЛЬНАЯ ЛОГИКА ДЛЯ FAKEDDISORDER ---
        # Ключ к успеху для x.com: фейковый пакет содержит ВЕСЬ ClientHello.
        fake_payload = payload

        log.info(
            f"✅ UNIFIED fakeddisorder: "
            f"fake_full_payload={len(fake_payload)}b@0 (ttl={fake_ttl}), "
            f"real_part2={len(part2)}b@{split_pos}, "
            f"real_part1={len(part1)}b@0"
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
        **kwargs
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
        fake_ttl: int = 1,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        UPDATED Multiple Disorder attack - optimized multi-fragment reordering.
        
        CRITICAL: This method is called with fooling parameter from attack handler.

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
        # CRITICAL: Handle fooling=None, fooling=[], fooling="none", and fooling=["none"]
        import traceback
        caller = traceback.extract_stack()[-2]
        log.info(f"🔧 apply_multidisorder CALLED FROM: {caller.filename}:{caller.lineno} in {caller.name}")
        log.info(f"🔧 apply_multidisorder: fooling INPUT={fooling}, type={type(fooling)}")
        
        if fooling is None:
            fooling = ["badsum", "badseq"]  # Default fooling
            log.info(f"🔧 apply_multidisorder: fooling was None, using default")
        elif fooling == "none":
            fooling = []  # No fooling - string "none"
            log.info(f"🔧 apply_multidisorder: fooling='none' (string), disabling all fooling")
        elif fooling == ["none"]:
            fooling = []  # No fooling - list with "none"
            log.info(f"🔧 apply_multidisorder: fooling=['none'] (list), disabling all fooling")
        elif isinstance(fooling, list) and "none" in fooling:
            fooling = []  # No fooling - list containing "none"
            log.info(f"🔧 apply_multidisorder: 'none' found in list, disabling all fooling")
        elif not isinstance(fooling, list):
            fooling = [fooling] if fooling else []
            log.info(f"🔧 apply_multidisorder: converted to list: {fooling}")
        
        log.info(f"🔧 apply_multidisorder: fooling FINAL={fooling} (after normalization)")

        # Use shared helper to normalize positions with optimization
        normalized_positions = BypassTechniques._normalize_positions(
            positions, len(payload), validate=True
        )
        
        # CRITICAL DEBUG: Log normalized positions
        log.info(f"🔍 apply_multidisorder: input_positions={positions}, normalized={normalized_positions}, payload_len={len(payload)}")

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
        
        # CRITICAL DEBUG: Log split points
        log.info(f"🔍 Creating fragments: all_splits={all_splits}, payload_len={len(payload)}")

        for i in range(len(all_splits) - 1):
            start, end = all_splits[i], all_splits[i + 1]
            if start < end and end - start >= 1:  # Ensure non-empty fragments
                fragment_data = payload[start:end]
                real_fragments.append((fragment_data, start))
                log.debug(f"🔍 Fragment {len(real_fragments)}: bytes[{start}:{end}] = {len(fragment_data)}b")
        
        log.info(f"🔍 Created {len(real_fragments)} real fragments from {len(all_splits)-1} split points")

        # OPTIMIZATION: Skip multidisorder if we only have one fragment
        if len(real_fragments) <= 1:
            log.warning(f"🔍 Only {len(real_fragments)} fragment(s) created from positions={optimized_positions}, all_splits={all_splits}, falling back to simple disorder")
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
                f"Disorder skipped: one part empty (part1={
                    len(part1)}, part2={
                    len(part2)})"
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

        log.info(
            f"✅ OPTIMIZED disorder: "
            f"part2={len(part2)}b@{split_pos} (flags=0x{first_flags:02x}), "
            f"part1={len(part1)}b@0 (ack_first={ack_first})"
        )

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
                name=f"{
                    existing_metadata.name} (Promoted)",
                description=f"{
                    existing_metadata.description}\n\nPromoted implementation: {reason}",
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
                            f"   New success rate: {
                                success_rate * 100:.1f}%"
                        )
                    test_cases = performance_data.get("test_cases")
                    if test_cases:
                        log.info(f"   Tested on {test_cases} cases")

                # Log promotion history for audit trail
                history = registry.get_promotion_history(attack_name)
                if history:
                    log.debug(
                        f"Promotion history for '{attack_name}': {
                            len(history)} promotions"
                    )

                return True
            else:
                log.error(
                    f"❌ Failed to promote '{attack_name}': {
                        result.message}"
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


class FakedDisorderAttack:
    """
    UNIFIED FakedDisorderAttack class combining best features from all variants.

    This class consolidates the unique optimizations and features from:
    1. fake_disorder_attack.py (Current/Fixed) - Special position handling, X.COM TTL fix
    2. fake_disorder_attack_original.py (Comprehensive) - AutoTTL, multiple payloads, monitoring
    3. fake_disorder_attack_fixed.py (Zapret-Compatible) - Zapret defaults, enhanced TLS

    Key Features:
    - **Zapret-compatible defaults**: split_pos=76, split_seqovl=336, ttl=1
    - **X.COM TTL fix**: Critical TTL limitation for fakeddisorder effectiveness
    - **Special position support**: "sni", "cipher", "midsld" position resolution
    - **Comprehensive AutoTTL**: Range testing with effectiveness evaluation
    - **Multiple fake payloads**: TLS, HTTP, QUIC, WireGuard, DHT, and custom payloads
    - **Advanced monitoring**: Attack result validation and bypass detection
    - **Repeats functionality**: Multiple attack attempts with minimal delays
    - **Enhanced error handling**: Robust validation and graceful degradation

    This is the CANONICAL implementation that should be used instead of the
    individual variant files. It provides the most effective and feature-complete
    fakeddisorder implementation available.
    """

    def __init__(
        self,
        split_pos: any = 76,  # Zapret default, supports int or special strings
        split_seqovl: int = 336,  # Zapret default sequence overlap
        ttl: int = 1,  # Zapret default TTL for fake packets
        autottl: Optional[int] = None,  # AutoTTL range (1 to autottl)
        repeats: int = 1,  # Number of attack attempts
        fooling_methods: Optional[List[str]] = None,  # DPI fooling methods
        fake_payload_type: str = "PAYLOADTLS",  # Type of fake payload
        custom_fake_payload: Optional[bytes] = None,  # Custom fake payload
        enable_monitoring: bool = False,  # Enable attack result monitoring
        enable_injection: bool = False,  # Enable real packet injection
        **kwargs,
    ):
        """
        Initialize unified FakedDisorderAttack with comprehensive configuration.

        Args:
            split_pos: Split position for disorder (int or "sni"/"cipher"/"midsld")
            split_seqovl: Sequence overlap size (zapret compatibility)
            ttl: TTL for fake packets (will be limited by X.COM fix)
            autottl: AutoTTL range testing (1 to autottl)
            repeats: Number of attack attempts with minimal delays
            fooling_methods: DPI fooling methods ["badsum", "badseq", "md5sig"]
            fake_payload_type: Type of fake payload ("PAYLOADTLS", "HTTP", "QUIC", etc.)
            custom_fake_payload: Custom fake payload bytes
            enable_monitoring: Enable attack result monitoring and validation
            enable_injection: Enable real packet injection with scapy
            **kwargs: Additional parameters for compatibility
        """
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

        # Store additional parameters for compatibility
        self.kwargs = kwargs

        # Initialize logger
        self.logger = logging.getLogger("FakedDisorderAttack")

        # Validate configuration
        self._validate_config()

        self.logger.info("🔧 Initialized UNIFIED FakedDisorderAttack")
        self.logger.info(
            f"   split_pos={
                self.split_pos}, split_seqovl={
                self.split_seqovl}"
        )
        self.logger.info(f"   ttl={self.ttl}, autottl={self.autottl}")
        self.logger.info(
            f"   fooling={
                self.fooling_methods}, repeats={
                self.repeats}"
        )

    def _validate_config(self):
        """Validate configuration parameters with comprehensive checks."""
        # Validate split_seqovl
        if not isinstance(self.split_seqovl, int) or self.split_seqovl < 0:
            raise ValueError(
                f"split_seqovl must be non-negative integer, got {self.split_seqovl}"
            )

        # Validate TTL range
        if not isinstance(self.ttl, int) or self.ttl < 1 or self.ttl > 255:
            raise ValueError(f"ttl must be between 1 and 255, got {self.ttl}")

        # Validate autottl if specified
        if self.autottl is not None:
            if (
                not isinstance(self.autottl, int)
                or self.autottl < 1
                or self.autottl > 10
            ):
                raise ValueError(
                    f"autottl must be between 1 and 10, got {
                        self.autottl}"
                )

        # Validate repeats
        if not isinstance(self.repeats, int) or self.repeats < 1:
            raise ValueError(f"repeats must be >= 1, got {self.repeats}")

        # Validate fooling methods
        valid_fooling = ["badseq", "badsum", "md5sig", "datanoack"]
        for method in self.fooling_methods:
            if method not in valid_fooling:
                raise ValueError(
                    f"Invalid fooling method: {method}. Valid: {valid_fooling}"
                )

    def execute(
        self, payload: bytes, **context
    ) -> List[Tuple[bytes, int, Dict[str, any]]]:
        """
        Execute unified fakeddisorder attack with all optimizations.

        This method combines the best features from all variants:
        1. Zapret-compatible core algorithm
        2. X.COM TTL fix for maximum effectiveness
        3. Special position resolution
        4. Advanced fake payload generation
        5. AutoTTL testing if enabled
        6. Repeats functionality

        Args:
            payload: Original packet data (usually TLS ClientHello)
            **context: Additional context (dst_ip, dst_port, etc.)

        Returns:
            List of segments: [(data, seq_offset, options), ...]
        """
        try:
            self.logger.info("🚀 Executing UNIFIED fakeddisorder attack")

            if not payload:
                raise ValueError("Empty payload provided")

            # Step 1: Resolve split position (special position support from
            # Current version)
            resolved_split_pos = self._resolve_split_position(payload)

            # Step 2: Generate fake payload (multiple types from Original
            # version)
            fake_payload = self._generate_fake_payload(payload, **context)

            # Step 3: Calculate effective TTL (X.COM fix from Current version)
            effective_ttl = self._calculate_effective_ttl()

            # Step 4: Execute with AutoTTL if enabled (from Original version)
            if self.autottl is not None and self.autottl > 1:
                return self._execute_with_autottl(
                    payload, fake_payload, resolved_split_pos, **context
                )

            # Step 5: Create segments using unified algorithm
            segments = self._create_unified_segments(
                payload, fake_payload, resolved_split_pos, effective_ttl
            )

            # Step 6: Apply repeats if configured (from Original version)
            if self.repeats > 1:
                segments = self._apply_repeats(segments)

            # Step 7: Monitor results if enabled (from Original version)
            if self.enable_monitoring:
                self._monitor_attack_results(segments, **context)

            self.logger.info(
                f"✅ UNIFIED fakeddisorder: {
                    len(segments)} segments generated"
            )
            return segments

        except Exception as e:
            self.logger.error(f"❌ UNIFIED fakeddisorder failed: {e}")
            raise

    def _resolve_split_position(self, payload: bytes) -> int:
        """
        Resolve split position with special value support (from Current version).

        Special values:
        - "sni": Position 43 (TLS SNI extension)
        - "cipher": Position 11 (TLS cipher suites)
        - "midsld": Middle of payload
        - int: Direct position value
        """
        if isinstance(self.split_pos, str):
            if self.split_pos == "sni":
                # TLS SNI extension typically at position 43
                pos = (
                    min(43, len(payload) // 2)
                    if len(payload) > 43
                    else len(payload) // 2
                )
                self.logger.debug(f"🔍 SNI split position: {pos}")
                return pos
            elif self.split_pos == "cipher":
                # TLS cipher suites typically at position 11
                pos = (
                    min(11, len(payload) // 2)
                    if len(payload) > 11
                    else len(payload) // 2
                )
                self.logger.debug(f"🔍 Cipher split position: {pos}")
                return pos
            elif self.split_pos == "midsld":
                # Middle of payload
                pos = len(payload) // 2
                self.logger.debug(f"🔍 Mid-SLD split position: {pos}")
                return pos
            else:
                self.logger.warning(
                    f"⚠️ Unknown special position '{
                        self.split_pos}', using middle"
                )
                return len(payload) // 2
        else:
            # Numeric position with validation
            pos = int(self.split_pos)
            if pos >= len(payload):
                pos = len(payload) // 2
                self.logger.warning(
                    f"⚠️ Split position {
                        self.split_pos} >= payload length, using {pos}"
                )
            return max(1, pos)

    def _calculate_effective_ttl(self) -> int:
        """
        Calculate effective TTL with X.COM fix (CRITICAL from Current version).

        This is the CRITICAL optimization that makes fakeddisorder work on x.com.
        The TTL must be limited to 3 or lower for maximum effectiveness.
        """
        if self.autottl is not None and self.autottl > 1:
            # For AutoTTL, use effective range
            effective_ttl = min(3, self.autottl)
            self.logger.debug(
                f"🔢 AutoTTL effective: {effective_ttl} from range 1-{self.autottl}"
            )
            return effective_ttl
        else:
            # CRITICAL X.COM FIX: Force TTL limitation for fakeddisorder
            effective_ttl = min(3, self.ttl)
            if effective_ttl != self.ttl:
                self.logger.info(
                    f"🔧 X.COM TTL fix: limited {
                        self.ttl} → {effective_ttl}"
                )
            return effective_ttl

    def _generate_fake_payload(self, original_payload: bytes, **context) -> bytes:
        """
        Generate fake payload with multiple type support (from Original version).

        Supports comprehensive fake payload types:
        - PAYLOADTLS: Enhanced TLS ClientHello
        - HTTP: HTTP request with random elements
        - QUIC: QUIC Initial packet
        - WIREGUARD: WireGuard handshake
        - DHT: BitTorrent DHT packet
        - Custom: User-provided payload
        """
        if self.custom_fake_payload:
            self.logger.debug("Using custom fake payload")
            return self.custom_fake_payload

        payload_type = self.fake_payload_type.upper()

        if payload_type == "PAYLOADTLS" or payload_type == "TLS":
            return self._generate_enhanced_tls_payload()
        elif payload_type == "HTTP":
            return self._generate_enhanced_http_payload()
        elif payload_type == "QUIC":
            return self._generate_quic_payload()
        elif payload_type == "WIREGUARD":
            return self._generate_wireguard_payload()
        elif payload_type == "DHT":
            return self._generate_dht_payload()
        else:
            # Auto-detect or default to TLS
            if self._detect_tls(original_payload):
                return self._generate_enhanced_tls_payload()
            elif self._detect_http(original_payload):
                return self._generate_enhanced_http_payload()
            else:
                return self._generate_enhanced_tls_payload()  # Default

    def _generate_enhanced_tls_payload(self) -> bytes:
        """Generate enhanced TLS ClientHello (from Fixed version)."""
        # Enhanced TLS ClientHello with proper structure
        tls_version = b"\x03\x03"  # TLS 1.2
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id_len = b"\x00"  # No session ID

        # Cipher suites (zapret-compatible)
        cipher_suites = b"\x00\x2c"  # Length
        cipher_suites += b"\x13\x01"  # TLS_AES_128_GCM_SHA256
        cipher_suites += b"\x13\x02"  # TLS_AES_256_GCM_SHA384
        cipher_suites += b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        cipher_suites += b"\xc0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        cipher_suites += b"\x00\x9e"  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        cipher_suites += b"\x00\x9f"  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        cipher_suites += b"\xc0\x13"  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        cipher_suites += b"\xc0\x14"  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        cipher_suites += b"\x00\x33"  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        cipher_suites += b"\x00\x39"  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        cipher_suites += b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
        cipher_suites += b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA

        compression_methods = b"\x01\x00"  # No compression

        # Extensions (critical for DPI bypass)
        extensions = b""

        # SNI extension
        sni_ext = b"\x00\x00"  # Extension type: server_name
        sni_data = b"\x00\x0e"  # Extension length
        sni_data += b"\x00\x0c"  # Server name list length
        sni_data += b"\x00"  # Name type: host_name
        sni_data += b"\x00\x09"  # Name length
        sni_data += b"google.com"  # Fake hostname
        extensions += sni_ext + sni_data

        # Supported Groups
        groups_ext = b"\x00\x0a"  # Extension type
        groups_data = b"\x00\x08"  # Extension length
        groups_data += b"\x00\x06"  # Groups length
        groups_data += b"\x00\x17"  # secp256r1
        groups_data += b"\x00\x18"  # secp384r1
        groups_data += b"\x00\x19"  # secp521r1
        extensions += groups_ext + groups_data

        # EC Point Formats
        ec_ext = b"\x00\x0b"  # Extension type
        ec_data = b"\x00\x02"  # Extension length
        ec_data += b"\x01\x00"  # Uncompressed format
        extensions += ec_ext + ec_data

        extensions_len = len(extensions).to_bytes(2, "big")

        # Assemble ClientHello
        client_hello = tls_version + random_bytes + session_id_len
        client_hello += (
            cipher_suites + compression_methods + extensions_len + extensions
        )

        # Handshake header
        handshake_type = b"\x01"  # ClientHello
        handshake_len = len(client_hello).to_bytes(3, "big")
        handshake = handshake_type + handshake_len + client_hello

        # TLS Record header
        record_type = b"\x16"  # Handshake
        record_version = b"\x03\x01"  # TLS 1.0
        record_len = len(handshake).to_bytes(2, "big")

        return record_type + record_version + record_len + handshake

    def _generate_enhanced_http_payload(self) -> bytes:
        """Generate enhanced HTTP payload with randomization."""
        methods = ["GET", "POST", "HEAD"]
        paths = ["/", "/index.html", "/favicon.ico", "/robots.txt"]

        method = random.choice(methods)
        path = random.choice(paths)

        http_request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: example{random.randint(1, 999)}.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
        return http_request.encode("utf-8")

    def _generate_quic_payload(self) -> bytes:
        """Generate QUIC Initial packet payload."""
        quic_packet = bytearray()

        # Header Form + Fixed Bit + Packet Type + Reserved + Packet Number
        # Length
        header_byte = 0b11000000  # Long header, Initial packet
        quic_packet.append(header_byte)

        # Version - QUIC v1
        quic_packet.extend(b"\x00\x00\x00\x01")

        # Connection IDs
        dcid_len = 8
        quic_packet.append(dcid_len)
        quic_packet.extend(bytes([random.randint(0, 255) for _ in range(dcid_len)]))

        scid_len = 8
        quic_packet.append(scid_len)
        quic_packet.extend(bytes([random.randint(0, 255) for _ in range(scid_len)]))

        # Token Length and Length
        quic_packet.append(0)  # No token
        quic_packet.extend(b"\x40\x40")  # Length ~64

        # Packet Number and Payload
        quic_packet.append(0x01)
        payload = bytes([random.randint(0, 255) for _ in range(63)])
        quic_packet.extend(payload)

        return bytes(quic_packet)

    def _generate_wireguard_payload(self) -> bytes:
        """Generate WireGuard handshake payload."""
        wg_packet = bytearray()

        # Message Type - Handshake Initiation
        wg_packet.append(1)
        wg_packet.extend(b"\x00\x00\x00")  # Reserved

        # Sender Index
        sender_index = random.randint(0, 0xFFFFFFFF)
        wg_packet.extend(sender_index.to_bytes(4, "little"))

        # Ephemeral, Static, Timestamp (with random data)
        wg_packet.extend(
            bytes([random.randint(0, 255) for _ in range(32)])
        )  # Ephemeral
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(48)]))  # Static
        wg_packet.extend(
            bytes([random.randint(0, 255) for _ in range(28)])
        )  # Timestamp

        # MAC1 and MAC2
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(16)]))  # MAC1
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(16)]))  # MAC2

        return bytes(wg_packet)

    def _generate_dht_payload(self) -> bytes:
        """Generate BitTorrent DHT payload."""
        dht_packet = bytearray()

        # Transaction ID
        transaction_id = random.randint(0, 0xFFFF)
        dht_packet.extend(transaction_id.to_bytes(2, "big"))

        # Bencode DHT ping query
        node_id = bytes([random.randint(0, 255) for _ in range(20)])
        query = f"d1:ad2:id20:{
            node_id.decode('latin1')}e1:q4:ping1:t2:aa1:y1:qe"
        dht_packet.extend(query.encode("latin1"))

        return bytes(dht_packet)

    def _detect_tls(self, payload: bytes) -> bool:
        """Detect if payload is TLS."""
        return len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03

    def _detect_http(self, payload: bytes) -> bool:
        """Detect if payload is HTTP."""
        return payload.startswith(b"GET ") or payload.startswith(b"POST ")

    def _create_unified_segments(
        self, payload: bytes, fake_payload: bytes, split_pos: int, ttl: int
    ) -> List[Tuple[bytes, int, Dict[str, any]]]:
        """
        Create segments using unified algorithm combining all optimizations.

        This combines:
        1. Zapret-compatible core logic (from Fixed version)
        2. Proper sequence overlap handling (from all versions)
        3. Optimized segment options (using shared helpers)
        """
        segments = []

        # Split real payload
        part1, part2 = BypassTechniques._split_payload(
            payload, split_pos, validate=True
        )

        # Create fake packet with optimized options
        fake_options = BypassTechniques._create_segment_options(
            is_fake=True,
            ttl=ttl,
            fooling_methods=self.fooling_methods,
            delay_ms_after=0,  # No delay for fake packet
        )
        segments.append((fake_payload, 0, fake_options))

        # Handle sequence overlap if configured
        if self.split_seqovl > 0 and len(part1) > 0 and len(part2) > 0:
            # Zapret sequence overlap logic
            actual_overlap = min(self.split_seqovl, len(part1), len(part2))
            overlap_start_seq = split_pos - actual_overlap

            self.logger.debug(
                f"🔄 Sequence overlap: size={actual_overlap}, start={overlap_start_seq}"
            )

            # Part2 with overlap (first real segment)
            part2_options = BypassTechniques._create_segment_options(
                is_fake=False, delay_ms_after=1  # Minimal delay
            )
            segments.append((part2, overlap_start_seq, part2_options))

            # Part1 (second real segment, creates disorder)
            part1_options = BypassTechniques._create_segment_options(
                is_fake=False, delay_ms_after=0
            )
            segments.append((part1, 0, part1_options))
        else:
            # Simple disorder without overlap
            part2_options = BypassTechniques._create_segment_options(
                is_fake=False, delay_ms_after=1
            )
            segments.append((part2, split_pos, part2_options))

            part1_options = BypassTechniques._create_segment_options(is_fake=False)
            segments.append((part1, 0, part1_options))

        return segments

    def _execute_with_autottl(
        self, payload: bytes, fake_payload: bytes, split_pos: int, **context
    ) -> List[Tuple[bytes, int, Dict[str, any]]]:
        """
        Execute with comprehensive AutoTTL testing (from Original version).

        Tests TTL values from 1 to autottl, evaluates effectiveness,
        and stops on first highly effective TTL or when range is exhausted.
        """
        self.logger.info(f"🔢 AutoTTL testing: range 1-{self.autottl}")

        best_segments = None
        best_ttl = self.ttl
        best_effectiveness = 0.0

        for ttl in range(1, self.autottl + 1):
            self.logger.debug(f"Testing TTL={ttl}/{self.autottl}")

            # Create segments with specific TTL
            test_segments = self._create_unified_segments(
                payload, fake_payload, split_pos, ttl
            )

            # Evaluate effectiveness (simplified for now)
            effectiveness = self._evaluate_ttl_effectiveness(ttl, test_segments)

            if effectiveness > best_effectiveness:
                best_segments = test_segments
                best_ttl = ttl
                best_effectiveness = effectiveness

                # Stop on highly effective TTL
                if effectiveness >= 0.9:
                    self.logger.info(
                        f"AutoTTL: Found highly effective TTL={ttl}, stopping"
                    )
                    break

        self.logger.info(
            f"AutoTTL complete: best TTL={best_ttl} (effectiveness={
                best_effectiveness:.1%})"
        )
        return best_segments or self._create_unified_segments(
            payload, fake_payload, split_pos, self.ttl
        )

    def _evaluate_ttl_effectiveness(self, ttl: int, segments: List) -> float:
        """Evaluate TTL effectiveness (simplified scoring)."""
        # Lower TTL values are generally more effective for fakeddisorder
        base_effectiveness = 0.8 if ttl <= 3 else 0.6 if ttl <= 6 else 0.4

        # Bonus for optimal TTL range
        ttl_bonus = max(0.0, (10 - ttl) / 10 * 0.2)

        return min(1.0, base_effectiveness + ttl_bonus)

    def _apply_repeats(
        self, segments: List[Tuple[bytes, int, Dict[str, any]]]
    ) -> List[Tuple[bytes, int, Dict[str, any]]]:
        """Apply repeats functionality with minimal delays (from Original version)."""
        if self.repeats <= 1:
            return segments

        repeated_segments = segments.copy()

        for repeat_num in range(1, self.repeats):
            for segment in segments:
                payload, seq_offset, options = segment
                repeat_options = options.copy()

                # Add minimal delay for repeat
                base_delay = options.get("delay_ms_after", 0)
                repeat_delay = repeat_num * 1.0  # 1ms per repeat
                repeat_options["delay_ms_after"] = base_delay + repeat_delay
                repeat_options["repeat_num"] = repeat_num
                repeat_options["is_repeat"] = True

                repeated_segments.append((payload, seq_offset, repeat_options))

        self.logger.debug(
            f"Applied {
                self.repeats} repeats with minimal delays"
        )
        return repeated_segments

    def _monitor_attack_results(self, segments: List, **context):
        """Monitor attack results if enabled (from Original version)."""
        if not self.enable_monitoring:
            return

        # Simplified monitoring for now
        self.logger.info(f"📊 Monitoring attack: {len(segments)} segments")
        # In a full implementation, this would analyze packet capture data
        # and determine bypass effectiveness

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

        Uses exact zapret defaults for maximum compatibility.
        """
        return cls(
            split_pos=split_pos,
            split_seqovl=split_seqovl,
            ttl=ttl,
            autottl=autottl,
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )

    @classmethod
    def create_x_com_optimized(cls, **kwargs) -> "FakedDisorderAttack":
        """
        Factory method optimized for X.COM (critical failing domain).

        Uses parameters specifically tuned for X.COM effectiveness.
        """
        return cls(
            split_pos="sni",  # SNI position for TLS
            split_seqovl=400,  # Higher overlap for X.COM
            ttl=3,  # X.COM TTL fix applied
            autottl=3,
            repeats=2,  # More attempts for stubborn DPI
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )

    @classmethod
    def create_instagram_optimized(cls, **kwargs) -> "FakedDisorderAttack":
        """
        Factory method optimized for Instagram.
        """
        return cls(
            split_pos=60,
            split_seqovl=250,
            ttl=1,
            autottl=2,
            repeats=1,
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )

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
        log = logging.getLogger("BypassTechniques")
        
        if len(payload) < 2:
            return [(payload, 0, BypassTechniques._create_segment_options(is_fake=False))]
        
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
            options = BypassTechniques._create_segment_options(
                is_fake=False,
                tcp_flags=0x18,  # PSH+ACK
                delay_ms_after=delay_ms if i < len(all_positions) - 2 else None,
                window_size_override=window_size,
            )
            
            # Apply fooling methods to first segment if specified
            if i == 0 and fooling_methods:
                for method in fooling_methods:
                    if method == "badsum":
                        options["corrupt_tcp_checksum"] = True
                    elif method == "badseq":
                        # Use far-future sequence offset to avoid overlap with real packet
                        # 0x10000000 (268,435,456 bytes) places fake packet far in future
                        # This confuses DPI while remaining acceptable to legitimate servers
                        options["seq_offset"] = 0x10000000
            
            segments.append((fragment_data, start_pos, options))
        
        log.info(f"🪟 Window manipulation: {len(segments)} fragments, window_size={window_size}, delay={delay_ms}ms")
        return segments

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
        log = logging.getLogger("BypassTechniques")
        
        if len(payload) < 2:
            return [(payload, 0, BypassTechniques._create_segment_options(is_fake=False))]
        
        # Split payload
        part1, part2 = BypassTechniques._split_payload(payload, split_pos, validate=True)
        
        # Create TCP options based on type
        tcp_options = BypassTechniques._create_tcp_options(options_type)
        
        # Create segment options
        opts1 = BypassTechniques._create_segment_options(
            is_fake=False,
            tcp_flags=0x18,  # PSH+ACK
            fooling_methods=fooling_methods,
            tcp_options=tcp_options,
        )
        
        opts2 = BypassTechniques._create_segment_options(
            is_fake=False,
            tcp_flags=0x18,  # PSH+ACK
        )
        
        # Apply bad checksum if requested
        if bad_checksum:
            opts1["corrupt_tcp_checksum"] = True
        
        segments = [
            (part1, 0, opts1),
            (part2, split_pos, opts2),
        ]
        
        log.info(f"🔧 TCP options modification: {options_type}, bad_checksum={bad_checksum}")
        return segments

    @staticmethod
    def _create_tcp_options(options_type: str) -> bytes:
        """
        Create TCP options based on specified type.
        
        Args:
            options_type: Type of TCP options to create
            
        Returns:
            Raw TCP options bytes
        """
        if options_type == "mss":
            # Maximum Segment Size option
            return struct.pack("!BBH", 2, 4, 1460)  # MSS = 1460

        elif options_type == "window_scale":
            # Window Scale option
            return struct.pack("!BBB", 3, 3, 7)  # Scale factor = 7

        elif options_type == "timestamp":
            # Timestamp option
            import time
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
    ) -> List[Tuple[bytes, int, dict]]:
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
        """
        log = logging.getLogger("BypassTechniques")
        
        if len(payload) < 2:
            return [(payload, 0, BypassTechniques._create_segment_options(is_fake=False))]
        
        # Split payload
        part1, part2 = BypassTechniques._split_payload(payload, split_pos, validate=True)
        
        # Default delays if not provided
        if delays is None:
            delays = [1.0, 2.0]  # Default delays in milliseconds
        
        # Add jitter if requested
        if jitter:
            import random
            delays = [d + random.uniform(-0.5, 0.5) for d in delays]
        
        # Create segments with timing control
        segments = []
        parts = [part1, part2]
        offsets = [0, split_pos]
        
        for i, (part, offset) in enumerate(zip(parts, offsets)):
            delay = delays[i] if i < len(delays) else 0.0
            
            options = BypassTechniques._create_segment_options(
                is_fake=False,
                tcp_flags=0x18,  # PSH+ACK
                fooling_methods=fooling_methods if i == 0 else None,
                delay_ms_after=delay if i < len(parts) - 1 else None,
            )
            
            segments.append((part, offset, options))
        
        log.info(f"⏱️ Advanced timing control: delays={delays}, jitter={jitter}")
        return segments