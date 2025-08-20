# recon/core/bypass/attacks/tcp/manipulation.py
"""
TCP Manipulation Attacks

Migrated and unified from:
- apply_tcp_window_scaling (core/fast_bypass.py)
- apply_urgent_pointer_manipulation (core/fast_bypass.py)
- apply_tcp_options_padding (core/fast_bypass.py)
- apply_tcp_timestamp_manipulation (core/fast_bypass.py)
"""

import time
import os
import random
from ..base import ManipulationAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


@register_attack
class TCPWindowScalingAttack(ManipulationAttack):
    """
    TCP Window Scaling Attack - manipulates TCP window scaling options.

    Migrated from:
    - apply_tcp_window_scaling (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "tcp_window_scaling"

    @property
    def description(self) -> str:
        return "Manipulates TCP window scaling to confuse DPI systems"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP window scaling attack."""
        start_time = time.time()

        try:
            payload = context.payload
            window_scale = context.params.get("window_scale", 2)
            split_pos = context.params.get("split_pos", 3)

            if not (0 < split_pos < len(payload)):
                # Send as single segment with window scaling
                segments = [(payload, 0, {"window_scale": window_scale})]
            else:
                # Split and apply different window scaling
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                segments = [
                    (part1, 0, {"window_scale": window_scale}),
                    (part2, split_pos, {"window_scale": window_scale * 2}),
                ]

            packets_sent = len(segments)
            bytes_sent = len(payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "window_scale": window_scale,
                    "split_pos": split_pos,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPOptionsModificationAttack(ManipulationAttack):
    """
    TCP Options Modification Attack - adds, removes, or modifies various TCP options.
    This is intended for testing DPI resilience to different TCP option configurations.
    """

    @property
    def name(self) -> str:
        return "tcp_options_modification"

    @property
    def description(self) -> str:
        return "Adds, removes, or modifies TCP options to test DPI option parsing"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP options modification attack."""
        start_time = time.time()

        try:
            payload = context.payload
            modification_type = context.params.get("modification_type", "add_mss_abuse")
            split_pos = context.params.get("split_pos", len(payload) // 2)

            segments = []
            part1 = payload[:split_pos]
            part2 = payload[split_pos:]

            options = {}
            if modification_type == "add_mss_abuse":
                # MSS option (Kind=2, Length=4, Value)
                # Abusing with a small value
                options = {"tcp_options": b"\x02\x04\x00\x40"}  # MSS = 64
            elif modification_type == "add_sack_perm":
                # SACK Permitted option (Kind=4, Length=2)
                options = {"tcp_options": b"\x04\x02"}
            elif modification_type == "add_nop_flood":
                # Flood with NOP options
                options = {"tcp_options": b"\x01" * 10}
            else:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Invalid modification_type: {modification_type}",
                )

            segments.append((part1, 0, options))
            if part2:
                segments.append(
                    (part2, split_pos, {})
                )  # Second part has no special options

            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "modification_type": modification_type,
                    "split_pos": split_pos,
                    "segment_count": len(segments),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPSequenceNumberManipulationAttack(ManipulationAttack):
    """
    TCP Sequence Number Manipulation Attack - creates ambiguity in TCP sequence numbers.
    This is intended for testing DPI resilience to non-standard sequence numbering.
    """

    @property
    def name(self) -> str:
        return "tcp_sequence_manipulation"

    @property
    def description(self) -> str:
        return "Directly manipulates TCP sequence numbers to create ambiguity"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP sequence number manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_type = context.params.get(
                "manipulation_type", "overlap_forward"
            )
            overlap_size = context.params.get("overlap_size", 4)
            gap_size = context.params.get("gap_size", 10)
            split_pos = context.params.get("split_pos", len(payload) // 2)

            segments = []
            part1 = payload[:split_pos]
            part2 = payload[split_pos:]

            if manipulation_type == "overlap_forward":
                if part2:
                    segments.append((part1, 0, {}))
                    overlap_start = max(0, split_pos - overlap_size)
                    segments.append((payload[overlap_start:], overlap_start, {}))
                else:
                    segments.append((payload, 0, {}))

            elif manipulation_type == "gap":
                if part2:
                    segments.append((part1, 0, {}))
                    segments.append((part2, split_pos + gap_size, {}))
                else:
                    segments.append((payload, 0, {}))

            elif manipulation_type == "duplicate":
                segments.append((part1, 0, {}))
                segments.append((part1, 0, {}))
                if part2:
                    segments.append((part2, split_pos, {}))

            else:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Invalid manipulation_type: {manipulation_type}",
                )

            packets_sent = len(segments)
            bytes_sent = sum(len(s[0]) for s in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "manipulation_type": manipulation_type,
                    "overlap_size": (
                        overlap_size if "overlap" in manipulation_type else None
                    ),
                    "gap_size": gap_size if "gap" in manipulation_type else None,
                    "split_pos": split_pos,
                    "segment_count": len(segments),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPWindowManipulationAttack(ManipulationAttack):
    """
    Advanced TCP Window Manipulation Attack - modifies TCP window size in various ways.
    This is intended for testing DPI resilience to non-standard window sizes.
    """

    @property
    def name(self) -> str:
        return "tcp_window_manipulation"

    @property
    def description(self) -> str:
        return "Modifies TCP window size in various ways to test DPI evasion"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced TCP window manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_type = context.params.get("manipulation_type", "small")
            split_pos = context.params.get("split_pos", len(payload) // 2)

            segments = []
            part1 = payload[:split_pos]
            part2 = payload[split_pos:]

            if manipulation_type == "zero":
                segments.append((part1, 0, {"window_size": 0}))
                if part2:
                    segments.append((part2, split_pos, {"window_size": 0}))
            elif manipulation_type == "small":
                small_window = random.randint(1, 10)
                segments.append((part1, 0, {"window_size": small_window}))
                if part2:
                    segments.append((part2, split_pos, {"window_size": small_window}))
            elif manipulation_type == "large":
                large_window = 65535
                segments.append((part1, 0, {"window_size": large_window}))
                if part2:
                    segments.append((part2, split_pos, {"window_size": large_window}))
            elif manipulation_type == "alternate":
                small_window = random.randint(1, 10)
                large_window = 65535
                segments.append((part1, 0, {"window_size": small_window}))
                if part2:
                    segments.append((part2, split_pos, {"window_size": large_window}))
            else:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Invalid manipulation_type: {manipulation_type}",
                )

            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "manipulation_type": manipulation_type,
                    "split_pos": split_pos,
                    "segment_count": len(segments),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPFragmentationAttack(ManipulationAttack):
    """
    TCP Fragmentation Attack - splits TCP payload into multiple segments.
    """

    @property
    def name(self) -> str:
        return "tcp_fragmentation"

    @property
    def description(self) -> str:
        return "Splits TCP payload into multiple segments to emulate fragmentation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP fragmentation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            frag_size = context.params.get("frag_size", 8)

            if len(payload) <= frag_size:
                # Payload too small to fragment
                segments = [(payload, 0, {})]
            else:
                segments = []
                offset = 0
                while offset < len(payload):
                    current_frag_size = min(frag_size, len(payload) - offset)
                    fragment_data = payload[offset : offset + current_frag_size]
                    segments.append((fragment_data, offset, {}))
                    offset += current_frag_size

            packets_sent = len(segments)
            bytes_sent = len(payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "frag_size": frag_size,
                    "fragments_count": len(segments),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class UrgentPointerAttack(ManipulationAttack):
    """
    Urgent Pointer Attack - manipulates TCP urgent pointer.

    Migrated from:
    - apply_urgent_pointer_manipulation (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "urgent_pointer_manipulation"

    @property
    def description(self) -> str:
        return "Manipulates TCP urgent pointer to confuse DPI systems"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute urgent pointer attack."""
        start_time = time.time()

        try:
            payload = context.payload
            split_pos = context.params.get("split_pos", 5)
            urgent_data_size = context.params.get("urgent_data_size", 2)

            if not (0 < split_pos < len(payload)):
                # Send as single segment with urgent data
                segments = [
                    (payload, 0, {"urgent": True, "urgent_size": urgent_data_size})
                ]
            else:
                # Split and mark first part as urgent
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                segments = [
                    (part1, 0, {"urgent": True, "urgent_size": urgent_data_size}),
                    (part2, split_pos, {"urgent": False}),
                ]

            packets_sent = len(segments)
            bytes_sent = len(payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "split_pos": split_pos,
                    "urgent_data_size": urgent_data_size,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPOptionsPaddingAttack(ManipulationAttack):
    """
    TCP Options Padding Attack - adds TCP options padding.

    Migrated from:
    - apply_tcp_options_padding (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "tcp_options_padding"

    @property
    def description(self) -> str:
        return "Adds TCP options padding to confuse DPI parsers"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP options padding attack."""
        start_time = time.time()

        try:
            payload = context.payload
            padding_size = context.params.get("padding_size", 8)
            split_pos = context.params.get("split_pos", 4)

            # Generate padding options (NOP options)
            padding_options = b"\x01" * padding_size  # NOP options

            if not (0 < split_pos < len(payload)):
                # Send as single segment with padding
                segments = [(payload, 0, {"tcp_options": padding_options})]
            else:
                # Split and apply different padding
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                segments = [
                    (part1, 0, {"tcp_options": padding_options}),
                    (part2, split_pos, {"tcp_options": b""}),
                ]

            packets_sent = len(segments)
            bytes_sent = len(payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "padding_size": padding_size,
                    "split_pos": split_pos,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPMultiSplitAttack(ManipulationAttack):
    """
    TCP Multi-Split Attack - splits payload into multiple segments.
    ENHANCED: Now handles split_count, seqovl, and fooling parameters directly.
    """

    @property
    def name(self) -> str:
        return "tcp_multisplit"

    @property
    def description(self) -> str:
        return "Splits payload into multiple segments with overlap and fooling"

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Executes the multisplit attack based on parameters from the context.
        """
        start_time = time.time()
        try:
            payload = context.payload
            params = context.params

            # --- ЭКСПЕРТНАЯ ЛОГИКА: Извлекаем параметры из контекста ---
            # Используем get для безопасного получения значений с default
            split_count = int(params.get("dpi-desync-split-count", 3))
            overlap_size = int(params.get("dpi-desync-split-seqovl", 0))
            fooling_methods = params.get("dpi-desync-fooling", "").split(",")

            self.logger.debug(
                f"Executing multisplit with count={split_count}, overlap={overlap_size}, fooling={fooling_methods}"
            )

            if len(payload) < split_count:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Payload too small ({len(payload)} bytes) for {split_count} splits.",
                )

            # --- ГЕНЕРАЦИЯ СЕГМЕНТОВ ---
            segments = []
            segment_size = len(payload) // split_count
            remainder = len(payload) % split_count
            current_pos = 0

            for i in range(split_count):
                size = segment_size + (1 if i < remainder else 0)
                end_pos = current_pos + size

                # Применяем overlap
                start_offset = (
                    max(0, current_pos - overlap_size) if i > 0 else current_pos
                )

                segment_payload = payload[start_offset:end_pos]

                if not segment_payload:
                    continue

                # --- ПРИМЕНЕНИЕ FOOLING ТЕХНИК ---
                options = {}
                if "badsum" in fooling_methods:
                    options["bad_checksum"] = True
                if "md5sig" in fooling_methods:
                    options["md5_signature"] = os.urandom(16)  # TCP MD5-sig option
                if "badseq" in fooling_methods:
                    # Эта опция будет обработана сборщиком пакетов
                    options["bad_sequence"] = True

                # Добавляем небольшую задержку между сегментами для надежности
                if i > 0:
                    options["delay_ms"] = random.randint(5, 20)

                # seq_offset для сегмента - это его начальная позиция в оригинальном payload
                segments.append((segment_payload, current_pos, options))
                current_pos = end_pos

            packets_sent = len(segments)
            bytes_sent = sum(len(s[0]) for s in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "split_count": split_count,
                    "overlap_size": overlap_size,
                    "fooling_methods": fooling_methods,
                    "segment_count": len(segments),
                    "segments": segments,  # Возвращаем сегменты для движка
                },
            )
        except Exception as e:
            self.logger.error(f"TCPMultiSplitAttack failed: {e}", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPTimestampAttack(ManipulationAttack):
    """
    TCP Timestamp Attack - manipulates TCP timestamps.

    Migrated from:
    - apply_tcp_timestamp_manipulation (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "tcp_timestamp_manipulation"

    @property
    def description(self) -> str:
        return "Manipulates TCP timestamps to evade DPI detection"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP timestamp attack."""
        start_time = time.time()

        try:
            payload = context.payload
            split_pos = context.params.get("split_pos", 6)

            # Generate different timestamp values for each segment
            ts_val1 = random.randint(1000000, 9999999)
            ts_val2 = random.randint(1000000, 9999999)

            if not (0 < split_pos < len(payload)):
                # Send as single segment with timestamp
                segments = [(payload, 0, {"timestamp": ts_val1})]
            else:
                # Split and apply different timestamps
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                segments = [
                    (part1, 0, {"timestamp": ts_val1}),
                    (part2, split_pos, {"timestamp": ts_val2}),
                ]

            packets_sent = len(segments)
            bytes_sent = len(payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "split_pos": split_pos,
                    "timestamp1": ts_val1,
                    "timestamp2": ts_val2,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TCPWindowSizeLimitAttack(ManipulationAttack):
    """
    TCP Window Size Limit Attack - limits TCP window size to confuse DPI.

    This attack sets the TCP window size to a very small value (typically 1 or 2)
    to make the connection appear slow or constrained, potentially bypassing
    DPI systems that expect normal window sizes.

    Migrated from:
    - apply_wssize_limit (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "tcp_wssize_limit"

    @property
    def description(self) -> str:
        return "Limits TCP window size to confuse DPI systems"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP window size limit attack."""
        start_time = time.time()

        try:
            payload = context.payload
            window_size = context.params.get("window_size", 1)
            split_pos = context.params.get("split_pos", len(payload) // 2)

            # Ensure window_size is reasonable (1-4)
            window_size = max(1, min(4, window_size))

            if not (0 < split_pos < len(payload)):
                # Send as single segment with limited window
                segments = [(payload, 0, {"window_size": window_size})]
            else:
                # Split payload and apply window size limit to all segments
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                segments = [
                    (part1, 0, {"window_size": window_size}),
                    (part2, split_pos, {"window_size": window_size}),
                ]

            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "window_size": window_size,
                    "split_pos": split_pos,
                    "segment_count": len(segments),
                    "attack_type": "window_size_limit",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
