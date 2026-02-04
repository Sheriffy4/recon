"""
Traffic Pattern Obfuscation Attacks

Advanced traffic pattern obfuscation techniques that modify packet timing,
sizes, and flow characteristics to evade behavioral DPI analysis.

This module provides four main attack classes:
- TrafficPatternObfuscationAttack: Modifies traffic patterns (timing, size, burst, flow mimicry)
- PacketSizeObfuscationAttack: Normalizes, randomizes, or fragments packet sizes
- TimingObfuscationAttack: Applies jitter, exponential, burst, or rhythm-breaking timing
- FlowObfuscationAttack: Creates bidirectional, multi-connection, or session-splitting flows

The implementation delegates complex logic to specialized utility modules:
- padding_utils: Padding generation strategies
- calculation_utils: Size and delay calculations
- flow_patterns: Flow pattern generators
- timing_strategies: Timing obfuscation strategies
"""

import time
import random
from typing import List, Dict, Any, Tuple
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.obfuscation.padding_utils import (
    generate_padding,
    generate_realistic_padding,
)
from core.bypass.attacks.obfuscation.calculation_utils import ObfuscationCalculator
from core.bypass.attacks.obfuscation.flow_patterns import FlowPatternGenerator
from core.bypass.attacks.obfuscation.timing_strategies import TimingStrategy
from core.bypass.attacks.obfuscation.segment_schema import (
    make_segment,
    next_seq_offset,
    normalize_segments,
)


@register_attack
class TrafficPatternObfuscationAttack(BaseAttack):
    """
    Traffic Pattern Obfuscation Attack.

    Modifies traffic patterns to break behavioral fingerprinting by
    altering packet timing, sizes, and flow characteristics.
    """

    @property
    def name(self) -> str:
        return "traffic_pattern_obfuscation"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "Modifies traffic patterns to evade behavioral DPI analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute traffic pattern obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            obfuscation_strategy = context.params.get("obfuscation_strategy", "mixed")
            intensity_level = context.params.get("intensity_level", "medium")
            mimic_application = context.params.get("mimic_application", "web_browsing")
            obfuscated_segments = await self._apply_pattern_obfuscation(
                payload, obfuscation_strategy, intensity_level, mimic_application
            )
            packets_sent = len(obfuscated_segments)
            bytes_sent = sum((len(seg[0]) for seg in obfuscated_segments))
            total_delay = sum(
                ((seg[2] or {}).get("delay_ms", 0) if len(seg) > 2 else 0)
                for seg in obfuscated_segments
            )
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="traffic_pattern_obfuscation",
                metadata={
                    "obfuscation_strategy": obfuscation_strategy,
                    "intensity_level": intensity_level,
                    "mimic_application": mimic_application,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "total_delay_ms": total_delay,
                    "expansion_ratio": bytes_sent / len(payload) if payload else 1.0,
                    "segments": obfuscated_segments,
                },
            )
        except (ValueError, TypeError, KeyError) as e:
            # Handle parameter validation and data structure errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="traffic_pattern_obfuscation",
                metadata={"error_type": type(e).__name__},
            )
        except Exception as e:
            # Catch-all for unexpected errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="traffic_pattern_obfuscation",
                metadata={"error_type": type(e).__name__},
            )

    async def _apply_pattern_obfuscation(
        self, payload: bytes, strategy: str, intensity: str, mimic_app: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply traffic pattern obfuscation based on strategy."""
        if strategy == "timing_randomization":
            return await self._apply_timing_randomization(payload, intensity)
        elif strategy == "size_padding":
            return await self._apply_size_padding(payload, intensity)
        elif strategy == "burst_shaping":
            return await self._apply_burst_shaping(payload, intensity)
        elif strategy == "flow_mimicry":
            return await self._apply_flow_mimicry(payload, mimic_app)
        elif strategy == "mixed":
            return await self._apply_mixed_obfuscation(payload, intensity)
        else:
            raise ValueError(f"Invalid obfuscation_strategy: {strategy}")

    async def _apply_timing_randomization(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply timing randomization obfuscation."""
        if not payload:
            return []
        segments = []
        seq_offset = 0
        chunk_size = ObfuscationCalculator.get_chunk_size(intensity)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            base_delay = ObfuscationCalculator.get_base_delay(intensity)
            jitter = ObfuscationCalculator.calculate_jitter(intensity)
            delay = max(0, int(base_delay + jitter))
            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="timing_randomization",
                    base_delay=base_delay,
                    jitter=jitter,
                    chunk_index=i // chunk_size,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments

    async def _apply_size_padding(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply size padding obfuscation."""
        if not payload:
            return []
        segments = []
        seq_offset = 0
        chunk_size = ObfuscationCalculator.get_chunk_size(intensity)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            padding_size = ObfuscationCalculator.calculate_padding_size(len(chunk), intensity)
            padding = generate_realistic_padding(padding_size)
            padded_chunk = chunk + padding
            delay = random.randint(10, 50)
            segments.append(
                make_segment(
                    padded_chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="size_padding",
                    original_size=len(chunk),
                    padding_size=padding_size,
                    padded_size=len(padded_chunk),
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(padded_chunk))
        return segments

    async def _apply_burst_shaping(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply burst shaping obfuscation."""
        if not payload:
            return []
        segments = []
        seq_offset = 0
        burst_config = self._get_burst_config(intensity)
        burst_size = burst_config["burst_size"]
        burst_interval = burst_config["burst_interval"]
        inter_burst_delay = burst_config["inter_burst_delay"]
        chunk_size = max(
            1, (len(payload) // burst_size) if len(payload) > burst_size else len(payload)
        )
        for burst_index in range(burst_size):
            start_pos = burst_index * chunk_size
            end_pos = min(start_pos + chunk_size, len(payload))
            if start_pos >= len(payload):
                break
            chunk = payload[start_pos:end_pos]
            if burst_index == 0:
                delay = 0
            else:
                delay = inter_burst_delay + random.randint(-10, 10)
            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="burst_shaping",
                    burst_index=burst_index,
                    burst_size=burst_size,
                    burst_interval=burst_interval,
                    inter_burst_delay=inter_burst_delay,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments

    async def _apply_flow_mimicry(
        self, payload: bytes, mimic_app: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply flow mimicry obfuscation."""
        if not payload:
            return []
        flow_pattern = self._get_flow_pattern(mimic_app)
        segments = []
        seq_offset = 0
        pattern_chunks = flow_pattern["chunk_sizes"]
        pattern_delays = flow_pattern["delays"]
        payload_pos = 0
        for i, (chunk_size, delay) in enumerate(zip(pattern_chunks, pattern_delays)):
            if payload_pos >= len(payload):
                break
            actual_chunk_size = min(chunk_size, len(payload) - payload_pos)
            chunk = payload[payload_pos : payload_pos + actual_chunk_size]
            if len(chunk) < chunk_size:
                padding = generate_realistic_padding(chunk_size - len(chunk))
                chunk = chunk + padding
            actual_delay = delay + random.randint(-delay // 4, delay // 4)
            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=actual_delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="flow_mimicry",
                    mimic_application=mimic_app,
                    pattern_index=i,
                    expected_size=chunk_size,
                    actual_size=len(chunk),
                )
            )
            payload_pos += actual_chunk_size
            seq_offset = next_seq_offset(seq_offset, len(chunk))
        if payload_pos < len(payload):
            remaining = payload[payload_pos:]
            delay = random.randint(50, 200)
            segments.append(
                make_segment(
                    remaining,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="flow_mimicry",
                    mimic_application=mimic_app,
                    pattern_index="overflow",
                    remaining_data=True,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(remaining))
        return segments

    async def _apply_mixed_obfuscation(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply mixed obfuscation techniques."""
        if not payload:
            return []
        segments = []
        seq_offset = 0
        techniques = ["timing", "padding", "burst"]
        chunk_size = ObfuscationCalculator.get_chunk_size(intensity)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            technique = random.choice(techniques)
            if technique == "timing":
                delay = ObfuscationCalculator.get_base_delay(
                    intensity
                ) + ObfuscationCalculator.calculate_jitter(intensity)
                obfuscated_chunk = chunk
            elif technique == "padding":
                padding_size = ObfuscationCalculator.calculate_padding_size(len(chunk), intensity)
                padding = generate_realistic_padding(padding_size)
                obfuscated_chunk = chunk + padding
                delay = random.randint(20, 80)
            else:
                obfuscated_chunk = chunk
                if i == 0:
                    delay = 0
                else:
                    delay = random.randint(100, 300)
            delay = max(0, int(delay))
            segments.append(
                make_segment(
                    obfuscated_chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="mixed",
                    technique_used=technique,
                    chunk_index=i // chunk_size,
                    intensity=intensity,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(obfuscated_chunk))
        return segments

    def _get_burst_config(self, intensity: str) -> Dict[str, int]:
        """Get burst configuration."""
        configs = {
            "low": {"burst_size": 3, "burst_interval": 50, "inter_burst_delay": 200},
            "medium": {"burst_size": 5, "burst_interval": 30, "inter_burst_delay": 150},
            "high": {"burst_size": 8, "burst_interval": 20, "inter_burst_delay": 100},
        }
        return configs.get(intensity, configs["medium"])

    def _get_flow_pattern(self, mimic_app: str) -> Dict[str, List[int]]:
        """Get flow pattern for application mimicry."""
        patterns = {
            "web_browsing": {
                "chunk_sizes": [1200, 800, 1500, 600, 1000],
                "delays": [0, 50, 100, 30, 80],
            },
            "video_streaming": {
                "chunk_sizes": [2000, 2000, 2000, 1500, 1800],
                "delays": [0, 33, 33, 33, 33],
            },
            "file_transfer": {
                "chunk_sizes": [1400, 1400, 1400, 1400, 1400],
                "delays": [0, 10, 10, 10, 10],
            },
            "messaging": {
                "chunk_sizes": [200, 150, 300, 100, 250],
                "delays": [0, 200, 500, 100, 300],
            },
        }
        return patterns.get(mimic_app, patterns["web_browsing"])


@register_attack
class PacketSizeObfuscationAttack(BaseAttack):
    """
    Packet Size Obfuscation Attack.

    Modifies packet sizes to break size-based fingerprinting by
    adding padding, fragmentation, or size normalization.
    """

    @property
    def name(self) -> str:
        return "packet_size_obfuscation"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "Modifies packet sizes to evade size-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute packet size obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            size_strategy = context.params.get("size_strategy", "normalize")
            target_size = context.params.get("target_size", 1200)
            size_variance = context.params.get("size_variance", 0.1)
            obfuscated_segments = await self._apply_size_obfuscation(
                payload, size_strategy, target_size, size_variance
            )
            packets_sent = len(obfuscated_segments)
            bytes_sent = sum((len(seg[0]) for seg in obfuscated_segments))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="packet_size_obfuscation",
                metadata={
                    "size_strategy": size_strategy,
                    "target_size": target_size,
                    "size_variance": size_variance,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "size_expansion": bytes_sent / len(payload) if payload else 1.0,
                    "segments": obfuscated_segments,
                },
            )
        except (ValueError, TypeError, KeyError) as e:
            # Handle parameter validation and data structure errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="packet_size_obfuscation",
                metadata={"error_type": type(e).__name__},
            )
        except Exception as e:
            # Catch-all for unexpected errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="packet_size_obfuscation",
                metadata={"error_type": type(e).__name__},
            )

    async def _apply_size_obfuscation(
        self, payload: bytes, strategy: str, target_size: int, variance: float
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply size obfuscation based on strategy."""
        if not payload:
            return []
        target_size = self._sanitize_positive_int(target_size, default=1200)
        variance = self._sanitize_variance(variance, default=0.1)
        if strategy == "normalize":
            return await self._normalize_packet_sizes(payload, target_size, variance)
        elif strategy == "randomize":
            return await self._randomize_packet_sizes(payload, target_size, variance)
        elif strategy == "fragment":
            return await self._fragment_packets(payload, target_size)
        elif strategy == "pad_to_mtu":
            return await self._pad_to_mtu(payload)
        else:
            return await self._normalize_packet_sizes(payload, target_size, variance)

    @staticmethod
    def _sanitize_positive_int(value: Any, default: int) -> int:
        try:
            iv = int(value)
            return iv if iv > 0 else int(default)
        except (TypeError, ValueError):
            return int(default)

    @staticmethod
    def _sanitize_variance(value: Any, default: float) -> float:
        try:
            fv = float(value)
        except (TypeError, ValueError):
            fv = float(default)
        # Clamp to sane bounds to avoid negative/zero packet sizes.
        return max(0.0, min(0.95, fv))

    async def _normalize_packet_sizes(
        self, payload: bytes, target_size: int, variance: float
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Normalize all packets to similar sizes."""
        segments = []
        seq_offset = 0
        for i in range(0, len(payload), target_size):
            chunk = payload[i : i + target_size]
            size_variation = int(target_size * variance * (random.random() - 0.5) * 2)
            actual_target = max(1, target_size + size_variation)
            if len(chunk) < actual_target:
                padding_size = actual_target - len(chunk)
                padding = generate_padding(padding_size, strategy="auto")
                normalized_chunk = chunk + padding
            else:
                normalized_chunk = chunk
            delay = random.randint(10, 50)
            segments.append(
                make_segment(
                    normalized_chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="normalize",
                    original_size=len(chunk),
                    target_size=actual_target,
                    final_size=len(normalized_chunk),
                    padding_added=len(normalized_chunk) - len(chunk),
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(normalized_chunk))
        return segments

    async def _randomize_packet_sizes(
        self, payload: bytes, base_size: int, variance: float
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Randomize packet sizes within a range."""
        segments = []
        seq_offset = 0
        base_size = self._sanitize_positive_int(base_size, default=1200)
        variance = self._sanitize_variance(variance, default=0.1)
        min_size = max(1, int(base_size * (1 - variance)))
        max_size = max(min_size, int(base_size * (1 + variance)))
        pos = 0
        while pos < len(payload):
            chunk_size = random.randint(min_size, max_size)
            chunk = payload[pos : pos + chunk_size]
            if len(chunk) < chunk_size and pos + len(chunk) == len(payload):
                padding_size = random.randint(0, chunk_size - len(chunk))
                padding = generate_padding(padding_size, strategy="auto")
                randomized_chunk = chunk + padding
            else:
                randomized_chunk = chunk
            delay = random.randint(5, 30)
            segments.append(
                make_segment(
                    randomized_chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="randomize",
                    expected_size=chunk_size,
                    actual_size=len(randomized_chunk),
                    position=pos,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(randomized_chunk))
            pos += len(chunk)
        return segments

    async def _fragment_packets(
        self, payload: bytes, fragment_size: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Fragment packets into smaller sizes."""
        segments = []
        seq_offset = 0
        fragment_size = self._sanitize_positive_int(fragment_size, default=1200)
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i : i + fragment_size]
            delay = random.randint(1, 10)
            segments.append(
                make_segment(
                    fragment,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="fragment",
                    fragment_index=i // fragment_size,
                    fragment_size=len(fragment),
                    is_last_fragment=(i + fragment_size >= len(payload)),
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(fragment))
        return segments

    async def _pad_to_mtu(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Pad packets to MTU size."""
        mtu_size = 1500
        segments = []
        seq_offset = 0
        for i in range(0, len(payload), mtu_size):
            chunk = payload[i : i + mtu_size]
            if len(chunk) < mtu_size:
                padding_size = mtu_size - len(chunk)
                padding = generate_padding(padding_size, strategy="auto")
                mtu_chunk = chunk + padding
            else:
                mtu_chunk = chunk
            delay = random.randint(15, 40)
            segments.append(
                make_segment(
                    mtu_chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    obfuscation_type="pad_to_mtu",
                    original_size=len(chunk),
                    mtu_size=mtu_size,
                    padding_added=len(mtu_chunk) - len(chunk),
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(mtu_chunk))
        return segments


@register_attack
class TimingObfuscationAttack(BaseAttack):
    """
    Timing Obfuscation Attack.

    Modifies packet timing patterns to evade timing-based fingerprinting
    through jitter injection, delay randomization, and rhythm breaking.
    """

    @property
    def name(self) -> str:
        return "timing_obfuscation"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "Modifies packet timing to evade timing-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute timing obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            timing_strategy = context.params.get("timing_strategy", "jitter")
            base_delay = context.params.get("base_delay", 50)
            jitter_range = context.params.get("jitter_range", 20)
            obfuscated_segments = await self._apply_timing_obfuscation(
                payload, timing_strategy, base_delay, jitter_range
            )
            packets_sent = len(obfuscated_segments)
            bytes_sent = sum((len(seg[0]) for seg in obfuscated_segments))
            total_delay = sum(
                ((seg[2] or {}).get("delay_ms", 0) if len(seg) > 2 else 0)
                for seg in obfuscated_segments
            )
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="timing_obfuscation",
                metadata={
                    "timing_strategy": timing_strategy,
                    "base_delay": base_delay,
                    "jitter_range": jitter_range,
                    "total_delay_ms": total_delay,
                    "average_delay": (total_delay / packets_sent if packets_sent > 0 else 0),
                    "segments": obfuscated_segments,
                },
            )
        except (ValueError, TypeError, KeyError) as e:
            # Handle parameter validation and data structure errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="timing_obfuscation",
                metadata={"error_type": type(e).__name__},
            )
        except Exception as e:
            # Catch-all for unexpected errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="timing_obfuscation",
                metadata={"error_type": type(e).__name__},
            )

    async def _apply_timing_obfuscation(
        self, payload: bytes, strategy: str, base_delay: int, jitter_range: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply timing obfuscation based on strategy."""
        if not payload:
            return []
        # Protect downstream strategies from invalid params (e.g., base_delay=0 -> expovariate error)
        try:
            base_delay = max(1, int(base_delay))
        except (TypeError, ValueError):
            base_delay = 1
        try:
            jitter_range = max(0, int(jitter_range))
        except (TypeError, ValueError):
            jitter_range = 0
        if strategy == "jitter":
            return normalize_segments(
                await TimingStrategy.apply_jitter_timing(payload, base_delay, jitter_range),
                treat_second_as="seq_offset",
                protocol="tcp",
                attack=self.name,
            )
        elif strategy == "exponential":
            return normalize_segments(
                await TimingStrategy.apply_exponential_timing(payload, base_delay),
                treat_second_as="seq_offset",
                protocol="tcp",
                attack=self.name,
            )
        elif strategy == "burst":
            return normalize_segments(
                await TimingStrategy.apply_burst_timing(payload, base_delay),
                treat_second_as="seq_offset",
                protocol="tcp",
                attack=self.name,
            )
        elif strategy == "rhythm_break":
            return normalize_segments(
                await TimingStrategy.apply_rhythm_breaking(payload, base_delay, jitter_range),
                treat_second_as="seq_offset",
                protocol="tcp",
                attack=self.name,
            )
        else:
            return normalize_segments(
                await TimingStrategy.apply_jitter_timing(payload, base_delay, jitter_range),
                treat_second_as="seq_offset",
                protocol="tcp",
                attack=self.name,
            )


@register_attack
class FlowObfuscationAttack(BaseAttack):
    """
    Flow Obfuscation Attack.

    Modifies traffic flow characteristics to evade flow-based fingerprinting
    by altering bidirectional patterns, connection behavior, and session structure.
    """

    @property
    def name(self) -> str:
        return "flow_obfuscation"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "Modifies traffic flow characteristics to evade flow-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute flow obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            flow_strategy = context.params.get("flow_strategy", "bidirectional")
            connection_pattern = context.params.get("connection_pattern", "persistent")
            fake_responses = context.params.get("fake_responses", True)
            obfuscated_segments = await self._apply_flow_obfuscation(
                payload, flow_strategy, connection_pattern, fake_responses, context
            )
            packets_sent = len(obfuscated_segments)
            bytes_sent = sum((len(seg[0]) for seg in obfuscated_segments))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="flow_obfuscation",
                metadata={
                    "flow_strategy": flow_strategy,
                    "connection_pattern": connection_pattern,
                    "fake_responses": fake_responses,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": obfuscated_segments,
                },
            )
        except (ValueError, TypeError, KeyError) as e:
            # Handle parameter validation and data structure errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="flow_obfuscation",
                metadata={"error_type": type(e).__name__},
            )
        except Exception as e:
            # Catch-all for unexpected errors
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="flow_obfuscation",
                metadata={"error_type": type(e).__name__},
            )

    async def _apply_flow_obfuscation(
        self,
        payload: bytes,
        strategy: str,
        pattern: str,
        fake_responses: bool,
        context: AttackContext,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply flow obfuscation based on strategy."""
        if not payload:
            return []
        if strategy == "bidirectional":
            segs = await FlowPatternGenerator.create_bidirectional_flow(payload, fake_responses)
        elif strategy == "multi_connection":
            segs = await FlowPatternGenerator.create_multi_connection_flow(payload)
        elif strategy == "session_splitting":
            segs = await FlowPatternGenerator.create_session_splitting_flow(payload)
        else:
            segs = await FlowPatternGenerator.create_bidirectional_flow(payload, fake_responses)
        # Ensure attack/protocol/segment_index are present even if generators evolve.
        return normalize_segments(
            segs, treat_second_as="seq_offset", protocol="tcp", attack=self.name
        )
