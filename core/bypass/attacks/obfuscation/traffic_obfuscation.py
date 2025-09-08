"""
Traffic Pattern Obfuscation Attacks

Advanced traffic pattern obfuscation techniques that modify packet timing,
sizes, and flow characteristics to evade behavioral DPI analysis.
"""

import time
import random
import asyncio
from typing import List, Dict, Any, Tuple
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack


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
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies traffic patterns to evade behavioral DPI analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

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
            total_delay = sum((seg[1] for seg in obfuscated_segments))
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
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="traffic_pattern_obfuscation",
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
            return await self._apply_flow_mimicry(payload, mimic_app, intensity)
        elif strategy == "mixed":
            return await self._apply_mixed_obfuscation(payload, intensity, mimic_app)
        else:
            raise ValueError(f"Invalid obfuscation_strategy: {strategy}")

    async def _apply_timing_randomization(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply timing randomization obfuscation."""
        segments = []
        chunk_size = self._get_chunk_size(intensity)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            base_delay = self._get_base_delay(intensity)
            jitter = self._calculate_jitter(intensity)
            delay = max(1, int(base_delay + jitter))
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "obfuscation_type": "timing_randomization",
                        "base_delay": base_delay,
                        "jitter": jitter,
                        "chunk_index": i // chunk_size,
                    },
                )
            )
        return segments

    async def _apply_size_padding(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply size padding obfuscation."""
        segments = []
        chunk_size = self._get_chunk_size(intensity)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            padding_size = self._calculate_padding_size(len(chunk), intensity)
            padding = self._generate_realistic_padding(padding_size)
            padded_chunk = chunk + padding
            delay = random.randint(10, 50)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    padded_chunk,
                    delay,
                    {
                        "obfuscation_type": "size_padding",
                        "original_size": len(chunk),
                        "padding_size": padding_size,
                        "padded_size": len(padded_chunk),
                    },
                )
            )
        return segments

    async def _apply_burst_shaping(
        self, payload: bytes, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply burst shaping obfuscation."""
        segments = []
        burst_config = self._get_burst_config(intensity)
        burst_size = burst_config["burst_size"]
        burst_interval = burst_config["burst_interval"]
        inter_burst_delay = burst_config["inter_burst_delay"]
        chunk_size = (
            len(payload) // burst_size if len(payload) > burst_size else len(payload)
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
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "obfuscation_type": "burst_shaping",
                        "burst_index": burst_index,
                        "burst_size": burst_size,
                        "inter_burst_delay": inter_burst_delay,
                    },
                )
            )
        return segments

    async def _apply_flow_mimicry(
        self, payload: bytes, mimic_app: str, intensity: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply flow mimicry obfuscation."""
        flow_pattern = self._get_flow_pattern(mimic_app)
        segments = []
        pattern_chunks = flow_pattern["chunk_sizes"]
        pattern_delays = flow_pattern["delays"]
        payload_pos = 0
        for i, (chunk_size, delay) in enumerate(zip(pattern_chunks, pattern_delays)):
            if payload_pos >= len(payload):
                break
            actual_chunk_size = min(chunk_size, len(payload) - payload_pos)
            chunk = payload[payload_pos : payload_pos + actual_chunk_size]
            if len(chunk) < chunk_size:
                padding = self._generate_realistic_padding(chunk_size - len(chunk))
                chunk = chunk + padding
            actual_delay = delay + random.randint(-delay // 4, delay // 4)
            await asyncio.sleep(actual_delay / 1000.0)
            segments.append(
                (
                    chunk,
                    actual_delay,
                    {
                        "obfuscation_type": "flow_mimicry",
                        "mimic_application": mimic_app,
                        "pattern_index": i,
                        "expected_size": chunk_size,
                        "actual_size": len(chunk),
                    },
                )
            )
            payload_pos += actual_chunk_size
        if payload_pos < len(payload):
            remaining = payload[payload_pos:]
            delay = random.randint(50, 200)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    remaining,
                    delay,
                    {
                        "obfuscation_type": "flow_mimicry",
                        "mimic_application": mimic_app,
                        "pattern_index": "overflow",
                        "remaining_data": True,
                    },
                )
            )
        return segments

    async def _apply_mixed_obfuscation(
        self, payload: bytes, intensity: str, mimic_app: str
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply mixed obfuscation techniques."""
        segments = []
        techniques = ["timing", "padding", "burst"]
        chunk_size = self._get_chunk_size(intensity)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            technique = random.choice(techniques)
            if technique == "timing":
                delay = self._get_base_delay(intensity) + self._calculate_jitter(
                    intensity
                )
                obfuscated_chunk = chunk
            elif technique == "padding":
                padding_size = self._calculate_padding_size(len(chunk), intensity)
                padding = self._generate_realistic_padding(padding_size)
                obfuscated_chunk = chunk + padding
                delay = random.randint(20, 80)
            else:
                obfuscated_chunk = chunk
                if i == 0:
                    delay = 0
                else:
                    delay = random.randint(100, 300)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    obfuscated_chunk,
                    delay,
                    {
                        "obfuscation_type": "mixed",
                        "technique_used": technique,
                        "chunk_index": i // chunk_size,
                        "intensity": intensity,
                    },
                )
            )
        return segments

    def _get_chunk_size(self, intensity: str) -> int:
        """Get chunk size based on intensity."""
        sizes = {
            "low": random.randint(200, 500),
            "medium": random.randint(100, 300),
            "high": random.randint(50, 150),
        }
        return sizes.get(intensity, 200)

    def _get_base_delay(self, intensity: str) -> int:
        """Get base delay based on intensity."""
        delays = {
            "low": random.randint(10, 50),
            "medium": random.randint(20, 100),
            "high": random.randint(50, 200),
        }
        return delays.get(intensity, 50)

    def _calculate_jitter(self, intensity: str) -> int:
        """Calculate timing jitter."""
        jitter_ranges = {"low": (-5, 5), "medium": (-20, 20), "high": (-50, 50)}
        min_jitter, max_jitter = jitter_ranges.get(intensity, (-10, 10))
        return random.randint(min_jitter, max_jitter)

    def _calculate_padding_size(self, original_size: int, intensity: str) -> int:
        """Calculate padding size."""
        padding_ratios = {"low": 0.1, "medium": 0.3, "high": 0.5}
        ratio = padding_ratios.get(intensity, 0.2)
        return int(original_size * ratio) + random.randint(10, 50)

    def _generate_realistic_padding(self, size: int) -> bytes:
        """Generate realistic padding data."""
        if size <= 0:
            return b""
        patterns = [
            b"\x00" * size,
            bytes([random.randint(0, 255) for _ in range(size)]),
            (b"PADDING" * (size // 7 + 1))[:size],
            b" " * size,
        ]
        return random.choice(patterns)

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
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies packet sizes to evade size-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

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
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="packet_size_obfuscation",
            )

    async def _apply_size_obfuscation(
        self, payload: bytes, strategy: str, target_size: int, variance: float
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply size obfuscation based on strategy."""
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

    async def _normalize_packet_sizes(
        self, payload: bytes, target_size: int, variance: float
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Normalize all packets to similar sizes."""
        segments = []
        for i in range(0, len(payload), target_size):
            chunk = payload[i : i + target_size]
            size_variation = int(target_size * variance * (random.random() - 0.5) * 2)
            actual_target = target_size + size_variation
            if len(chunk) < actual_target:
                padding_size = actual_target - len(chunk)
                padding = self._generate_size_padding(padding_size)
                normalized_chunk = chunk + padding
            else:
                normalized_chunk = chunk
            delay = random.randint(10, 50)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    normalized_chunk,
                    delay,
                    {
                        "obfuscation_type": "normalize",
                        "original_size": len(chunk),
                        "target_size": actual_target,
                        "final_size": len(normalized_chunk),
                        "padding_added": len(normalized_chunk) - len(chunk),
                    },
                )
            )
        return segments

    async def _randomize_packet_sizes(
        self, payload: bytes, base_size: int, variance: float
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Randomize packet sizes within a range."""
        segments = []
        min_size = int(base_size * (1 - variance))
        max_size = int(base_size * (1 + variance))
        pos = 0
        while pos < len(payload):
            chunk_size = random.randint(min_size, max_size)
            chunk = payload[pos : pos + chunk_size]
            if len(chunk) < chunk_size and pos + len(chunk) == len(payload):
                padding_size = random.randint(0, chunk_size - len(chunk))
                padding = self._generate_size_padding(padding_size)
                randomized_chunk = chunk + padding
            else:
                randomized_chunk = chunk
            delay = random.randint(5, 30)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    randomized_chunk,
                    delay,
                    {
                        "obfuscation_type": "randomize",
                        "expected_size": chunk_size,
                        "actual_size": len(randomized_chunk),
                        "position": pos,
                    },
                )
            )
            pos += len(chunk)
        return segments

    async def _fragment_packets(
        self, payload: bytes, fragment_size: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Fragment packets into smaller sizes."""
        segments = []
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i : i + fragment_size]
            delay = random.randint(1, 10)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    fragment,
                    delay,
                    {
                        "obfuscation_type": "fragment",
                        "fragment_index": i // fragment_size,
                        "fragment_size": len(fragment),
                        "is_last_fragment": i + fragment_size >= len(payload),
                    },
                )
            )
        return segments

    async def _pad_to_mtu(
        self, payload: bytes
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Pad packets to MTU size."""
        mtu_size = 1500
        segments = []
        for i in range(0, len(payload), mtu_size):
            chunk = payload[i : i + mtu_size]
            if len(chunk) < mtu_size:
                padding_size = mtu_size - len(chunk)
                padding = self._generate_size_padding(padding_size)
                mtu_chunk = chunk + padding
            else:
                mtu_chunk = chunk
            delay = random.randint(15, 40)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    mtu_chunk,
                    delay,
                    {
                        "obfuscation_type": "pad_to_mtu",
                        "original_size": len(chunk),
                        "mtu_size": mtu_size,
                        "padding_added": len(mtu_chunk) - len(chunk),
                    },
                )
            )
        return segments

    def _generate_size_padding(self, size: int) -> bytes:
        """Generate padding for size obfuscation."""
        if size <= 0:
            return b""
        strategies = ["zero", "random", "pattern", "http_like"]
        strategy = random.choice(strategies)
        if strategy == "zero":
            return b"\x00" * size
        elif strategy == "random":
            return bytes([random.randint(0, 255) for _ in range(size)])
        elif strategy == "pattern":
            pattern = b"ABCDEFGH"
            return (pattern * (size // len(pattern) + 1))[:size]
        else:
            http_padding = (
                b"X-Padding: " + b"x" * (size - 11) if size > 11 else b"x" * size
            )
            return http_padding[:size]


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
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies packet timing to evade timing-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

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
            total_delay = sum((seg[1] for seg in obfuscated_segments))
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
                    "average_delay": (
                        total_delay / packets_sent if packets_sent > 0 else 0
                    ),
                    "segments": obfuscated_segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="timing_obfuscation",
            )

    async def _apply_timing_obfuscation(
        self, payload: bytes, strategy: str, base_delay: int, jitter_range: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply timing obfuscation based on strategy."""
        if strategy == "jitter":
            return await self._apply_jitter_timing(payload, base_delay, jitter_range)
        elif strategy == "exponential":
            return await self._apply_exponential_timing(payload, base_delay)
        elif strategy == "burst":
            return await self._apply_burst_timing(payload, base_delay)
        elif strategy == "rhythm_break":
            return await self._apply_rhythm_breaking(payload, base_delay, jitter_range)
        else:
            return await self._apply_jitter_timing(payload, base_delay, jitter_range)

    async def _apply_jitter_timing(
        self, payload: bytes, base_delay: int, jitter_range: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply jitter-based timing obfuscation."""
        segments = []
        chunk_size = random.randint(100, 300)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            jitter = random.randint(-jitter_range, jitter_range)
            delay = max(1, base_delay + jitter)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "timing_type": "jitter",
                        "base_delay": base_delay,
                        "jitter": jitter,
                        "final_delay": delay,
                    },
                )
            )
        return segments

    async def _apply_exponential_timing(
        self, payload: bytes, base_delay: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply exponential timing distribution."""
        segments = []
        chunk_size = random.randint(150, 400)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            delay = int(random.expovariate(1.0 / base_delay))
            delay = max(1, min(delay, base_delay * 5))
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "timing_type": "exponential",
                        "base_delay": base_delay,
                        "calculated_delay": delay,
                    },
                )
            )
        return segments

    async def _apply_burst_timing(
        self, payload: bytes, base_delay: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply burst timing patterns."""
        segments = []
        burst_size = random.randint(3, 6)
        burst_delay = base_delay * 3
        chunk_size = (
            len(payload) // burst_size if len(payload) > burst_size else len(payload)
        )
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            burst_index = i // chunk_size
            if burst_index % burst_size == 0:
                delay = burst_delay + random.randint(-10, 10)
            else:
                delay = random.randint(5, 15)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "timing_type": "burst",
                        "burst_index": burst_index,
                        "burst_size": burst_size,
                        "is_burst_start": burst_index % burst_size == 0,
                    },
                )
            )
        return segments

    async def _apply_rhythm_breaking(
        self, payload: bytes, base_delay: int, jitter_range: int
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply rhythm-breaking timing patterns."""
        segments = []
        chunk_size = random.randint(80, 250)
        rhythm_pattern = [1.0, 0.5, 2.0, 0.3, 1.5, 0.8, 2.5]
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            pattern_index = i // chunk_size % len(rhythm_pattern)
            rhythm_multiplier = rhythm_pattern[pattern_index]
            jitter = random.randint(-jitter_range // 2, jitter_range // 2)
            delay = max(1, int(base_delay * rhythm_multiplier) + jitter)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "timing_type": "rhythm_break",
                        "pattern_index": pattern_index,
                        "rhythm_multiplier": rhythm_multiplier,
                        "jitter": jitter,
                        "final_delay": delay,
                    },
                )
            )
        return segments


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
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return (
            "Modifies traffic flow characteristics to evade flow-based fingerprinting"
        )

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

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
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="flow_obfuscation",
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
        if strategy == "bidirectional":
            return await self._create_bidirectional_flow(
                payload, fake_responses, context
            )
        elif strategy == "multi_connection":
            return await self._create_multi_connection_flow(payload, pattern, context)
        elif strategy == "session_splitting":
            return await self._create_session_splitting_flow(payload, context)
        else:
            return await self._create_bidirectional_flow(
                payload, fake_responses, context
            )

    async def _create_bidirectional_flow(
        self, payload: bytes, fake_responses: bool, context: AttackContext
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create bidirectional flow pattern."""
        segments = []
        chunk_size = random.randint(200, 500)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            delay = random.randint(10, 50)
            await asyncio.sleep(delay / 1000.0)
            segments.append(
                (
                    chunk,
                    delay,
                    {
                        "flow_type": "bidirectional",
                        "direction": "client_to_server",
                        "chunk_index": i // chunk_size,
                    },
                )
            )
            if fake_responses:
                response_size = random.randint(50, 200)
                fake_response = self._generate_fake_server_response(response_size)
                delay = random.randint(20, 100)
                await asyncio.sleep(delay / 1000.0)
                segments.append(
                    (
                        fake_response,
                        delay,
                        {
                            "flow_type": "bidirectional",
                            "direction": "server_to_client",
                            "is_fake_response": True,
                            "response_size": response_size,
                        },
                    )
                )
        return segments

    async def _create_multi_connection_flow(
        self, payload: bytes, pattern: str, context: AttackContext
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create multi-connection flow pattern."""
        segments = []
        num_connections = random.randint(2, 4)
        connection_chunks = []
        chunk_size = len(payload) // num_connections
        for i in range(num_connections):
            start = i * chunk_size
            end = start + chunk_size if i < num_connections - 1 else len(payload)
            connection_chunks.append(payload[start:end])
        max_chunks = max((len(chunk) // 100 + 1 for chunk in connection_chunks))
        for chunk_index in range(max_chunks):
            for conn_id, conn_data in enumerate(connection_chunks):
                start_pos = chunk_index * 100
                if start_pos < len(conn_data):
                    end_pos = min(start_pos + 100, len(conn_data))
                    data_chunk = conn_data[start_pos:end_pos]
                    delay = random.randint(5, 30)
                    await asyncio.sleep(delay / 1000.0)
                    segments.append(
                        (
                            data_chunk,
                            delay,
                            {
                                "flow_type": "multi_connection",
                                "connection_id": conn_id,
                                "chunk_index": chunk_index,
                                "total_connections": num_connections,
                            },
                        )
                    )
        return segments

    async def _create_session_splitting_flow(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create session splitting flow pattern."""
        segments = []
        num_sessions = random.randint(2, 3)
        session_size = len(payload) // num_sessions
        for session_id in range(num_sessions):
            start = session_id * session_size
            end = (
                start + session_size if session_id < num_sessions - 1 else len(payload)
            )
            session_data = payload[start:end]
            if session_id > 0:
                gap_delay = random.randint(200, 500)
                await asyncio.sleep(gap_delay / 1000.0)
                segments.append(
                    (
                        b"",
                        gap_delay,
                        {
                            "flow_type": "session_splitting",
                            "is_session_gap": True,
                            "session_id": session_id,
                        },
                    )
                )
            chunk_size = random.randint(150, 300)
            for i in range(0, len(session_data), chunk_size):
                chunk = session_data[i : i + chunk_size]
                delay = random.randint(10, 40)
                await asyncio.sleep(delay / 1000.0)
                segments.append(
                    (
                        chunk,
                        delay,
                        {
                            "flow_type": "session_splitting",
                            "session_id": session_id,
                            "chunk_in_session": i // chunk_size,
                            "is_session_data": True,
                        },
                    )
                )
        return segments

    def _generate_fake_server_response(self, size: int) -> bytes:
        """Generate fake server response data."""
        response_types = ["http_ok", "json_response", "binary_data"]
        response_type = random.choice(response_types)
        if response_type == "http_ok":
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(size - 50).encode()
                + b"\r\n\r\n"
            )
            response += b"x" * (size - len(response))
        elif response_type == "json_response":
            response = b'{"status":"ok","data":"' + b"x" * (size - 20) + b'"}'
        else:
            response = bytes([random.randint(0, 255) for _ in range(size)])
        return response[:size]
