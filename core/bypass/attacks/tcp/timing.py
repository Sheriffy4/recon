import time
import random
from typing import Optional
from core.bypass.attacks.tcp.race_attacks import RaceAttackConfig
from core.bypass.attacks.base import (
    BaseAttack,
    TimingAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack

try:
    from scapy.all import IP, TCP, Raw, send, sr1

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@register_attack
class DripFeedAttack(BaseAttack):
    """
    Drip Feed Attack for Gradual Data Transmission.

    This attack sends data in very small chunks with controlled timing
    to bypass DPI systems that have thresholds for data rate analysis
    or that timeout on slow connections.
    """

    def __init__(self, config: Optional[RaceAttackConfig] = None):
        super().__init__()
        self.config = config or RaceAttackConfig()
        self._name = "drip_feed"
        self._category = "tcp"
        self._description = "Gradual data transmission to bypass rate-based DPI"

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    @property
    def description(self) -> str:
        return self._description

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute drip feed attack."""
        start_time = time.time()
        try:
            payload = context.payload or b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            chunk_size = self.config.drip_chunk_size
            delay_ms = self.config.drip_delay_ms
            segments = []
            offset = 0
            while offset < len(payload):
                chunk = payload[offset : offset + chunk_size]
                segment_delay = delay_ms if offset > 0 else 0
                if self.config.drip_randomize:
                    segment_delay *= random.uniform(0.5, 1.5)
                segments.append((chunk, offset, {"delay_ms": segment_delay}))
                offset += chunk_size
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=(time.time() - start_time) * 1000,
                packets_sent=len(segments),
                bytes_sent=len(payload),
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "drip_chunk_size": chunk_size,
                    "drip_delay_ms": delay_ms,
                    "packet_count": len(segments),
                    "randomized_timing": self.config.drip_randomize,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Drip feed attack failed: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class TimingBasedEvasionAttack(TimingAttack):
    """
    Timing-Based Evasion Attack - introduces delays between segments.

    Migrated from:
    - apply_timing_based_evasion (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "timing_based_evasion"

    @property
    def description(self) -> str:
        return "Introduces timing delays between segments to evade DPI"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute timing-based evasion attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_pos = context.params.get("split_pos", 4)
            delay_ms = context.params.get("delay_ms", 10)
            if not 0 < split_pos < len(payload):
                segments = [(payload, 0, {"delay_ms": 0})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                segments = [
                    (part1, 0, {"delay_ms": 0}),
                    (part2, split_pos, {"delay_ms": delay_ms}),
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
                    "delay_ms": delay_ms,
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
class BurstTimingEvasionAttack(TimingAttack):
    """
    Burst Timing Evasion Attack - sends payload in bursts with delays.

    Migrated from:
    - apply_burst_timing_evasion (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "burst_timing_evasion"

    @property
    def description(self) -> str:
        return "Sends payload in bursts with timing delays between bursts"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute burst timing evasion attack."""
        start_time = time.time()
        try:
            payload = context.payload
            burst_size = context.params.get("burst_size", 3)
            burst_delay_ms = context.params.get("burst_delay_ms", 5)
            segments = []
            offset = 0
            burst_count = 0
            while offset < len(payload):
                current_size = min(burst_size, len(payload) - offset)
                segment_data = payload[offset : offset + current_size]
                delay = burst_delay_ms if burst_count > 0 else 0
                segments.append((segment_data, offset, {"delay_ms": delay}))
                offset += current_size
                burst_count += 1
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
                    "burst_size": burst_size,
                    "burst_delay_ms": burst_delay_ms,
                    "bursts_count": burst_count,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
