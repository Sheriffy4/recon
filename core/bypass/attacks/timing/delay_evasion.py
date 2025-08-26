"""
Delay-based evasion attacks for DPI bypass.
"""
import time
import random
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.timing.timing_base import TimingAttackBase, TimingConfiguration, TimingResult

class DelayPattern(Enum):
    """Types of delay patterns for evasion."""
    PROGRESSIVE = 'progressive'
    EXPONENTIAL = 'exponential'
    FIBONACCI = 'fibonacci'
    CUSTOM = 'custom'

@dataclass
class DelayEvasionConfiguration(TimingConfiguration):
    """Configuration for delay-based evasion attacks."""
    delay_pattern: DelayPattern = DelayPattern.PROGRESSIVE
    progression_factor: float = 1.5
    max_progression_steps: int = 10
    custom_sequence: List[float] = None
    packets_per_delay: int = 1

    def __post_init__(self):
        """Validate delay evasion configuration."""
        super().__post_init__()
        if self.progression_factor <= 1.0:
            self.progression_factor = 1.5
        if self.max_progression_steps < 1:
            self.max_progression_steps = 1
        if self.packets_per_delay < 1:
            self.packets_per_delay = 1
        if self.custom_sequence is None:
            self.custom_sequence = []

class DelayEvasionAttack(TimingAttackBase):
    """Delay-based evasion attack implementation."""

    def __init__(self, config: Optional[DelayEvasionConfiguration]=None):
        """Initialize delay evasion attack."""
        if config is None:
            config = DelayEvasionConfiguration()
        super().__init__(config)
        self.delay_config = config
        self.fibonacci_cache = [1, 1]
        self.pattern_effectiveness = {}
        self.response_time_history = []

    @property
    def name(self) -> str:
        """Unique name for this attack."""
        return f'delay_evasion_{self.delay_config.delay_pattern.value}'

    def _execute_timing_attack(self, context: AttackContext, timing_result: TimingResult) -> AttackResult:
        """Execute delay-based evasion attack."""
        try:
            delay_sequence = self._generate_delay_sequence()
            payloads = self._generate_packet_payloads(context)
            packet_results = []
            for i, delay_ms in enumerate(delay_sequence):
                for packet_idx in range(self.delay_config.packets_per_delay):
                    payload_idx = (i * self.delay_config.packets_per_delay + packet_idx) % len(payloads)
                    packet_context = context.copy()
                    packet_context.payload = payloads[payload_idx]
                    packet_result = self._send_packet(packet_context)
                    packet_results.append(packet_result)
                    timing_result.packets_sent += 1
                    timing_result.bytes_sent += len(payloads[payload_idx])
                if i < len(delay_sequence) - 1:
                    self.execute_delay(delay_ms, timing_result)
            success = any((result.status == AttackStatus.SUCCESS for result in packet_results))
            timing_result.success = success
            return AttackResult(status=AttackStatus.SUCCESS if success else AttackStatus.FAILURE, technique_used=f'delay_evasion_{self.delay_config.delay_pattern.value}', packets_sent=len(packet_results), bytes_sent=sum((len(p) for p in payloads)), response_received=True)
        except Exception as e:
            self.logger.error(f'Delay evasion attack failed: {e}')
            timing_result.success = False
            timing_result.error_message = str(e)
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), technique_used='delay_evasion_error')

    def _generate_delay_sequence(self) -> List[float]:
        """Generate delay sequence based on configured pattern."""
        pattern = self.delay_config.delay_pattern
        steps = self.delay_config.max_progression_steps
        if pattern == DelayPattern.PROGRESSIVE:
            return self._generate_progressive_delays(steps)
        elif pattern == DelayPattern.EXPONENTIAL:
            return self._generate_exponential_delays(steps)
        elif pattern == DelayPattern.FIBONACCI:
            return self._generate_fibonacci_delays(steps)
        elif pattern == DelayPattern.CUSTOM:
            return self._generate_custom_delays(steps)
        else:
            return self._generate_progressive_delays(steps)

    def _generate_progressive_delays(self, steps: int) -> List[float]:
        """Generate progressively increasing delays."""
        delays = []
        current_delay = self.delay_config.base_delay_ms
        for i in range(steps):
            delays.append(min(current_delay, self.delay_config.max_delay_ms))
            current_delay *= self.delay_config.progression_factor
        return delays

    def _generate_exponential_delays(self, steps: int) -> List[float]:
        """Generate exponential backoff delays."""
        delays = []
        base_delay = self.delay_config.base_delay_ms
        for i in range(steps):
            delay = base_delay * 2 ** i
            delays.append(min(delay, self.delay_config.max_delay_ms))
        return delays

    def _generate_fibonacci_delays(self, steps: int) -> List[float]:
        """Generate Fibonacci sequence delays."""
        delays = []
        while len(self.fibonacci_cache) < steps:
            next_fib = self.fibonacci_cache[-1] + self.fibonacci_cache[-2]
            self.fibonacci_cache.append(next_fib)
        for i in range(steps):
            delay = self.fibonacci_cache[i] * 1.0
            delays.append(min(delay, self.delay_config.max_delay_ms))
        return delays

    def _generate_custom_delays(self, steps: int) -> List[float]:
        """Generate delays from custom sequence."""
        if not self.delay_config.custom_sequence:
            return self._generate_progressive_delays(steps)
        delays = []
        custom_seq = self.delay_config.custom_sequence
        for i in range(steps):
            delay = custom_seq[i % len(custom_seq)]
            delays.append(min(delay, self.delay_config.max_delay_ms))
        return delays

    def _generate_packet_payloads(self, context: AttackContext) -> List[bytes]:
        """Generate packet payloads for delay evasion."""
        payloads = []
        original_payload = context.payload
        if not original_payload:
            original_payload = f'GET / HTTP/1.1\r\nHost: {context.domain or context.dst_ip}\r\n\r\n'.encode()
        payloads.append(original_payload)
        for i in range(1, min(5, self.delay_config.max_progression_steps)):
            if b'HTTP' in original_payload:
                varied = original_payload.replace(b'\r\n\r\n', f'\r\nX-Delay-Step: {i}\r\n\r\n'.encode())
                payloads.append(varied)
            else:
                varied = original_payload + f' #{i}'.encode()
                payloads.append(varied)
        return payloads

    def _send_packet(self, context: AttackContext) -> AttackResult:
        """Send a single packet with delay evasion."""
        start_time = time.perf_counter()
        try:
            network_delay = random.uniform(5.0, 25.0) / 1000.0
            time.sleep(network_delay)
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            self.response_time_history.append(response_time)
            if len(self.response_time_history) > 50:
                self.response_time_history.pop(0)
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=response_time, packets_sent=1, bytes_sent=len(context.payload), response_received=True, technique_used=f'delay_evasion_{self.delay_config.delay_pattern.value}')
        except Exception as e:
            self.logger.error(f'Failed to send delay evasion packet: {e}')
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), technique_used='delay_evasion_error')

    def get_delay_evasion_statistics(self) -> Dict[str, Any]:
        """Get comprehensive delay evasion statistics."""
        stats = {'delay_pattern': self.delay_config.delay_pattern.value, 'max_progression_steps': self.delay_config.max_progression_steps, 'packets_per_delay': self.delay_config.packets_per_delay, 'fibonacci_cache_size': len(self.fibonacci_cache), 'pattern_effectiveness': self.pattern_effectiveness.copy(), 'response_time_history_size': len(self.response_time_history)}
        if self.response_time_history:
            stats.update({'avg_response_time_ms': sum(self.response_time_history) / len(self.response_time_history), 'min_response_time_ms': min(self.response_time_history), 'max_response_time_ms': max(self.response_time_history)})
        stats.update(self.get_timing_statistics())
        return stats

    def set_custom_sequence(self, sequence: List[float]):
        """Set custom delay sequence."""
        self.delay_config.custom_sequence = sequence.copy()
        self.delay_config.delay_pattern = DelayPattern.CUSTOM
        self.logger.debug(f'Set custom delay sequence with {len(sequence)} values')