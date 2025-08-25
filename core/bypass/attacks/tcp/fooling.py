"""
TCP Fooling Attacks

These attacks use various TCP header manipulation techniques to fool DPI systems
by corrupting or modifying specific fields that DPI systems rely on for analysis.

Migrated from:
- apply_badsum_fooling (core/fast_bypass.py)
- apply_md5sig_fooling (core/fast_bypass.py)
- apply_badseq_fooling (core/fast_bypass.py)
"""
import time
import random
from core.bypass.attacks.base import ManipulationAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import register_attack

@register_attack
class BadSumFoolingAttack(ManipulationAttack):
    """
    Bad Checksum Fooling Attack - corrupts TCP checksum to fool DPI.

    Migrated from:
    - apply_badsum_fooling (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'badsum_fooling'

    @property
    def description(self) -> str:
        return 'Corrupts TCP checksum to fool DPI systems'

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute bad checksum fooling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_pos = context.params.get('split_pos', 4)
            if not 0 < split_pos < len(payload):
                segments = [(payload, 0, {'bad_checksum': True})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                segments = [(part1, 0, {'bad_checksum': True}), (part2, split_pos, {'bad_checksum': False})]
            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'split_pos': split_pos, 'checksum_corruption': 'badsum', 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class MD5SigFoolingAttack(ManipulationAttack):
    """
    MD5 Signature Fooling Attack - adds fake MD5 signature to fool DPI.

    Migrated from:
    - apply_md5sig_fooling (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'md5sig_fooling'

    @property
    def description(self) -> str:
        return 'Adds fake MD5 signature to TCP options to fool DPI systems'

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute MD5 signature fooling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_pos = context.params.get('split_pos', 4)
            fake_md5_sig = bytes([random.randint(0, 255) for _ in range(16)])
            if not 0 < split_pos < len(payload):
                segments = [(payload, 0, {'md5_signature': fake_md5_sig})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                segments = [(part1, 0, {'md5_signature': fake_md5_sig}), (part2, split_pos, {'md5_signature': None})]
            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'split_pos': split_pos, 'md5_signature_length': len(fake_md5_sig), 'fooling_method': 'md5sig', 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class BadSeqFoolingAttack(ManipulationAttack):
    """
    Bad Sequence Fooling Attack - corrupts TCP sequence numbers to fool DPI.

    Migrated from:
    - apply_badseq_fooling (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'badseq_fooling'

    @property
    def description(self) -> str:
        return 'Corrupts TCP sequence numbers to fool DPI systems'

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute bad sequence fooling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_pos = context.params.get('split_pos', 4)
            if not 0 < split_pos < len(payload):
                segments = [(payload, 0, {'bad_sequence': True})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                segments = [(part1, 0, {'bad_sequence': True}), (part2, split_pos, {'bad_sequence': False})]
            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'split_pos': split_pos, 'sequence_corruption': 'badseq', 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class TTLManipulationAttack(ManipulationAttack):
    """
    TTL Manipulation Attack - manipulates IP TTL values to fool DPI.

    This attack uses low TTL values to make packets expire before reaching
    the target, potentially poisoning DPI caches.
    """

    @property
    def name(self) -> str:
        return 'ttl_manipulation'

    @property
    def description(self) -> str:
        return 'Manipulates IP TTL values to fool DPI systems'

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TTL manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            ttl_value = context.params.get('ttl', 2)
            split_pos = context.params.get('split_pos', 4)
            if not 0 < split_pos < len(payload):
                segments = [(payload, 0, {'ttl': ttl_value})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                segments = [(part1, 0, {'ttl': ttl_value}), (part2, split_pos, {'ttl': 64})]
            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'split_pos': split_pos, 'ttl_value': ttl_value, 'manipulation_type': 'ttl', 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)