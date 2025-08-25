"""
IP Fragmentation Attacks

Migrated and unified from:
- apply_ip_fragmentation_advanced (core/fast_bypass.py)
- apply_ip_fragmentation_disorder (core/fast_bypass.py)
- PacketBuilder.fragment_packet methods
"""
import asyncio
import time
import random
from typing import List
from recon.core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.registry import register_attack

@register_attack
class IPFragmentationAdvancedAttack(BaseAttack):
    """
    Advanced IP Fragmentation Attack with overlapping fragments.

    Migrated from:
    - apply_ip_fragmentation_advanced (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'ip_fragmentation_advanced'

    @property
    def category(self) -> str:
        return 'ip'

    @property
    def description(self) -> str:
        return 'Advanced IP fragmentation with overlapping fragments to confuse DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp', 'udp', 'icmp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced IP fragmentation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            frag_size = context.params.get('frag_size', 8)
            overlap_bytes = context.params.get('overlap_bytes', 4)
            if len(payload) <= frag_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                while offset < len(payload):
                    current_frag_size = min(frag_size, len(payload) - offset)
                    if offset > 0 and overlap_bytes > 0:
                        overlap_start = max(0, offset - overlap_bytes)
                        fragment_data = payload[overlap_start:offset + current_frag_size]
                        fragments.append((fragment_data, overlap_start))
                    else:
                        fragment_data = payload[offset:offset + current_frag_size]
                        fragments.append((fragment_data, offset))
                    offset += current_frag_size
            packets_sent = len(fragments)
            bytes_sent = sum((len(frag[0]) for frag in fragments))
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'frag_size': frag_size, 'overlap_bytes': overlap_bytes, 'fragments_count': len(fragments), 'fragments': fragments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class IPFragmentationDisorderAttack(BaseAttack):
    """
    IP Fragmentation Disorder Attack - sends fragments in reverse order.

    Migrated from:
    - apply_ip_fragmentation_disorder (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'ip_fragmentation_disorder'

    @property
    def category(self) -> str:
        return 'ip'

    @property
    def description(self) -> str:
        return 'Fragments payload and sends fragments in reverse order'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp', 'udp', 'icmp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute IP fragmentation disorder attack."""
        start_time = time.time()
        try:
            payload = context.payload
            frag_size = context.params.get('frag_size', 12)
            if len(payload) <= frag_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                while offset < len(payload):
                    current_frag_size = min(frag_size, len(payload) - offset)
                    fragment_data = payload[offset:offset + current_frag_size]
                    fragments.append((fragment_data, offset))
                    offset += current_frag_size
                fragments = fragments[::-1]
            packets_sent = len(fragments)
            bytes_sent = len(payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'frag_size': frag_size, 'fragments_count': len(fragments), 'reversed': True, 'fragments': fragments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class IPFragmentationRandomAttack(BaseAttack):
    """
    Random IP Fragmentation Attack - fragments with random sizes.
    """

    @property
    def name(self) -> str:
        return 'ip_fragmentation_random'

    @property
    def category(self) -> str:
        return 'ip'

    @property
    def description(self) -> str:
        return 'Fragments payload with random fragment sizes'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp', 'udp', 'icmp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute random IP fragmentation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            min_frag_size = context.params.get('min_frag_size', 4)
            max_frag_size = context.params.get('max_frag_size', 16)
            if len(payload) <= min_frag_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                while offset < len(payload):
                    remaining = len(payload) - offset
                    max_size = min(max_frag_size, remaining)
                    frag_size = random.randint(min_frag_size, max(min_frag_size, max_size))
                    fragment_data = payload[offset:offset + frag_size]
                    fragments.append((fragment_data, offset))
                    offset += frag_size
            packets_sent = len(fragments)
            bytes_sent = len(payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'min_frag_size': min_frag_size, 'max_frag_size': max_frag_size, 'fragments_count': len(fragments), 'fragments': fragments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)