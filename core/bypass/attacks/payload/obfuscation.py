"""
Payload Obfuscation Attacks

Migrated from:
- apply_payload_obfuscation (core/fast_bypass.py)
"""
import asyncio
import time
import random
from recon.core.bypass.attacks.base import PayloadAttack, AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.registry import register_attack

@register_attack
class PayloadObfuscationAttack(PayloadAttack):
    """
    Payload Obfuscation Attack - obfuscates payload using byte rotation.

    Migrated from:
    - apply_payload_obfuscation (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'payload_obfuscation'

    @property
    def description(self) -> str:
        return 'Obfuscates payload using byte rotation'

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_pos = context.params.get('split_pos', 6)
            shift = context.params.get('shift', 13)
            if not 0 < split_pos < len(payload):
                obfuscated = self.obfuscate_bytes(payload, shift)
                segments = [(obfuscated, 0, {'obfuscated': True, 'shift': shift})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                obfuscated1 = self.obfuscate_bytes(part1, shift)
                obfuscated2 = self.obfuscate_bytes(part2, shift)
                segments = [(obfuscated1, 0, {'obfuscated': True, 'shift': shift}), (obfuscated2, split_pos, {'obfuscated': True, 'shift': shift})]
            packets_sent = len(segments)
            bytes_sent = len(payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'split_pos': split_pos, 'shift': shift, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class PayloadByteSwapAttack(PayloadAttack):
    """
    Payload Byte Swap Attack - swaps adjacent bytes.
    """

    @property
    def name(self) -> str:
        return 'payload_byte_swap'

    @property
    def description(self) -> str:
        return 'Swaps adjacent bytes in payload to obfuscate content'

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload byte swap attack."""
        start_time = time.time()
        try:
            payload = context.payload
            swapped = bytearray()
            for i in range(0, len(payload), 2):
                if i + 1 < len(payload):
                    swapped.append(payload[i + 1])
                    swapped.append(payload[i])
                else:
                    swapped.append(payload[i])
            segments = [(bytes(swapped), 0, {'byte_swapped': True})]
            packets_sent = 1
            bytes_sent = len(swapped)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'original_size': len(payload), 'swapped_size': len(swapped), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class PayloadBitFlipAttack(PayloadAttack):
    """
    Payload Bit Flip Attack - flips random bits in payload.
    """

    @property
    def name(self) -> str:
        return 'payload_bit_flip'

    @property
    def description(self) -> str:
        return 'Flips random bits in payload to create variations'

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload bit flip attack."""
        start_time = time.time()
        try:
            payload = context.payload
            flip_probability = context.params.get('flip_probability', 0.01)
            flipped = bytearray(payload)
            bits_flipped = 0
            for i in range(len(flipped)):
                for bit in range(8):
                    if random.random() < flip_probability:
                        flipped[i] ^= 1 << bit
                        bits_flipped += 1
            segments = [(bytes(flipped), 0, {'bits_flipped': bits_flipped})]
            packets_sent = 1
            bytes_sent = len(flipped)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'flip_probability': flip_probability, 'bits_flipped': bits_flipped, 'total_bits': len(payload) * 8, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)