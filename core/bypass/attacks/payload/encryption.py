"""
Payload Encryption Attacks

Migrated from:
- apply_payload_encryption (core/fast_bypass.py)
"""

import asyncio
import time
from core.bypass.attacks.base import (
    PayloadAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack


@register_attack
class PayloadEncryptionAttack(PayloadAttack):
    """
    Payload Encryption Attack - encrypts payload using XOR.

    Migrated from:
    - apply_payload_encryption (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "payload_encryption"

    @property
    def description(self) -> str:
        return "Encrypts payload using XOR encryption to evade DPI"

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload encryption attack."""
        start_time = time.time()
        try:
            payload = context.payload
            key = context.params.get("key", b"\xaa\xbb\xcc\xdd")
            split_pos = context.params.get("split_pos", 8)
            if not 0 < split_pos < len(payload):
                encrypted = self.xor_encrypt(payload, key)
                segments = [(encrypted, 0, {"encrypted": True, "key": key})]
            else:
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]
                key1 = key
                key2 = bytes([(b + 1) % 256 for b in key])
                encrypted1 = self.xor_encrypt(part1, key1)
                encrypted2 = self.xor_encrypt(part2, key2)
                segments = [
                    (encrypted1, 0, {"encrypted": True, "key": key1}),
                    (encrypted2, split_pos, {"encrypted": True, "key": key2}),
                ]
            packets_sent = len(segments)
            bytes_sent = len(payload)
            await asyncio.sleep(0)
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
                    "key_length": len(key),
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
class PayloadBase64Attack(PayloadAttack):
    """
    Payload Base64 Attack - encodes payload using Base64.
    """

    @property
    def name(self) -> str:
        return "payload_base64"

    @property
    def description(self) -> str:
        return "Encodes payload using Base64 encoding"

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload Base64 attack."""
        start_time = time.time()
        try:
            import base64

            payload = context.payload
            encoded_payload = base64.b64encode(payload)
            segments = [(encoded_payload, 0, {"encoded": "base64"})]
            packets_sent = 1
            bytes_sent = len(encoded_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "original_size": len(payload),
                    "encoded_size": len(encoded_payload),
                    "encoding": "base64",
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
class PayloadROT13Attack(PayloadAttack):
    """
    Payload ROT13 Attack - applies ROT13 transformation.
    """

    @property
    def name(self) -> str:
        return "payload_rot13"

    @property
    def description(self) -> str:
        return "Applies ROT13 transformation to payload"

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload ROT13 attack."""
        start_time = time.time()
        try:
            payload = context.payload
            rot13_payload = bytearray()
            for byte in payload:
                if 65 <= byte <= 90:
                    rot13_payload.append((byte - 65 + 13) % 26 + 65)
                elif 97 <= byte <= 122:
                    rot13_payload.append((byte - 97 + 13) % 26 + 97)
                else:
                    rot13_payload.append(byte)
            segments = [(bytes(rot13_payload), 0, {"transformed": "rot13"})]
            packets_sent = 1
            bytes_sent = len(rot13_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "transformation": "rot13",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
