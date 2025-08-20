# recon/core/bypass/attacks/payload/noise.py
"""
Payload Noise Injection Attacks

Migrated from:
- apply_noise_injection (core/fast_bypass.py)
- apply_decoy_packets (core/fast_bypass.py)
"""

import time
import random
from ..base import PayloadAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


@register_attack
class NoiseInjectionAttack(PayloadAttack):
    """
    Noise Injection Attack - injects random noise into payload.

    Migrated from:
    - apply_noise_injection (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "noise_injection"

    @property
    def description(self) -> str:
        return "Injects random noise bytes into payload"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute noise injection attack."""
        start_time = time.time()

        try:
            payload = context.payload
            noise_ratio = context.params.get("noise_ratio", 0.1)
            split_pos = context.params.get("split_pos", 7)

            if not (0 < split_pos < len(payload)):
                # Inject noise into entire payload
                noisy_payload = self._inject_noise(payload, noise_ratio)
                segments = [(noisy_payload, 0, {"noise_injected": True})]
            else:
                # Split and inject noise into each part
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                noisy1 = self._inject_noise(part1, noise_ratio)
                noisy2 = self._inject_noise(part2, noise_ratio)

                segments = [
                    (noisy1, 0, {"noise_injected": True}),
                    (noisy2, split_pos, {"noise_injected": True}),
                ]

            packets_sent = len(segments)
            bytes_sent = sum(len(seg[0]) for seg in segments)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "noise_ratio": noise_ratio,
                    "original_size": len(payload),
                    "final_size": bytes_sent,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _inject_noise(self, data: bytes, noise_ratio: float) -> bytes:
        """Inject random noise bytes into data."""
        if noise_ratio <= 0:
            return data

        result = bytearray()
        for byte in data:
            result.append(byte)
            if random.random() < noise_ratio:
                result.append(random.randint(0, 255))

        return bytes(result)


@register_attack
class DecoyPacketsAttack(PayloadAttack):
    """
    Decoy Packets Attack - generates decoy packets to confuse DPI.

    Migrated from:
    - apply_decoy_packets (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "decoy_packets"

    @property
    def description(self) -> str:
        return "Generates decoy packets to confuse DPI systems"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute decoy packets attack."""
        start_time = time.time()

        try:
            payload = context.payload
            decoy_count = context.params.get("decoy_count", 2)
            split_pos = context.params.get("split_pos", 5)

            if not (0 < split_pos < len(payload)):
                # Generate decoys for entire payload
                segments = [(payload, 0, {"decoy": False})]

                # Add decoy packets
                for i in range(decoy_count):
                    decoy_data = self._generate_decoy_data(len(payload))
                    segments.append((decoy_data, -1, {"decoy": True, "decoy_id": i}))
            else:
                # Split payload and add decoys
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                segments = [(part1, 0, {"decoy": False})]

                # Add decoys between real segments
                for i in range(decoy_count):
                    decoy_data = self._generate_decoy_data(len(part1))
                    segments.append((decoy_data, -1, {"decoy": True, "decoy_id": i}))

                segments.append((part2, split_pos, {"decoy": False}))

            packets_sent = len(segments)
            bytes_sent = sum(len(seg[0]) for seg in segments)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "decoy_count": decoy_count,
                    "real_packets": len(
                        [s for s in segments if not s[2].get("decoy", False)]
                    ),
                    "decoy_packets": len(
                        [s for s in segments if s[2].get("decoy", False)]
                    ),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _generate_decoy_data(self, size: int) -> bytes:
        """Generate random decoy data."""
        return bytes([random.randint(0, 255) for _ in range(size)])


@register_attack
class PayloadPaddingAttack(PayloadAttack):
    """
    Payload Padding Attack - adds padding to payload.
    """

    @property
    def name(self) -> str:
        return "payload_padding"

    @property
    def description(self) -> str:
        return "Adds padding to payload to change its size"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute payload padding attack."""
        start_time = time.time()

        try:
            payload = context.payload
            padding_size = context.params.get("padding_size", 16)
            padding_type = context.params.get("padding_type", "zero")

            # Generate padding based on type
            if padding_type == "zero":
                padding = b"\x00" * padding_size
            elif padding_type == "random":
                padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
            elif padding_type == "pattern":
                pattern = context.params.get("pattern", b"\xaa\xbb")
                padding = (pattern * (padding_size // len(pattern) + 1))[:padding_size]
            else:
                padding = b"\x00" * padding_size

            # Add padding to payload
            padded_payload = payload + padding

            segments = [
                (padded_payload, 0, {"padded": True, "padding_size": padding_size})
            ]

            packets_sent = 1
            bytes_sent = len(padded_payload)

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
                    "padding_type": padding_type,
                    "original_size": len(payload),
                    "padded_size": len(padded_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
