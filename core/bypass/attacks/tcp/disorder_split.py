"""
Disorder Split Attack - combines disorder and split functionality.

This attack splits the payload and sends segments in reverse order (disorder).
"""

import time
from core.bypass.attacks.base import (
    ManipulationAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack


@register_attack
class DisorderSplitAttack(ManipulationAttack):
    """
    Disorder Split Attack - splits payload and sends segments in reverse order.

    This combines:
    - Split: Divides payload into segments
    - Disorder: Sends segments in reverse order

    The attack confuses DPI by sending the second part first, then the first part.
    TCP stack will reorder correctly, but DPI may fail to reassemble.
    """

    @property
    def name(self) -> str:
        return "disorder_split"

    @property
    def description(self) -> str:
        return "Splits payload and sends segments in reverse order to confuse DPI"

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "split_pos": "Position to split payload (default: middle)",
            "split_count": "Number of splits (default: 2)",
            "disorder_delay_ms": "Delay between disordered packets (default: 1.0)",
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute disorder split attack."""
        start_time = time.time()
        try:
            payload = context.payload
            params = context.params

            # Get split parameters
            split_pos = params.get("split_pos")
            split_count = params.get("split_count", 2)

            if split_pos is not None:
                # Single split at specific position
                if not 0 < split_pos < len(payload):
                    return AttackResult(
                        status=AttackStatus.INVALID_PARAMS,
                        error_message=f"split_pos {split_pos} out of range for payload length {len(payload)}",
                    )

                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                # Send in reverse order (disorder)
                segments = [
                    (part2, split_pos, {}),  # Second part first
                    (part1, 0, {}),  # First part second
                ]
            else:
                # Multiple splits with disorder
                if len(payload) < split_count:
                    return AttackResult(
                        status=AttackStatus.INVALID_PARAMS,
                        error_message=f"Payload too small ({len(payload)} bytes) for {split_count} splits",
                    )

                # Calculate segment sizes
                segment_size = len(payload) // split_count
                remainder = len(payload) % split_count

                # Create segments
                segments = []
                current_pos = 0
                for i in range(split_count):
                    size = segment_size + (1 if i < remainder else 0)
                    end_pos = current_pos + size
                    segment_data = payload[current_pos:end_pos]
                    segments.append((segment_data, current_pos, {}))
                    current_pos = end_pos

                # Reverse order for disorder
                segments.reverse()

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
                    "split_count": split_count,
                    "segment_count": len(segments),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            self.logger.error(f"DisorderSplitAttack failed: {e}", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
