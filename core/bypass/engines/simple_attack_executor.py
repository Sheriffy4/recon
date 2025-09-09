"""
Simple attack executor for testing purposes.
Converts strategies to AttackResult objects.
"""

import logging
from core.bypass.attacks.base import AttackContext, AttackResult, AttackResultHelper

LOG = logging.getLogger("SimpleAttackExecutor")


class SimpleAttackExecutor:
    """
    Simple executor that converts strategy dictionaries to AttackResult objects.
    Used for testing effectiveness without full attack infrastructure.
    """

    def __init__(self):
        self.logger = LOG

    def execute_attack(self, attack_type: str, context: AttackContext) -> AttackResult:
        """
        Execute a simple attack based on type.

        This is a simplified version that creates fake attack results
        for testing purposes.
        """
        self.logger.debug(f"Executing attack type: {attack_type}")
        try:
            if attack_type == "fake_split":
                return self._execute_fake_split(context)
            elif attack_type == "disorder":
                return self._execute_disorder(context)
            elif attack_type == "fake":
                return self._execute_fake(context)
            else:
                return AttackResultHelper.create_success_result(
                    technique_used=attack_type,
                    metadata={"segments": [context.payload]},
                    packets_sent=1,
                )
        except Exception as e:
            self.logger.error(f"Attack execution error: {e}")
            return AttackResultHelper.create_failure_result(
                error_message=str(e), technique_used=attack_type
            )

    def _execute_fake_split(self, context: AttackContext) -> AttackResult:
        """Execute fake + split attack with all strategy params."""
        payload = context.payload
        params = getattr(context, 'params', {}) or {}
        # Use actual split_pos from params, default to 3
        split_pos = int(params.get('split_pos', 3))
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        # Build fake packet
        fake_payload = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
        # Apply fooling methods
        fooling = params.get('fooling', [])
        segments = [fake_payload, part1, part2]
        meta = {"segments": segments, "fooling": fooling}
        # Set TTL if specified
        ttl = params.get('ttl')
        if ttl is not None:
            meta['ttl'] = ttl
        return AttackResultHelper.create_success_result(
            technique_used="fake_split",
            metadata=meta,
            packets_sent=len(segments),
        )

    def _execute_disorder(self, context: AttackContext) -> AttackResult:
        """Execute disorder attack with all strategy params."""
        payload = context.payload
        params = getattr(context, 'params', {}) or {}
        split_pos = int(params.get('split_pos', 1))
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        fooling = params.get('fooling', [])
        segments = [part2, part1]
        meta = {"segments": segments, "fooling": fooling}
        ttl = params.get('ttl')
        if ttl is not None:
            meta['ttl'] = ttl
        return AttackResultHelper.create_success_result(
            technique_used="disorder",
            metadata=meta,
            packets_sent=len(segments),
        )

    def _execute_fake(self, context: AttackContext) -> AttackResult:
        """Execute fake packet attack with all strategy params."""
        params = getattr(context, 'params', {}) or {}
        fake_payload = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
        fooling = params.get('fooling', [])
        meta = {"segments": [fake_payload, context.payload], "fooling": fooling}
        ttl = params.get('ttl')
        if ttl is not None:
            meta['ttl'] = ttl
        return AttackResultHelper.create_success_result(
            technique_used="fake",
            metadata=meta,
            packets_sent=2,
        )
