"""
Simple attack executor for testing purposes.
Converts strategies to AttackResult objects.
"""
import logging
from core.bypass.attacks.base import AttackContext, AttackResult, AttackResultHelper
LOG = logging.getLogger('SimpleAttackExecutor')

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
        self.logger.debug(f'Executing attack type: {attack_type}')
        try:
            if attack_type == 'fake_split':
                return self._execute_fake_split(context)
            elif attack_type == 'disorder':
                return self._execute_disorder(context)
            elif attack_type == 'fake':
                return self._execute_fake(context)
            else:
                return AttackResultHelper.create_success_result(technique_used=attack_type, metadata={'segments': [context.payload]}, packets_sent=1)
        except Exception as e:
            self.logger.error(f'Attack execution error: {e}')
            return AttackResultHelper.create_failure_result(error_message=str(e), technique_used=attack_type)

    def _execute_fake_split(self, context: AttackContext) -> AttackResult:
        """Execute fake + split attack."""
        payload = context.payload
        fake_payload = b'GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n'
        split_pos = min(3, len(payload))
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        return AttackResultHelper.create_success_result(technique_used='fake_split', metadata={'segments': [fake_payload, part1, part2]}, packets_sent=3)

    def _execute_disorder(self, context: AttackContext) -> AttackResult:
        """Execute disorder attack."""
        payload = context.payload
        part1 = payload[:1]
        part2 = payload[1:]
        return AttackResultHelper.create_success_result(technique_used='disorder', metadata={'segments': [part2, part1]}, packets_sent=2)

    def _execute_fake(self, context: AttackContext) -> AttackResult:
        """Execute fake packet attack."""
        fake_payload = b'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
        return AttackResultHelper.create_success_result(technique_used='fake', metadata={'segments': [fake_payload, context.payload]}, packets_sent=2)