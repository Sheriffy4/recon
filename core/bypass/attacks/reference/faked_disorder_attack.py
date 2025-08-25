"""
FakedDisorderAttack implementation using segments architecture.

This attack creates a fake packet with low TTL followed by the real payload
split into two parts sent in reverse order. This confuses DPI systems that
expect packets in sequential order.

Attack Strategy:
1. Send fake packet with low TTL (will be dropped by intermediate routers)
2. Send second part of real payload
3. Send first part of real payload

The DPI system sees: [fake_packet] -> [part2] -> [part1]
The destination sees: [part1] -> [part2] (fake packet is dropped)
"""
import asyncio
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from recon.core.bypass.attacks.base import BaseAttack, AttackResult, AttackStatus, AttackContext

@dataclass
class FakedDisorderConfig:
    """Configuration for FakedDisorderAttack."""
    split_pos: float = 0.5
    fake_ttl: int = 1
    fake_delay_ms: float = 20.0
    part2_delay_ms: float = 8.0
    part1_delay_ms: float = 5.0
    use_different_fake_payload: bool = True
    custom_fake_payload: Optional[bytes] = None
    corrupt_fake_checksum: bool = False
    fake_tcp_flags: Optional[int] = None
    randomize_fake_content: bool = True

class FakedDisorderAttack(BaseAttack):
    """
    FakedDisorderAttack using segments architecture.

    This attack implements the "fake packet + disorder" technique commonly
    used to bypass DPI systems that rely on packet order analysis.
    """

    def __init__(self, name: str='faked_disorder', config: Optional[FakedDisorderConfig]=None):
        super().__init__(name)
        self.config = config or FakedDisorderConfig()
        self.logger = logging.getLogger(f'FakedDisorderAttack.{name}')
        self._validate_config()

    def _validate_config(self):
        """Validate attack configuration."""
        if not 0.0 < self.config.split_pos < 1.0:
            raise ValueError(f'split_pos must be between 0.0 and 1.0, got {self.config.split_pos}')
        if self.config.fake_ttl < 1 or self.config.fake_ttl > 255:
            raise ValueError(f'fake_ttl must be between 1 and 255, got {self.config.fake_ttl}')
        if self.config.fake_delay_ms < 0:
            raise ValueError(f'fake_delay_ms must be non-negative, got {self.config.fake_delay_ms}')
        if self.config.part2_delay_ms < 0:
            raise ValueError(f'part2_delay_ms must be non-negative, got {self.config.part2_delay_ms}')
        if self.config.part1_delay_ms < 0:
            raise ValueError(f'part1_delay_ms must be non-negative, got {self.config.part1_delay_ms}')

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute FakedDisorderAttack.

        Args:
            context: Attack context containing payload and connection info

        Returns:
            AttackResult with segments for fake packet + disordered real payload
        """
        try:
            self.logger.info(f'Executing FakedDisorderAttack on {context.connection_id}')
            if not context.payload:
                return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': 'Empty payload provided'})
            payload_len = len(context.payload)
            split_byte_pos = int(payload_len * self.config.split_pos)
            split_byte_pos = max(1, min(split_byte_pos, payload_len - 1))
            part1 = context.payload[:split_byte_pos]
            part2 = context.payload[split_byte_pos:]
            self.logger.debug(f'Split payload: part1={len(part1)} bytes, part2={len(part2)} bytes at pos {split_byte_pos}')
            fake_payload = self._generate_fake_payload(context.payload, part1, part2)
            segments = await self._create_segments(fake_payload, part1, part2, split_byte_pos)
            result = AttackResult(status=AttackStatus.SUCCESS, modified_payload=None, metadata={'attack_type': 'faked_disorder', 'segments': segments, 'split_position': split_byte_pos, 'split_ratio': self.config.split_pos, 'fake_payload_size': len(fake_payload), 'part1_size': len(part1), 'part2_size': len(part2), 'total_segments': len(segments), 'config': {'fake_ttl': self.config.fake_ttl, 'fake_delay_ms': self.config.fake_delay_ms, 'part2_delay_ms': self.config.part2_delay_ms, 'part1_delay_ms': self.config.part1_delay_ms, 'use_different_fake_payload': self.config.use_different_fake_payload, 'corrupt_fake_checksum': self.config.corrupt_fake_checksum, 'randomize_fake_content': self.config.randomize_fake_content}})
            result._segments = segments
            self.logger.info(f'FakedDisorderAttack created {len(segments)} segments: fake({len(fake_payload)}b) -> part2({len(part2)}b) -> part1({len(part1)}b)')
            return result
        except Exception as e:
            self.logger.error(f'FakedDisorderAttack failed: {e}')
            return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': str(e), 'attack_type': 'faked_disorder'})

    def _generate_fake_payload(self, original_payload: bytes, part1: bytes, part2: bytes) -> bytes:
        """
        Generate fake payload for the fake packet.

        Args:
            original_payload: Original payload
            part1: First part of split payload
            part2: Second part of split payload

        Returns:
            Fake payload bytes
        """
        if self.config.custom_fake_payload:
            return self.config.custom_fake_payload
        if not self.config.use_different_fake_payload:
            return original_payload
        fake_payload = self._create_deceptive_fake_payload(original_payload)
        if self.config.randomize_fake_content:
            fake_payload = self._randomize_payload_content(fake_payload)
        return fake_payload

    def _create_deceptive_fake_payload(self, original_payload: bytes) -> bytes:
        """
        Create deceptive fake payload that looks legitimate but is different.

        Args:
            original_payload: Original payload to base fake on

        Returns:
            Deceptive fake payload
        """
        try:
            payload_str = original_payload.decode('utf-8', errors='ignore')
            if payload_str.startswith('GET '):
                lines = payload_str.split('\r\n')
                if lines:
                    fake_lines = [lines[0].replace(lines[0].split()[1], '/favicon.ico')]
                    fake_lines.extend(lines[1:])
                    return '\r\n'.join(fake_lines).encode('utf-8')
            elif payload_str.startswith('POST '):
                lines = payload_str.split('\r\n')
                if lines:
                    fake_lines = ['GET /robots.txt HTTP/1.1']
                    for line in lines[1:]:
                        if not line.lower().startswith('content-length:') and line.strip():
                            fake_lines.append(line)
                        elif not line.strip():
                            break
                    return '\r\n'.join(fake_lines).encode('utf-8') + b'\r\n\r\n'
            elif b'\\x16\\x03' in original_payload[:10]:
                fake_payload = bytearray(original_payload)
                if len(fake_payload) > 50:
                    fake_payload[30:35] = b'fake\\x00'
                return bytes(fake_payload)
            elif b'Host:' in original_payload:
                fake_str = payload_str.replace('Host:', 'Host: example.com\\r\\nX-Fake:')
                return fake_str.encode('utf-8')
            else:
                return self._create_generic_fake_payload(original_payload)
        except Exception:
            return self._create_generic_fake_payload(original_payload)

    def _create_generic_fake_payload(self, original_payload: bytes) -> bytes:
        """
        Create generic fake payload when specific detection fails.

        Args:
            original_payload: Original payload

        Returns:
            Generic fake payload
        """
        fake_size = min(len(original_payload), 200)
        fake_payload = b'GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: Mozilla/5.0\\r\\nAccept: text/html\\r\\nConnection: close\\r\\n\\r\\n'
        if len(fake_payload) < fake_size:
            padding = b'X' * (fake_size - len(fake_payload))
            fake_payload += padding
        else:
            fake_payload = fake_payload[:fake_size]
        return fake_payload

    def _randomize_payload_content(self, payload: bytes) -> bytes:
        """
        Randomize some content in the payload while keeping it valid-looking.

        Args:
            payload: Payload to randomize

        Returns:
            Randomized payload
        """
        import random
        payload_array = bytearray(payload)
        start_pos = len(payload_array) // 4
        end_pos = 3 * len(payload_array) // 4
        for _ in range(min(5, (end_pos - start_pos) // 10)):
            if start_pos < end_pos:
                pos = random.randint(start_pos, end_pos - 1)
                payload_array[pos] = random.randint(65, 90)
        return bytes(payload_array)

    async def _create_segments(self, fake_payload: bytes, part1: bytes, part2: bytes, split_pos: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create segments for the faked disorder attack.

        Args:
            fake_payload: Fake payload for first packet
            part1: First part of real payload
            part2: Second part of real payload
            split_pos: Split position in original payload

        Returns:
            List of segment tuples (payload, seq_offset, options)
        """
        segments = []
        fake_options = {'ttl': self.config.fake_ttl, 'delay_ms': self.config.fake_delay_ms, 'flags': self.config.fake_tcp_flags if self.config.fake_tcp_flags else 24}
        if self.config.corrupt_fake_checksum:
            fake_options['bad_checksum'] = True
        await asyncio.sleep(self.config.fake_delay_ms / 1000.0)
        segments.append((fake_payload, 0, fake_options))
        part2_options = {'ttl': 64, 'delay_ms': self.config.part2_delay_ms, 'flags': 24}
        await asyncio.sleep(self.config.part2_delay_ms / 1000.0)
        segments.append((part2, split_pos, part2_options))
        part1_options = {'ttl': 64, 'delay_ms': self.config.part1_delay_ms, 'flags': 24}
        await asyncio.sleep(self.config.part1_delay_ms / 1000.0)
        segments.append((part1, 0, part1_options))
        return segments

    def get_attack_info(self) -> Dict[str, Any]:
        """
        Get information about this attack.

        Returns:
            Dictionary with attack information
        """
        return {'name': self.name, 'type': 'faked_disorder', 'description': 'Sends fake packet with low TTL followed by real payload in reverse order', 'technique': 'packet_disorder', 'effectiveness': 'high_against_order_dependent_dpi', 'config': {'split_pos': self.config.split_pos, 'fake_ttl': self.config.fake_ttl, 'fake_delay_ms': self.config.fake_delay_ms, 'part2_delay_ms': self.config.part2_delay_ms, 'part1_delay_ms': self.config.part1_delay_ms, 'use_different_fake_payload': self.config.use_different_fake_payload, 'corrupt_fake_checksum': self.config.corrupt_fake_checksum, 'randomize_fake_content': self.config.randomize_fake_content}, 'segments_created': 3, 'execution_order': ['fake_packet', 'part2', 'part1'], 'destination_sees': ['part1', 'part2'], 'dpi_sees': ['fake_packet', 'part2', 'part1']}

    def estimate_effectiveness(self, context: AttackContext) -> float:
        """
        Estimate attack effectiveness for given context.

        Args:
            context: Attack context

        Returns:
            Effectiveness score (0.0 to 1.0)
        """
        effectiveness = 0.7
        if context.payload and b'HTTP/' in context.payload:
            effectiveness += 0.1
        if context.payload and len(context.payload) > 100:
            effectiveness += 0.1
        if self.config.split_pos < 0.2 or self.config.split_pos > 0.8:
            effectiveness -= 0.1
        if self.config.use_different_fake_payload:
            effectiveness += 0.05
        if self.config.corrupt_fake_checksum:
            effectiveness += 0.05
        return min(1.0, max(0.0, effectiveness))

    def get_required_capabilities(self) -> List[str]:
        """
        Get list of required capabilities for this attack.

        Returns:
            List of required capability names
        """
        return ['packet_construction', 'ttl_modification', 'timing_control', 'sequence_manipulation', 'checksum_corruption' if self.config.corrupt_fake_checksum else None, 'tcp_flags_modification' if self.config.fake_tcp_flags else None]

    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """
        Validate if attack can be executed with given context.

        Args:
            context: Attack context to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not context.payload:
            return (False, 'Empty payload provided')
        if len(context.payload) < 10:
            return (False, f'Payload too short for splitting: {len(context.payload)} bytes')
        split_byte_pos = int(len(context.payload) * self.config.split_pos)
        if split_byte_pos <= 0 or split_byte_pos >= len(context.payload):
            return (False, f'Invalid split position: {split_byte_pos} for payload length {len(context.payload)}')
        if hasattr(context, 'tcp_seq') and context.tcp_seq is not None:
            if context.tcp_seq < 0:
                return (False, f'Invalid TCP sequence number: {context.tcp_seq}')
        return (True, None)

def create_faked_disorder_attack(name: str='faked_disorder', split_pos: float=0.5, fake_ttl: int=1, fake_delay_ms: float=20.0, part2_delay_ms: float=8.0, part1_delay_ms: float=5.0, use_different_fake_payload: bool=True, corrupt_fake_checksum: bool=False, randomize_fake_content: bool=True) -> FakedDisorderAttack:
    """
    Factory function to create FakedDisorderAttack with custom configuration.

    Args:
        name: Attack name
        split_pos: Position to split payload (0.0 to 1.0)
        fake_ttl: TTL for fake packet
        fake_delay_ms: Delay after fake packet
        part2_delay_ms: Delay after second part
        part1_delay_ms: Delay after first part
        use_different_fake_payload: Whether to generate different fake payload
        corrupt_fake_checksum: Whether to corrupt fake packet checksum
        randomize_fake_content: Whether to randomize fake content

    Returns:
        Configured FakedDisorderAttack instance
    """
    config = FakedDisorderConfig(split_pos=split_pos, fake_ttl=fake_ttl, fake_delay_ms=fake_delay_ms, part2_delay_ms=part2_delay_ms, part1_delay_ms=part1_delay_ms, use_different_fake_payload=use_different_fake_payload, corrupt_fake_checksum=corrupt_fake_checksum, randomize_fake_content=randomize_fake_content)
    return FakedDisorderAttack(name=name, config=config)

def create_aggressive_faked_disorder() -> FakedDisorderAttack:
    """Create aggressive variant with maximum confusion."""
    return create_faked_disorder_attack(name='aggressive_faked_disorder', split_pos=0.3, fake_ttl=1, fake_delay_ms=30.0, part2_delay_ms=12.0, part1_delay_ms=8.0, use_different_fake_payload=True, corrupt_fake_checksum=True, randomize_fake_content=True)

def create_subtle_faked_disorder() -> FakedDisorderAttack:
    """Create subtle variant with minimal delays."""
    return create_faked_disorder_attack(name='subtle_faked_disorder', split_pos=0.6, fake_ttl=2, fake_delay_ms=10.0, part2_delay_ms=3.0, part1_delay_ms=2.0, use_different_fake_payload=True, corrupt_fake_checksum=False, randomize_fake_content=False)

def create_http_optimized_faked_disorder() -> FakedDisorderAttack:
    """Create variant optimized for HTTP traffic."""
    return create_faked_disorder_attack(name='http_faked_disorder', split_pos=0.4, fake_ttl=1, fake_delay_ms=25.0, part2_delay_ms=10.0, part1_delay_ms=6.0, use_different_fake_payload=True, corrupt_fake_checksum=False, randomize_fake_content=True)