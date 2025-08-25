"""
PayloadObfuscationAttack implementation using segments architecture.

This attack obfuscates payload content using various encoding and transformation
techniques to bypass DPI systems that rely on content inspection and pattern matching.
"""
import asyncio
import logging
import random
import base64
import zlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
from recon.core.bypass.attacks.base import BaseAttack, AttackResult, AttackStatus, AttackContext

class ObfuscationMethod(Enum):
    """Different obfuscation methods."""
    BASE64 = 'base64'
    HEX_ENCODING = 'hex_encoding'
    XOR_CIPHER = 'xor_cipher'
    ROT13 = 'rot13'
    COMPRESSION = 'compression'
    BYTE_SUBSTITUTION = 'byte_substitution'
    MIXED_ENCODING = 'mixed_encoding'

@dataclass
class PayloadObfuscationConfig:
    """Configuration for PayloadObfuscationAttack."""
    obfuscation_method: ObfuscationMethod = ObfuscationMethod.MIXED_ENCODING
    segment_count: int = 3
    per_segment_obfuscation: bool = True
    xor_key: bytes = b'bypass_key_123'
    add_decoding_headers: bool = True
    base_delay_ms: float = 6.0
    add_noise: bool = True
    noise_size_range: Tuple[int, int] = (5, 20)
    vary_tcp_flags: bool = True
    vary_window_size: bool = True
    window_size_range: Tuple[int, int] = (32768, 65535)

class PayloadObfuscationAttack(BaseAttack):
    """
    PayloadObfuscationAttack using segments architecture.

    This attack obfuscates payload content to bypass content-based DPI analysis.
    """

    def __init__(self, name: str='payload_obfuscation', config: Optional[PayloadObfuscationConfig]=None):
        super().__init__(name)
        self.config = config or PayloadObfuscationConfig()
        self.logger = logging.getLogger(f'PayloadObfuscationAttack.{name}')
        self._validate_config()

    def _validate_config(self):
        """Validate attack configuration."""
        if not 2 <= self.config.segment_count <= 10:
            raise ValueError(f'segment_count must be between 2 and 10, got {self.config.segment_count}')
        if self.config.base_delay_ms < 0:
            raise ValueError('base_delay_ms must be non-negative')
        if not self.config.xor_key:
            raise ValueError('xor_key cannot be empty')
        if self.config.noise_size_range[0] > self.config.noise_size_range[1]:
            raise ValueError('Invalid noise_size_range')

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute PayloadObfuscationAttack."""
        try:
            self.logger.info(f'Executing PayloadObfuscationAttack on {context.connection_id}')
            if not context.payload:
                return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': 'Empty payload provided'})
            segments = await self._create_obfuscated_segments(context.payload)
            result = AttackResult(status=AttackStatus.SUCCESS, modified_payload=None, metadata={'attack_type': 'payload_obfuscation', 'segments': segments, 'total_segments': len(segments), 'obfuscation_method': self.config.obfuscation_method.value, 'original_payload_size': len(context.payload), 'config': {'obfuscation_method': self.config.obfuscation_method.value, 'segment_count': self.config.segment_count, 'per_segment_obfuscation': self.config.per_segment_obfuscation, 'add_decoding_headers': self.config.add_decoding_headers, 'add_noise': self.config.add_noise, 'vary_tcp_flags': self.config.vary_tcp_flags, 'vary_window_size': self.config.vary_window_size}})
            result._segments = segments
            self.logger.info(f'PayloadObfuscationAttack created {len(segments)} segments with {self.config.obfuscation_method.value} obfuscation')
            return result
        except Exception as e:
            self.logger.error(f'PayloadObfuscationAttack failed: {e}')
            return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': str(e), 'attack_type': 'payload_obfuscation'})

    def _create_obfuscated_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create segments with payload obfuscation."""
        segments = []
        segment_size = len(payload) // self.config.segment_count
        remainder = len(payload) % self.config.segment_count
        current_pos = 0
        for i in range(self.config.segment_count):
            size = segment_size + (1 if i < remainder else 0)
            segment_payload = payload[current_pos:current_pos + size]
            if self.config.per_segment_obfuscation:
                methods = list(ObfuscationMethod)
                method = methods[i % len(methods)]
            else:
                method = self.config.obfuscation_method
            obfuscated_payload = self._obfuscate_payload(segment_payload, method)
            if self.config.add_decoding_headers:
                header = self._create_decoding_header(method)
                obfuscated_payload = header + obfuscated_payload
            if self.config.add_noise:
                noise = self._generate_noise()
                obfuscated_payload = noise + obfuscated_payload + noise
            options = self._create_segment_options(i)
            segments.append((obfuscated_payload, current_pos, options))
            current_pos += size
        return segments

    def _obfuscate_payload(self, payload: bytes, method: ObfuscationMethod) -> bytes:
        """Obfuscate payload using specified method."""
        try:
            if method == ObfuscationMethod.BASE64:
                return base64.b64encode(payload)
            elif method == ObfuscationMethod.HEX_ENCODING:
                return payload.hex().encode('ascii')
            elif method == ObfuscationMethod.XOR_CIPHER:
                return self._xor_encrypt(payload, self.config.xor_key)
            elif method == ObfuscationMethod.ROT13:
                return self._rot13_encode(payload)
            elif method == ObfuscationMethod.COMPRESSION:
                compressed = zlib.compress(payload)
                return base64.b64encode(compressed)
            elif method == ObfuscationMethod.BYTE_SUBSTITUTION:
                return self._byte_substitution(payload)
            elif method == ObfuscationMethod.MIXED_ENCODING:
                temp = self._xor_encrypt(payload, self.config.xor_key)
                temp = base64.b64encode(temp)
                return self._byte_substitution(temp)
            else:
                return payload
        except Exception as e:
            self.logger.warning(f'Obfuscation failed with method {method.value}: {e}')
            return payload

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encrypt data with key."""
        result = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)

    def _rot13_encode(self, data: bytes) -> bytes:
        """ROT13 encode data (for ASCII characters)."""
        result = bytearray()
        for byte in data:
            if 65 <= byte <= 90:
                result.append((byte - 65 + 13) % 26 + 65)
            elif 97 <= byte <= 122:
                result.append((byte - 97 + 13) % 26 + 97)
            else:
                result.append(byte)
        return bytes(result)

    def _byte_substitution(self, data: bytes) -> bytes:
        """Simple byte substitution cipher."""
        substitution = list(range(256))
        random.seed(42)
        random.shuffle(substitution)
        result = bytearray()
        for byte in data:
            result.append(substitution[byte])
        return bytes(result)

    def _create_decoding_header(self, method: ObfuscationMethod) -> bytes:
        """Create header indicating decoding method."""
        headers = {ObfuscationMethod.BASE64: b'B64:', ObfuscationMethod.HEX_ENCODING: b'HEX:', ObfuscationMethod.XOR_CIPHER: b'XOR:', ObfuscationMethod.ROT13: b'R13:', ObfuscationMethod.COMPRESSION: b'ZIP:', ObfuscationMethod.BYTE_SUBSTITUTION: b'SUB:', ObfuscationMethod.MIXED_ENCODING: b'MIX:'}
        return headers.get(method, b'UNK:')

    def _generate_noise(self) -> bytes:
        """Generate random noise data."""
        noise_size = random.randint(self.config.noise_size_range[0], self.config.noise_size_range[1])
        return bytes([random.randint(0, 255) for _ in range(noise_size)])

    def _create_segment_options(self, segment_index: int) -> Dict[str, Any]:
        """Create options for a segment."""
        options = {'delay_ms': self.config.base_delay_ms, 'ttl': 64}
        if self.config.vary_tcp_flags:
            flag_options = [24, 16, 8]
            options['flags'] = random.choice(flag_options)
        else:
            options['flags'] = 24
        if self.config.vary_window_size:
            window_size = random.randint(self.config.window_size_range[0], self.config.window_size_range[1])
            options['window_size'] = window_size
        return options

    def get_attack_info(self) -> Dict[str, Any]:
        """Get information about this attack."""
        return {'name': self.name, 'type': 'payload_obfuscation', 'description': 'Obfuscates payload content using various encoding techniques', 'technique': 'content_obfuscation', 'effectiveness': 'high_against_content_inspection_dpi', 'config': {'obfuscation_method': self.config.obfuscation_method.value, 'segment_count': self.config.segment_count, 'per_segment_obfuscation': self.config.per_segment_obfuscation, 'add_decoding_headers': self.config.add_decoding_headers, 'add_noise': self.config.add_noise, 'vary_tcp_flags': self.config.vary_tcp_flags, 'vary_window_size': self.config.vary_window_size}, 'obfuscation_methods': [method.value for method in ObfuscationMethod], 'advantages': ['Hides payload content from DPI inspection', 'Multiple obfuscation methods available', 'Per-segment obfuscation support', 'Noise injection for additional confusion', 'Decoding headers for legitimate reconstruction']}

    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        effectiveness = 0.8
        if self.config.per_segment_obfuscation:
            effectiveness += 0.05
        if self.config.add_noise:
            effectiveness += 0.05
        if self.config.obfuscation_method in [ObfuscationMethod.MIXED_ENCODING, ObfuscationMethod.COMPRESSION]:
            effectiveness += 0.05
        if self.config.vary_tcp_flags or self.config.vary_window_size:
            effectiveness += 0.05
        return min(1.0, max(0.0, effectiveness))

    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        capabilities = ['packet_construction', 'payload_modification', 'timing_control', 'sequence_manipulation']
        if self.config.vary_tcp_flags:
            capabilities.append('tcp_flags_modification')
        if self.config.vary_window_size:
            capabilities.append('window_size_modification')
        return capabilities

    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return (False, 'Empty payload provided')
        min_payload_size = self.config.segment_count * 5
        if len(context.payload) < min_payload_size:
            return (False, f'Payload too small for {self.config.segment_count} segments')
        return (True, None)

def create_payload_obfuscation_attack(name: str='payload_obfuscation', obfuscation_method: ObfuscationMethod=ObfuscationMethod.MIXED_ENCODING, segment_count: int=3, per_segment_obfuscation: bool=True, add_decoding_headers: bool=True, add_noise: bool=True, vary_tcp_flags: bool=True, vary_window_size: bool=True) -> PayloadObfuscationAttack:
    """Factory function to create PayloadObfuscationAttack."""
    config = PayloadObfuscationConfig(obfuscation_method=obfuscation_method, segment_count=segment_count, per_segment_obfuscation=per_segment_obfuscation, add_decoding_headers=add_decoding_headers, add_noise=add_noise, vary_tcp_flags=vary_tcp_flags, vary_window_size=vary_window_size)
    return PayloadObfuscationAttack(name=name, config=config)

def create_base64_obfuscation_attack() -> PayloadObfuscationAttack:
    """Create Base64 obfuscation variant."""
    return create_payload_obfuscation_attack(name='base64_obfuscation_attack', obfuscation_method=ObfuscationMethod.BASE64, segment_count=4, per_segment_obfuscation=False, add_decoding_headers=True, add_noise=False)

def create_xor_obfuscation_attack() -> PayloadObfuscationAttack:
    """Create XOR obfuscation variant."""
    return create_payload_obfuscation_attack(name='xor_obfuscation_attack', obfuscation_method=ObfuscationMethod.XOR_CIPHER, segment_count=3, per_segment_obfuscation=False, add_decoding_headers=True, add_noise=True)

def create_mixed_obfuscation_attack() -> PayloadObfuscationAttack:
    """Create mixed obfuscation variant."""
    return create_payload_obfuscation_attack(name='mixed_obfuscation_attack', obfuscation_method=ObfuscationMethod.MIXED_ENCODING, segment_count=5, per_segment_obfuscation=True, add_decoding_headers=True, add_noise=True, vary_tcp_flags=True, vary_window_size=True)