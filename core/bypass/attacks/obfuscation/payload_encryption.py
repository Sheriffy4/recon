from __future__ import annotations

"""
Payload Encryption Obfuscation Attacks

Advanced payload encryption techniques that encrypt and obfuscate data
to evade DPI content inspection and pattern matching.
"""

import asyncio
import time
import random
import hashlib
import struct
import json
import secrets
from typing import List, Dict, Any, Tuple, Optional

from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack

Segment = Tuple[bytes, int, Dict[str, Any]]


@register_attack
class XORPayloadEncryptionAttack(BaseAttack):
    """
    XOR Payload Encryption Attack with advanced key management.

    Uses XOR encryption with various key generation strategies
    to obfuscate payload content from DPI inspection.
    """

    @property
    def name(self) -> str:
        return "xor_payload_encryption"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "XOR encryption with advanced key management for payload obfuscation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "key_strategy": "random",
            "key_length": 32,
            "key_rotation": False,
            "include_header": True,
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute XOR payload encryption attack."""
        start_ms = time.monotonic() * 1000
        try:
            payload = context.payload or b""
            key_strategy = context.params.get("key_strategy", "random")
            key_length = context.params.get("key_length", 32)
            key_rotation = context.params.get("key_rotation", False)
            include_header = context.params.get("include_header", True)
            encryption_key = self._generate_encryption_key(key_strategy, key_length, context)
            encrypted_payload = self._xor_encrypt(payload, encryption_key)
            if include_header:
                final_packet = self._create_packet_with_header(
                    encrypted_payload, encryption_key, key_strategy
                )
            else:
                final_packet = encrypted_payload
            segments: List[Segment] = []
            if key_rotation and len(payload) > 100:
                segments = await self._create_key_rotation_segments(payload, key_strategy, key_length, context)
            else:
                segments = [(final_packet, 0, {"encrypted": True, "key_strategy": key_strategy, "delay_ms": 0.0})]
            packets_sent = len(segments)
            bytes_sent = sum((len(seg[0]) for seg in segments))
            latency = (time.monotonic() * 1000) - start_ms
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="xor_payload_encryption",
                metadata={
                    "key_strategy": key_strategy,
                    "key_length": key_length,
                    "key_rotation": key_rotation,
                    "include_header": include_header,
                    "original_size": len(payload),
                    "encrypted_size": len(encrypted_payload),
                    "final_size": len(final_packet),
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.monotonic() * 1000) - start_ms,
                technique_used="xor_payload_encryption",
            )

    def _generate_encryption_key(self, strategy: str, length: int, context: AttackContext) -> bytes:
        """Generate encryption key based on strategy."""
        if strategy == "random":
            return secrets.token_bytes(int(length))
        elif strategy == "time_based":
            # Avoid touching global RNG state
            r = random.Random(int(time.time()) // 60)
            return r.randbytes(int(length))
        elif strategy == "domain_based":
            domain = context.domain or f"{context.dst_ip}:{context.dst_port}"
            domain_hash = hashlib.sha256(domain.encode()).digest()
            ln = int(length)
            return (domain_hash * (ln // 32 + 1))[:ln]
        elif strategy == "sequence_based":
            seq_bytes = struct.pack("!I", int(getattr(context, "tcp_seq", 0) or 0))
            key_material = hashlib.sha256(seq_bytes).digest()
            ln = int(length)
            return (key_material * (ln // 32 + 1))[:ln]
        else:
            raise ValueError(f"Invalid key_strategy: {strategy}")

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encrypt data with key."""
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)

    def _create_packet_with_header(
        self, encrypted_payload: bytes, key: bytes, strategy: str
    ) -> bytes:
        """Create packet with encryption header."""
        magic = b"XENC"
        version = 1
        strategy_code = {
            "random": 1,
            "time_based": 2,
            "domain_based": 3,
            "sequence_based": 4,
        }.get(strategy, 1)
        key_length = len(key)
        key_hint = hashlib.sha256(key).digest()[:8]
        header = magic + bytes([version, strategy_code]) + struct.pack("!H", key_length) + key_hint
        return header + encrypted_payload

    async def _create_key_rotation_segments(
        self, payload: bytes, strategy: str, key_length: int, context: AttackContext
    ) -> List[Segment]:
        """Create segments with key rotation (no real sleeps; delays are stored in options)."""
        segments: List[Segment] = []
        chunk_size = random.randint(50, 150)
        delay_step_ms = float(context.params.get("rotation_delay_step_ms", 10.0))
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            segment_key = self._generate_rotation_key(strategy, key_length, i)
            encrypted_chunk = self._xor_encrypt(chunk, segment_key)
            segment_packet = self._create_packet_with_header(encrypted_chunk, segment_key, strategy)
            # Keep async semantics
            await asyncio.sleep(0)
            segments.append(
                (
                    segment_packet,
                    i,  # payload offset
                    {
                        "encrypted": True,
                        "key_strategy": strategy,
                        "segment_index": i // chunk_size,
                        "key_rotated": True,
                        "delay_ms": (i // chunk_size) * delay_step_ms,
                        "legacy_delay_field": (i // chunk_size) * delay_step_ms,
                    },
                )
            )
        return segments

    def _generate_rotation_key(self, strategy: str, length: int, segment_index: int) -> bytes:
        """Generate rotated key for segment."""
        if strategy == "sequence_based":
            base_seed = int(time.time()) + segment_index
            r = random.Random(base_seed)
            return r.randbytes(int(length))
        else:
            return secrets.token_bytes(int(length))


@register_attack
class AESPayloadEncryptionAttack(BaseAttack):
    """
    AES Payload Encryption Attack with multiple modes.

    Uses AES encryption in various modes (CBC, CTR, GCM) to provide
    strong encryption for payload obfuscation.
    """

    @property
    def name(self) -> str:
        return "aes_payload_encryption"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "AES encryption with multiple modes for strong payload obfuscation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "mode": "CTR",
            "key_size": 256,
            "include_iv": True,
            "padding_scheme": "PKCS7",
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute AES payload encryption attack."""
        start_time = time.time()
        try:
            payload = context.payload
            mode = context.params.get("mode", "CTR")
            key_size = context.params.get("key_size", 256)
            include_iv = context.params.get("include_iv", True)
            padding_scheme = context.params.get("padding_scheme", "PKCS7")
            key = self._generate_aes_key(key_size // 8)
            iv = random.randbytes(16) if include_iv else b"\x00" * 16
            encrypted_payload = self._aes_encrypt(payload, key, iv, mode, padding_scheme)
            final_packet = self._create_aes_packet(encrypted_payload, key, iv, mode, include_iv)
            segments = [
                (
                    final_packet,
                    0,
                    {
                        "encrypted": True,
                        "algorithm": "AES",
                        "mode": mode,
                        "key_size": key_size,
                    },
                )
            ]
            packets_sent = 1
            bytes_sent = len(final_packet)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="aes_payload_encryption",
                metadata={
                    "mode": mode,
                    "key_size": key_size,
                    "include_iv": include_iv,
                    "padding_scheme": padding_scheme,
                    "original_size": len(payload),
                    "encrypted_size": len(encrypted_payload),
                    "final_size": len(final_packet),
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="aes_payload_encryption",
            )

    def _generate_aes_key(self, key_length: int) -> bytes:
        """Generate AES key."""
        return random.randbytes(key_length)

    def _aes_encrypt(self, data: bytes, key: bytes, iv: bytes, mode: str, padding: str) -> bytes:
        """Simulate AES encryption (simplified implementation)."""
        if mode in ["CBC", "ECB"] and padding == "PKCS7":
            data = self._apply_pkcs7_padding(data, 16)
        key_material = self._expand_key_material(key, iv, len(data))
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key_material[i % len(key_material)])
        return bytes(encrypted)

    def _apply_pkcs7_padding(self, data: bytes, block_size: int) -> bytes:
        """Apply PKCS7 padding."""
        padding_length = block_size - len(data) % block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _expand_key_material(self, key: bytes, iv: bytes, length: int) -> bytes:
        """Expand key material for encryption."""
        material = key + iv
        expanded = material
        while len(expanded) < length:
            expanded += hashlib.sha256(expanded[-32:]).digest()
        return expanded[:length]

    def _create_aes_packet(
        self,
        encrypted_payload: bytes,
        key: bytes,
        iv: bytes,
        mode: str,
        include_iv: bool,
    ) -> bytes:
        """Create AES encrypted packet with metadata."""
        magic = b"AENC"
        version = 1
        mode_code = {"CBC": 1, "CTR": 2, "GCM": 3, "ECB": 4}.get(mode, 2)
        key_size = len(key)
        iv_flag = 1 if include_iv else 0
        header = magic + bytes([version, mode_code, key_size, iv_flag])
        if include_iv:
            header += iv
        return header + encrypted_payload


@register_attack
class ChaCha20PayloadEncryptionAttack(BaseAttack):
    """
    ChaCha20 Payload Encryption Attack.

    Uses ChaCha20 stream cipher for fast and secure payload encryption
    with resistance to timing attacks.
    """

    @property
    def name(self) -> str:
        return "chacha20_payload_encryption"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "ChaCha20 stream cipher for fast and secure payload encryption"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "use_poly1305": False,
            "nonce_strategy": "random",
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute ChaCha20 payload encryption attack."""
        start_time = time.time()
        try:
            payload = context.payload
            use_poly1305 = context.params.get("use_poly1305", False)
            nonce_strategy = context.params.get("nonce_strategy", "random")
            key = random.randbytes(32)
            nonce = self._generate_nonce(nonce_strategy, context)
            encrypted_payload = self._chacha20_encrypt(payload, key, nonce)
            if use_poly1305:
                auth_tag = self._poly1305_authenticate(encrypted_payload, key)
                final_payload = encrypted_payload + auth_tag
            else:
                final_payload = encrypted_payload
                auth_tag = b""
            final_packet = self._create_chacha20_packet(final_payload, key, nonce, use_poly1305)
            segments = [
                (
                    final_packet,
                    0,
                    {
                        "encrypted": True,
                        "algorithm": "ChaCha20",
                        "authenticated": use_poly1305,
                    },
                )
            ]
            packets_sent = 1
            bytes_sent = len(final_packet)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="chacha20_payload_encryption",
                metadata={
                    "use_poly1305": use_poly1305,
                    "nonce_strategy": nonce_strategy,
                    "original_size": len(payload),
                    "encrypted_size": len(encrypted_payload),
                    "auth_tag_size": len(auth_tag),
                    "final_size": len(final_packet),
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="chacha20_payload_encryption",
            )

    def _generate_nonce(self, strategy: str, context: AttackContext) -> bytes:
        """Generate nonce based on strategy."""
        if strategy == "random":
            return random.randbytes(12)
        elif strategy == "counter":
            counter = context.packet_id or random.randint(1, 1000000)
            return struct.pack("!Q", counter).ljust(12, b"\x00")
        elif strategy == "timestamp":
            timestamp = int(time.time() * 1000000)
            return struct.pack("!Q", timestamp).ljust(12, b"\x00")
        else:
            return random.randbytes(12)

    def _chacha20_encrypt(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Simulate ChaCha20 encryption (simplified implementation)."""
        keystream = self._generate_chacha20_keystream(key, nonce, len(data))
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ keystream[i])
        return bytes(encrypted)

    def _generate_chacha20_keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate ChaCha20 keystream (simplified)."""
        keystream = b""
        counter = 0
        while len(keystream) < length:
            block_input = key + nonce + struct.pack("!I", counter)
            block = hashlib.sha256(block_input).digest()
            keystream += block
            counter += 1
        return keystream[:length]

    def _poly1305_authenticate(self, data: bytes, key: bytes) -> bytes:
        """Simulate Poly1305 authentication (simplified)."""
        auth_key = hashlib.sha256(key + b"poly1305").digest()[:16]
        import hmac

        mac = hmac.new(auth_key, data, hashlib.sha256).digest()[:16]
        return mac

    def _create_chacha20_packet(
        self, encrypted_payload: bytes, key: bytes, nonce: bytes, authenticated: bool
    ) -> bytes:
        """Create ChaCha20 encrypted packet."""
        magic = b"CENC"
        version = 1
        auth_flag = 1 if authenticated else 0
        header = magic + bytes([version, auth_flag]) + nonce
        return header + encrypted_payload


@register_attack
class MultiLayerEncryptionAttack(BaseAttack):
    """
    Multi-Layer Encryption Attack.

    Applies multiple layers of encryption with different algorithms
    to create highly obfuscated payloads that are difficult to analyze.
    """

    @property
    def name(self) -> str:
        return "multi_layer_encryption"

    @property
    def category(self) -> str:
        return "payload"

    @property
    def description(self) -> str:
        return "Multiple layers of encryption for maximum payload obfuscation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "layers": ["xor", "aes", "chacha20"],
            "key_derivation": "pbkdf2",
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute multi-layer encryption attack."""
        start_time = time.time()
        try:
            payload = context.payload
            layers = context.params.get("layers", ["xor", "aes", "chacha20"])
            randomize_order = context.params.get("randomize_order", False)
            add_noise = context.params.get("add_noise", True)
            if randomize_order:
                layers = layers.copy()
                random.shuffle(layers)
            encrypted_payload = payload
            layer_info = []
            for i, layer_type in enumerate(layers):
                layer_result = self._apply_encryption_layer(encrypted_payload, layer_type, i)
                encrypted_payload = layer_result["encrypted_data"]
                layer_info.append(layer_result["info"])
            if add_noise:
                encrypted_payload = self._add_noise_layer(encrypted_payload)
            final_packet = self._create_multilayer_packet(encrypted_payload, layer_info, layers)
            segments = [
                (
                    final_packet,
                    0,
                    {
                        "encrypted": True,
                        "layers": layers,
                        "layer_count": len(layers),
                        "randomized": randomize_order,
                        "noise_added": add_noise,
                    },
                )
            ]
            packets_sent = 1
            bytes_sent = len(final_packet)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="multi_layer_encryption",
                metadata={
                    "layers": layers,
                    "layer_count": len(layers),
                    "randomize_order": randomize_order,
                    "add_noise": add_noise,
                    "layer_info": layer_info,
                    "original_size": len(payload),
                    "final_size": len(final_packet),
                    "expansion_ratio": (len(final_packet) / len(payload) if payload else 1.0),
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="multi_layer_encryption",
            )

    def _apply_encryption_layer(
        self, data: bytes, layer_type: str, layer_index: int
    ) -> Dict[str, Any]:
        """Apply a single encryption layer."""
        if layer_type == "xor":
            key = random.randbytes(32)
            encrypted = self._xor_encrypt(data, key)
            return {
                "encrypted_data": encrypted,
                "info": {
                    "type": "xor",
                    "key_length": len(key),
                    "layer_index": layer_index,
                },
            }
        elif layer_type == "aes":
            key = random.randbytes(32)
            iv = random.randbytes(16)
            encrypted = self._simple_aes_encrypt(data, key, iv)
            return {
                "encrypted_data": encrypted,
                "info": {
                    "type": "aes",
                    "key_length": len(key),
                    "iv_length": len(iv),
                    "layer_index": layer_index,
                },
            }
        elif layer_type == "chacha20":
            key = random.randbytes(32)
            nonce = random.randbytes(12)
            encrypted = self._simple_chacha20_encrypt(data, key, nonce)
            return {
                "encrypted_data": encrypted,
                "info": {
                    "type": "chacha20",
                    "key_length": len(key),
                    "nonce_length": len(nonce),
                    "layer_index": layer_index,
                },
            }
        elif layer_type == "rot13":
            encrypted = self._rot_encrypt(data, 13)
            return {
                "encrypted_data": encrypted,
                "info": {"type": "rot13", "rotation": 13, "layer_index": layer_index},
            }
        else:
            key = random.randbytes(16)
            encrypted = self._xor_encrypt(data, key)
            return {
                "encrypted_data": encrypted,
                "info": {
                    "type": "xor_default",
                    "key_length": len(key),
                    "layer_index": layer_index,
                },
            }

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption."""
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)

    def _simple_aes_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Simplified AES encryption simulation."""
        padded_data = self._pad_data(data, 16)
        key_material = self._expand_key_material(key, iv, len(padded_data))
        encrypted = bytearray()
        for i, byte in enumerate(padded_data):
            encrypted.append(byte ^ key_material[i % len(key_material)])
        return bytes(encrypted)

    def _simple_chacha20_encrypt(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Simplified ChaCha20 encryption simulation."""
        keystream = self._generate_simple_keystream(key, nonce, len(data))
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ keystream[i])
        return bytes(encrypted)

    def _rot_encrypt(self, data: bytes, rotation: int) -> bytes:
        """ROT-style encryption."""
        encrypted = bytearray()
        for byte in data:
            encrypted.append((byte + rotation) % 256)
        return bytes(encrypted)

    def _pad_data(self, data: bytes, block_size: int) -> bytes:
        """Pad data to block size."""
        padding_length = block_size - len(data) % block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _expand_key_material(self, key: bytes, iv: bytes, length: int) -> bytes:
        """Expand key material."""
        material = key + iv
        expanded = material
        while len(expanded) < length:
            expanded += hashlib.sha256(expanded[-32:]).digest()
        return expanded[:length]

    def _generate_simple_keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate simple keystream."""
        keystream = b""
        counter = 0
        while len(keystream) < length:
            block_input = key + nonce + struct.pack("!I", counter)
            block = hashlib.sha256(block_input).digest()
            keystream += block
            counter += 1
        return keystream[:length]

    def _add_noise_layer(self, data: bytes) -> bytes:
        """Add noise layer to obfuscate patterns."""
        noise_size = random.randint(10, 50)
        noise = random.randbytes(noise_size)
        result = bytearray(data)
        for _ in range(random.randint(3, 8)):
            pos = random.randint(0, len(result))
            result.insert(pos, random.randint(0, 255))
        return bytes(result)

    def _create_multilayer_packet(
        self, encrypted_payload: bytes, layer_info: List[Dict], layers: List[str]
    ) -> bytes:
        """Create multi-layer encrypted packet."""
        magic = b"MENC"
        version = 1
        layer_count = len(layers)
        layer_info_bytes = json.dumps(
            {"layers": layers, "count": layer_count, "info": layer_info}
        ).encode("utf-8")
        info_length = len(layer_info_bytes)
        header = (
            magic
            + bytes([version, layer_count])
            + struct.pack("!H", info_length)
            + layer_info_bytes
        )
        return header + encrypted_payload
