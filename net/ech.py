from dataclasses import dataclass
from enum import IntEnum
from typing import List
import struct


class ECHVersion(IntEnum):
    DRAFT_12 = 0xFE0D
    DRAFT_13 = 0xFE0E


class ECHCipherSuite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303


@dataclass
class ECHConfig:
    """ECH Configuration"""

    version: ECHVersion
    config_id: int
    cipher_suites: List[ECHCipherSuite]
    public_name: str
    public_key: bytes
    maximum_name_length: int

    @classmethod
    def parse(cls, data: bytes) -> "ECHConfig":
        """Parse ECH config from bytes"""
        version = ECHVersion(struct.unpack("!H", data[0:2])[0])
        length = struct.unpack("!H", data[2:4])[0]
        config_id = data[4]

        # Parse cipher suites
        cipher_count = struct.unpack("!H", data[5:7])[0]
        pos = 7
        cipher_suites = []
        for _ in range(cipher_count):
            suite = ECHCipherSuite(struct.unpack("!H", data[pos : pos + 2])[0])
            cipher_suites.append(suite)
            pos += 2

        # Parse public name
        name_length = data[pos]
        pos += 1
        public_name = data[pos : pos + name_length].decode("utf-8")
        pos += name_length

        # Parse public key
        key_length = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        public_key = data[pos : pos + key_length]
        pos += key_length

        # Parse maximum name length
        maximum_name_length = struct.unpack("!H", data[pos : pos + 2])[0]

        return cls(
            version=version,
            config_id=config_id,
            cipher_suites=cipher_suites,
            public_name=public_name,
            public_key=public_key,
            maximum_name_length=maximum_name_length,
        )

    def serialize(self) -> bytes:
        """Serialize ECH config to bytes"""
        result = struct.pack("!H", self.version)

        # Placeholder for length
        result += b"\x00\x00"

        result += bytes([self.config_id])

        # Cipher suites
        result += struct.pack("!H", len(self.cipher_suites))
        for suite in self.cipher_suites:
            result += struct.pack("!H", suite)

        # Public name
        name_bytes = self.public_name.encode("utf-8")
        result += bytes([len(name_bytes)])
        result += name_bytes

        # Public key
        result += struct.pack("!H", len(self.public_key))
        result += self.public_key

        # Maximum name length
        result += struct.pack("!H", self.maximum_name_length)

        # Update length
        length = len(result) - 4
        result = result[:2] + struct.pack("!H", length) + result[4:]

        return result


@dataclass
class ECHClientHello:
    """ECH Client Hello extension"""

    config_id: int
    cipher_suite: ECHCipherSuite
    encrypted_ch: bytes

    @classmethod
    def parse(cls, data: bytes) -> "ECHClientHello":
        """Parse ECH ClientHello from bytes"""
        config_id = data[0]
        cipher_suite = ECHCipherSuite(struct.unpack("!H", data[1:3])[0])

        enc_length = struct.unpack("!H", data[3:5])[0]
        encrypted_ch = data[5 : 5 + enc_length]

        return cls(
            config_id=config_id, cipher_suite=cipher_suite, encrypted_ch=encrypted_ch
        )

    def serialize(self) -> bytes:
        """Serialize ECH ClientHello to bytes"""
        result = bytes([self.config_id])
        result += struct.pack("!H", self.cipher_suite)
        result += struct.pack("!H", len(self.encrypted_ch))
        result += self.encrypted_ch
        return result


class ECHNonce:
    """Helper class for generating ECH nonces"""

    @staticmethod
    def generate(config_id: int, enc_size: int) -> bytes:
        """Generate nonce for ECH encryption"""
        import os

        # 12 bytes nonce as per specification
        return os.urandom(12)
