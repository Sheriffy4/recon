# recon/core/bypass/attacks/tls/confusion.py
"""
TLS Protocol Confusion Attacks

Migrated and unified from:
- ProtocolConfusionAttack (core/attacks/tls_attacks.py)
"""

import time
from typing import List
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


@register_attack
class ProtocolConfusionAttack(BaseAttack):
    """
    Protocol Confusion Attack - prepends fake protocol headers.

    Migrated from:
    - ProtocolConfusionAttack (tls_attacks.py)
    """

    @property
    def name(self) -> str:
        return "protocol_confusion"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Prepends fake protocol headers to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute protocol confusion attack."""
        start_time = time.time()

        try:
            payload = context.payload
            fake_protocol = context.params.get("fake_protocol", "smtp")

            # Generate fake header based on protocol
            if fake_protocol == "smtp":
                fake_header = b"EHLO mail.example.com\r\n"
            elif fake_protocol == "http":
                fake_header = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            elif fake_protocol == "ftp":
                fake_header = b"USER anonymous\r\n"
            elif fake_protocol == "pop3":
                fake_header = b"USER test@example.com\r\n"
            else:
                fake_header = context.params.get("custom_header", b"HELLO\r\n")

            # Combine fake header with real payload
            combined_payload = fake_header + payload

            segments = [(combined_payload, 0)]

            packets_sent = 1
            bytes_sent = len(combined_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fake_protocol": fake_protocol,
                    "fake_header_size": len(fake_header),
                    "original_payload_size": len(payload),
                    "combined_size": len(combined_payload),
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
class TLSVersionConfusionAttack(BaseAttack):
    """
    TLS Version Confusion Attack - modifies TLS version fields.
    """

    @property
    def name(self) -> str:
        return "tls_version_confusion"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Modifies TLS version fields to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS version confusion attack."""
        start_time = time.time()

        try:
            payload = context.payload
            fake_version = context.params.get("fake_version", b"\x03\x00")  # SSL 3.0

            # Check if this is a TLS record
            if not (len(payload) >= 3 and payload[0] == 0x16):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Not a TLS record"
                )

            # Replace TLS version
            modified_payload = payload[:1] + fake_version + payload[3:]

            segments = [(modified_payload, 0)]

            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fake_version": fake_version.hex(),
                    "original_version": (
                        payload[1:3].hex() if len(payload) >= 3 else None
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


@register_attack
class TLSContentTypeConfusionAttack(BaseAttack):
    """
    TLS Content Type Confusion Attack - modifies TLS content type.
    """

    @property
    def name(self) -> str:
        return "tls_content_type_confusion"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Modifies TLS content type to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS content type confusion attack."""
        start_time = time.time()

        try:
            payload = context.payload
            fake_content_type = context.params.get(
                "fake_content_type", 0x17
            )  # Application Data

            # Check if this is a TLS record
            if len(payload) < 1:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Payload too short",
                )

            # Replace content type
            modified_payload = bytes([fake_content_type]) + payload[1:]

            segments = [(modified_payload, 0)]

            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fake_content_type": fake_content_type,
                    "original_content_type": payload[0],
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
