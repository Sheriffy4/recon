"""
ICMP Tunneling Attacks

Attacks that use ICMP protocol for tunneling data to evade DPI.
"""

import time
import struct
import random
from typing import List, Dict, Any
from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)


@register_attack(
    name="icmp_data_tunneling",
    category=AttackCategories.TUNNELING,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "icmp_type": 8,
        "icmp_code": 0,
        "chunk_size": 64
    },
    aliases=["icmp_tunnel", "icmp_data"],
    description="Tunnels data through ICMP packets to evade DPI"
)
class ICMPDataTunnelingAttack(BaseAttack):
    """
    ICMP Data Tunneling Attack - embeds data in ICMP packets.
    """

    @property
    def name(self) -> str:
        return "icmp_data_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP packet payloads"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "icmp_type": 8,
            "icmp_code": 0,
            "packet_size": 64,
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP data tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            icmp_type = context.params.get("icmp_type", 8)
            icmp_code = context.params.get("icmp_code", 0)
            packet_size = context.params.get("packet_size", 64)
            chunks = self._split_payload(payload, packet_size - 8)
            icmp_packets = []
            for i, chunk in enumerate(chunks):
                icmp_packet = self._create_icmp_packet(icmp_type, icmp_code, i, chunk)
                icmp_packets.append(icmp_packet)
            combined_payload = b"".join(icmp_packets)
            segments = [(packet, i * 100) for i, packet in enumerate(icmp_packets)]
            packets_sent = len(icmp_packets)
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
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                    "packet_count": len(icmp_packets),
                    "original_size": len(payload),
                    "tunneled_size": len(combined_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _split_payload(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """Split payload into chunks."""
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunks.append(payload[i : i + chunk_size])
        return chunks

    def _create_icmp_packet(
        self, icmp_type: int, icmp_code: int, sequence: int, data: bytes
    ) -> bytes:
        """Create ICMP packet with embedded data."""
        icmp_id = random.randint(0, 65535)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        packet = header + data
        checksum = self._calculate_checksum(packet)
        header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence
        )
        return header + data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum += checksum >> 16
        return ~checksum & 65535


@register_attack(
    name="icmp_timestamp_tunneling",
    category=AttackCategories.TUNNELING,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "use_originate_timestamp": True,
        "use_receive_timestamp": True,
        "use_transmit_timestamp": True
    },
    aliases=["icmp_timestamp", "icmp_ts_tunnel"],
    description="Tunnels data through ICMP timestamp packets"
)
class ICMPTimestampTunnelingAttack(BaseAttack):
    """
    ICMP Timestamp Tunneling Attack - uses ICMP timestamp fields for data.
    """

    @property
    def name(self) -> str:
        return "icmp_timestamp_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP timestamp fields"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP timestamp tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            chunks = self._split_payload(payload, 4)
            icmp_packets = []
            for i, chunk in enumerate(chunks):
                if len(chunk) < 4:
                    chunk += b"\x00" * (4 - len(chunk))
                timestamp_value = struct.unpack("!I", chunk)[0]
                icmp_packet = self._create_timestamp_packet(i, timestamp_value)
                icmp_packets.append(icmp_packet)
            combined_payload = b"".join(icmp_packets)
            segments = [(packet, i * 100) for i, packet in enumerate(icmp_packets)]
            packets_sent = len(icmp_packets)
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
                    "packet_count": len(icmp_packets),
                    "original_size": len(payload),
                    "tunneled_size": len(combined_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _split_payload(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """Split payload into chunks."""
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunks.append(payload[i : i + chunk_size])
        return chunks

    def _create_timestamp_packet(self, sequence: int, timestamp: int) -> bytes:
        """Create ICMP timestamp packet."""
        icmp_type = 13
        icmp_code = 0
        icmp_id = random.randint(0, 65535)
        originate_time = timestamp
        receive_time = 0
        transmit_time = 0
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        timestamps = struct.pack("!III", originate_time, receive_time, transmit_time)
        packet = header + timestamps
        checksum = self._calculate_checksum(packet)
        header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence
        )
        return header + timestamps

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum += checksum >> 16
        return ~checksum & 65535


@register_attack
class ICMPRedirectTunnelingAttack(BaseAttack):
    """
    ICMP Redirect Tunneling Attack - uses ICMP redirect messages for tunneling.
    """

    @property
    def name(self) -> str:
        return "icmp_redirect_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP redirect messages"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "gateway_ip": "192.168.1.1",
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP redirect tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            gateway_ip = context.params.get("gateway_ip", "192.168.1.1")
            chunks = self._split_payload(payload, 28)
            icmp_packets = []
            for i, chunk in enumerate(chunks):
                icmp_packet = self._create_redirect_packet(gateway_ip, chunk, i)
                icmp_packets.append(icmp_packet)
            combined_payload = b"".join(icmp_packets)
            segments = [(packet, i * 100) for i, packet in enumerate(icmp_packets)]
            packets_sent = len(icmp_packets)
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
                    "gateway_ip": gateway_ip,
                    "packet_count": len(icmp_packets),
                    "original_size": len(payload),
                    "tunneled_size": len(combined_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _split_payload(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """Split payload into chunks."""
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunks.append(payload[i : i + chunk_size])
        return chunks

    def _create_redirect_packet(
        self, gateway_ip: str, data: bytes, sequence: int
    ) -> bytes:
        """Create ICMP redirect packet."""
        icmp_type = 5
        icmp_code = 1
        icmp_id = random.randint(0, 65535)
        gateway_parts = gateway_ip.split(".")
        gateway_bytes = bytes([int(part) for part in gateway_parts])
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        redirect_data = gateway_bytes + data
        if len(redirect_data) < 8:
            redirect_data += b"\x00" * (8 - len(redirect_data))
        packet = header + redirect_data
        checksum = self._calculate_checksum(packet)
        header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence
        )
        return header + redirect_data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum += checksum >> 16
        return ~checksum & 65535


@register_attack
class ICMPCovertChannelAttack(BaseAttack):
    """
    ICMP Covert Channel Attack - creates covert communication channel.
    """

    @property
    def name(self) -> str:
        return "icmp_covert_channel"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Creates covert communication channel using ICMP"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "channel_type": "timing",
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP covert channel attack."""
        start_time = time.time()
        try:
            payload = context.payload
            channel_type = context.params.get("channel_type", "timing")
            if channel_type == "timing":
                icmp_packets = self._create_timing_channel(payload)
            elif channel_type == "size":
                icmp_packets = self._create_size_channel(payload)
            elif channel_type == "sequence":
                icmp_packets = self._create_sequence_channel(payload)
            else:
                icmp_packets = [payload]
            combined_payload = b"".join(icmp_packets)
            segments = [(packet, i * 200) for i, packet in enumerate(icmp_packets)]
            packets_sent = len(icmp_packets)
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
                    "channel_type": channel_type,
                    "packet_count": len(icmp_packets),
                    "original_size": len(payload),
                    "covert_size": len(combined_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_timing_channel(self, payload: bytes) -> List[bytes]:
        """Create timing-based covert channel."""
        packets = []
        for byte in payload:
            packet_size = 8 + byte % 56
            padding = b"\x00" * (packet_size - 8)
            icmp_packet = self._create_icmp_packet(8, 0, byte, padding)
            packets.append(icmp_packet)
        return packets

    def _create_size_channel(self, payload: bytes) -> List[bytes]:
        """Create size-based covert channel."""
        packets = []
        for i, byte in enumerate(payload):
            data_size = byte if byte > 0 else 1
            data = b"A" * data_size
            icmp_packet = self._create_icmp_packet(8, 0, i, data)
            packets.append(icmp_packet)
        return packets

    def _create_sequence_channel(self, payload: bytes) -> List[bytes]:
        """Create sequence-based covert channel."""
        packets = []
        for i, byte in enumerate(payload):
            icmp_packet = self._create_icmp_packet(8, 0, byte, b"covert")
            packets.append(icmp_packet)
        return packets

    def _create_icmp_packet(
        self, icmp_type: int, icmp_code: int, sequence: int, data: bytes
    ) -> bytes:
        """Create ICMP packet."""
        icmp_id = random.randint(0, 65535)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        packet = header + data
        checksum = self._calculate_checksum(packet)
        header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence
        )
        return header + data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum += checksum >> 16
        return ~checksum & 65535
