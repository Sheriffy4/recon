"""
ICMP Obfuscation Attacks

Advanced ICMP-based obfuscation techniques that use ICMP protocol features
to tunnel data and evade DPI detection through legitimate-looking ICMP traffic.
"""

import asyncio
import time
import random
import struct
from typing import List, Dict, Any, Tuple
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.obfuscation.segment_schema import make_segment, next_seq_offset


@register_attack
class ICMPDataTunnelingObfuscationAttack(BaseAttack):
    """
    ICMP Data Tunneling Attack.

    Tunnels data through ICMP echo request/reply packets by embedding
    data in the ICMP payload section.
    """

    @property
    def name(self) -> str:
        return "icmp_data_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP echo request/reply packets"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "packet_size": 64,
            "use_replies": True,
            "randomize_id": True,
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP data tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            packet_size = int(context.params.get("packet_size", 64) or 64)
            use_replies = context.params.get("use_replies", True)
            randomize_id = context.params.get("randomize_id", True)
            icmp_packets = self._create_icmp_data_packets(
                payload, packet_size, use_replies, randomize_id, context
            )
            segments = []
            seq_offset = 0
            for i, packet in enumerate(icmp_packets):
                delay = random.randint(100, 1000)
                packet_type = "echo_reply" if use_replies and i % 2 == 1 else "echo_request"
                segments.append(
                    make_segment(
                        packet,
                        seq_offset,
                        delay_ms=delay,
                        protocol="icmp",
                        attack=self.name,
                        segment_index=i,
                        segment_kind="data",
                        direction="unknown",
                        packet_type=packet_type,
                        packet_size=packet_size,
                        sequence=i,
                    )
                )
                seq_offset = next_seq_offset(seq_offset, len(packet))
            await asyncio.sleep(0)
            packets_sent = len(icmp_packets)
            bytes_sent = sum((len(packet) for packet in icmp_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="icmp_data_tunneling_obfuscation",
                metadata={
                    "packet_size": packet_size,
                    "use_replies": use_replies,
                    "randomize_id": randomize_id,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="icmp_data_tunneling_obfuscation",
            )

    def _create_icmp_data_packets(
        self,
        payload: bytes,
        packet_size: int,
        use_replies: bool,
        randomize_id: bool,
        context: AttackContext,
    ) -> List[bytes]:
        """Create ICMP packets with data tunneling."""
        packets = []
        # ICMP header is 8 bytes; guard against invalid packet_size.
        packet_size = max(16, int(packet_size or 64))
        data_per_packet = max(1, packet_size - 8)
        for i in range(0, len(payload), data_per_packet):
            chunk = payload[i : i + data_per_packet]
            if len(chunk) < data_per_packet:
                padding = b"\x00" * (data_per_packet - len(chunk))
                chunk = chunk + padding
            echo_request = self._create_icmp_echo_packet(
                chunk, i // data_per_packet, randomize_id, False
            )
            packets.append(echo_request)
            if use_replies:
                echo_reply = self._create_icmp_echo_packet(
                    chunk, i // data_per_packet, randomize_id, True
                )
                packets.append(echo_reply)
        return packets

    def _create_icmp_echo_packet(
        self, data: bytes, sequence: int, randomize_id: bool, is_reply: bool
    ) -> bytes:
        """Create ICMP echo request or reply packet."""
        icmp_type = 0 if is_reply else 8
        code = 0
        checksum = 0
        if randomize_id:
            packet_id = random.randint(1, 65535)
        else:
            packet_id = 12345
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        packet = header + data
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        return header + data

    def _calculate_icmp_checksum(self, packet: bytes) -> int:
        """Calculate ICMP checksum."""
        checksum = 0
        if len(packet) % 2 == 1:
            packet += b"\x00"
        for i in range(0, len(packet), 2):
            word = (packet[i] << 8) + packet[i + 1]
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        return ~checksum & 65535


@register_attack
class ICMPTimestampTunnelingObfuscationAttack(BaseAttack):
    """
    ICMP Timestamp Tunneling Attack.

    Tunnels data through ICMP timestamp request/reply packets by
    encoding data in timestamp fields.
    """

    @property
    def name(self) -> str:
        return "icmp_timestamp_tunneling_obfuscation"

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
        return {
            "use_replies": True,
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP timestamp tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            use_replies = context.params.get("use_replies", True)
            icmp_packets = self._create_icmp_timestamp_packets(payload, use_replies)
            segments = []
            seq_offset = 0
            for i, packet in enumerate(icmp_packets):
                delay = random.randint(500, 2000)
                packet_type = (
                    "timestamp_reply" if use_replies and i % 2 == 1 else "timestamp_request"
                )
                segments.append(
                    make_segment(
                        packet,
                        seq_offset,
                        delay_ms=delay,
                        protocol="icmp",
                        attack=self.name,
                        segment_index=i,
                        segment_kind="control",
                        direction="unknown",
                        packet_type=packet_type,
                        sequence=(i // 2 if use_replies else i),
                    )
                )
                seq_offset = next_seq_offset(seq_offset, len(packet))
            await asyncio.sleep(0)
            packets_sent = len(icmp_packets)
            bytes_sent = sum((len(packet) for packet in icmp_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="icmp_timestamp_tunneling_obfuscation",
                metadata={
                    "use_replies": use_replies,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "data_per_packet": 4,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="icmp_timestamp_tunneling_obfuscation",
            )

    def _create_icmp_timestamp_packets(self, payload: bytes, use_replies: bool) -> List[bytes]:
        """Create ICMP timestamp packets with data encoding."""
        packets = []
        data_per_packet = 4
        for i in range(0, len(payload), data_per_packet):
            chunk = payload[i : i + data_per_packet]
            if len(chunk) < data_per_packet:
                chunk = chunk + b"\x00" * (data_per_packet - len(chunk))
            timestamp_request = self._create_icmp_timestamp_packet(
                chunk, i // data_per_packet, False
            )
            packets.append(timestamp_request)
            if use_replies:
                timestamp_reply = self._create_icmp_timestamp_packet(
                    chunk, i // data_per_packet, True
                )
                packets.append(timestamp_reply)
        return packets

    def _create_icmp_timestamp_packet(self, data: bytes, sequence: int, is_reply: bool) -> bytes:
        """Create ICMP timestamp request or reply packet."""
        icmp_type = 14 if is_reply else 13
        code = 0
        checksum = 0
        packet_id = random.randint(1, 65535)
        originate_timestamp = struct.unpack("!I", data)[0]
        receive_timestamp = int(time.time() * 1000) % 2**32
        transmit_timestamp = receive_timestamp + random.randint(1, 10)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        timestamps = struct.pack("!III", originate_timestamp, receive_timestamp, transmit_timestamp)
        packet = header + timestamps
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        return header + timestamps

    def _calculate_icmp_checksum(self, packet: bytes) -> int:
        """Calculate ICMP checksum."""
        checksum = 0
        if len(packet) % 2 == 1:
            packet += b"\x00"
        for i in range(0, len(packet), 2):
            word = (packet[i] << 8) + packet[i + 1]
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        return ~checksum & 65535


@register_attack
class ICMPRedirectTunnelingObfuscationAttack(BaseAttack):
    """
    ICMP Redirect Tunneling Attack.

    Tunnels data through ICMP redirect packets by encoding data
    in the gateway IP address field.
    """

    @property
    def name(self) -> str:
        return "icmp_redirect_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP redirect gateway fields"

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
            "redirect_code": 1,
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP redirect tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            gateway_ip = context.params.get("gateway_ip", "192.168.1.1")
            redirect_code = context.params.get("redirect_code", 1)
            icmp_packets = self._create_icmp_redirect_packets(payload, gateway_ip, redirect_code)
            segments = []
            seq_offset = 0
            for i, packet in enumerate(icmp_packets):
                delay = random.randint(1000, 5000)
                segments.append(
                    make_segment(
                        packet,
                        seq_offset,
                        delay_ms=delay,
                        protocol="icmp",
                        attack=self.name,
                        segment_index=i,
                        segment_kind="control",
                        direction="unknown",
                        packet_type="redirect",
                        redirect_code=redirect_code,
                        sequence=i,
                    )
                )
                seq_offset = next_seq_offset(seq_offset, len(packet))
            await asyncio.sleep(0)
            packets_sent = len(icmp_packets)
            bytes_sent = sum((len(packet) for packet in icmp_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="icmp_redirect_tunneling_obfuscation",
                metadata={
                    "gateway_ip": gateway_ip,
                    "redirect_code": redirect_code,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "data_per_packet": 4,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="icmp_redirect_tunneling_obfuscation",
            )

    def _create_icmp_redirect_packets(
        self, payload: bytes, gateway_ip: str, redirect_code: int
    ) -> List[bytes]:
        """Create ICMP redirect packets with data encoding."""
        packets = []
        data_per_packet = 4
        for i in range(0, len(payload), data_per_packet):
            chunk = payload[i : i + data_per_packet]
            if len(chunk) < data_per_packet:
                chunk = chunk + b"\x00" * (data_per_packet - len(chunk))
            redirect_packet = self._create_icmp_redirect_packet(chunk, gateway_ip, redirect_code)
            packets.append(redirect_packet)
        return packets

    def _create_icmp_redirect_packet(
        self, data: bytes, gateway_ip: str, redirect_code: int
    ) -> bytes:
        """Create ICMP redirect packet."""
        icmp_type = 5
        code = redirect_code
        checksum = 0
        encoded_gateway = data
        original_header = self._create_fake_ip_header()
        header = struct.pack("!BBH", icmp_type, code, checksum)
        packet = header + encoded_gateway + original_header
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack("!BBH", icmp_type, code, checksum)
        return header + encoded_gateway + original_header

    def _create_fake_ip_header(self) -> bytes:
        """Create fake IP header for redirect packet."""
        version_ihl = 69
        tos = 0
        length = 28
        packet_id = random.randint(1, 65535)
        flags_frag = 16384
        ttl = 64
        protocol = 1
        checksum = 0
        src_ip = struct.pack("!I", random.randint(0, 2**32 - 1))
        dst_ip = struct.pack("!I", random.randint(0, 2**32 - 1))
        header = struct.pack(
            "!BBHHHBBH",
            version_ihl,
            tos,
            length,
            packet_id,
            flags_frag,
            ttl,
            protocol,
            checksum,
        )
        header += src_ip + dst_ip
        return header

    def _calculate_icmp_checksum(self, packet: bytes) -> int:
        """Calculate ICMP checksum."""
        checksum = 0
        if len(packet) % 2 == 1:
            packet += b"\x00"
        for i in range(0, len(packet), 2):
            word = (packet[i] << 8) + packet[i + 1]
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        return ~checksum & 65535


@register_attack
class ICMPCovertChannelObfuscationAttack(BaseAttack):
    """
    ICMP Covert Channel Attack.

    Creates covert channels using various ICMP packet characteristics
    like timing, size variations, and sequence patterns.
    """

    @property
    def name(self) -> str:
        return "icmp_covert_channel_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Creates covert channels using ICMP packet characteristics"

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
            "base_interval": 1000,
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP covert channel attack."""
        start_time = time.time()
        try:
            payload = context.payload
            channel_type = context.params.get("channel_type", "timing")
            base_interval = context.params.get("base_interval", 1000)
            if channel_type not in ["timing", "size", "sequence"]:
                raise ValueError(f"Invalid channel_type: {channel_type}")
            if channel_type == "timing":
                icmp_packets, segments = await self._create_timing_covert_channel(
                    payload, base_interval
                )
            elif channel_type == "size":
                icmp_packets, segments = await self._create_size_covert_channel(payload)
            elif channel_type == "sequence":
                icmp_packets, segments = await self._create_sequence_covert_channel(payload)
            packets_sent = len(icmp_packets)
            bytes_sent = sum((len(packet) for packet in icmp_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="icmp_covert_channel_obfuscation",
                metadata={
                    "channel_type": channel_type,
                    "base_interval": base_interval,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="icmp_covert_channel_obfuscation",
            )

    async def _create_timing_covert_channel(
        self, payload: bytes, base_interval: int
    ) -> Tuple[List[bytes], List[Tuple[bytes, int, Dict[str, Any]]]]:
        """Create timing-based covert channel."""
        packets = []
        segments = []
        seq_offset = 0
        for i, byte in enumerate(payload):
            for bit_pos in range(8):
                packet = self._create_standard_icmp_echo(i * 8 + bit_pos)
                packets.append(packet)
                bit = byte >> 7 - bit_pos & 1
                delay = base_interval if bit == 0 else base_interval * 2
                segments.append(
                    make_segment(
                        packet,
                        seq_offset,
                        delay_ms=delay,
                        protocol="icmp",
                        attack=self.name,
                        segment_index=len(segments),
                        segment_kind="covert",
                        direction="unknown",
                        channel_type="timing",
                        byte_index=i,
                        bit_position=bit_pos,
                        bit_value=bit,
                        # keep legacy key too (compat)
                        delay=delay,
                    )
                )
                seq_offset = next_seq_offset(seq_offset, len(packet))
        return (packets, segments)

    async def _create_size_covert_channel(
        self, payload: bytes
    ) -> Tuple[List[bytes], List[Tuple[bytes, int, Dict[str, Any]]]]:
        """Create size-based covert channel."""
        packets = []
        segments = []
        seq_offset = 0
        for i, byte in enumerate(payload):
            padding_size = byte
            packet = self._create_variable_size_icmp_echo(i, padding_size)
            packets.append(packet)
            delay = random.randint(500, 1500)
            segments.append(
                make_segment(
                    packet,
                    seq_offset,
                    delay_ms=delay,
                    protocol="icmp",
                    attack=self.name,
                    segment_index=i,
                    segment_kind="covert",
                    direction="unknown",
                    channel_type="size",
                    byte_index=i,
                    byte_value=byte,
                    padding_size=padding_size,
                    packet_size=len(packet),
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(packet))
        return (packets, segments)

    async def _create_sequence_covert_channel(
        self, payload: bytes
    ) -> Tuple[List[bytes], List[Tuple[bytes, int, Dict[str, Any]]]]:
        """Create sequence-based covert channel."""
        packets = []
        segments = []
        seq_offset = 0
        for i, byte in enumerate(payload):
            sequence = byte * 256 + i
            packet = self._create_icmp_echo_with_sequence(sequence)
            packets.append(packet)
            delay = random.randint(800, 1200)
            segments.append(
                make_segment(
                    packet,
                    seq_offset,
                    delay_ms=delay,
                    protocol="icmp",
                    attack=self.name,
                    segment_index=i,
                    segment_kind="covert",
                    direction="unknown",
                    channel_type="sequence",
                    byte_index=i,
                    byte_value=byte,
                    sequence_number=sequence,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(packet))
        return (packets, segments)

    def _create_standard_icmp_echo(self, sequence: int) -> bytes:
        """Create standard ICMP echo packet."""
        icmp_type = 8
        code = 0
        checksum = 0
        packet_id = 12345
        payload = b"abcdefghijklmnopqrstuvwabcdefghi"
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        packet = header + payload
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        return header + payload

    def _create_variable_size_icmp_echo(self, sequence: int, padding_size: int) -> bytes:
        """Create ICMP echo packet with variable size."""
        icmp_type = 8
        code = 0
        checksum = 0
        packet_id = 12345
        base_payload = b"ping_data_"
        padding = b"x" * padding_size
        payload = base_payload + padding
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        packet = header + payload
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        return header + payload

    def _create_icmp_echo_with_sequence(self, sequence: int) -> bytes:
        """Create ICMP echo packet with specific sequence number."""
        icmp_type = 8
        code = 0
        checksum = 0
        packet_id = 12345
        payload = b"sequence_encoded_data_here_padding"
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        packet = header + payload
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, sequence)
        return header + payload

    def _calculate_icmp_checksum(self, packet: bytes) -> int:
        """Calculate ICMP checksum."""
        checksum = 0
        if len(packet) % 2 == 1:
            packet += b"\x00"
        for i in range(0, len(packet), 2):
            word = (packet[i] << 8) + packet[i + 1]
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        return ~checksum & 65535
