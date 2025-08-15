# recon/core/bypass/attacks/obfuscation/icmp_obfuscation.py
"""
ICMP Obfuscation Attacks

Advanced techniques to tunnel data or create covert channels using various
ICMP message types to evade DPI detection.
"""

import time
import struct
import random
from typing import List, Dict, Any
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


@register_attack
class ICMPDataTunnelingObfuscationAttack(BaseAttack):
    """
    Embeds data in the payload of ICMP echo request packets.
    """

    @property
    def name(self) -> str:
        return "icmp_data_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP echo packet payloads"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP data tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            icmp_type = context.params.get("icmp_type", 8)  # Echo Request
            icmp_code = context.params.get("icmp_code", 0)
            packet_size = context.params.get("packet_size", 64)

            if packet_size <= 8:
                raise ValueError("packet_size must be greater than 8")

            chunks = self._split_payload(payload, packet_size - 8)
            icmp_packets = [self._create_icmp_packet(icmp_type, icmp_code, i, chunk) for i, chunk in enumerate(chunks)]

            segments = [(packet, i * 50, {"icmp_type": icmp_type, "sequence": i}) for i, packet in enumerate(icmp_packets)]

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=(time.time() - start_time) * 1000,
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "icmp_type": icmp_type,
                    "packet_count": len(segments),
                    "original_size": len(payload),
                    "segments": segments
                }
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used=self.name
            )

    def _split_payload(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """Split payload into chunks."""
        return [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]

    def _create_icmp_packet(self, icmp_type: int, icmp_code: int, sequence: int, data: bytes) -> bytes:
        """Create ICMP packet with embedded data."""
        icmp_id = random.randint(0, 65535)
        # Create header without checksum to calculate checksum
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        checksum = self._calculate_checksum(header + data)
        # Create final header with correct checksum
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence)
        return header + data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        # Pad to even number of bytes
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        # Sum all 16-bit words
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        # Fold 32-bit sum to 16 bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # Take one's complement
        return (~checksum) & 0xFFFF


@register_attack
class ICMPTimestampTunnelingObfuscationAttack(BaseAttack):
    """
    Tunnels data by encoding it in the timestamp fields of ICMP packets.
    """

    @property
    def name(self) -> str:
        return "icmp_timestamp_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP timestamp fields"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP timestamp tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            # Each chunk must be 4 bytes to fit in the timestamp field
            chunks = self._split_payload(payload, 4)

            icmp_packets = []
            for i, chunk in enumerate(chunks):
                # Pad chunk to 4 bytes if it's the last one and is smaller
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, b'\x00')

                timestamp_value = struct.unpack("!I", chunk)[0]
                icmp_packet = self._create_timestamp_packet(i, timestamp_value)
                icmp_packets.append(icmp_packet)

            segments = [(packet, i * 100, {"sequence": i}) for i, packet in enumerate(icmp_packets)]

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=(time.time() - start_time) * 1000,
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "packet_count": len(segments),
                    "original_size": len(payload),
                    "segments": segments
                }
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used=self.name
            )

    def _split_payload(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """Split payload into chunks."""
        return [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]

    def _create_timestamp_packet(self, sequence: int, timestamp: int) -> bytes:
        """Create ICMP timestamp packet."""
        icmp_type = 13  # Timestamp Request
        icmp_code = 0
        icmp_id = random.randint(0, 65535)

        # ICMP timestamp packet: type(1) + code(1) + checksum(2) + id(2) + sequence(2) + originate(4) + receive(4) + transmit(4)
        # We hide data in the originate timestamp field.
        originate_time = timestamp
        receive_time = 0
        transmit_time = 0

        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        timestamps = struct.pack("!III", originate_time, receive_time, transmit_time)

        checksum = self._calculate_checksum(header + timestamps)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence)
        return header + timestamps

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return (~checksum) & 0xFFFF


@register_attack
class ICMPCovertChannelObfuscationAttack(BaseAttack):
    """
    Creates a covert communication channel using various ICMP properties.
    """

    @property
    def name(self) -> str:
        return "icmp_covert_channel_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Creates covert communication channel using ICMP properties (timing, size, sequence)"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

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
                raise ValueError(f"Invalid channel_type: {channel_type}")

            segments = [(packet, i * 200, {"channel_type": channel_type}) for i, packet in enumerate(icmp_packets)]

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=(time.time() - start_time) * 1000,
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "channel_type": channel_type,
                    "packet_count": len(segments),
                    "original_size": len(payload),
                    "segments": segments
                }
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used=self.name
            )

    def _create_timing_channel(self, payload: bytes) -> List[bytes]:
        """Create timing-based covert channel."""
        packets = []
        for byte in payload:
            # Use byte value to determine packet timing/size
            packet_size = 8 + (byte % 56)  # Variable size based on data
            padding = b"\x00" * (packet_size - 8)
            icmp_packet = self._create_icmp_packet(8, 0, byte, padding)
            packets.append(icmp_packet)
        return packets

    def _create_size_channel(self, payload: bytes) -> List[bytes]:
        """Create size-based covert channel."""
        packets = []
        for i, byte in enumerate(payload):
            # Use byte value to determine packet size
            data_size = byte if byte > 0 else 1
            data = b"A" * data_size
            icmp_packet = self._create_icmp_packet(8, 0, i, data)
            packets.append(icmp_packet)
        return packets

    def _create_sequence_channel(self, payload: bytes) -> List[bytes]:
        """Create sequence-based covert channel."""
        packets = []
        for i, byte in enumerate(payload):
            # Use byte value as sequence number
            icmp_packet = self._create_icmp_packet(8, 0, byte, b"covert")
            packets.append(icmp_packet)
        return packets

    def _create_icmp_packet(self, icmp_type: int, icmp_code: int, sequence: int, data: bytes) -> bytes:
        """Create ICMP packet."""
        icmp_id = random.randint(0, 65535)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        checksum = self._calculate_checksum(header + data)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence)
        return header + data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return (~checksum) & 0xFFFF


@register_attack
class ICMPRedirectTunnelingObfuscationAttack(BaseAttack):
    """
    Tunnels data by embedding it in the IP header portion of ICMP redirect messages.
    """

    @property
    def name(self) -> str:
        return "icmp_redirect_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Tunnels data through ICMP redirect messages"

    @property
    def supported_protocols(self) -> List[str]:
        return ["icmp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ICMP redirect tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            gateway_ip = context.params.get("gateway_ip", "192.168.1.254")

            # Max data in redirect is 28 bytes (IP header + 8 bytes of original datagram)
            chunks = self._split_payload(payload, 28)

            icmp_packets = [self._create_redirect_packet(gateway_ip, chunk, i) for i, chunk in enumerate(chunks)]

            segments = [(packet, i * 100, {"gateway_ip": gateway_ip, "sequence": i}) for i, packet in enumerate(icmp_packets)]

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=(time.time() - start_time) * 1000,
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "gateway_ip": gateway_ip,
                    "packet_count": len(segments),
                    "original_size": len(payload),
                    "segments": segments
                }
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used=self.name
            )

    def _split_payload(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """Split payload into chunks."""
        return [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]

    def _create_redirect_packet(self, gateway_ip: str, data: bytes, sequence: int) -> bytes:
        """Create ICMP redirect packet."""
        icmp_type = 5  # Redirect
        icmp_code = 1  # Redirect for host
        icmp_id = random.randint(0, 65535)

        try:
            gateway_bytes = bytes(map(int, gateway_ip.split('.')))
        except ValueError:
            raise ValueError("Invalid gateway_ip format. Must be like 'x.x.x.x'")

        # The data portion of an ICMP redirect includes the gateway address
        # and the original IP header + 8 bytes of the datagram that triggered it.
        # We use this space to hide our data.
        redirect_data = gateway_bytes + data.ljust(28, b'\x00') # Pad to 28 bytes

        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, sequence)
        checksum = self._calculate_checksum(header + redirect_data)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, sequence)
        return header + redirect_data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return (~checksum) & 0xFFFF
