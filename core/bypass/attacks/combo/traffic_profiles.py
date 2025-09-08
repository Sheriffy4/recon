"""
Traffic Profiles for Popular Applications

Implements realistic traffic patterns for popular applications to enable
effective traffic mimicry and behavioral DPI evasion.
"""

import asyncio
import random
import re
from typing import List, Tuple
from core.bypass.attacks.combo.traffic_mimicry import (
    TrafficProfile,
    TrafficPattern,
    TrafficType,
)
from core.bypass.attacks.base import AttackContext


class ZoomTrafficProfile(TrafficProfile):
    """
    Traffic profile for Zoom video conferencing.

    Characteristics:
    - High bandwidth usage with consistent packet flow
    - Mix of audio (small packets) and video (larger packets)
    - Regular keep-alive packets
    - Bidirectional traffic with slight upstream bias
    """

    @property
    def name(self) -> str:
        return "zoom"

    @property
    def traffic_type(self) -> TrafficType:
        return TrafficType.VIDEO_CALL

    @property
    def pattern(self) -> TrafficPattern:
        return TrafficPattern(
            packet_sizes=(200, 1400, 900),
            inter_packet_delays=(15.0, 40.0, 25.0),
            burst_size_range=(3, 8),
            burst_interval_range=(30.0, 50.0),
            session_duration_range=(300.0, 3600.0),
            idle_periods=[(0.5, 2.0)],
            bidirectional_ratio=0.85,
            keep_alive_interval=15.0,
            protocol_headers={
                "user_agent": b"Zoom/5.0",
                "content_type": b"application/octet-stream",
            },
            content_patterns=[b"\x00\x01\x02\x03", b"ZOOM_DATA", b"\xff\xfe\xfd\xfc"],
        )

    def should_use_for_domain(self, domain: str) -> bool:
        """Use for video conferencing domains."""
        video_patterns = [
            ".*zoom.*",
            ".*meet.*",
            ".*webex.*",
            ".*teams.*",
            ".*skype.*",
            ".*conference.*",
            ".*video.*call.*",
        ]
        domain_lower = domain.lower()
        return any((re.match(pattern, domain_lower) for pattern in video_patterns))

    async def generate_packet_sequence(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, float]]:
        """Generate Zoom-like packet sequence."""
        sequence = []
        remaining_payload = payload
        sequence.extend(self._generate_connection_setup())
        while remaining_payload:
            burst_size = random.randint(*self.pattern.burst_size_range)
            for _ in range(burst_size):
                if not remaining_payload:
                    break
                if random.random() < 0.3:
                    packet_size = random.randint(200, 400)
                else:
                    packet_size = random.randint(800, 1400)
                chunk_size = min(len(remaining_payload), packet_size - 50)
                chunk = remaining_payload[:chunk_size]
                remaining_payload = remaining_payload[chunk_size:]
                packet_data = self._create_zoom_packet(chunk)
                delay = self.get_random_delay()
                await asyncio.sleep(delay / 1000.0)
                sequence.append((packet_data, delay))
            if remaining_payload:
                burst_delay = random.uniform(*self.pattern.burst_interval_range)
                await asyncio.sleep(burst_delay / 1000.0)
                sequence.append((b"", burst_delay))
        sequence.extend(self._generate_keep_alive_packets())
        return sequence

    def _generate_connection_setup(self) -> List[Tuple[bytes, float]]:
        """Generate connection setup packets."""
        setup_packets = [
            (b"ZOOM_HELLO\x00\x01", 0.0),
            (b"ZOOM_AUTH\x00\x02", 50.0),
            (b"ZOOM_READY\x00\x03", 30.0),
        ]
        return setup_packets

    def _generate_keep_alive_packets(self) -> List[Tuple[bytes, float]]:
        """Generate keep-alive packets."""
        keep_alive_packets = [
            (b"ZOOM_PING\x00\x04", 1000.0),
            (b"ZOOM_PONG\x00\x05", 100.0),
        ]
        return keep_alive_packets

    def _create_zoom_packet(self, payload_chunk: bytes) -> bytes:
        """Create a packet that looks like Zoom traffic."""
        header = b"\x00\x01\x02\x03"
        header += len(payload_chunk).to_bytes(2, "big")
        header += b"\x00\x00"
        target_size = self.get_random_packet_size()
        current_size = len(header) + len(payload_chunk)
        padding = self.create_padding(target_size, current_size)
        return header + payload_chunk + padding


class TelegramTrafficProfile(TrafficProfile):
    """
    Traffic profile for Telegram messaging.

    Characteristics:
    - Bursty traffic patterns (messages sent in groups)
    - Small to medium packet sizes
    - Irregular timing based on user interaction
    - Encrypted payload patterns
    """

    @property
    def name(self) -> str:
        return "telegram"

    @property
    def traffic_type(self) -> TrafficType:
        return TrafficType.MESSAGING

    @property
    def pattern(self) -> TrafficPattern:
        return TrafficPattern(
            packet_sizes=(100, 800, 300),
            inter_packet_delays=(100.0, 2000.0, 500.0),
            burst_size_range=(1, 4),
            burst_interval_range=(500.0, 5000.0),
            session_duration_range=(60.0, 1800.0),
            idle_periods=[(5.0, 30.0), (60.0, 300.0)],
            bidirectional_ratio=0.6,
            keep_alive_interval=60.0,
            protocol_headers={
                "user_agent": b"Telegram/9.0",
                "content_type": b"application/x-telegram",
            },
            content_patterns=[b"\xef\xbb\xbf", b"TG_MSG", b"\x00\x00\x00\x01"],
        )

    def should_use_for_domain(self, domain: str) -> bool:
        """Use for messaging and social domains."""
        messaging_patterns = [
            ".*telegram.*",
            ".*whatsapp.*",
            ".*signal.*",
            ".*discord.*",
            ".*slack.*",
            ".*messenger.*",
            ".*chat.*",
            ".*msg.*",
        ]
        domain_lower = domain.lower()
        return any((re.match(pattern, domain_lower) for pattern in messaging_patterns))

    async def generate_packet_sequence(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, float]]:
        """Generate Telegram-like packet sequence."""
        sequence = []
        remaining_payload = payload
        sequence.extend(self._generate_telegram_handshake())
        while remaining_payload:
            if random.random() < 0.3:
                delay = random.uniform(100, 500)
                await asyncio.sleep(delay / 1000.0)
                sequence.append((b"TG_TYPING\x00\x01", delay))
            burst_size = random.randint(*self.pattern.burst_size_range)
            for _ in range(burst_size):
                if not remaining_payload:
                    break
                packet_size = random.randint(150, 600)
                chunk_size = min(len(remaining_payload), packet_size - 30)
                chunk = remaining_payload[:chunk_size]
                remaining_payload = remaining_payload[chunk_size:]
                packet_data = self._create_telegram_packet(chunk)
                delay = self.get_random_delay()
                await asyncio.sleep(delay / 1000.0)
                sequence.append((packet_data, delay))
            if remaining_payload:
                thinking_delay = random.uniform(1000.0, 10000.0)
                await asyncio.sleep(thinking_delay / 1000.0)
                sequence.append((b"", thinking_delay))
        return sequence

    def _generate_telegram_handshake(self) -> List[Tuple[bytes, float]]:
        """Generate Telegram connection handshake."""
        handshake = [
            (b"TG_CONNECT\x00\x01", 0.0),
            (b"TG_AUTH\x00\x02", 100.0),
            (b"TG_SYNC\x00\x03", 200.0),
        ]
        return handshake

    def _create_telegram_packet(self, payload_chunk: bytes) -> bytes:
        """Create a Telegram-like packet."""
        header = b"\xef\xbb\xbf"
        header += b"TG_MSG"
        header += len(payload_chunk).to_bytes(2, "big")
        encrypted_chunk = bytes([b ^ 170 for b in payload_chunk])
        target_size = self.get_random_packet_size()
        current_size = len(header) + len(encrypted_chunk)
        padding = self.create_padding(target_size, current_size)
        return header + encrypted_chunk + padding


class WhatsAppTrafficProfile(TrafficProfile):
    """
    Traffic profile for WhatsApp messaging.

    Characteristics:
    - Similar to Telegram but with different timing patterns
    - More frequent keep-alives
    - Smaller average packet sizes
    - Status update patterns
    """

    @property
    def name(self) -> str:
        return "whatsapp"

    @property
    def traffic_type(self) -> TrafficType:
        return TrafficType.MESSAGING

    @property
    def pattern(self) -> TrafficPattern:
        return TrafficPattern(
            packet_sizes=(80, 600, 250),
            inter_packet_delays=(50.0, 1000.0, 300.0),
            burst_size_range=(1, 3),
            burst_interval_range=(300.0, 3000.0),
            session_duration_range=(30.0, 900.0),
            idle_periods=[(2.0, 15.0), (30.0, 120.0)],
            bidirectional_ratio=0.75,
            keep_alive_interval=30.0,
            protocol_headers={
                "user_agent": b"WhatsApp/2.0",
                "content_type": b"application/x-whatsapp",
            },
            content_patterns=[b"WA_MSG", b"\x00\x01\x02", b"STATUS_UPDATE"],
        )

    def should_use_for_domain(self, domain: str) -> bool:
        """Use specifically for WhatsApp and similar instant messaging."""
        whatsapp_patterns = [
            ".*whatsapp.*",
            ".*wa\\.me.*",
            ".*instagram.*direct.*",
            ".*fb.*messenger.*",
        ]
        domain_lower = domain.lower()
        return any((re.match(pattern, domain_lower) for pattern in whatsapp_patterns))

    async def generate_packet_sequence(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, float]]:
        """Generate WhatsApp-like packet sequence."""
        sequence = []
        remaining_payload = payload
        sequence.extend(self._generate_whatsapp_connection())
        sequence.extend(await self._generate_status_updates())
        while remaining_payload:
            packet_size = random.randint(100, 400)
            chunk_size = min(len(remaining_payload), packet_size - 25)
            chunk = remaining_payload[:chunk_size]
            remaining_payload = remaining_payload[chunk_size:]
            packet_data = self._create_whatsapp_packet(chunk)
            delay = self.get_random_delay()
            await asyncio.sleep(delay / 1000.0)
            sequence.append((packet_data, delay))
            if random.random() < 0.8:
                await asyncio.sleep(0.05)
                sequence.append((b"WA_DELIVERED\x00\x01", 50.0))
            if random.random() < 0.6:
                delay = random.uniform(100, 2000)
                await asyncio.sleep(delay / 1000.0)
                sequence.append((b"WA_READ\x00\x02", delay))
        return sequence

    def _generate_whatsapp_connection(self) -> List[Tuple[bytes, float]]:
        """Generate WhatsApp connection sequence."""
        connection = [
            (b"WA_HELLO\x00\x01", 0.0),
            (b"WA_AUTH\x00\x02", 80.0),
            (b"WA_PRESENCE\x00\x03", 50.0),
        ]
        return connection

    async def _generate_status_updates(self) -> List[Tuple[bytes, float]]:
        """Generate status update packets."""
        status_updates = []
        await asyncio.sleep(0.1)
        status_updates.append((b"WA_ONLINE\x00\x04", 100.0))
        await asyncio.sleep(0.2)
        status_updates.append((b"WA_TYPING\x00\x05", 200.0))
        await asyncio.sleep(1.0)
        status_updates.append((b"WA_STOP_TYPING\x00\x06", 1000.0))
        return status_updates

    def _create_whatsapp_packet(self, payload_chunk: bytes) -> bytes:
        """Create a WhatsApp-like packet."""
        header = b"WA_MSG"
        header += len(payload_chunk).to_bytes(2, "big")
        header += b"\x00\x01"
        obfuscated_chunk = bytes([(b + 13) % 256 for b in payload_chunk])
        target_size = self.get_random_packet_size()
        current_size = len(header) + len(obfuscated_chunk)
        padding = self.create_padding(target_size, current_size)
        return header + obfuscated_chunk + padding


class GenericBrowsingProfile(TrafficProfile):
    """
    Generic web browsing traffic profile.

    Used as a fallback when no specific application profile matches.
    Mimics typical HTTPS web browsing patterns.
    """

    @property
    def name(self) -> str:
        return "generic_browsing"

    @property
    def traffic_type(self) -> TrafficType:
        return TrafficType.BROWSING

    @property
    def pattern(self) -> TrafficPattern:
        return TrafficPattern(
            packet_sizes=(200, 1500, 700),
            inter_packet_delays=(20.0, 500.0, 100.0),
            burst_size_range=(2, 6),
            burst_interval_range=(100.0, 1000.0),
            session_duration_range=(120.0, 1800.0),
            idle_periods=[(1.0, 10.0), (30.0, 180.0)],
            bidirectional_ratio=0.65,
            keep_alive_interval=45.0,
            protocol_headers={
                "user_agent": b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "content_type": b"text/html",
            },
            content_patterns=[b"HTTP/1.1", b"GET /", b"POST /"],
        )

    def should_use_for_domain(self, domain: str) -> bool:
        """Use as fallback for any domain."""
        return True

    async def generate_packet_sequence(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, float]]:
        """Generate generic browsing packet sequence."""
        sequence = []
        remaining_payload = payload
        sequence.append(
            (
                (
                    b"GET / HTTP/1.1\r\nHost: " + context.domain.encode()
                    if context.domain
                    else b"example.com" + b"\r\n\r\n"
                ),
                0.0,
            )
        )
        while remaining_payload:
            packet_size = random.randint(300, 1200)
            chunk_size = min(len(remaining_payload), packet_size - 50)
            chunk = remaining_payload[:chunk_size]
            remaining_payload = remaining_payload[chunk_size:]
            packet_data = self._create_http_packet(chunk)
            delay = self.get_random_delay()
            await asyncio.sleep(delay / 1000.0)
            sequence.append((packet_data, delay))
        return sequence

    def _create_http_packet(self, payload_chunk: bytes) -> bytes:
        """Create an HTTP-like packet."""
        header = (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(payload_chunk)).encode()
            + b"\r\n\r\n"
        )
        return header + payload_chunk
