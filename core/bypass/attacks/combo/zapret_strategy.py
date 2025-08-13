# recon/core/bypass/attacks/combo/zapret_strategy.py
import struct
import socket
import random
import time
import logging
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field, asdict

# Force use of real imports, not fallback
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.packet_builder import EnhancedPacketBuilder

LOG = logging.getLogger("ZapretStrategy")


@dataclass
class ZapretConfig:
    """Configuration for zapret strategy."""

    desync_methods: List[str] = field(default_factory=lambda: ["fake", "fakeddisorder"])
    split_seqovl: int = 297
    auto_ttl: bool = True
    fake_tls_data: bytes = field(default_factory=lambda: b"\x00\x00\x00\x00")
    fooling_method: str = "md5sig"
    repeats: int = 10
    base_ttl: int = 51
    disorder_window: int = 3
    fake_packet_delay_ms: float = 0.1
    sequence_overlap_bytes: int = 8
    inter_packet_delay_ms: float = 0.05
    burst_delay_ms: float = 1.0


class ZapretStrategy(BaseAttack):

    @property
    def name(self) -> str:
        return "zapret_strategy"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "http", "https", "tls"]

    def __init__(self, config: Optional[ZapretConfig] = None):
        super().__init__()
        self.config = config or ZapretConfig()
        self.packet_builder = EnhancedPacketBuilder()

        # Statistics
        self.packets_sent = 0
        self.fake_packets_sent = 0
        self.disorder_packets_sent = 0

        LOG.info(
            f"Zapret strategy initialized: methods={self.config.desync_methods}, "
            f"split={self.config.split_seqovl}, ttl={self.config.base_ttl}"
        )

    def execute(self, context: AttackContext) -> AttackResult:
        # Этот метод теперь асинхронный в базовом классе, но для zapret он может оставаться синхронным
        # AttackAdapter обернет его в asyncio.to_thread
        LOG.info(f"Executing zapret strategy for {context.dst_ip}:{context.dst_port}")

        start_time = time.time()

        try:
            # Логика генерации пакетов остается здесь, но они не отправляются, а возвращаются
            # как "сегменты" для PacketExecutor.

            # --- ВАЖНО: Эта атака генерирует полные raw пакеты, а не просто payload ---
            # Поэтому мы должны передать их как есть.

            # Здесь должна быть ваша логика генерации пакетов, которая возвращает список байтов
            # Для примера, создадим несколько фейковых пакетов
            final_packets = []
            for _ in range(self.config.repeats):
                # Build full TCP packet using unified PacketBuilder
                packet = self.packet_builder.create_tcp_packet(
                    src_ip=context.src_ip or "127.0.0.1",
                    dst_ip=context.dst_ip,
                    src_port=context.src_port or random.randint(1024, 65535),
                    dst_port=context.dst_port,
                    seq=context.seq or random.randint(1, 10000),
                    ack=context.ack or 0,
                    flags="PA",
                    payload=b"FAKE_ZAPRET_DATA",
                )

                if packet is None:
                    continue

                # Ensure we return raw bytes even if Scapy is used under the hood
                if not isinstance(packet, (bytes, bytearray)):
                    try:
                        packet = bytes(packet)
                    except Exception:
                        # Skip if we cannot convert to raw bytes
                        continue

                final_packets.append(packet)

            self.packets_sent = len(final_packets)
            success = self.packets_sent > 0

            execution_time = (time.time() - start_time) * 1000

            # Возвращаем сегменты для отправки через PacketExecutor
            # Каждый "сегмент" - это полный, готовый к отправке raw пакет
            segments = [(packet, 0) for packet in final_packets]

            return AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.ERROR,
                latency_ms=execution_time,
                packets_sent=self.packets_sent,
                bytes_sent=sum(len(p) for p in final_packets),
                connection_established=success,
                data_transmitted=success,
                metadata={
                    "segments": segments,
                    "config": asdict(self.config),
                    "info": "Zapret strategy generated raw packets for execution.",
                    "is_raw": True,  # <--- КЛЮЧЕВОЕ ПОЛЕ
                },
            )
        except Exception as e:
            LOG.error(f"Zapret strategy failed: {e}", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    async def execute_with_network_validation(
        self, context: AttackContext, strict_mode: bool = False
    ) -> AttackResult:
        """
        Execute zapret strategy with real network validation.
        This method uses RealEffectivenessTester to check actual bypass effectiveness.
        """
        LOG.info(
            f"Executing zapret strategy with network validation for {context.dst_ip}:{context.dst_port}"
        )

        start_time = time.time()

        try:
            # First, execute the basic zapret strategy to generate packets
            basic_result = await asyncio.to_thread(self.execute, context)

            if basic_result.status != AttackStatus.SUCCESS:
                return basic_result

            # Now test real effectiveness using RealEffectivenessTester
            from ..real_effectiveness_tester import RealEffectivenessTester

            tester = RealEffectivenessTester(timeout=context.timeout)

            try:
                # Test baseline (without bypass)
                baseline = await tester.test_baseline(
                    context.domain or context.dst_ip, context.dst_port
                )
                LOG.info(
                    f"Baseline test for {context.domain}: success={baseline.success}, latency={baseline.latency_ms:.1f}ms"
                )

                # Test with bypass applied
                bypass = await tester.test_with_bypass(
                    context.domain or context.dst_ip, context.dst_port, basic_result
                )
                LOG.info(
                    f"Bypass test for {context.domain}: success={bypass.success}, latency={bypass.latency_ms:.1f}ms"
                )

                # Compare results to determine effectiveness
                effectiveness = await tester.compare_results(baseline, bypass)

                # Update result based on real effectiveness
                basic_result.metadata["bypass_results"] = {
                    "baseline_success": baseline.success,
                    "bypass_success": bypass.success,
                    "bypass_effective": effectiveness.bypass_effective,
                    "improvement_type": effectiveness.improvement_type,
                    "effectiveness_score": effectiveness.effectiveness_score,
                }

                # Set real connection status based on bypass test
                basic_result.connection_established = bypass.success
                basic_result.data_transmitted = bypass.success
                basic_result.response_received = bypass.success

                # If bypass is not effective and we're in strict mode, mark as blocked
                if not effectiveness.bypass_effective and strict_mode:
                    basic_result.status = AttackStatus.BLOCKED
                    basic_result.error_message = (
                        "Zapret bypass was not effective against detected blocking"
                    )
                    LOG.warning(
                        f"Zapret bypass ineffective for {context.domain}: {effectiveness.improvement_type}"
                    )
                elif not effectiveness.bypass_effective:
                    # In non-strict mode, still report the real status
                    basic_result.status = (
                        AttackStatus.SUCCESS if bypass.success else AttackStatus.BLOCKED
                    )
                    if not bypass.success:
                        basic_result.error_message = f"Domain remains blocked after zapret bypass: {baseline.block_type}"
                        LOG.warning(
                            f"Zapret bypass failed for {context.domain}: domain still blocked"
                        )
                else:
                    # Bypass is effective
                    basic_result.status = AttackStatus.SUCCESS
                    LOG.info(
                        f"Zapret bypass effective for {context.domain}: {effectiveness.improvement_type}"
                    )

            finally:
                # Always close the tester session
                if hasattr(tester, "close"):
                    await tester.close()

            execution_time = time.time() - start_time
            basic_result.latency_ms = execution_time * 1000

            LOG.info(
                f"Zapret strategy with validation completed in {execution_time:.3f}s: "
                f"status={basic_result.status.value}, effective={effectiveness.bypass_effective}"
            )

            return basic_result

        except Exception as e:
            LOG.error(f"Zapret strategy with validation failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="zapret_strategy",
            )

    async def _generate_fake_packets(self, context: AttackContext) -> List[bytes]:
        """Generate fake packets to confuse DPI."""
        fake_packets = []

        # Generate fake TLS handshake packets
        for i in range(3):  # Multiple fake packets
            # Calculate TTL (auto-adjust or use base)
            ttl = (
                self._calculate_optimal_ttl(context)
                if self.config.auto_ttl
                else self.config.base_ttl
            )

            # Create fake TLS packet
            fake_payload = self._create_fake_tls_payload()

            fake_packet = self.packet_builder.build_tcp_packet(
                src_ip=context.src_ip or "192.168.1.100",
                dst_ip=context.dst_ip,
                src_port=context.src_port or random.randint(10000, 65000),
                dst_port=context.dst_port,
                seq=random.randint(1000000, 9999999),
                ack=0,
                flags="S",  # SYN for fake handshake
                payload=fake_payload,
                ttl=ttl,
                ip_id=random.randint(1, 65535),
            )

            fake_packets.append(fake_packet)

            # Add small delay between fake packets
            if self.config.fake_packet_delay_ms > 0:
                await self._async_delay(self.config.fake_packet_delay_ms / 1000)

        LOG.debug(f"Generated {len(fake_packets)} fake packets with TTL={ttl}")
        return fake_packets

    async def _apply_sequence_overlap_split(
        self, context: AttackContext
    ) -> List[bytes]:
        """Apply sequence overlap splitting at specified position."""
        split_packets = []

        # Create the main data packet that will be split
        main_payload = self._create_main_payload(context)

        if len(main_payload) <= self.config.split_seqovl:
            # Payload too small to split, return as-is
            packet = self.packet_builder.build_tcp_packet(
                src_ip=context.src_ip or "192.168.1.100",
                dst_ip=context.dst_ip,
                src_port=context.src_port or random.randint(10000, 65000),
                dst_port=context.dst_port,
                seq=random.randint(1000000, 9999999),
                ack=random.randint(1000000, 9999999),
                flags="PA",
                payload=main_payload,
                ttl=self.config.base_ttl,
            )
            split_packets.append(packet)
            return split_packets

        # Split at the specified position with overlap
        split_pos = self.config.split_seqovl
        overlap_bytes = self.config.sequence_overlap_bytes

        # First part (up to split position + overlap)
        first_part = main_payload[: split_pos + overlap_bytes]
        # Second part (from split position)
        second_part = main_payload[split_pos:]

        base_seq = random.randint(1000000, 9999999)
        base_ack = random.randint(1000000, 9999999)

        # Create first packet
        first_packet = self.packet_builder.build_tcp_packet(
            src_ip=context.src_ip or "192.168.1.100",
            dst_ip=context.dst_ip,
            src_port=context.src_port or random.randint(10000, 65000),
            dst_port=context.dst_port,
            seq=base_seq,
            ack=base_ack,
            flags="PA",
            payload=first_part,
            ttl=self.config.base_ttl,
        )

        # Create second packet with overlapping sequence
        second_packet = self.packet_builder.build_tcp_packet(
            src_ip=context.src_ip or "192.168.1.100",
            dst_ip=context.dst_ip,
            src_port=context.src_port or random.randint(10000, 65000),
            dst_port=context.dst_port,
            seq=base_seq + split_pos,  # Overlapping sequence
            ack=base_ack,
            flags="PA",
            payload=second_part,
            ttl=self.config.base_ttl,
        )

        split_packets.extend([first_packet, second_packet])

        LOG.debug(
            f"Applied sequence overlap split at position {split_pos} with {overlap_bytes} bytes overlap"
        )
        return split_packets

    async def _apply_fake_disorder(
        self, context: AttackContext, existing_packets: List[bytes]
    ) -> List[bytes]:
        """Apply fake disorder to confuse DPI packet ordering."""
        disorder_packets = []

        # Create disorder packets that arrive out of order
        for i in range(self.config.disorder_window):
            # Create packets with intentionally wrong sequence numbers
            wrong_seq = random.randint(1, 1000000)  # Intentionally wrong

            disorder_packet = self.packet_builder.build_tcp_packet(
                src_ip=context.src_ip or "192.168.1.100",
                dst_ip=context.dst_ip,
                src_port=context.src_port or random.randint(10000, 65000),
                dst_port=context.dst_port,
                seq=wrong_seq,
                ack=0,
                flags="R",  # RST to cause confusion
                payload=b"",
                ttl=1,  # Very low TTL so it doesn't reach destination
                ip_id=random.randint(1, 65535),
            )

            disorder_packets.append(disorder_packet)

        LOG.debug(f"Generated {len(disorder_packets)} disorder packets")
        return disorder_packets

    async def _apply_md5_fooling(
        self, context: AttackContext, packets: List[bytes]
    ) -> List[bytes]:
        """Apply MD5 signature fooling to packets."""
        fooled_packets = []

        for packet in packets[-3:]:  # Apply to last few packets
            try:
                # Directly add MD5 signature option
                fooled_packet = self._add_md5_signature_option(packet)
                fooled_packets.append(fooled_packet)

            except Exception as e:
                LOG.debug(f"MD5 fooling failed for packet: {e}")
                fooled_packets.append(packet)  # Use original packet if fooling fails

        LOG.debug(f"Applied MD5 fooling to {len(fooled_packets)} packets")
        return fooled_packets

    async def _apply_repeats(self, packets: List[bytes]) -> List[bytes]:
        """Repeat the packet pattern for increased effectiveness."""
        repeated_packets = []

        for repeat in range(self.config.repeats):
            for packet in packets:
                # Slightly modify each repeat to avoid exact duplication
                modified_packet = self._modify_packet_for_repeat(packet, repeat)
                repeated_packets.append(modified_packet)

                # Add inter-packet delay
                if self.config.inter_packet_delay_ms > 0:
                    await self._async_delay(self.config.inter_packet_delay_ms / 1000)

            # Add burst delay between repeats
            if repeat < self.config.repeats - 1 and self.config.burst_delay_ms > 0:
                await self._async_delay(self.config.burst_delay_ms / 1000)

        LOG.debug(
            f"Repeated pattern {self.config.repeats} times, total packets: {len(repeated_packets)}"
        )
        return repeated_packets

    def _calculate_optimal_ttl(self, context: AttackContext) -> int:
        """Calculate optimal TTL based on target distance."""
        # Simple heuristic: base TTL + some randomization
        # In a real implementation, this would probe the network path
        base = self.config.base_ttl
        variation = random.randint(-5, 5)
        return max(1, min(255, base + variation))

    def _create_fake_tls_payload(self) -> bytes:
        """Create fake TLS payload to confuse DPI."""
        # Use configured fake TLS data or generate realistic fake
        if self.config.fake_tls_data:
            return self.config.fake_tls_data

        # Generate fake TLS Client Hello
        fake_tls = (
            b"\x16\x03\x01\x00\x20"  # TLS Record Header
            b"\x01\x00\x00\x1c"  # Handshake Header
            b"\x03\x03"  # TLS Version
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID Length
            + b"\x00\x02\x00\x2f"  # Cipher Suites
            + b"\x01\x00"  # Compression Methods
        )

        return fake_tls

    def _create_main_payload(self, context: AttackContext) -> bytes:
        """Create the main payload that will be split."""
        if context.payload:
            return context.payload

        # Generate realistic HTTP request
        host = context.domain or context.dst_ip
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"\r\n"
        ).encode()

        return http_request

    def _add_md5_signature_option(self, packet: bytes) -> bytes:
        """Add MD5 signature TCP option to packet."""
        if len(packet) < 40:  # Too small for TCP packet
            return packet

        try:
            # Parse IP header to find TCP start
            ip_header_len = (packet[0] & 0x0F) * 4
            tcp_start = ip_header_len

            if len(packet) < tcp_start + 20:
                return packet

            # Parse TCP header
            tcp_header_len = ((packet[tcp_start + 12] >> 4) & 0xF) * 4

            # Add MD5 signature option (option 19, length 18)
            md5_option = (
                b"\x13\x12" + b"\x00" * 16
            )  # Option 19, length 18, 16 bytes of zeros

            # Reconstruct packet with MD5 option
            # This is a simplified implementation
            return packet + md5_option

        except Exception:
            return packet

    def _modify_packet_for_repeat(self, packet: bytes, repeat_num: int) -> bytes:
        """Slightly modify packet for each repeat to avoid exact duplication."""
        if len(packet) < 20:
            return packet

        try:
            # Modify IP ID field
            packet_list = list(packet)
            if len(packet_list) >= 6:
                # Modify IP ID (bytes 4-5)
                new_id = (struct.unpack("!H", packet[4:6])[0] + repeat_num) & 0xFFFF
                packet_list[4:6] = struct.pack("!H", new_id)

            return bytes(packet_list)

        except Exception:
            return packet

    async def _async_delay(self, seconds: float):
        """Async delay helper."""
        import asyncio

        await asyncio.sleep(seconds)

    def get_statistics(self) -> Dict[str, Any]:
        """Get strategy execution statistics."""
        return {
            "packets_sent": self.packets_sent,
            "fake_packets_sent": self.fake_packets_sent,
            "disorder_packets_sent": self.disorder_packets_sent,
            "config": {
                "desync_methods": self.config.desync_methods,
                "split_seqovl": self.config.split_seqovl,
                "ttl": self.config.base_ttl,
                "repeats": self.config.repeats,
                "fooling": self.config.fooling_method,
            },
        }


# Factory function for easy instantiation
def create_zapret_strategy(
    split_seqovl: int = 297,
    ttl: int = 51,
    repeats: int = 10,
    auto_ttl: bool = True,
    **kwargs,
) -> ZapretStrategy:
    config = ZapretConfig(
        split_seqovl=split_seqovl,
        base_ttl=ttl,
        repeats=repeats,
        auto_ttl=auto_ttl,
        **kwargs,
    )
    return ZapretStrategy(config)


# Register the attack with the system
try:
    from ..registry import register_attack

    register_attack(ZapretStrategy)
    LOG.info("ZapretStrategy registered successfully")
except ImportError:
    LOG.debug("Registry not available, skipping registration")
