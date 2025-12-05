import struct
import random
import time
import logging
import asyncio
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.packet_builder import EnhancedPacketBuilder
from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories

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

@register_attack(
    name="zapret_strategy",
    category=AttackCategories.COMBO,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "desync_methods": ["fake", "fakeddisorder"],
        "split_seqovl": 297,
        "auto_ttl": True,
        "fake_tls_data": b"\x00\x00\x00\x00",
        "fooling_method": "md5sig",
        "repeats": 10,
        "base_ttl": 51,
        "disorder_window": 3,
        "fake_packet_delay_ms": 0.1,
        "sequence_overlap_bytes": 8,
        "inter_packet_delay_ms": 0.05,
        "burst_delay_ms": 1.0
    },
    aliases=["zapret", "zapret_combo"],
    description="Zapret-style multi-method DPI bypass strategy"
)
class ZapretStrategy(BaseAttack):

    @property
    def name(self) -> str:
        return "zapret_strategy"

    @property
    def category(self) -> str:
        return AttackCategories.COMBO

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "http", "https", "tls"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        # Return parameters from the config as a dictionary
        # Use default config if self.config is not available (during registration)
        if hasattr(self, 'config') and self.config:
            return asdict(self.config)
        else:
            # Return default parameters for registration
            return asdict(ZapretConfig())
    
    def __init__(self, config: Optional[ZapretConfig] = None):
        super().__init__()
        self.config = config or ZapretConfig()
        self.packet_builder = EnhancedPacketBuilder()
        self.packets_sent = 0
        self.fake_packets_sent = 0
        self.disorder_packets_sent = 0
        LOG.info(
            f"Zapret strategy initialized: methods={self.config.desync_methods}, split={self.config.split_seqovl}, ttl={self.config.base_ttl}"
        )

    def execute(self, context: AttackContext) -> AttackResult:
        LOG.info(f"Executing zapret strategy for {context.dst_ip}:{context.dst_port}")
        start_time = time.time()
        try:
            final_packets = []
            for _ in range(self.config.repeats):
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
                if not isinstance(packet, (bytes, bytearray)):
                    try:
                        packet = bytes(packet)
                    except Exception:
                        continue
                final_packets.append(packet)
            self.packets_sent = len(final_packets)
            success = self.packets_sent > 0
            # Removed async sleep for sync execution
            execution_time = (time.time() - start_time) * 1000
            segments = [(packet, 0, {}) for packet in final_packets]
            
            result = AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.ERROR,
                latency_ms=execution_time,
                packets_sent=self.packets_sent,
                bytes_sent=sum((len(p) for p in final_packets)),
                connection_established=success,
                data_transmitted=success,
                technique_used=self.name,
                metadata={
                    "config": asdict(self.config),
                    "info": "Zapret strategy generated raw packets for execution.",
                    "is_raw": True,
                },
            )
            result.segments = segments
            return result
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
            basic_result = await asyncio.to_thread(self.execute, context)
            if basic_result.status != AttackStatus.SUCCESS:
                return basic_result
            from core.bypass.attacks.real_effectiveness_tester import (
                RealEffectivenessTester,
            )

            tester = RealEffectivenessTester(timeout=context.timeout)
            try:
                baseline = await tester.test_baseline(
                    context.domain or context.dst_ip, context.dst_port
                )
                LOG.info(
                    f"Baseline test for {context.domain}: success={baseline.success}, latency={baseline.latency_ms:.1f}ms"
                )
                bypass = await tester.test_with_bypass(
                    context.domain or context.dst_ip, context.dst_port, basic_result
                )
                LOG.info(
                    f"Bypass test for {context.domain}: success={bypass.success}, latency={bypass.latency_ms:.1f}ms"
                )
                effectiveness = await tester.compare_results(baseline, bypass)
                basic_result.metadata["bypass_results"] = {
                    "baseline_success": baseline.success,
                    "bypass_success": bypass.success,
                    "bypass_effective": effectiveness.bypass_effective,
                    "improvement_type": effectiveness.improvement_type,
                    "effectiveness_score": effectiveness.effectiveness_score,
                }
                basic_result.connection_established = bypass.success
                basic_result.data_transmitted = bypass.success
                basic_result.response_received = bypass.success
                if not effectiveness.bypass_effective and strict_mode:
                    basic_result.status = AttackStatus.BLOCKED
                    basic_result.error_message = (
                        "Zapret bypass was not effective against detected blocking"
                    )
                    LOG.warning(
                        f"Zapret bypass ineffective for {context.domain}: {effectiveness.improvement_type}"
                    )
                elif not effectiveness.bypass_effective:
                    basic_result.status = (
                        AttackStatus.SUCCESS if bypass.success else AttackStatus.BLOCKED
                    )
                    if not bypass.success:
                        basic_result.error_message = f"Domain remains blocked after zapret bypass: {baseline.block_type}"
                        LOG.warning(
                            f"Zapret bypass failed for {context.domain}: domain still blocked"
                        )
                else:
                    basic_result.status = AttackStatus.SUCCESS
                    LOG.info(
                        f"Zapret bypass effective for {context.domain}: {effectiveness.improvement_type}"
                    )
            finally:
                if hasattr(tester, "close"):
                    await tester.close()
            execution_time = time.time() - start_time
            basic_result.latency_ms = execution_time * 1000
            LOG.info(
                f"Zapret strategy with validation completed in {execution_time:.3f}s: status={basic_result.status.value}, effective={effectiveness.bypass_effective}"
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
        for i in range(3):
            ttl = (
                self._calculate_optimal_ttl(context)
                if self.config.auto_ttl
                else self.config.base_ttl
            )
            fake_payload = self._create_fake_tls_payload()
            fake_packet = self.packet_builder.build_tcp_packet(
                src_ip=context.src_ip or "192.168.1.100",
                dst_ip=context.dst_ip,
                src_port=context.src_port or random.randint(10000, 65000),
                dst_port=context.dst_port,
                seq=random.randint(1000000, 9999999),
                ack=0,
                flags="S",
                payload=fake_payload,
                ttl=ttl,
                ip_id=random.randint(1, 65535),
            )
            fake_packets.append(fake_packet)
            if self.config.fake_packet_delay_ms > 0:
                await self._async_delay(self.config.fake_packet_delay_ms / 1000)
        LOG.debug(f"Generated {len(fake_packets)} fake packets with TTL={ttl}")
        return fake_packets

    async def _apply_sequence_overlap_split(
        self, context: AttackContext
    ) -> List[bytes]:
        """Apply sequence overlap splitting at specified position."""
        split_packets = []
        main_payload = self._create_main_payload(context)
        if len(main_payload) <= self.config.split_seqovl:
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
        split_pos = self.config.split_seqovl
        overlap_bytes = self.config.sequence_overlap_bytes
        first_part = main_payload[: split_pos + overlap_bytes]
        second_part = main_payload[split_pos:]
        base_seq = random.randint(1000000, 9999999)
        base_ack = random.randint(1000000, 9999999)
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
        second_packet = self.packet_builder.build_tcp_packet(
            src_ip=context.src_ip or "192.168.1.100",
            dst_ip=context.dst_ip,
            src_port=context.src_port or random.randint(10000, 65000),
            dst_port=context.dst_port,
            seq=base_seq + split_pos,
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
        for i in range(self.config.disorder_window):
            wrong_seq = random.randint(1, 1000000)
            disorder_packet = self.packet_builder.build_tcp_packet(
                src_ip=context.src_ip or "192.168.1.100",
                dst_ip=context.dst_ip,
                src_port=context.src_port or random.randint(10000, 65000),
                dst_port=context.dst_port,
                seq=wrong_seq,
                ack=0,
                flags="R",
                payload=b"",
                ttl=1,
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
        for packet in packets[-3:]:
            try:
                fooled_packet = self._add_md5_signature_option(packet)
                fooled_packets.append(fooled_packet)
            except Exception as e:
                LOG.debug(f"MD5 fooling failed for packet: {e}")
                fooled_packets.append(packet)
        LOG.debug(f"Applied MD5 fooling to {len(fooled_packets)} packets")
        return fooled_packets

    async def _apply_repeats(self, packets: List[bytes]) -> List[bytes]:
        """Repeat the packet pattern for increased effectiveness."""
        repeated_packets = []
        for repeat in range(self.config.repeats):
            for packet in packets:
                modified_packet = self._modify_packet_for_repeat(packet, repeat)
                repeated_packets.append(modified_packet)
                if self.config.inter_packet_delay_ms > 0:
                    await self._async_delay(self.config.inter_packet_delay_ms / 1000)
            if repeat < self.config.repeats - 1 and self.config.burst_delay_ms > 0:
                await self._async_delay(self.config.burst_delay_ms / 1000)
        LOG.debug(
            f"Repeated pattern {self.config.repeats} times, total packets: {len(repeated_packets)}"
        )
        return repeated_packets

    def _calculate_optimal_ttl(self, context: AttackContext) -> int:
        """Calculate optimal TTL based on target distance."""
        base = self.config.base_ttl
        variation = random.randint(-5, 5)
        return max(1, min(255, base + variation))

    def _create_fake_tls_payload(self) -> bytes:
        """Create fake TLS payload to confuse DPI."""
        if self.config.fake_tls_data:
            return self.config.fake_tls_data
        fake_tls = (
            b"\x16\x03\x01\x00 \x01\x00\x00\x1c\x03\x03"
            + b"\x00" * 32
            + b"\x00"
            + b"\x00\x02\x00/"
            + b"\x01\x00"
        )
        return fake_tls

    def _create_main_payload(self, context: AttackContext) -> bytes:
        """Create the main payload that will be split."""
        if context.payload:
            return context.payload
        host = context.domain or context.dst_ip
        http_request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n".encode()
        return http_request

    def _add_md5_signature_option(self, packet: bytes) -> bytes:
        """Add MD5 signature TCP option to packet."""
        if len(packet) < 40:
            return packet
        try:
            ip_header_len = (packet[0] & 15) * 4
            tcp_start = ip_header_len
            if len(packet) < tcp_start + 20:
                return packet
            tcp_header_len = (packet[tcp_start + 12] >> 4 & 15) * 4
            md5_option = b"\x13\x12" + b"\x00" * 16
            return packet + md5_option
        except Exception:
            return packet

    def _modify_packet_for_repeat(self, packet: bytes, repeat_num: int) -> bytes:
        """Slightly modify packet for each repeat to avoid exact duplication."""
        if len(packet) < 20:
            return packet
        try:
            packet_list = list(packet)
            if len(packet_list) >= 6:
                new_id = struct.unpack("!H", packet[4:6])[0] + repeat_num & 65535
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


try:
    from core.bypass.attacks.attack_registry import AttackRegistry

    register_attack(ZapretStrategy)
    LOG.info("ZapretStrategy registered successfully")
except ImportError:
    LOG.debug("Registry not available, skipping registration")
