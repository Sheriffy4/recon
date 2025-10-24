"""
Full Session Simulation Attack
Simulates a complete user session lifecycle from DNS resolution through
TCP/TLS handshake to application data and keep-alive packets. This creates
the most realistic traffic pattern possible to evade sophisticated DPI systems
that analyze complete session behavior.
Enhanced for maximum realism and behavioral DPI evasion.
"""

import asyncio
import time
import random
import socket
import struct
import logging
import hashlib
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack
from core.dns.robust_dns_handler import RobustDNSHandler

LOG = logging.getLogger(__name__)

class SessionPhase(Enum):
    """Phases of a complete user session."""

    DNS_RESOLUTION = "dns_resolution"
    TCP_HANDSHAKE = "tcp_handshake"
    TLS_HANDSHAKE = "tls_handshake"
    APPLICATION_DATA = "application_data"
    KEEP_ALIVE = "keep_alive"
    SESSION_TEARDOWN = "session_teardown"


@dataclass
class SessionTiming:
    """Timing configuration for session phases - enhanced for maximum realism."""

    dns_resolution_delay: Tuple[float, float] = (5.0, 25.0)
    dns_cache_check_delay: Tuple[float, float] = (1.0, 5.0)
    dns_retry_delay: Tuple[float, float] = (100.0, 300.0)
    tcp_syn_delay: float = 0.0
    tcp_syn_ack_delay: Tuple[float, float] = (10.0, 80.0)
    tcp_ack_delay: Tuple[float, float] = (2.0, 15.0)
    client_hello_delay: Tuple[float, float] = (20.0, 100.0)
    server_hello_delay: Tuple[float, float] = (50.0, 200.0)
    certificate_delay: Tuple[float, float] = (30.0, 120.0)
    key_exchange_delay: Tuple[float, float] = (10.0, 60.0)
    finished_delay: Tuple[float, float] = (5.0, 30.0)
    first_request_delay: Tuple[float, float] = (50.0, 300.0)
    response_delay: Tuple[float, float] = (100.0, 800.0)
    subsequent_request_delay: Tuple[float, float] = (500.0, 3000.0)
    user_think_time: Tuple[float, float] = (2.0, 10.0)
    keep_alive_interval: Tuple[float, float] = (45.0, 120.0)
    keep_alive_response_delay: Tuple[float, float] = (20.0, 100.0)
    fin_delay: Tuple[float, float] = (50.0, 300.0)
    fin_ack_delay: Tuple[float, float] = (10.0, 50.0)
    final_ack_delay: Tuple[float, float] = (5.0, 25.0)
    page_load_delay: Tuple[float, float] = (200.0, 1000.0)
    resource_fetch_delay: Tuple[float, float] = (50.0, 200.0)
    idle_time: Tuple[float, float] = (5.0, 30.0)


@dataclass
class SessionConfig:
    """Configuration for full session simulation - enhanced for behavioral DPI evasion."""

    simulate_dns: bool = True
    simulate_tcp_handshake: bool = True
    simulate_tls_handshake: bool = True
    simulate_keep_alive: bool = True
    simulate_teardown: bool = True
    session_duration_range: Tuple[float, float] = (120.0, 600.0)
    application_requests_count: Tuple[int, int] = (5, 15)
    keep_alive_count: Tuple[int, int] = (3, 8)
    add_user_behavior_delays: bool = True
    simulate_browser_behavior: bool = True
    add_background_noise: bool = True
    simulate_real_user_patterns: bool = True
    add_browser_fingerprinting: bool = True
    simulate_resource_loading: bool = True
    vary_packet_sizes: bool = True
    add_jitter_to_timing: bool = True
    simulate_network_conditions: bool = True
    add_protocol_compliance: bool = True
    browser_type: str = "chrome"
    os_type: str = "windows"
    user_agent_rotation: bool = True
    accept_language: str = "en-US,en;q=0.9"
    timing: SessionTiming = field(default_factory=SessionTiming)

@register_attack
class FullSessionSimulationAttack(BaseAttack):
    """
    Full Session Simulation Attack that creates a complete realistic user session
    from DNS resolution through application data to session teardown.
    """

    def __init__(self, config: Optional[SessionConfig] = None):
        super().__init__()
        self.config = config or SessionConfig()
        self.dns_handler = RobustDNSHandler()
        self._session_state = {}

    @property
    def name(self) -> str:
        return "full_session_simulation"

    @property
    def description(self) -> str:
        return (
            "Simulates complete user session lifecycle for maximum DPI evasion realism"
        )

    @property
    def category(self) -> str:
        return "combo"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "simulate_dns": True,
            "simulate_tcp_handshake": True,
            "simulate_tls_handshake": True,
            "simulate_keep_alive": True,
            "simulate_teardown": True,
            "browser_type": "chrome",
        }
    
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute full session simulation attack with maximum realism.
        Args:
            context: Attack execution context
        Returns:
            Attack result with session simulation details
        """
        start_time = time.time()
        session_packets = []
        total_bytes_sent = 0
        try:
            self._session_state = {
                "domain": context.domain or f"{context.dst_ip}:{context.dst_port}",
                "target_ip": context.dst_ip,
                "target_port": context.dst_port,
                "session_id": self._generate_realistic_session_id(),
                "tcp_seq": self._generate_realistic_tcp_seq(),
                "tcp_ack": 0,
                "tls_session_id": self._generate_tls_session_id(),
                "phase_results": {},
                "browser_fingerprint": self._generate_browser_fingerprint(),
                "connection_start_time": start_time,
                "packet_sequence": 0,
                "bytes_transferred": 0,
                "dns_last_id": None,
            }
            LOG.debug(
                f"Starting enhanced full session simulation for {self._session_state['domain']} (Browser: {self.config.browser_type}, OS: {self.config.os_type})"
            )
            if self.config.simulate_dns:
                dns_result = await self._simulate_enhanced_dns_phase(context)
                session_packets.extend(dns_result["packets"])
                total_bytes_sent += dns_result["bytes_sent"]
                self._session_state["phase_results"]["dns"] = dns_result
            if self.config.simulate_tcp_handshake:
                tcp_result = await self._simulate_enhanced_tcp_handshake_phase(context)
                session_packets.extend(tcp_result["packets"])
                total_bytes_sent += tcp_result["bytes_sent"]
                self._session_state["phase_results"]["tcp_handshake"] = tcp_result
            if self.config.simulate_tls_handshake:
                tls_result = await self._simulate_enhanced_tls_handshake_phase(context)
                session_packets.extend(tls_result["packets"])
                total_bytes_sent += tls_result["bytes_sent"]
                self._session_state["phase_results"]["tls_handshake"] = tls_result
            app_result = await self._simulate_enhanced_application_data_phase(context)
            session_packets.extend(app_result["packets"])
            total_bytes_sent += app_result["bytes_sent"]
            self._session_state["phase_results"]["application_data"] = app_result
            if self.config.simulate_resource_loading:
                resource_result = await self._simulate_resource_loading_phase(context)
                session_packets.extend(resource_result["packets"])
                total_bytes_sent += resource_result["bytes_sent"]
                self._session_state["phase_results"][
                    "resource_loading"
                ] = resource_result
            if self.config.simulate_keep_alive:
                keepalive_result = await self._simulate_enhanced_keep_alive_phase(
                    context
                )
                session_packets.extend(keepalive_result["packets"])
                total_bytes_sent += keepalive_result["bytes_sent"]
                self._session_state["phase_results"]["keep_alive"] = keepalive_result
            if self.config.simulate_teardown:
                teardown_result = await self._simulate_enhanced_teardown_phase(context)
                session_packets.extend(teardown_result["packets"])
                total_bytes_sent += teardown_result["bytes_sent"]
                self._session_state["phase_results"]["teardown"] = teardown_result
            execution_time = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=execution_time,
                packets_sent=len(session_packets),
                bytes_sent=total_bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "session_id": self._session_state["session_id"],
                    "phases_completed": list(
                        self._session_state["phase_results"].keys()
                    ),
                    "total_session_duration": execution_time / 1000.0,
                    "phase_results": self._session_state["phase_results"],
                    "realism_score": self._calculate_enhanced_realism_score(),
                    "browser_fingerprint": self._session_state["browser_fingerprint"],
                    "behavioral_metrics": self._calculate_behavioral_metrics(),
                    "is_raw": True,
                },
            )
        except Exception as e:
            LOG.error(f"Enhanced full session simulation failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    async def _simulate_enhanced_dns_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate enhanced DNS resolution phase with realistic behavior.
        Args:
            context: Attack context
        Returns:
            DNS phase results
        """
        start_time = time.time()
        packets = []
        domain = context.domain or f"{context.dst_ip}"
        cache_check_delay = (
            random.uniform(*self.config.timing.dns_cache_check_delay) / 1000.0
        )
        await asyncio.sleep(cache_check_delay)
        base_delay = random.uniform(*self.config.timing.dns_resolution_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-5.0, 5.0)
            dns_delay = max(1.0, base_delay + jitter) / 1000.0
        else:
            dns_delay = base_delay / 1000.0
        await asyncio.sleep(dns_delay)
        dns_query, qid = self._create_enhanced_dns_query_packet(domain)
        self._session_state["dns_last_id"] = qid
        packets.append((dns_query, cache_check_delay * 1000))
        network_rtt = random.uniform(10.0, 80.0)
        processing_delay = random.uniform(5.0, 20.0)
        response_delay = (network_rtt + processing_delay) / 1000.0
        await asyncio.sleep(response_delay)
        dns_response = self._create_enhanced_dns_response_packet(
            domain, context.dst_ip, self._session_state.get("dns_last_id")
        )
        packets.append((dns_response, response_delay * 1000))
        if self.config.simulate_real_user_patterns:
            ipv6_delay = random.uniform(5.0, 15.0) / 1000.0
            await asyncio.sleep(ipv6_delay)
            dns_aaaa_query = self._create_dns_aaaa_query_packet(domain)
            packets.append((dns_aaaa_query, ipv6_delay * 1000))
            aaaa_response_delay = random.uniform(10.0, 50.0) / 1000.0
            await asyncio.sleep(aaaa_response_delay)
            dns_aaaa_response = self._create_dns_aaaa_response_packet(domain)
            packets.append((dns_aaaa_response, aaaa_response_delay * 1000))
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        LOG.debug(
            f"Enhanced DNS phase completed: {len(packets)} packets, {bytes_sent} bytes"
        )
        return {
            "phase": SessionPhase.DNS_RESOLUTION.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "domain_resolved": domain,
            "resolved_ip": context.dst_ip,
            "queries_sent": len([1 for p,_ in packets if p]) // 2,
            "cache_behavior": "miss",
        }

    async def _simulate_enhanced_tcp_handshake_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate enhanced TCP three-way handshake with realistic network behavior.
        Args:
            context: Attack context
        Returns:
            TCP handshake phase results
        """
        start_time = time.time()
        packets = []
        # Initial client seq
        cli_isn = random.randint(0, 0xFFFFFFFF)
        self._session_state["tcp_seq"] = cli_isn
        self._session_state["tcp_ack"] = 0
        syn_packet = self._create_enhanced_tcp_syn_packet(context, cli_isn)
        packets.append((syn_packet, 0.0))
        base_rtt = random.uniform(*self.config.timing.tcp_syn_ack_delay)
        if self.config.simulate_network_conditions:
            network_load = random.uniform(0.8, 1.2)
            syn_ack_delay = base_rtt * network_load
        else:
            syn_ack_delay = base_rtt
        await asyncio.sleep(syn_ack_delay / 1000.0)
        # Server ISN
        srv_isn = random.randint(0, 0xFFFFFFFF)
        syn_ack_packet = self._create_enhanced_tcp_syn_ack_packet(context, srv_isn, cli_isn)
        packets.append((syn_ack_packet, syn_ack_delay))
        ack_delay = random.uniform(*self.config.timing.tcp_ack_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-2.0, 2.0)
            ack_delay = max(1.0, ack_delay + jitter)
        await asyncio.sleep(ack_delay / 1000.0)
        self._session_state["tcp_ack"] = (srv_isn + 1) & 0xFFFFFFFF
        self._session_state["tcp_seq"] = (cli_isn + 1) & 0xFFFFFFFF
        ack_packet = self._create_enhanced_tcp_ack_packet(context, self._session_state["tcp_seq"], self._session_state["tcp_ack"])
        packets.append((ack_packet, ack_delay))
        self._session_state["tcp_window"] = 65535
        self._session_state["mss"] = 1460
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        LOG.debug(
            f"Enhanced TCP handshake completed: {len(packets)} packets, {bytes_sent} bytes, RTT: {syn_ack_delay:.1f}ms"
        )
        return {
            "phase": SessionPhase.TCP_HANDSHAKE.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "connection_established": True,
            "rtt_ms": syn_ack_delay,
            "mss": self._session_state["mss"],
            "window_size": self._session_state["tcp_window"],
        }

    async def _simulate_enhanced_tls_handshake_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate enhanced TLS handshake phase with browser-like behavior.
        Args:
            context: Attack context
        Returns:
            TLS handshake phase results
        """
        start_time = time.time()
        packets = []
        client_hello_delay = random.uniform(*self.config.timing.client_hello_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-10.0, 10.0)
            client_hello_delay = max(5.0, client_hello_delay + jitter)
        await asyncio.sleep(client_hello_delay / 1000.0)
        client_hello = self._create_enhanced_tls_client_hello(context)
        packets.append((client_hello, client_hello_delay))
        server_hello_delay = random.uniform(*self.config.timing.server_hello_delay)
        if self.config.simulate_network_conditions:
            processing_load = random.uniform(0.9, 1.3)
            server_hello_delay *= processing_load
        await asyncio.sleep(server_hello_delay / 1000.0)
        server_hello = self._create_enhanced_tls_server_hello(context)
        packets.append((server_hello, server_hello_delay))
        cert_delay = random.uniform(*self.config.timing.certificate_delay)
        await asyncio.sleep(cert_delay / 1000.0)
        certificate_chain = self._create_enhanced_tls_certificate_chain(context)
        packets.append((certificate_chain, cert_delay))
        hello_done_delay = random.uniform(5.0, 20.0)
        await asyncio.sleep(hello_done_delay / 1000.0)
        hello_done = self._create_tls_server_hello_done(context)
        packets.append((hello_done, hello_done_delay))
        key_exchange_delay = random.uniform(*self.config.timing.key_exchange_delay)
        if self.config.add_protocol_compliance:
            crypto_delay = random.uniform(10.0, 30.0)
            key_exchange_delay += crypto_delay
        await asyncio.sleep(key_exchange_delay / 1000.0)
        key_exchange = self._create_enhanced_tls_key_exchange(context)
        packets.append((key_exchange, key_exchange_delay))
        ccs_delay = random.uniform(2.0, 10.0)
        await asyncio.sleep(ccs_delay / 1000.0)
        change_cipher_spec = self._create_tls_change_cipher_spec(context)
        packets.append((change_cipher_spec, ccs_delay))
        finished_delay = random.uniform(*self.config.timing.finished_delay)
        await asyncio.sleep(finished_delay / 1000.0)
        client_finished = self._create_enhanced_tls_finished(context, is_client=True)
        packets.append((client_finished, finished_delay))
        server_ccs_delay = random.uniform(10.0, 40.0)
        await asyncio.sleep(server_ccs_delay / 1000.0)
        server_ccs = self._create_tls_change_cipher_spec(context, is_server=True)
        packets.append((server_ccs, server_ccs_delay))
        server_finished_delay = random.uniform(5.0, 20.0)
        await asyncio.sleep(server_finished_delay / 1000.0)
        server_finished = self._create_enhanced_tls_finished(context, is_client=False)
        packets.append((server_finished, server_finished_delay))
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        LOG.debug(
            f"Enhanced TLS handshake completed: {len(packets)} packets, {bytes_sent} bytes, Total time: {(time.time() - start_time) * 1000:.1f}ms"
        )
        return {
            "phase": SessionPhase.TLS_HANDSHAKE.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "tls_established": True,
            "session_id": self._session_state["tls_session_id"],
            "tls_version": "1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "certificate_chain_length": 3,
        }

    async def _simulate_enhanced_application_data_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate enhanced application data exchange with realistic browser behavior.
        Args:
            context: Attack context
        Returns:
            Application data phase results
        """
        start_time = time.time()
        packets = []
        first_request_delay = random.uniform(*self.config.timing.first_request_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-20.0, 20.0)
            first_request_delay = max(10.0, first_request_delay + jitter)
        await asyncio.sleep(first_request_delay / 1000.0)
        http_request = self._create_enhanced_http_request_with_payload(context)
        packets.append((http_request, first_request_delay))
        response_delay = random.uniform(*self.config.timing.response_delay)
        if self.config.simulate_network_conditions:
            server_load = random.uniform(0.8, 1.5)
            response_delay *= server_load
        await asyncio.sleep(response_delay / 1000.0)
        http_response = self._create_enhanced_http_response(context)
        packets.append((http_response, response_delay))
        request_count = random.randint(*self.config.application_requests_count)
        for i in range(request_count - 1):
            if self.config.simulate_real_user_patterns:
                think_time = random.uniform(*self.config.timing.user_think_time) * 1000
            else:
                think_time = random.uniform(
                    *self.config.timing.subsequent_request_delay
                )
            await asyncio.sleep(think_time / 1000.0)
            additional_request = self._create_enhanced_additional_http_request(
                context, i
            )
            packets.append((additional_request, think_time))
            add_response_delay = random.uniform(*self.config.timing.response_delay)
            if self.config.add_jitter_to_timing:
                jitter = random.uniform(-50.0, 50.0)
                add_response_delay = max(50.0, add_response_delay + jitter)
            await asyncio.sleep(add_response_delay / 1000.0)
            additional_response = self._create_enhanced_http_response(
                context, request_id=i
            )
            packets.append((additional_response, add_response_delay))
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)
        LOG.debug(
            f"Enhanced application data phase completed: {len(packets)} packets, {bytes_sent} bytes, Requests: {request_count}"
        )
        return {
            "phase": SessionPhase.APPLICATION_DATA.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "requests_sent": request_count,
            "main_payload_sent": True,
            "user_behavior_simulated": self.config.simulate_real_user_patterns,
            "average_think_time_ms": sum((p[1] for p in packets[2::2]))
            / max(len(packets[2::2]), 1),
        }

    async def _simulate_resource_loading_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate resource loading phase (CSS, JS, images) for maximum realism.
        Args:
            context: Attack context
        Returns:
            Resource loading phase results
        """
        start_time = time.time()
        packets = []
        if not self.config.simulate_resource_loading:
            return {
                "phase": "resource_loading",
                "packets": [],
                "bytes_sent": 0,
                "duration_ms": 0,
                "resources_loaded": 0,
            }
        resources = [
            ("/static/css/main.css", "text/css", random.randint(5000, 15000)),
            (
                "/static/js/app.js",
                "application/javascript",
                random.randint(20000, 50000),
            ),
            (
                "/static/js/vendor.js",
                "application/javascript",
                random.randint(100000, 200000),
            ),
            ("/favicon.ico", "image/x-icon", random.randint(1000, 5000)),
            ("/static/images/logo.png", "image/png", random.randint(10000, 30000)),
        ]
        for i, (path, content_type, size) in enumerate(resources):
            if i == 0:
                resource_delay = random.uniform(*self.config.timing.page_load_delay)
            else:
                resource_delay = random.uniform(
                    *self.config.timing.resource_fetch_delay
                )
            await asyncio.sleep(resource_delay / 1000.0)
            resource_request = self._create_resource_request(
                context, path, content_type
            )
            packets.append((resource_request, resource_delay))
            resource_response_delay = random.uniform(50.0, 200.0)
            await asyncio.sleep(resource_response_delay / 1000.0)
            resource_response = self._create_resource_response(
                context, content_type, size
            )
            packets.append((resource_response, resource_response_delay))
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)
        LOG.debug(
            f"Resource loading phase completed: {len(packets)} packets, {bytes_sent} bytes, Resources: {len(resources)}"
        )
        return {
            "phase": "resource_loading",
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "resources_loaded": len(resources),
            "resource_types": [r[1] for r in resources],
        }

    async def _simulate_enhanced_keep_alive_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate enhanced keep-alive phase with realistic connection maintenance.
        Args:
            context: Attack context
        Returns:
            Keep-alive phase results
        """
        start_time = time.time()
        packets = []
        keep_alive_count = random.randint(*self.config.keep_alive_count)
        for i in range(keep_alive_count):
            base_interval = random.uniform(*self.config.timing.keep_alive_interval)
            if self.config.add_jitter_to_timing:
                jitter = random.uniform(-10.0, 10.0)
                ka_interval = max(30.0, base_interval + jitter)
            else:
                ka_interval = base_interval
            await asyncio.sleep(ka_interval)
            keep_alive_packet = self._create_enhanced_keep_alive_packet(context, i)
            packets.append((keep_alive_packet, ka_interval * 1000))
            ka_response_delay = random.uniform(
                *self.config.timing.keep_alive_response_delay
            )
            await asyncio.sleep(ka_response_delay / 1000.0)
            keep_alive_response = self._create_enhanced_keep_alive_response(context, i)
            packets.append((keep_alive_response, ka_response_delay))
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)
        LOG.debug(
            f"Enhanced keep-alive phase completed: {len(packets)} packets, {bytes_sent} bytes, Keep-alives: {keep_alive_count}"
        )
        return {
            "phase": SessionPhase.KEEP_ALIVE.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "keep_alive_count": keep_alive_count,
            "average_interval_seconds": sum((p[1] for p in packets[::2]))
            / max(len(packets[::2]), 1)
            / 1000,
        }

    async def _simulate_enhanced_teardown_phase(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """
        Simulate enhanced session teardown with graceful connection closure.
        Args:
            context: Attack context
        Returns:
            Teardown phase results
        """
        start_time = time.time()
        packets = []
        fin_delay = random.uniform(*self.config.timing.fin_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-20.0, 20.0)
            fin_delay = max(10.0, fin_delay + jitter)
        await asyncio.sleep(fin_delay / 1000.0)
        fin_packet = self._create_enhanced_tcp_fin_packet(context)
        packets.append((fin_packet, fin_delay))
        fin_ack_delay = random.uniform(*self.config.timing.fin_ack_delay)
        await asyncio.sleep(fin_ack_delay / 1000.0)
        fin_ack_packet = self._create_enhanced_tcp_fin_ack_packet(context)
        packets.append((fin_ack_packet, fin_ack_delay))
        final_ack_delay = random.uniform(*self.config.timing.final_ack_delay)
        await asyncio.sleep(final_ack_delay / 1000.0)
        final_ack_packet = self._create_enhanced_tcp_final_ack_packet(context)
        packets.append((final_ack_packet, final_ack_delay))
        bytes_sent = sum((len(packet) for packet, _ in packets if packet))
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)
        LOG.debug(
            f"Enhanced teardown phase completed: {len(packets)} packets, {bytes_sent} bytes"
        )
        return {
            "phase": SessionPhase.SESSION_TEARDOWN.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "connection_closed": True,
            "teardown_type": "graceful",
        }

    def _create_enhanced_dns_query_packet(self, domain: str) -> Tuple[bytes, int]:
        """Create enhanced DNS query packet with realistic structure, returns (packet, id)."""
        query_id = random.randint(1, 65535)
        flags = 0x0100 # recursion desired
        header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
        labels = domain.split(".")
        qname = b"".join(struct.pack("!B", len(l)) + l.encode("ascii", "ignore") for l in labels) + b"\x00"
        question = struct.pack("!HH", 1, 1) # A, IN
        return header + qname + question, query_id

    def _create_dns_aaaa_query_packet(self, domain: str) -> bytes:
        """Create DNS AAAA (IPv6) query packet."""
        query_id = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += struct.pack("!B", len(part)) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 28, 1) # QTYPE=AAAA, QCLASS=IN
        return header + question

    def _create_enhanced_dns_response_packet(self, domain: str, ip: str, query_id: Optional[int]) -> bytes:
        """Create enhanced DNS response packet."""
        if query_id is None:
            query_id = random.randint(1, 65535)
        flags = 0x8180 # response, recursion available, no error
        header = struct.pack("!HHHHHH", query_id, flags, 1, 1, 0, 0)
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += struct.pack("!B", len(part)) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" # Pointer to domain name in question
        ttl = random.randint(60, 300)
        answer += struct.pack("!HHIH", 1, 1, ttl, 4) # TYPE=A, CLASS=IN, TTL, RDLENGTH=4
        answer += socket.inet_aton(ip)
        return header + question + answer

    def _create_dns_aaaa_response_packet(self, domain: str) -> bytes:
        """Create DNS AAAA response packet (no IPv6 address)."""
        response_id = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", response_id, 33155, 1, 0, 1, 0)
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 28, 1)
        return header + question

    def _build_tcp_segment(self, src_port: int, dst_port: int, seq: int, ack: int, flags: int, window: int = 65535, options: bytes = b"", payload: bytes = b"") -> bytes:
        """
        Build a minimal TCP header (no IP, no checksum) for simulation. Do not use on wire.
        """
        # Data offset: (5 base words + options_len_words)
        opt_pad = (4 - (len(options) % 4)) % 4
        options_padded = options + b"\x00" * opt_pad
        data_offset = 5 + (len(options_padded) // 4)
        tcp_header = struct.pack("!HHLLBBHHH",
            src_port,
            dst_port,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            (data_offset << 4) & 0xF0,
            flags & 0x3F,
            window,
            0, # checksum (ignored in simulation)
            0) # urgent ptr
        return tcp_header + options_padded + payload

    def _create_enhanced_tcp_syn_packet(self, context: AttackContext, cli_isn: int) -> bytes:
        """Create enhanced TCP SYN packet with realistic options (simulation)."""
        src_port = random.randint(32768, 65535)
        self._session_state["src_port"] = src_port
        self._session_state["dst_port"] = context.dst_port
        # Options: MSS(1460), WS(7), SACK-Permitted, TSval/TSecr, NOP padding
        opts = b""
        opts += struct.pack("!BBH", 2, 4, 1460) # MSS
        opts += struct.pack("!BBB", 3, 3, 7) # Window scale 7
        opts += struct.pack("!BB", 4, 2) # SACK Permitted
        opts += struct.pack("!BBII", 8, 10, int(time.time()), 0) # Timestamps
        opts += b"\x01" # NOP
        return self._build_tcp_segment(src_port, context.dst_port, cli_isn, 0, flags=0x02, options=opts)

    def _create_enhanced_tcp_syn_ack_packet(self, context: AttackContext, srv_isn: int, cli_isn: int) -> bytes:
        """Create enhanced TCP SYN-ACK packet (simulation)."""
        # Reuse dst/src swapped
        opts = b""
        opts += struct.pack("!BBH", 2, 4, 1460)
        opts += struct.pack("!BB", 4, 2)
        opts += struct.pack("!BBII", 8, 10, int(time.time()), int(time.time()) - 1)
        return self._build_tcp_segment(context.dst_port, self._session_state.get("src_port", 55555), srv_isn, (cli_isn + 1) & 0xFFFFFFFF, flags=0x12, options=opts)

    def _create_enhanced_tcp_ack_packet(self, context: AttackContext, seq: int, ack: int) -> bytes:
        """Create enhanced TCP ACK packet (simulation)."""
        return self._build_tcp_segment(self._session_state.get("src_port", 55555), context.dst_port, seq, ack, flags=0x10)

    def _create_enhanced_tls_client_hello(self, context: AttackContext) -> bytes:
        """Create enhanced TLS ClientHello with realistic extensions (lengths consistent)."""
        host = (context.domain or "example.com").encode("ascii", "ignore")
        rnd = os.urandom(32)
        session_id = b""
        session_id_len = len(session_id).to_bytes(1, "big")
        suites = [0x1301, 0x1302, 0xC02F, 0xC030, 0x009E, 0x009F, 0x002F, 0x0035]
        suites_bytes = b"".join(struct.pack("!H", s) for s in suites)
        suites_len = len(suites_bytes).to_bytes(2, "big")
        compression = b"\x01\x00"
        # SNI
        sni_name = b"\x00" + struct.pack("!H", len(host)) + host
        sni_list = struct.pack("!H", len(sni_name)) + sni_name
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        # Groups
        groups = [0x001D, 0x0017, 0x0018]
        groups_b = b"".join(struct.pack("!H", g) for g in groups)
        groups_ext = struct.pack("!HH", 0x000A, len(groups_b) + 2) + struct.pack("!H", len(groups_b)) + groups_b
        # EC point formats
        ecpf = b"\x01\x00"
        ecpf_ext = struct.pack("!HH", 0x000B, len(ecpf)) + ecpf
        # ALPN
        alpn = b"\x00\x02h2\x08http/1.1"
        alpn_ext = struct.pack("!HH", 0x0010, len(alpn)) + alpn
        exts = sni_ext + groups_ext + ecpf_ext + alpn_ext
        exts = struct.pack("!H", len(exts)) + exts
        ch_body = b"\x03\x03" + rnd + session_id_len + session_id + suites_len + suites_bytes + compression + exts
        hs = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
        rec = b"\x16" + b"\x03\x01" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _create_enhanced_tls_server_hello(self, context: AttackContext) -> bytes:
        """Create minimal TLS ServerHello (simulation, lengths consistent)."""
        rnd = os.urandom(32)
        session_id = os.urandom(16)
        body = b"\x03\x03" + rnd + bytes([len(session_id)]) + session_id + struct.pack("!H", 0xC02F) + b"\x00"
        hs = b"\x02" + len(body).to_bytes(3, "big") + body
        rec = b"\x16" + b"\x03\x03" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _create_enhanced_tls_certificate_chain(self, context: AttackContext) -> bytes:
        """Create TLS Certificate handshake with dummy chain."""
        leaf = b"\x30" + os.urandom(256)
        inter = b"\x30" + os.urandom(180)
        def pkcs_len(b): return struct.pack("!I", len(b))[1:]
        entries = pkcs_len(leaf) + leaf + pkcs_len(inter) + inter
        chain = pkcs_len(entries) + entries
        hs = b"\x0b" + len(chain).to_bytes(3, "big") + chain
        rec = b"\x16" + b"\x03\x03" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _create_tls_server_hello_done(self, context: AttackContext) -> bytes:
        """Create TLS ServerHelloDone handshake."""
        hs = b"\x0e\x00\x00\x00"
        rec = b"\x16" + b"\x03\x03" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _create_enhanced_tls_key_exchange(self, context: AttackContext) -> bytes:
        """Create TLS ClientKeyExchange (EC) with random key."""
        key = os.urandom(65)
        body = len(key).to_bytes(1, "big") + key
        hs = b"\x10" + len(body).to_bytes(3, "big") + body
        rec = b"\x16" + b"\x03\x03" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _create_tls_change_cipher_spec(
        self, context: AttackContext, is_server: bool = False
    ) -> bytes:
        """Create TLS Change Cipher Spec packet."""
        return b"\x14\x03\x03\x00\x01\x01"

    def _create_enhanced_tls_finished(
        self, context: AttackContext, is_client: bool = True
    ) -> bytes:
        """Create TLS Finished handshake with random verify_data."""
        vd = os.urandom(12)
        hs = b"\x14" + len(vd).to_bytes(3, "big") + vd
        rec = b"\x16" + b"\x03\x03" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _create_enhanced_http_request_with_payload(
        self, context: AttackContext
    ) -> bytes:
        """Create enhanced HTTP request with realistic browser headers."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"
        fingerprint = self._session_state["browser_fingerprint"]
        request_lines = [
            "POST /api/data HTTP/1.1",
            f"Host: {domain}",
            f"User-Agent: {fingerprint['user_agent']}",
            f"Accept: {fingerprint['accept']}",
            f"Accept-Language: {fingerprint['accept_language']}",
            f"Accept-Encoding: {fingerprint['accept_encoding']}",
            "Content-Type: application/json",
            f"Content-Length: {len(context.payload)}",
            "Connection: keep-alive",
        ]
        request_lines.extend(["", ""])
        http_header = "\r\n".join(request_lines).encode()
        # Wrap into TLS ApplicationData (simulate encrypted record with plaintext payload)
        app = http_header + (context.payload or b"")
        return b"\x17\x03\x03" + len(app).to_bytes(2, "big") + app

    def _create_enhanced_http_response(
        self, context: AttackContext, request_id: int = 0
    ) -> bytes:
        """Create enhanced HTTP response with realistic server headers."""
        response_body = f"""{{"status": "success", "request_id": {request_id}}}"""
        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(response_body)}",
            "Connection: keep-alive",
            "Server: nginx/1.20.2",
            "",
            response_body,
        ]
        http_resp = "\r\n".join(response_lines).encode()
        return b"\x17\x03\x03" + len(http_resp).to_bytes(2, "big") + http_resp

    def _create_enhanced_additional_http_request(
        self, context: AttackContext, request_id: int
    ) -> bytes:
        """Create enhanced additional HTTP request with varied content."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"
        fingerprint = self._session_state["browser_fingerprint"]
        path = random.choice(["/api/status", "/api/user/profile", "/api/notifications"])
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {domain}",
            f"User-Agent: {fingerprint['user_agent']}",
            "Connection: keep-alive",
            "",
            "",
        ]
        http_req = "\r\n".join(request_lines).encode()
        return b"\x17\x03\x03" + len(http_req).to_bytes(2, "big") + http_req

    def _create_resource_request(
        self, context: AttackContext, path: str, content_type: str
    ) -> bytes:
        """Create resource request (CSS, JS, images)."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"
        fingerprint = self._session_state["browser_fingerprint"]
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {domain}",
            f"User-Agent: {fingerprint['user_agent']}",
            f"Accept: {self._get_accept_header_for_resource(content_type)}",
            "Connection: keep-alive",
            "",
            "",
        ]
        http_req = "\r\n".join(request_lines).encode()
        return b"\x17\x03\x03" + len(http_req).to_bytes(2, "big") + http_req

    def _create_resource_response(
        self, context: AttackContext, content_type: str, size: int
    ) -> bytes:
        """Create resource response."""
        resource_content = os.urandom(size)
        response_lines = [
            "HTTP/1.1 200 OK",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(resource_content)}",
            "Connection: keep-alive",
            "",
        ]
        http_resp = "\r\n".join(response_lines).encode() + resource_content
        return b"\x17\x03\x03" + len(http_resp).to_bytes(2, "big") + http_resp

    def _get_accept_header_for_resource(self, content_type: str) -> str:
        """Get appropriate Accept header for resource type."""
        if "css" in content_type:
            return "text/css,*/*;q=0.1"
        elif "javascript" in content_type:
            return "*/*"
        elif "image" in content_type:
            return "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
        else:
            return "*/*"

    def _create_enhanced_keep_alive_packet(
        self, context: AttackContext, ka_id: int
    ) -> bytes:
        """Create enhanced keep-alive packet."""
        seq = (self._session_state.get("tcp_seq", 0) + ka_id) & 0xFFFFFFFF
        ack = self._session_state.get("tcp_ack", 0)
        return self._build_tcp_segment(self._session_state.get("src_port", 55555), context.dst_port, seq, ack, flags=0x10)

    def _create_enhanced_keep_alive_response(
        self, context: AttackContext, ka_id: int
    ) -> bytes:
        """Create enhanced keep-alive response packet."""
        seq = (self._session_state.get("tcp_ack", 0) + ka_id) & 0xFFFFFFFF
        ack = (self._session_state.get("tcp_seq", 0)) & 0xFFFFFFFF
        return self._build_tcp_segment(context.dst_port, self._session_state.get("src_port", 55555), seq, ack, flags=0x10)

    def _create_enhanced_tcp_fin_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP FIN packet."""
        seq = (self._session_state.get("tcp_seq", 0) + 1000) & 0xFFFFFFFF
        ack = self._session_state.get("tcp_ack", 0)
        return self._build_tcp_segment(self._session_state.get("src_port", 55555), context.dst_port, seq, ack, flags=0x01)

    def _create_enhanced_tcp_fin_ack_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP FIN-ACK packet."""
        seq = (self._session_state.get("tcp_ack", 0) + 1) & 0xFFFFFFFF
        ack = (self._session_state.get("tcp_seq", 0) + 1001) & 0xFFFFFFFF
        return self._build_tcp_segment(context.dst_port, self._session_state.get("src_port", 55555), seq, ack, flags=0x11)

    def _create_enhanced_tcp_final_ack_packet(self, context: AttackContext) -> bytes:
        """Create enhanced final ACK packet."""
        seq = (self._session_state.get("tcp_seq", 0) + 1001) & 0xFFFFFFFF
        ack = (self._session_state.get("tcp_ack", 0) + 1) & 0xFFFFFFFF
        return self._build_tcp_segment(self._session_state.get("src_port", 55555), context.dst_port, seq, ack, flags=0x10)

    def _generate_realistic_session_id(self) -> int:
        """Generate realistic session ID based on timestamp."""
        return int(time.time() * 1000)

    def _generate_realistic_tcp_seq(self) -> int:
        """Generate realistic TCP sequence number."""
        return random.randint(100000000, 1000000000)

    def _generate_browser_fingerprint(self) -> Dict[str, Any]:
        """Generate realistic browser fingerprint."""
        fingerprints = {
            "chrome": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "accept_encoding": "gzip, deflate, br",
                "accept_language": "en-US,en;q=0.9",
                "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                "sec_ch_ua_mobile": "?0",
                "sec_ch_ua_platform": '"Windows"',
            },
            "firefox": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "accept_encoding": "gzip, deflate, br",
                "accept_language": "en-US,en;q=0.5",
            },
            "safari": {
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept_encoding": "gzip, deflate, br",
                "accept_language": "en-US,en;q=0.9",
            },
        }
        return fingerprints.get(self.config.browser_type, fingerprints["chrome"])

    def _calculate_enhanced_realism_score(self) -> float:
        """Calculate enhanced realism score based on session characteristics."""
        score = 0.0
        if self.config.simulate_dns: score += 0.15
        if self.config.simulate_tcp_handshake: score += 0.15
        if self.config.simulate_tls_handshake: score += 0.15
        if self.config.simulate_resource_loading: score += 0.15
        if self.config.simulate_keep_alive: score += 0.10
        if self.config.simulate_teardown: score += 0.10
        if self.config.add_browser_fingerprinting: score += 0.15
        return min(1.0, score)

    def _calculate_behavioral_metrics(self) -> Dict[str, Any]:
        """Calculate behavioral metrics for DPI evasion analysis."""
        total_duration = time.time() - self._session_state["connection_start_time"]
        return {
            "session_duration_seconds": total_duration,
            "packets_per_second": self._session_state["packet_sequence"]
            / max(total_duration, 1),
            "bytes_per_second": self._session_state["bytes_transferred"]
            / max(total_duration, 1),
        }

    def _generate_tls_session_id(self) -> bytes:
        """Generate TLS session ID."""
        return os.urandom(32)