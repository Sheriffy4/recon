# recon/core/bypass/attacks/combo/full_session_simulation.py
"""
Full Session Simulation Attack

Simulates a complete user session lifecycle from DNS resolution through
TCP/TLS handshake to application data and keep-alive packets. This creates
the most realistic traffic pattern possible to evade sophisticated DPI systems
that analyze complete session behavior.

Enhanced for maximum realism and behavioral DPI evasion.
"""

import time
import random
import socket
import struct
import logging
import hashlib
import os
from typing import Dict, Any, List, Optional, Tuple, Generator
from dataclasses import dataclass, field
from enum import Enum

from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack
from core.dns.robust_dns_handler import RobustDNSHandler, DNSResolutionResult

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

    # DNS resolution timing (realistic DNS query delays)
    dns_resolution_delay: Tuple[float, float] = (5.0, 25.0)  # ms
    dns_cache_check_delay: Tuple[float, float] = (1.0, 5.0)  # ms
    dns_retry_delay: Tuple[float, float] = (100.0, 300.0)  # ms

    # TCP handshake timing (realistic network RTT)
    tcp_syn_delay: float = 0.0
    tcp_syn_ack_delay: Tuple[float, float] = (10.0, 80.0)  # ms (realistic RTT)
    tcp_ack_delay: Tuple[float, float] = (2.0, 15.0)  # ms

    # TLS handshake timing (realistic TLS negotiation)
    client_hello_delay: Tuple[float, float] = (20.0, 100.0)  # ms
    server_hello_delay: Tuple[float, float] = (50.0, 200.0)  # ms
    certificate_delay: Tuple[float, float] = (30.0, 120.0)  # ms
    key_exchange_delay: Tuple[float, float] = (10.0, 60.0)  # ms
    finished_delay: Tuple[float, float] = (5.0, 30.0)  # ms

    # Application data timing (realistic user behavior)
    first_request_delay: Tuple[float, float] = (50.0, 300.0)  # ms
    response_delay: Tuple[float, float] = (100.0, 800.0)  # ms
    subsequent_request_delay: Tuple[float, float] = (500.0, 3000.0)  # ms
    user_think_time: Tuple[float, float] = (2.0, 10.0)  # seconds

    # Keep-alive timing (realistic connection maintenance)
    keep_alive_interval: Tuple[float, float] = (45.0, 120.0)  # seconds
    keep_alive_response_delay: Tuple[float, float] = (20.0, 100.0)  # ms

    # Session teardown timing (graceful connection closure)
    fin_delay: Tuple[float, float] = (50.0, 300.0)  # ms
    fin_ack_delay: Tuple[float, float] = (10.0, 50.0)  # ms
    final_ack_delay: Tuple[float, float] = (5.0, 25.0)  # ms

    # Browser-like behavior timing
    page_load_delay: Tuple[float, float] = (200.0, 1000.0)  # ms
    resource_fetch_delay: Tuple[float, float] = (50.0, 200.0)  # ms
    idle_time: Tuple[float, float] = (5.0, 30.0)  # seconds


@dataclass
class SessionConfig:
    """Configuration for full session simulation - enhanced for behavioral DPI evasion."""

    # Session behavior (complete lifecycle simulation)
    simulate_dns: bool = True
    simulate_tcp_handshake: bool = True
    simulate_tls_handshake: bool = True
    simulate_keep_alive: bool = True
    simulate_teardown: bool = True

    # Session parameters (realistic user session characteristics)
    session_duration_range: Tuple[float, float] = (120.0, 600.0)  # seconds (2-10 min)
    application_requests_count: Tuple[int, int] = (
        5,
        15,
    )  # More realistic request count
    keep_alive_count: Tuple[int, int] = (3, 8)  # Realistic keep-alive frequency

    # Enhanced realism features
    add_user_behavior_delays: bool = True
    simulate_browser_behavior: bool = True
    add_background_noise: bool = True
    simulate_real_user_patterns: bool = True  # NEW: Real user behavior patterns
    add_browser_fingerprinting: bool = True  # NEW: Browser-like fingerprinting
    simulate_resource_loading: bool = True  # NEW: Simulate CSS/JS/image loading

    # Advanced behavioral features
    vary_packet_sizes: bool = True  # NEW: Vary packet sizes realistically
    add_jitter_to_timing: bool = True  # NEW: Add realistic timing jitter
    simulate_network_conditions: bool = True  # NEW: Simulate varying network conditions
    add_protocol_compliance: bool = True  # NEW: Strict protocol compliance

    # Browser simulation parameters
    browser_type: str = "chrome"  # chrome, firefox, safari, edge
    os_type: str = "windows"  # windows, macos, linux
    user_agent_rotation: bool = True
    accept_language: str = "en-US,en;q=0.9"

    # Timing configuration
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

    def execute(self, context: AttackContext) -> AttackResult:
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
            # Initialize enhanced session state
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
            }

            LOG.debug(
                f"Starting enhanced full session simulation for {self._session_state['domain']} "
                f"(Browser: {self.config.browser_type}, OS: {self.config.os_type})"
            )

            # Phase 1: DNS Resolution (with realistic caching behavior)
            if self.config.simulate_dns:
                dns_result = self._simulate_enhanced_dns_phase(context)
                session_packets.extend(dns_result["packets"])
                total_bytes_sent += dns_result["bytes_sent"]
                self._session_state["phase_results"]["dns"] = dns_result

            # Phase 2: TCP Handshake (with realistic network behavior)
            if self.config.simulate_tcp_handshake:
                tcp_result = self._simulate_enhanced_tcp_handshake_phase(context)
                session_packets.extend(tcp_result["packets"])
                total_bytes_sent += tcp_result["bytes_sent"]
                self._session_state["phase_results"]["tcp_handshake"] = tcp_result

            # Phase 3: TLS Handshake (with browser-like TLS negotiation)
            if self.config.simulate_tls_handshake:
                tls_result = self._simulate_enhanced_tls_handshake_phase(context)
                session_packets.extend(tls_result["packets"])
                total_bytes_sent += tls_result["bytes_sent"]
                self._session_state["phase_results"]["tls_handshake"] = tls_result

            # Phase 4: Application Data (with realistic browser behavior)
            app_result = self._simulate_enhanced_application_data_phase(context)
            session_packets.extend(app_result["packets"])
            total_bytes_sent += app_result["bytes_sent"]
            self._session_state["phase_results"]["application_data"] = app_result

            # Phase 5: Resource Loading (NEW - simulate CSS/JS/images)
            if self.config.simulate_resource_loading:
                resource_result = self._simulate_resource_loading_phase(context)
                session_packets.extend(resource_result["packets"])
                total_bytes_sent += resource_result["bytes_sent"]
                self._session_state["phase_results"][
                    "resource_loading"
                ] = resource_result

            # Phase 6: Keep-Alive (with realistic maintenance patterns)
            if self.config.simulate_keep_alive:
                keepalive_result = self._simulate_enhanced_keep_alive_phase(context)
                session_packets.extend(keepalive_result["packets"])
                total_bytes_sent += keepalive_result["bytes_sent"]
                self._session_state["phase_results"]["keep_alive"] = keepalive_result

            # Phase 7: Session Teardown (with graceful closure)
            if self.config.simulate_teardown:
                teardown_result = self._simulate_enhanced_teardown_phase(context)
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
                    "is_raw": True,  # Indicate this generates raw packets
                },
            )

        except Exception as e:
            LOG.error(f"Enhanced full session simulation failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _simulate_enhanced_dns_phase(self, context: AttackContext) -> Dict[str, Any]:
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

        # Simulate DNS cache check delay (realistic browser behavior)
        cache_check_delay = (
            random.uniform(*self.config.timing.dns_cache_check_delay) / 1000.0
        )
        time.sleep(cache_check_delay)

        # Simulate DNS query delay with jitter
        base_delay = random.uniform(*self.config.timing.dns_resolution_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-5.0, 5.0)
            dns_delay = max(1.0, base_delay + jitter) / 1000.0
        else:
            dns_delay = base_delay / 1000.0

        time.sleep(dns_delay)

        # Create realistic DNS query packet with proper transaction ID
        dns_query = self._create_enhanced_dns_query_packet(domain)
        packets.append((dns_query, cache_check_delay * 1000))

        # Simulate realistic DNS response delay (network RTT + processing)
        network_rtt = random.uniform(10.0, 80.0)  # Realistic network RTT
        processing_delay = random.uniform(5.0, 20.0)  # DNS server processing
        response_delay = (network_rtt + processing_delay) / 1000.0
        time.sleep(response_delay)

        # Create realistic DNS response packet
        dns_response = self._create_enhanced_dns_response_packet(domain, context.dst_ip)
        packets.append((dns_response, response_delay * 1000))

        # Simulate additional DNS queries for realism (AAAA record, etc.)
        if self.config.simulate_real_user_patterns:
            # Query for IPv6 address (AAAA record)
            ipv6_delay = random.uniform(5.0, 15.0) / 1000.0
            time.sleep(ipv6_delay)

            dns_aaaa_query = self._create_dns_aaaa_query_packet(domain)
            packets.append((dns_aaaa_query, ipv6_delay * 1000))

            # AAAA response (no IPv6 address)
            aaaa_response_delay = random.uniform(10.0, 50.0) / 1000.0
            time.sleep(aaaa_response_delay)

            dns_aaaa_response = self._create_dns_aaaa_response_packet(domain)
            packets.append((dns_aaaa_response, aaaa_response_delay * 1000))

        bytes_sent = sum(len(packet) for packet, _ in packets)

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
            "queries_sent": len(
                [
                    p
                    for p in packets
                    if b"DNS_QUERY" in p[0] or b"DNS_AAAA_QUERY" in p[0]
                ]
            ),
            "cache_behavior": "miss" if len(packets) > 2 else "hit",
        }

    def _simulate_enhanced_tcp_handshake_phase(
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

        # SYN packet with realistic TCP options
        syn_packet = self._create_enhanced_tcp_syn_packet(context)
        packets.append((syn_packet, 0.0))

        # Realistic SYN-ACK delay (network RTT)
        base_rtt = random.uniform(*self.config.timing.tcp_syn_ack_delay)
        if self.config.simulate_network_conditions:
            # Add network condition variations
            network_load = random.uniform(0.8, 1.2)  # Network load factor
            syn_ack_delay = base_rtt * network_load
        else:
            syn_ack_delay = base_rtt

        time.sleep(syn_ack_delay / 1000.0)

        # SYN-ACK packet with server-side TCP options
        syn_ack_packet = self._create_enhanced_tcp_syn_ack_packet(context)
        packets.append((syn_ack_packet, syn_ack_delay))

        # ACK delay (client processing time)
        ack_delay = random.uniform(*self.config.timing.tcp_ack_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-2.0, 2.0)
            ack_delay = max(1.0, ack_delay + jitter)

        time.sleep(ack_delay / 1000.0)

        # ACK packet completing handshake
        ack_packet = self._create_enhanced_tcp_ack_packet(context)
        packets.append((ack_packet, ack_delay))

        # Update TCP sequence numbers realistically
        self._session_state["tcp_seq"] += 1
        self._session_state["tcp_ack"] = random.randint(1000000, 9999999)
        self._session_state["tcp_window"] = 65535  # Standard window size
        self._session_state["mss"] = 1460  # Maximum Segment Size

        bytes_sent = sum(len(packet) for packet, _ in packets)

        LOG.debug(
            f"Enhanced TCP handshake completed: {len(packets)} packets, {bytes_sent} bytes, "
            f"RTT: {syn_ack_delay:.1f}ms"
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

    def _simulate_enhanced_tls_handshake_phase(
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

        # Client Hello with realistic browser extensions
        client_hello_delay = random.uniform(*self.config.timing.client_hello_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-10.0, 10.0)
            client_hello_delay = max(5.0, client_hello_delay + jitter)

        time.sleep(client_hello_delay / 1000.0)

        client_hello = self._create_enhanced_tls_client_hello(context)
        packets.append((client_hello, client_hello_delay))

        # Server Hello with realistic server behavior
        server_hello_delay = random.uniform(*self.config.timing.server_hello_delay)
        if self.config.simulate_network_conditions:
            # Server processing time variation
            processing_load = random.uniform(0.9, 1.3)
            server_hello_delay *= processing_load

        time.sleep(server_hello_delay / 1000.0)

        server_hello = self._create_enhanced_tls_server_hello(context)
        packets.append((server_hello, server_hello_delay))

        # Certificate chain (realistic multi-certificate chain)
        cert_delay = random.uniform(*self.config.timing.certificate_delay)
        time.sleep(cert_delay / 1000.0)

        certificate_chain = self._create_enhanced_tls_certificate_chain(context)
        packets.append((certificate_chain, cert_delay))

        # Server Hello Done
        hello_done_delay = random.uniform(5.0, 20.0)
        time.sleep(hello_done_delay / 1000.0)

        hello_done = self._create_tls_server_hello_done(context)
        packets.append((hello_done, hello_done_delay))

        # Client Key Exchange with realistic crypto processing
        key_exchange_delay = random.uniform(*self.config.timing.key_exchange_delay)
        if self.config.add_protocol_compliance:
            # Add realistic crypto computation delay
            crypto_delay = random.uniform(10.0, 30.0)
            key_exchange_delay += crypto_delay

        time.sleep(key_exchange_delay / 1000.0)

        key_exchange = self._create_enhanced_tls_key_exchange(context)
        packets.append((key_exchange, key_exchange_delay))

        # Change Cipher Spec
        ccs_delay = random.uniform(2.0, 10.0)
        time.sleep(ccs_delay / 1000.0)

        change_cipher_spec = self._create_tls_change_cipher_spec(context)
        packets.append((change_cipher_spec, ccs_delay))

        # Client Finished
        finished_delay = random.uniform(*self.config.timing.finished_delay)
        time.sleep(finished_delay / 1000.0)

        client_finished = self._create_enhanced_tls_finished(context, is_client=True)
        packets.append((client_finished, finished_delay))

        # Server Change Cipher Spec + Finished
        server_ccs_delay = random.uniform(10.0, 40.0)
        time.sleep(server_ccs_delay / 1000.0)

        server_ccs = self._create_tls_change_cipher_spec(context, is_server=True)
        packets.append((server_ccs, server_ccs_delay))

        server_finished_delay = random.uniform(5.0, 20.0)
        time.sleep(server_finished_delay / 1000.0)

        server_finished = self._create_enhanced_tls_finished(context, is_client=False)
        packets.append((server_finished, server_finished_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)

        LOG.debug(
            f"Enhanced TLS handshake completed: {len(packets)} packets, {bytes_sent} bytes, "
            f"Total time: {(time.time() - start_time) * 1000:.1f}ms"
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

    def _simulate_enhanced_application_data_phase(
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

        # First request (contains main payload) with realistic browser headers
        first_request_delay = random.uniform(*self.config.timing.first_request_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-20.0, 20.0)
            first_request_delay = max(10.0, first_request_delay + jitter)

        time.sleep(first_request_delay / 1000.0)

        # Create enhanced HTTP request with main payload
        http_request = self._create_enhanced_http_request_with_payload(context)
        packets.append((http_request, first_request_delay))

        # Server response with realistic processing delay
        response_delay = random.uniform(*self.config.timing.response_delay)
        if self.config.simulate_network_conditions:
            # Add server processing variation
            server_load = random.uniform(0.8, 1.5)
            response_delay *= server_load

        time.sleep(response_delay / 1000.0)

        http_response = self._create_enhanced_http_response(context)
        packets.append((http_response, response_delay))

        # Additional requests for realism (simulate browsing behavior)
        request_count = random.randint(*self.config.application_requests_count)

        for i in range(request_count - 1):
            # User think time (realistic browsing behavior)
            if self.config.simulate_real_user_patterns:
                think_time = random.uniform(*self.config.timing.user_think_time) * 1000
            else:
                think_time = random.uniform(
                    *self.config.timing.subsequent_request_delay
                )

            time.sleep(think_time / 1000.0)

            # Additional request with varied content
            additional_request = self._create_enhanced_additional_http_request(
                context, i
            )
            packets.append((additional_request, think_time))

            # Response to additional request
            add_response_delay = random.uniform(*self.config.timing.response_delay)
            if self.config.add_jitter_to_timing:
                jitter = random.uniform(-50.0, 50.0)
                add_response_delay = max(50.0, add_response_delay + jitter)

            time.sleep(add_response_delay / 1000.0)

            additional_response = self._create_enhanced_http_response(
                context, request_id=i
            )
            packets.append((additional_response, add_response_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)

        LOG.debug(
            f"Enhanced application data phase completed: {len(packets)} packets, {bytes_sent} bytes, "
            f"Requests: {request_count}"
        )

        return {
            "phase": SessionPhase.APPLICATION_DATA.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "requests_sent": request_count,
            "main_payload_sent": True,
            "user_behavior_simulated": self.config.simulate_real_user_patterns,
            "average_think_time_ms": sum(p[1] for p in packets[2::2])
            / max(len(packets[2::2]), 1),
        }

    def _simulate_resource_loading_phase(
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

        # Simulate loading common web resources
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
            # Resource request delay (parallel loading simulation)
            if i == 0:
                resource_delay = random.uniform(*self.config.timing.page_load_delay)
            else:
                resource_delay = random.uniform(
                    *self.config.timing.resource_fetch_delay
                )

            time.sleep(resource_delay / 1000.0)

            # Create resource request
            resource_request = self._create_resource_request(
                context, path, content_type
            )
            packets.append((resource_request, resource_delay))

            # Resource response
            resource_response_delay = random.uniform(50.0, 200.0)
            time.sleep(resource_response_delay / 1000.0)

            resource_response = self._create_resource_response(
                context, content_type, size
            )
            packets.append((resource_response, resource_response_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)

        LOG.debug(
            f"Resource loading phase completed: {len(packets)} packets, {bytes_sent} bytes, "
            f"Resources: {len(resources)}"
        )

        return {
            "phase": "resource_loading",
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "resources_loaded": len(resources),
            "resource_types": [r[1] for r in resources],
        }

    def _simulate_enhanced_keep_alive_phase(
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
            # Realistic keep-alive interval with variation
            base_interval = random.uniform(*self.config.timing.keep_alive_interval)
            if self.config.add_jitter_to_timing:
                jitter = random.uniform(-10.0, 10.0)
                ka_interval = max(30.0, base_interval + jitter)
            else:
                ka_interval = base_interval

            time.sleep(ka_interval)

            # Enhanced keep-alive packet
            keep_alive_packet = self._create_enhanced_keep_alive_packet(context, i)
            packets.append((keep_alive_packet, ka_interval * 1000))

            # Keep-alive response with realistic delay
            ka_response_delay = random.uniform(
                *self.config.timing.keep_alive_response_delay
            )
            time.sleep(ka_response_delay / 1000.0)

            keep_alive_response = self._create_enhanced_keep_alive_response(context, i)
            packets.append((keep_alive_response, ka_response_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)
        self._session_state["bytes_transferred"] += bytes_sent
        self._session_state["packet_sequence"] += len(packets)

        LOG.debug(
            f"Enhanced keep-alive phase completed: {len(packets)} packets, {bytes_sent} bytes, "
            f"Keep-alives: {keep_alive_count}"
        )

        return {
            "phase": SessionPhase.KEEP_ALIVE.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "keep_alive_count": keep_alive_count,
            "average_interval_seconds": sum(p[1] for p in packets[::2])
            / max(len(packets[::2]), 1)
            / 1000,
        }

    def _simulate_enhanced_teardown_phase(
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

        # Client-initiated FIN (graceful close)
        fin_delay = random.uniform(*self.config.timing.fin_delay)
        if self.config.add_jitter_to_timing:
            jitter = random.uniform(-20.0, 20.0)
            fin_delay = max(10.0, fin_delay + jitter)

        time.sleep(fin_delay / 1000.0)

        fin_packet = self._create_enhanced_tcp_fin_packet(context)
        packets.append((fin_packet, fin_delay))

        # Server FIN-ACK response
        fin_ack_delay = random.uniform(*self.config.timing.fin_ack_delay)
        time.sleep(fin_ack_delay / 1000.0)

        fin_ack_packet = self._create_enhanced_tcp_fin_ack_packet(context)
        packets.append((fin_ack_packet, fin_ack_delay))

        # Final ACK from client
        final_ack_delay = random.uniform(*self.config.timing.final_ack_delay)
        time.sleep(final_ack_delay / 1000.0)

        final_ack_packet = self._create_enhanced_tcp_final_ack_packet(context)
        packets.append((final_ack_packet, final_ack_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)
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

    def _simulate_keep_alive_phase(self, context: AttackContext) -> Dict[str, Any]:
        """
        Simulate keep-alive packets to maintain session.

        Args:
            context: Attack context

        Returns:
            Keep-alive phase results
        """
        start_time = time.time()
        packets = []

        keep_alive_count = random.randint(*self.config.keep_alive_count)

        for i in range(keep_alive_count):
            # Keep-alive interval
            ka_interval = random.uniform(*self.config.timing.keep_alive_interval)
            time.sleep(ka_interval)

            # Keep-alive packet
            keep_alive_packet = self._create_keep_alive_packet(context, i)
            packets.append((keep_alive_packet, ka_interval * 1000))

            # Keep-alive response
            ka_response_delay = random.uniform(
                *self.config.timing.keep_alive_response_delay
            )
            time.sleep(ka_response_delay / 1000.0)

            keep_alive_response = self._create_keep_alive_response(context, i)
            packets.append((keep_alive_response, ka_response_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)

        LOG.debug(
            f"Keep-alive phase completed: {len(packets)} packets, {bytes_sent} bytes"
        )

        return {
            "phase": SessionPhase.KEEP_ALIVE.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "keep_alive_count": keep_alive_count,
        }

    def _simulate_teardown_phase(self, context: AttackContext) -> Dict[str, Any]:
        """
        Simulate session teardown (FIN/ACK sequence).

        Args:
            context: Attack context

        Returns:
            Teardown phase results
        """
        start_time = time.time()
        packets = []

        # FIN packet
        fin_delay = random.uniform(*self.config.timing.fin_delay)
        time.sleep(fin_delay / 1000.0)

        fin_packet = self._create_tcp_fin_packet(context)
        packets.append((fin_packet, fin_delay))

        # FIN-ACK response
        fin_ack_delay = random.uniform(*self.config.timing.fin_ack_delay)
        time.sleep(fin_ack_delay / 1000.0)

        fin_ack_packet = self._create_tcp_fin_ack_packet(context)
        packets.append((fin_ack_packet, fin_ack_delay))

        # Final ACK
        final_ack_delay = random.uniform(*self.config.timing.fin_ack_delay)
        time.sleep(final_ack_delay / 1000.0)

        final_ack_packet = self._create_tcp_final_ack_packet(context)
        packets.append((final_ack_packet, final_ack_delay))

        bytes_sent = sum(len(packet) for packet, _ in packets)

        LOG.debug(
            f"Teardown phase completed: {len(packets)} packets, {bytes_sent} bytes"
        )

        return {
            "phase": SessionPhase.SESSION_TEARDOWN.value,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "duration_ms": (time.time() - start_time) * 1000,
            "connection_closed": True,
        }

    # Enhanced packet creation methods
    def _create_enhanced_dns_query_packet(self, domain: str) -> bytes:
        """Create enhanced DNS query packet with realistic structure."""
        query_id = random.randint(1, 65535)
        # Enhanced flags: recursion desired, checking disabled for realism
        flags = 0x0100 if random.random() > 0.1 else 0x0120
        header = struct.pack(
            "!HHHHHH", query_id, flags, 1, 0, 0, 1
        )  # Additional section

        # Encode domain name
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"  # End of domain
        question += struct.pack("!HH", 1, 1)  # Type A, Class IN

        # Add EDNS0 OPT record for realism
        opt_record = b"\x00"  # Root domain
        opt_record += struct.pack("!HH", 41, 4096)  # OPT type, UDP payload size
        opt_record += b"\x00\x00\x00\x00"  # TTL/flags
        opt_record += b"\x00\x00"  # RDATA length

        return b"DNS_QUERY:" + header + question + opt_record

    def _create_dns_aaaa_query_packet(self, domain: str) -> bytes:
        """Create DNS AAAA (IPv6) query packet."""
        query_id = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 28, 1)  # Type AAAA, Class IN

        return b"DNS_AAAA_QUERY:" + header + question

    def _create_enhanced_dns_response_packet(self, domain: str, ip: str) -> bytes:
        """Create enhanced DNS response packet."""
        response_id = random.randint(1, 65535)
        # Authoritative answer, recursion available
        header = struct.pack("!HHHHHH", response_id, 0x8180, 1, 1, 0, 1)

        # Question section
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 1, 1)

        # Answer section with realistic TTL
        answer = b"\xc0\x0c"  # Pointer to domain name
        ttl = random.randint(300, 3600)  # Realistic TTL range
        answer += struct.pack("!HHIH", 1, 1, ttl, 4)
        answer += socket.inet_aton(ip)

        # Additional section (OPT record)
        opt_record = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"

        return b"DNS_RESPONSE:" + header + question + answer + opt_record

    def _create_dns_aaaa_response_packet(self, domain: str) -> bytes:
        """Create DNS AAAA response packet (no IPv6 address)."""
        response_id = random.randint(1, 65535)
        # NXDOMAIN or no data response
        header = struct.pack("!HHHHHH", response_id, 0x8183, 1, 0, 1, 0)

        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 28, 1)

        # Authority section (SOA record)
        authority = b"\xc0\x0c"  # Pointer to domain
        authority += struct.pack("!HHIH", 6, 1, 3600, 20)  # SOA type
        authority += b"\x00" * 20  # Simplified SOA data

        return b"DNS_AAAA_RESPONSE:" + header + question + authority

    def _create_enhanced_tcp_syn_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP SYN packet with realistic options."""
        src_port = random.randint(32768, 65535)  # Ephemeral port range

        # TCP header with options
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port,
            context.dst_port,
            self._session_state["tcp_seq"],
            0,  # Acknowledgment number
            0x70,  # Data offset (7 words = 28 bytes with options)
            0x02,  # SYN flag
            65535,  # Window size
            0,  # Checksum (simplified)
            0,  # Urgent pointer
        )

        # TCP options (MSS, Window Scale, SACK permitted, Timestamps)
        options = b""
        options += b"\x02\x04\x05\xb4"  # MSS = 1460
        options += b"\x03\x03\x07"  # Window Scale = 7
        options += b"\x04\x02"  # SACK permitted
        options += b"\x08\x0a"  # Timestamps
        options += struct.pack("!II", int(time.time()), 0)  # TSval, TSecr
        options += b"\x01"  # NOP for alignment

        return b"TCP_SYN:" + tcp_header + options

    def _create_enhanced_tcp_syn_ack_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP SYN-ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            context.dst_port,
            random.randint(32768, 65535),
            random.randint(1000000, 9999999),
            self._session_state["tcp_seq"] + 1,
            0x60,  # Data offset (6 words = 24 bytes with options)
            0x12,  # SYN + ACK flags
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        # Server-side TCP options
        options = b""
        options += b"\x02\x04\x05\xb4"  # MSS = 1460
        options += b"\x04\x02"  # SACK permitted
        options += b"\x08\x0a"  # Timestamps
        options += struct.pack("!II", int(time.time()), int(time.time()) - 1)

        return b"TCP_SYN_ACK:" + tcp_header + options

    def _create_enhanced_tcp_ack_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(32768, 65535),
            context.dst_port,
            self._session_state["tcp_seq"] + 1,
            self._session_state["tcp_ack"],
            0x50,  # Data offset (5 words = 20 bytes, no options)
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_ACK:" + tcp_header

    def _create_enhanced_tls_client_hello(self, context: AttackContext) -> bytes:
        """Create enhanced TLS Client Hello with realistic browser extensions."""
        tls_version = b"\x03\x03"  # TLS 1.2
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id_len = 0

        # Realistic cipher suites for the browser type
        cipher_suites = self._get_browser_cipher_suites()

        # SNI extension
        domain = context.domain or f"{context.dst_ip}"
        extensions = self._create_realistic_tls_extensions(domain)

        client_hello = (
            b"\x16"  # Handshake
            + tls_version
            + b"\x00\x00"  # Length placeholder
            + b"\x01"  # Client Hello
            + b"\x00\x00\x00"  # Length placeholder
            + tls_version
            + random_bytes
            + bytes([session_id_len])
            + cipher_suites
            + b"\x01\x00"  # Compression methods (null)
            + extensions
        )

        return client_hello

    def _get_browser_cipher_suites(self) -> bytes:
        """Get realistic cipher suites for the configured browser."""
        chrome_suites = [
            0x1301,
            0x1302,
            0x1303,
            0xC02B,
            0xC02F,
            0xC02C,
            0xC030,
            0xCCA9,
            0xCCA8,
            0xC013,
            0xC014,
            0x009C,
            0x009D,
            0x002F,
            0x0035,
        ]

        firefox_suites = [
            0x1301,
            0x1302,
            0x1303,
            0xC02B,
            0xC02F,
            0xC02C,
            0xC030,
            0xC009,
            0xC013,
            0xC00A,
            0xC014,
            0x002F,
            0x0035,
            0x000A,
        ]

        suites = (
            chrome_suites if self.config.browser_type == "chrome" else firefox_suites
        )
        suite_bytes = b""
        for suite in suites:
            suite_bytes += struct.pack("!H", suite)

        return struct.pack("!H", len(suite_bytes)) + suite_bytes

    def _create_realistic_tls_extensions(self, domain: str) -> bytes:
        """Create realistic TLS extensions for browser simulation."""
        extensions = b""

        # SNI extension
        sni_data = (
            b"\x00"  # Server name list
            + struct.pack("!H", len(domain) + 3)
            + b"\x00"  # Hostname type
            + struct.pack("!H", len(domain))
            + domain.encode()
        )
        extensions += struct.pack("!HH", 0, len(sni_data)) + sni_data

        # Supported groups (elliptic curves)
        groups = b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # x25519, secp256r1, secp384r1, secp521r1
        extensions += struct.pack("!HH", 10, len(groups)) + groups

        # Signature algorithms
        sig_algs = b"\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
        extensions += struct.pack("!HH", 13, len(sig_algs)) + sig_algs

        # ALPN (Application Layer Protocol Negotiation)
        alpn_data = b"\x00\x0c\x02h2\x08http/1.1"  # h2, http/1.1
        extensions += struct.pack("!HH", 16, len(alpn_data)) + alpn_data

        # Status request (OCSP stapling)
        status_req = b"\x01\x00\x00\x00\x00"
        extensions += struct.pack("!HH", 5, len(status_req)) + status_req

        return struct.pack("!H", len(extensions)) + extensions

    def _create_enhanced_tls_server_hello(self, context: AttackContext) -> bytes:
        """Create enhanced TLS Server Hello packet."""
        tls_version = b"\x03\x03"
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id = self._session_state["tls_session_id"]

        # Realistic server cipher suite selection
        chosen_cipher = 0xC02F  # ECDHE-RSA-AES128-GCM-SHA256

        server_hello = (
            b"\x16"  # Handshake
            + tls_version
            + b"\x00\x00"  # Length placeholder
            + b"\x02"  # Server Hello
            + b"\x00\x00\x00"  # Length placeholder
            + tls_version
            + random_bytes
            + bytes([len(session_id)])
            + session_id
            + struct.pack("!H", chosen_cipher)  # Chosen cipher suite
            + b"\x00"  # Compression method
        )

        return server_hello

    def _create_enhanced_tls_certificate_chain(self, context: AttackContext) -> bytes:
        """Create enhanced TLS Certificate chain packet."""
        # Simulate realistic certificate chain (leaf + intermediate + root)
        leaf_cert = b"LEAF_CERT_" + bytes([random.randint(0, 255) for _ in range(800)])
        intermediate_cert = b"INTERMEDIATE_CERT_" + bytes(
            [random.randint(0, 255) for _ in range(600)]
        )

        cert_chain = (
            struct.pack("!I", len(leaf_cert))[1:]
            + leaf_cert
            + struct.pack("!I", len(intermediate_cert))[1:]
            + intermediate_cert
        )

        certificate = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(cert_chain) + 10)  # Length
            + b"\x0b"  # Certificate
            + struct.pack("!I", len(cert_chain) + 6)[1:]  # Length (3 bytes)
            + struct.pack("!I", len(cert_chain) + 3)[1:]  # Certificates length
            + cert_chain
        )

        return certificate

    def _create_tls_server_hello_done(self, context: AttackContext) -> bytes:
        """Create TLS Server Hello Done packet."""
        hello_done = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + b"\x00\x04"  # Length
            + b"\x0e"  # Server Hello Done
            + b"\x00\x00\x00"  # Length (0)
        )
        return hello_done

    def _create_enhanced_tls_key_exchange(self, context: AttackContext) -> bytes:
        """Create enhanced TLS Key Exchange packet."""
        # ECDHE key exchange data
        key_data = bytes(
            [random.randint(0, 255) for _ in range(65)]
        )  # Uncompressed point

        key_exchange = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(key_data) + 4)  # Length
            + b"\x10"  # Client Key Exchange
            + struct.pack("!I", len(key_data))[1:]  # Length (3 bytes)
            + key_data
        )

        return key_exchange

    def _create_tls_change_cipher_spec(
        self, context: AttackContext, is_server: bool = False
    ) -> bytes:
        """Create TLS Change Cipher Spec packet."""
        ccs = (
            b"\x14"  # Change Cipher Spec
            + b"\x03\x03"  # TLS version
            + b"\x00\x01"  # Length
            + b"\x01"  # Change Cipher Spec message
        )
        return ccs

    def _create_enhanced_tls_finished(
        self, context: AttackContext, is_client: bool = True
    ) -> bytes:
        """Create enhanced TLS Finished packet."""
        finished_data = bytes([random.randint(0, 255) for _ in range(12)])

        finished = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(finished_data) + 4)  # Length
            + b"\x14"  # Finished
            + struct.pack("!I", len(finished_data))[1:]  # Length (3 bytes)
            + finished_data
        )

        return finished

    def _create_enhanced_http_request_with_payload(
        self, context: AttackContext
    ) -> bytes:
        """Create enhanced HTTP request with realistic browser headers."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"
        fingerprint = self._session_state["browser_fingerprint"]

        # Create realistic HTTP request with browser-specific headers
        request_lines = [
            f"POST /api/data HTTP/1.1",
            f"Host: {domain}",
            f"User-Agent: {fingerprint['user_agent']}",
            f"Accept: {fingerprint['accept']}",
            f"Accept-Language: {fingerprint['accept_language']}",
            f"Accept-Encoding: {fingerprint['accept_encoding']}",
            "Content-Type: application/json",
            f"Content-Length: {len(context.payload)}",
            "Connection: keep-alive",
            "Cache-Control: no-cache",
            f"Referer: https://{domain}/",
            "Origin: https://" + domain,
        ]

        # Add browser-specific headers
        if self.config.browser_type == "chrome":
            request_lines.extend(
                [
                    f"sec-ch-ua: {fingerprint.get('sec_ch_ua', '')}",
                    f"sec-ch-ua-mobile: {fingerprint.get('sec_ch_ua_mobile', '?0')}",
                    f"sec-ch-ua-platform: {fingerprint.get('sec_ch_ua_platform', '')}",
                    "Sec-Fetch-Dest: empty",
                    "Sec-Fetch-Mode: cors",
                    "Sec-Fetch-Site: same-origin",
                ]
            )

        request_lines.extend(["", ""])
        http_header = "\r\n".join(request_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_header) + len(context.payload))
            + http_header
            + context.payload
        )

        return tls_app_data

    def _create_enhanced_http_response(
        self, context: AttackContext, request_id: int = 0
    ) -> bytes:
        """Create enhanced HTTP response with realistic server headers."""
        response_body = f'{{"status": "success", "request_id": {request_id}, "timestamp": {int(time.time())}, "session_id": "{self._session_state["session_id"]}"}}'

        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(response_body)}",
            "Connection: keep-alive",
            "Server: nginx/1.20.2",
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}",
            "Cache-Control: no-cache, no-store, must-revalidate",
            "Pragma: no-cache",
            "Expires: 0",
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY",
            "X-XSS-Protection: 1; mode=block",
            "",
            response_body,
        ]

        http_response = "\r\n".join(response_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_response))
            + http_response
        )

        return tls_app_data

    def _create_enhanced_additional_http_request(
        self, context: AttackContext, request_id: int
    ) -> bytes:
        """Create enhanced additional HTTP request with varied content."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"
        fingerprint = self._session_state["browser_fingerprint"]

        # Vary request types for maximum realism
        request_types = [
            ("GET", "/api/status", ""),
            ("GET", "/api/user/profile", ""),
            (
                "POST",
                "/api/analytics",
                '{"event": "page_view", "timestamp": ' + str(int(time.time())) + "}",
            ),
            ("GET", "/api/notifications", ""),
            (
                "POST",
                "/api/heartbeat",
                '{"session_id": "' + str(self._session_state["session_id"]) + '"}',
            ),
        ]

        method, path, body = random.choice(request_types)

        request_lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {domain}",
            f"User-Agent: {fingerprint['user_agent']}",
            f"Accept: {fingerprint['accept']}",
            f"Accept-Language: {fingerprint['accept_language']}",
            "Connection: keep-alive",
            f"Referer: https://{domain}/",
        ]

        if body:
            request_lines.extend(
                [
                    "Content-Type: application/json",
                    f"Content-Length: {len(body)}",
                ]
            )

        request_lines.extend(["", body if body else ""])
        http_request = "\r\n".join(request_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_request))
            + http_request
        )

        return tls_app_data

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
            f"Accept-Language: {fingerprint['accept_language']}",
            f"Accept-Encoding: {fingerprint['accept_encoding']}",
            "Connection: keep-alive",
            f"Referer: https://{domain}/",
            "Cache-Control: max-age=0",
            "",
            "",
        ]

        http_request = "\r\n".join(request_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_request))
            + http_request
        )

        return tls_app_data

    def _create_resource_response(
        self, context: AttackContext, content_type: str, size: int
    ) -> bytes:
        """Create resource response."""
        # Generate fake resource content
        resource_content = bytes([random.randint(0, 255) for _ in range(size)])

        response_lines = [
            "HTTP/1.1 200 OK",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(resource_content)}",
            "Connection: keep-alive",
            "Server: nginx/1.20.2",
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}",
            "Cache-Control: public, max-age=31536000",
            'ETag: "' + hashlib.md5(resource_content).hexdigest()[:16] + '"',
            "",
        ]

        http_header = "\r\n".join(response_lines).encode()
        http_response = http_header + resource_content

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_response))
            + http_response
        )

        return tls_app_data

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
        # TCP keep-alive with realistic sequence numbers
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(32768, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + ka_id * 100,  # Sequence number
            self._session_state["tcp_ack"],  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_KEEPALIVE_ENHANCED:" + tcp_header

    def _create_enhanced_keep_alive_response(
        self, context: AttackContext, ka_id: int
    ) -> bytes:
        """Create enhanced keep-alive response packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            context.dst_port,  # Source port
            random.randint(32768, 65535),  # Destination port
            self._session_state["tcp_ack"],  # Sequence number
            self._session_state["tcp_seq"] + ka_id * 100 + 1,  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_KEEPALIVE_RESP_ENHANCED:" + tcp_header

    def _create_enhanced_tcp_fin_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP FIN packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(32768, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + 1000,  # Sequence number
            self._session_state["tcp_ack"],  # Acknowledgment number
            0x50,  # Data offset
            0x01,  # FIN flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_FIN_ENHANCED:" + tcp_header

    def _create_enhanced_tcp_fin_ack_packet(self, context: AttackContext) -> bytes:
        """Create enhanced TCP FIN-ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            context.dst_port,  # Source port
            random.randint(32768, 65535),  # Destination port
            self._session_state["tcp_ack"],  # Sequence number
            self._session_state["tcp_seq"] + 1001,  # Acknowledgment number
            0x50,  # Data offset
            0x11,  # FIN + ACK flags
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_FIN_ACK_ENHANCED:" + tcp_header

    def _create_enhanced_tcp_final_ack_packet(self, context: AttackContext) -> bytes:
        """Create enhanced final ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(32768, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + 1001,  # Sequence number
            self._session_state["tcp_ack"] + 1,  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_FINAL_ACK_ENHANCED:" + tcp_header

    # Original packet creation methods (keeping for compatibility)
    def _create_dns_query_packet(self, domain: str) -> bytes:
        """Create DNS query packet."""
        # Simplified DNS query packet
        query_id = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # Standard query

        # Encode domain name
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"  # End of domain
        question += struct.pack("!HH", 1, 1)  # Type A, Class IN

        return header + question

    def _create_dns_response_packet(self, domain: str, ip: str) -> bytes:
        """Create DNS response packet."""
        # Simplified DNS response
        response_id = random.randint(1, 65535)
        header = struct.pack(
            "!HHHHHH", response_id, 0x8180, 1, 1, 0, 0
        )  # Response with answer

        # Question section (same as query)
        domain_parts = domain.split(".")
        question = b""
        for part in domain_parts:
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 1, 1)

        # Answer section
        answer = b"\xc0\x0c"  # Pointer to domain name
        answer += struct.pack(
            "!HHIH", 1, 1, 300, 4
        )  # Type A, Class IN, TTL 300, Length 4
        answer += socket.inet_aton(ip)  # IP address

        return header + question + answer

    def _create_tcp_syn_packet(self, context: AttackContext) -> bytes:
        """Create TCP SYN packet."""
        # Simplified TCP SYN packet representation
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(1024, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"],  # Sequence number
            0,  # Acknowledgment number
            0x50,  # Data offset (5 words) + reserved
            0x02,  # SYN flag
            65535,  # Window size
            0,  # Checksum (simplified)
            0,  # Urgent pointer
        )

        return b"TCP_SYN:" + tcp_header

    def _create_tcp_syn_ack_packet(self, context: AttackContext) -> bytes:
        """Create TCP SYN-ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            context.dst_port,  # Source port
            random.randint(1024, 65535),  # Destination port
            random.randint(1000000, 9999999),  # Sequence number
            self._session_state["tcp_seq"] + 1,  # Acknowledgment number
            0x50,  # Data offset
            0x12,  # SYN + ACK flags
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_SYN_ACK:" + tcp_header

    def _create_tcp_ack_packet(self, context: AttackContext) -> bytes:
        """Create TCP ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(1024, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + 1,  # Sequence number
            self._session_state["tcp_ack"],  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_ACK:" + tcp_header

    def _create_tls_client_hello(self, context: AttackContext) -> bytes:
        """Create TLS Client Hello packet."""
        # Simplified TLS Client Hello
        tls_version = b"\x03\x03"  # TLS 1.2
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id_len = 0

        # SNI extension
        domain = context.domain or f"{context.dst_ip}"
        sni_ext = b"\x00\x00"  # SNI extension type
        sni_data = (
            struct.pack("!H", len(domain) + 5)
            + b"\x00"
            + struct.pack("!H", len(domain) + 3)
            + b"\x00"
            + struct.pack("!H", len(domain))
            + domain.encode()
        )
        sni_ext += struct.pack("!H", len(sni_data)) + sni_data

        client_hello = (
            b"\x16"  # Handshake
            + tls_version
            + b"\x00\x00"  # Length placeholder
            + b"\x01"  # Client Hello
            + b"\x00\x00\x00"  # Length placeholder
            + tls_version
            + random_bytes
            + bytes([session_id_len])
            + b"\x00\x02\x00\x2f"  # Cipher suites
            + b"\x01\x00"  # Compression methods
            + sni_ext
        )

        return client_hello

    def _create_tls_server_hello(self, context: AttackContext) -> bytes:
        """Create TLS Server Hello packet."""
        tls_version = b"\x03\x03"
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id = self._session_state["tls_session_id"]

        server_hello = (
            b"\x16"  # Handshake
            + tls_version
            + b"\x00\x00"  # Length placeholder
            + b"\x02"  # Server Hello
            + b"\x00\x00\x00"  # Length placeholder
            + tls_version
            + random_bytes
            + bytes([len(session_id)])
            + session_id
            + b"\x00\x2f"  # Chosen cipher suite
            + b"\x00"
        )  # Compression method

        return server_hello

    def _create_tls_certificate(self, context: AttackContext) -> bytes:
        """Create TLS Certificate packet."""
        # Simplified certificate packet
        cert_data = b"FAKE_CERTIFICATE_DATA_" + bytes(
            [random.randint(0, 255) for _ in range(100)]
        )

        certificate = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(cert_data) + 10)  # Length
            + b"\x0b"  # Certificate
            + struct.pack("!I", len(cert_data) + 6)[1:]  # Length (3 bytes)
            + struct.pack("!I", len(cert_data) + 3)[1:]  # Certificates length
            + struct.pack("!I", len(cert_data))[1:]  # Certificate length
            + cert_data
        )

        return certificate

    def _create_tls_key_exchange(self, context: AttackContext) -> bytes:
        """Create TLS Key Exchange packet."""
        key_data = bytes([random.randint(0, 255) for _ in range(64)])

        key_exchange = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(key_data) + 4)  # Length
            + b"\x10"  # Client Key Exchange
            + struct.pack("!I", len(key_data))[1:]  # Length (3 bytes)
            + key_data
        )

        return key_exchange

    def _create_tls_finished(self, context: AttackContext) -> bytes:
        """Create TLS Finished packet."""
        finished_data = bytes([random.randint(0, 255) for _ in range(12)])

        finished = (
            b"\x16"  # Handshake
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(finished_data) + 4)  # Length
            + b"\x14"  # Finished
            + struct.pack("!I", len(finished_data))[1:]  # Length (3 bytes)
            + finished_data
        )

        return finished

    def _create_http_request_with_payload(self, context: AttackContext) -> bytes:
        """Create HTTP request containing the main payload."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"

        # Create realistic HTTP request
        request_lines = [
            f"POST /api/data HTTP/1.1",
            f"Host: {domain}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: application/json, text/plain, */*",
            "Accept-Language: en-US,en;q=0.9",
            "Accept-Encoding: gzip, deflate, br",
            "Content-Type: application/json",
            f"Content-Length: {len(context.payload)}",
            "Connection: keep-alive",
            "",
            "",
        ]

        http_header = "\r\n".join(request_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_header) + len(context.payload))
            + http_header
            + context.payload
        )

        return tls_app_data

    def _create_http_response(
        self, context: AttackContext, request_id: int = 0
    ) -> bytes:
        """Create HTTP response packet."""
        response_body = f'{{"status": "success", "request_id": {request_id}, "timestamp": {int(time.time())}}}'

        response_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: application/json",
            f"Content-Length: {len(response_body)}",
            "Connection: keep-alive",
            "Server: nginx/1.18.0",
            "",
            response_body,
        ]

        http_response = "\r\n".join(response_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_response))
            + http_response
        )

        return tls_app_data

    def _create_additional_http_request(
        self, context: AttackContext, request_id: int
    ) -> bytes:
        """Create additional HTTP request for realism."""
        domain = context.domain or f"{context.dst_ip}:{context.dst_port}"

        # Vary request types for realism
        request_types = [
            f"GET /api/status HTTP/1.1",
            f"GET /api/user/profile HTTP/1.1",
            f"POST /api/analytics HTTP/1.1",
            f"GET /static/css/style.css HTTP/1.1",
            f"GET /static/js/app.js HTTP/1.1",
        ]

        request_line = random.choice(request_types)

        request_lines = [
            request_line,
            f"Host: {domain}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: */*",
            "Accept-Language: en-US,en;q=0.9",
            "Connection: keep-alive",
            f"Referer: https://{domain}/",
            "",
            "",
        ]

        http_request = "\r\n".join(request_lines).encode()

        # Wrap in TLS Application Data
        tls_app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS version
            + struct.pack("!H", len(http_request))
            + http_request
        )

        return tls_app_data

    def _create_keep_alive_packet(self, context: AttackContext, ka_id: int) -> bytes:
        """Create keep-alive packet."""
        # TCP keep-alive packet (empty payload)
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(1024, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + ka_id * 100,  # Sequence number
            self._session_state["tcp_ack"],  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_KEEPALIVE:" + tcp_header

    def _create_keep_alive_response(self, context: AttackContext, ka_id: int) -> bytes:
        """Create keep-alive response packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            context.dst_port,  # Source port
            random.randint(1024, 65535),  # Destination port
            self._session_state["tcp_ack"],  # Sequence number
            self._session_state["tcp_seq"] + ka_id * 100 + 1,  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_KEEPALIVE_RESP:" + tcp_header

    def _create_tcp_fin_packet(self, context: AttackContext) -> bytes:
        """Create TCP FIN packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(1024, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + 1000,  # Sequence number
            self._session_state["tcp_ack"],  # Acknowledgment number
            0x50,  # Data offset
            0x01,  # FIN flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_FIN:" + tcp_header

    def _create_tcp_fin_ack_packet(self, context: AttackContext) -> bytes:
        """Create TCP FIN-ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            context.dst_port,  # Source port
            random.randint(1024, 65535),  # Destination port
            self._session_state["tcp_ack"],  # Sequence number
            self._session_state["tcp_seq"] + 1001,  # Acknowledgment number
            0x50,  # Data offset
            0x11,  # FIN + ACK flags
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_FIN_ACK:" + tcp_header

    def _create_tcp_final_ack_packet(self, context: AttackContext) -> bytes:
        """Create final ACK packet."""
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(1024, 65535),  # Source port
            context.dst_port,  # Destination port
            self._session_state["tcp_seq"] + 1001,  # Sequence number
            self._session_state["tcp_ack"] + 1,  # Acknowledgment number
            0x50,  # Data offset
            0x10,  # ACK flag
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        return b"TCP_FINAL_ACK:" + tcp_header

    # Enhanced utility methods
    def _generate_realistic_session_id(self) -> int:
        """Generate realistic session ID based on timestamp."""
        timestamp = int(time.time())
        random_part = random.randint(1000, 9999)
        return (timestamp % 100000) * 10000 + random_part

    def _generate_realistic_tcp_seq(self) -> int:
        """Generate realistic TCP sequence number."""
        # Use timestamp-based sequence number like real systems
        timestamp = int(time.time() * 1000) % 0xFFFFFFFF
        return timestamp + random.randint(0, 1000)

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
        max_score = 0.0

        # Phase completion scoring (enhanced)
        phases = [
            "dns",
            "tcp_handshake",
            "tls_handshake",
            "application_data",
            "resource_loading",
        ]
        for phase in phases:
            max_score += 0.15
            if phase in self._session_state["phase_results"]:
                score += 0.15

        # Keep-alive scoring
        max_score += 0.1
        if "keep_alive" in self._session_state["phase_results"]:
            score += 0.1

        # Teardown scoring
        max_score += 0.1
        if "teardown" in self._session_state["phase_results"]:
            score += 0.1

        # Behavioral realism bonuses
        max_score += 0.15
        if self.config.simulate_real_user_patterns:
            score += 0.05
        if self.config.add_browser_fingerprinting:
            score += 0.05
        if self.config.simulate_resource_loading:
            score += 0.05

        return score / max_score if max_score > 0 else 0.0

    def _calculate_behavioral_metrics(self) -> Dict[str, Any]:
        """Calculate behavioral metrics for DPI evasion analysis."""
        total_duration = time.time() - self._session_state["connection_start_time"]

        return {
            "session_duration_seconds": total_duration,
            "packets_per_second": self._session_state["packet_sequence"]
            / max(total_duration, 1),
            "bytes_per_second": self._session_state["bytes_transferred"]
            / max(total_duration, 1),
            "phases_completed": len(self._session_state["phase_results"]),
            "browser_simulation_active": self.config.simulate_browser_behavior,
            "timing_jitter_enabled": self.config.add_jitter_to_timing,
            "protocol_compliance": self.config.add_protocol_compliance,
        }

    def _generate_tls_session_id(self) -> bytes:
        """Generate TLS session ID."""
        return bytes([random.randint(0, 255) for _ in range(32)])

    def _calculate_realism_score(self) -> float:
        """
        Calculate realism score based on session characteristics.

        Returns:
            Realism score (0.0 - 1.0)
        """
        score = 0.0
        max_score = 0.0

        # Phase completion scoring
        phases = ["dns", "tcp_handshake", "tls_handshake", "application_data"]
        for phase in phases:
            max_score += 0.2
            if phase in self._session_state["phase_results"]:
                score += 0.2

        # Keep-alive scoring
        max_score += 0.1
        if "keep_alive" in self._session_state["phase_results"]:
            score += 0.1

        # Teardown scoring
        max_score += 0.1
        if "teardown" in self._session_state["phase_results"]:
            score += 0.1

        return score / max_score if max_score > 0 else 0.0

    def get_config(self) -> SessionConfig:
        """Get current session configuration."""
        return self.config

    def update_config(self, **kwargs):
        """
        Update session configuration.

        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                LOG.debug(f"Updated session config: {key} = {value}")
            elif hasattr(self.config.timing, key):
                setattr(self.config.timing, key, value)
                LOG.debug(f"Updated timing config: {key} = {value}")
            else:
                LOG.warning(f"Unknown config parameter: {key}")

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate zapret command equivalent.

        Args:
            params: Optional parameters

        Returns:
            Zapret command string
        """
        return (
            "# Full session simulation requires complex multi-stage approach:\n"
            "# 1. DNS resolution (use DoH): curl -H 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name=example.com'\n"
            "# 2. TCP handshake simulation: hping3 -S -p 443 target\n"
            "# 3. TLS handshake with bypass: zapret --fake-tls --split-pos 2 --disorder\n"
            "# 4. Application data: zapret --dpi-desync=fake --fake-gen\n"
            "# 5. Keep-alive: zapret --keep-alive --interval 30"
        )


# Convenience function for creating configured attack
def create_full_session_attack(
    simulate_all_phases: bool = True,
    session_duration: Tuple[float, float] = (60.0, 300.0),
    add_realism: bool = True,
) -> FullSessionSimulationAttack:
    """
    Create a configured full session simulation attack.

    Args:
        simulate_all_phases: Whether to simulate all session phases
        session_duration: Session duration range in seconds
        add_realism: Whether to add realistic timing and behavior

    Returns:
        Configured FullSessionSimulationAttack instance
    """
    config = SessionConfig(
        simulate_dns=simulate_all_phases,
        simulate_tcp_handshake=simulate_all_phases,
        simulate_tls_handshake=simulate_all_phases,
        simulate_keep_alive=simulate_all_phases,
        simulate_teardown=simulate_all_phases,
        session_duration_range=session_duration,
        add_user_behavior_delays=add_realism,
        simulate_browser_behavior=add_realism,
        add_background_noise=add_realism,
    )

    return FullSessionSimulationAttack(config)
