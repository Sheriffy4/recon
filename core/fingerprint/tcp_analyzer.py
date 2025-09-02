"""
TCP Behavior Analyzer - Task 4 Implementation
Implements TCP-specific DPI behavior analysis including RST injection detection,
TCP window manipulation, sequence number anomaly detection, and fragmentation handling.
"""

import asyncio
import time
import socket
import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import deque
from enum import Enum

try:
    from scapy.all import IP, TCP, Raw, sr1, send, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
from core.fingerprint.advanced_models import NetworkAnalysisError

LOG = logging.getLogger(__name__)


@dataclass
class TCPAnalysisResult:
    """Result container for TCP behavior analysis"""

    target: str
    timestamp: float = field(default_factory=time.time)
    rst_injection_detected: bool = False
    tcp_window_manipulation: bool = False
    sequence_number_anomalies: bool = False
    fragmentation_handling: str = "unknown"
    mss_clamping_detected: bool = False
    tcp_options_filtering: List[str] = field(default_factory=list)
    window_size: Optional[int] = None
    mss: Optional[int] = None
    sack_permitted: bool = False
    timestamps_enabled: bool = False
    syn_ack_to_client_hello_delta: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class TCPAnalyzer:
    """
    TCP-specific DPI behavior analyzer.
    """

    def __init__(self, timeout: float = 10.0, max_attempts: int = 3):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)
        self.is_available = SCAPY_AVAILABLE

    async def analyze_tcp_behavior(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Main method to analyze TCP-specific DPI behavior.
        """
        if not self.is_available:
            self.logger.warning("Scapy not available, TCP analysis is disabled.")
            return {}
        self.logger.info(f"Starting TCP behavior analysis for {target}:{port}")
        result = TCPAnalysisResult(target=target)
        target_ip = await self._resolve_target(target)
        probes = [
            self._probe_rst_injection(result, target_ip, port),
            self._probe_tcp_options_and_timing(result, target_ip, port),
            self._probe_fragmentation(result, target_ip, port),
        ]
        await asyncio.gather(*probes)
        return result.to_dict()

    async def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(target, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except Exception as e:
            raise NetworkAnalysisError(f"DNS resolution failed: {e}")

    async def _run_probe(self, probe_func, *args):
        """Helper to run a probe with retries."""
        for i in range(self.max_attempts):
            try:
                return await probe_func(*args)
            except Exception as e:
                self.logger.debug(
                    f"Probe {probe_func.__name__} attempt {i + 1} failed: {e}"
                )
                await asyncio.sleep(0.1)
        return None

    async def _probe_rst_injection(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyzes RST injection."""

        def probe():
            response = sr1(
                IP(dst=target_ip) / TCP(dport=port, flags="S"),
                timeout=self.timeout,
                verbose=0,
            )
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags & 4:
                result.rst_injection_detected = True

        await self._run_probe(
            lambda: asyncio.get_event_loop().run_in_executor(None, probe)
        )

    async def _probe_tcp_options_and_timing(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Probes various TCP options and measures timing."""

        def probe():
            syn_packet = IP(dst=target_ip) / TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="S",
                options=[
                    ("MSS", 1460),
                    ("SAckOK", b""),
                    ("Timestamp", (0, 0)),
                    ("WScale", 10),
                ],
            )
            start_time = time.perf_counter()
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            end_time = time.perf_counter()
            if (
                response
                and response.haslayer(TCP)
                and response.getlayer(TCP).flags & 18
            ):
                result.syn_ack_to_client_hello_delta = (end_time - start_time) * 1000
                tcp_layer = response[TCP]
                result.window_size = tcp_layer.window
                response_options = {opt[0] for opt in tcp_layer.options}
                if "MSS" in response_options:
                    for opt in tcp_layer.options:
                        if opt[0] == "MSS":
                            result.mss = opt[1]
                            break
                if "SAckOK" in response_options:
                    result.sack_permitted = True
                if "Timestamp" in response_options:
                    result.timestamps_enabled = True

        await self._run_probe(
            lambda: asyncio.get_event_loop().run_in_executor(None, probe)
        )

    async def _probe_fragmentation(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyzes fragmentation handling."""

        def probe():
            payload = b"X" * 2000
            frag1 = (
                IP(dst=target_ip, flags="MF", frag=0)
                / TCP(dport=port, flags="S")
                / payload[:1000]
            )
            frag2 = IP(dst=target_ip, frag=125) / payload[1000:]
            send(frag1, verbose=0)
            time.sleep(0.1)
            response = sr1(
                IP(dst=target_ip)
                / TCP(
                    dport=port,
                    sport=frag1[TCP].sport,
                    flags="A",
                    seq=frag1.seq + 1,
                    ack=1,
                ),
                timeout=self.timeout,
                verbose=0,
            )
            if (
                response
                and response.haslayer(TCP)
                and response.getlayer(TCP).flags & 18
            ):
                result.fragmentation_handling = "allowed"
            else:
                result.fragmentation_handling = "blocked"

        await self._run_probe(
            lambda: asyncio.get_event_loop().run_in_executor(None, probe)
        )
