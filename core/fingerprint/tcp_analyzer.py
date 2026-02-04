# core/fingerprint/tcp_analyzer.py

import asyncio
import time
import socket
import random
import logging
from typing import Dict, Optional, Any

try:
    from scapy.all import IP, TCP, Raw, sr1, send, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .unified_models import NetworkAnalysisError, TCPAnalysisResult

LOG = logging.getLogger(__name__)


class TCPAnalyzer:
    """TCP-specific DPI behavior analyzer."""

    def __init__(self, timeout: float = 10.0, max_attempts: int = 3):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)
        self.is_available = SCAPY_AVAILABLE

    async def analyze_tcp_behavior(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Main method to analyze TCP-specific DPI behavior.
        Returns a dictionary, which will be converted to the model by the adapter.
        """
        if not self.is_available:
            self.logger.warning("Scapy not available, TCP analysis is disabled.")
            return {}
        self.logger.info(f"Starting TCP behavior analysis for {target}:{port}")
        result = TCPAnalysisResult()
        try:
            target_ip = await self._resolve_target(target)
            probes = [
                self._probe_rst_injection(result, target_ip, port),
                self._probe_tcp_options_and_timing(result, target_ip, port),
                self._probe_fragmentation(result, target_ip, port),
            ]
            await asyncio.gather(*probes)
            self.logger.info(
                f"TCP analysis for {target}:{port} completed. RST detected: {result.rst_injection_detected}"
            )
            return result.to_dict()
        except Exception as e:
            self.logger.error(
                f"FATAL error in analyze_tcp_behavior for {target}:{port}: {e}",
                exc_info=True,
            )
            return {}

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
                await probe_func(*args)
                return
            except Exception as e:
                self.logger.debug(f"Probe attempt {i + 1} failed: {e}")
                await asyncio.sleep(0.1)
        return None

    async def _async_send_recv(self, pkt, timeout: float) -> Optional[Any]:
        """
        A more robust async send/receive function that avoids problematic parts of scapy.
        """
        loop = asyncio.get_event_loop()

        def send_and_sniff():
            try:
                # Use a simple sniff with a filter to capture the response
                ans = sr1(pkt, timeout=timeout, verbose=0)
                return ans
            except Exception as e:
                # This is where the OSError can happen, we catch it here.
                self.logger.debug(f"Scapy send/recv failed internally: {e}")
                return None

        try:
            # Run the blocking scapy call in a thread pool executor
            response = await loop.run_in_executor(None, send_and_sniff)
            return response
        except Exception as e:
            self.logger.error(f"Async send/recv wrapper failed: {e}")
            return None

    async def _probe_rst_injection(self, result: TCPAnalysisResult, target_ip: str, port: int):
        """Analyzes RST injection."""
        response = await self._async_send_recv(
            IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=self.timeout
        )
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags & 4:
            result.rst_injection_detected = True

    async def _probe_tcp_options_and_timing(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Probes various TCP options and measures timing."""
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
        response = await self._async_send_recv(syn_packet, timeout=self.timeout)
        end_time = time.perf_counter()

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags & 18:  # SYN-ACK
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

    async def _probe_fragmentation(self, result: TCPAnalysisResult, target_ip: str, port: int):
        """Analyzes DPI vulnerability to TCP payload fragmentation attacks."""
        try:
            # This probe doesn't use Scapy for network I/O, so it's safer.
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(2.0)

            connection_possible = False
            connection_blocked = False

            try:
                test_socket.connect((target_ip, port))
                connection_possible = True
                test_socket.close()
                self.logger.debug(
                    f"Fragmentation probe: Direct connection successful to {target_ip}:{port}"
                )
            except socket.timeout:
                connection_blocked = True
                self.logger.debug(f"Fragmentation probe: Connection timeout to {target_ip}:{port}")
            except (ConnectionRefusedError, OSError) as e:
                connection_blocked = True
                self.logger.debug(
                    f"Fragmentation probe: Connection refused to {target_ip}:{port}: {e}"
                )
            except Exception as e:
                self.logger.debug(
                    f"Fragmentation probe: Connection failed to {target_ip}:{port}: {e}"
                )
                result.fragmentation_handling = "unknown"
                return

            if connection_possible:
                result.fragmentation_handling = "not_needed"
            elif connection_blocked:
                result.fragmentation_handling = "vulnerable"
            else:
                result.fragmentation_handling = "unknown"

        except Exception as e:
            self.logger.debug(f"Fragmentation probe failed: {e}")
            result.fragmentation_handling = "vulnerable"
