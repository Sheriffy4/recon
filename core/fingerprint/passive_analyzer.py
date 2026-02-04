# core/fingerprint/passive_analyzer.py
"""
Passive DPI Analyzer - Analyzes blocking methods WITHOUT establishing full connections.
Based on RST packets, timeouts, and ICMP responses.
"""

import logging
import socket
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

LOG = logging.getLogger(__name__)


class BlockingMethod(Enum):
    """Types of blocking methods detected"""

    TCP_RST_INJECTION = "tcp_rst_injection"
    SILENT_DROP = "silent_drop"
    TLS_SNI_FILTERING = "tls_sni_filtering"
    HTTP_FILTERING = "http_filtering"
    DNS_POISONING = "dns_poisoning"
    UNKNOWN = "unknown"


@dataclass
class PassiveAnalysisResult:
    """Result of passive DPI analysis"""

    target: str
    port: int
    blocking_method: BlockingMethod = BlockingMethod.UNKNOWN
    rst_detected: bool = False
    rst_ttl: Optional[int] = None
    timeout_stage: Optional[str] = None
    recommended_bypasses: List[str] = field(default_factory=list)
    confidence: float = 0.0
    analysis_duration: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


class PassiveDPIAnalyzer:
    """
    Analyzes DPI without establishing full connections.
    Uses lightweight probes to detect blocking methods.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def analyze_blocking_method(self, target: str, port: int = 443) -> PassiveAnalysisResult:
        """
        Determine blocking method WITHOUT successful connection.

        Args:
            target: Target hostname or IP
            port: Target port (default 443)

        Returns:
            PassiveAnalysisResult with blocking method and recommendations
        """
        start_time = time.time()
        result = PassiveAnalysisResult(target=target, port=port)

        try:
            # 1. TCP SYN probe
            tcp_result = await self._probe_tcp_handshake(target, port)
            result.details["tcp_probe"] = tcp_result

            if tcp_result.get("rst_received"):
                result.rst_detected = True
                result.rst_ttl = tcp_result.get("rst_ttl")
                result.blocking_method = BlockingMethod.TCP_RST_INJECTION

                # Recommendations based on TTL
                if result.rst_ttl and result.rst_ttl <= 10:
                    result.recommended_bypasses = [
                        "fakeddisorder(ttl=1)",
                        "badsum_race(ttl=2)",
                        "ip_fragmentation",
                    ]
                    result.confidence = 0.8
                else:
                    result.recommended_bypasses = [
                        "multisplit",
                        "seqovl(overlap_size=20)",
                    ]
                    result.confidence = 0.6

            elif tcp_result.get("timeout"):
                result.timeout_stage = "TCP_SYN"
                result.blocking_method = BlockingMethod.SILENT_DROP
                result.recommended_bypasses = ["multisplit", "seqovl(overlap_size=336)"]
                result.confidence = 0.5

            # 2. TLS ClientHello probe (only if TCP succeeded)
            if tcp_result.get("syn_ack_received"):
                tls_result = await self._probe_tls_handshake(target, port)
                result.details["tls_probe"] = tls_result

                if tls_result.get("rst_after_client_hello"):
                    result.blocking_method = BlockingMethod.TLS_SNI_FILTERING
                    result.recommended_bypasses = [
                        "fakeddisorder(split_pos=sni)",
                        "multidisorder(positions=[5,10,15])",
                        "tlsrec_split(split_pos=5)",
                    ]
                    result.confidence = 0.9
                elif tls_result.get("timeout"):
                    result.timeout_stage = "TLS_HANDSHAKE"
                    result.blocking_method = BlockingMethod.TLS_SNI_FILTERING
                    result.recommended_bypasses = [
                        "fakeddisorder(ttl=1,split_pos=cipher)",
                        "seqovl(ttl=2,overlap_size=20)",
                    ]
                    result.confidence = 0.7

        except Exception as e:
            self.logger.error(f"Passive analysis failed for {target}:{port}: {e}")
            result.details["error"] = str(e)

        result.analysis_duration = time.time() - start_time
        return result

    async def _probe_tcp_handshake(self, target: str, port: int) -> Dict[str, Any]:
        """
        Send TCP SYN and analyze response.
        Falls back to socket-based probe if scapy unavailable.
        """
        try:
            # Try scapy first for detailed analysis
            try:
                from scapy.all import IP, TCP, sr1

                syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)

                if response is None:
                    return {
                        "timeout": True,
                        "syn_ack_received": False,
                        "rst_received": False,
                    }

                if response.haslayer(TCP):
                    tcp_layer = response[TCP]

                    if tcp_layer.flags == "SA":  # SYN-ACK
                        return {
                            "syn_ack_received": True,
                            "rst_received": False,
                            "timeout": False,
                        }

                    if tcp_layer.flags in ["R", "RA"]:  # RST
                        return {
                            "rst_received": True,
                            "rst_ttl": response[IP].ttl,
                            "syn_ack_received": False,
                            "timeout": False,
                        }

                return {
                    "timeout": False,
                    "syn_ack_received": False,
                    "rst_received": False,
                }

            except ImportError:
                # Fallback to socket-based probe
                return await self._socket_tcp_probe(target, port)

        except Exception as e:
            self.logger.debug(f"TCP probe failed: {e}")
            return {"error": str(e)}

    async def _socket_tcp_probe(self, target: str, port: int) -> Dict[str, Any]:
        """Socket-based TCP connection probe (fallback)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            start_time = time.time()
            try:
                sock.connect((target, port))
                sock.close()
                return {
                    "syn_ack_received": True,
                    "rst_received": False,
                    "timeout": False,
                    "connect_time": time.time() - start_time,
                }
            except socket.timeout:
                return {
                    "timeout": True,
                    "syn_ack_received": False,
                    "rst_received": False,
                }
            except ConnectionRefusedError:
                return {
                    "rst_received": True,
                    "syn_ack_received": False,
                    "timeout": False,
                }
            except Exception as e:
                return {"error": str(e), "timeout": False}
            finally:
                sock.close()

        except Exception as e:
            self.logger.debug(f"Socket probe failed: {e}")
            return {"error": str(e)}

    async def _probe_tls_handshake(self, target: str, port: int) -> Dict[str, Any]:
        """
        Send TLS ClientHello and check for RST/timeout.
        """
        try:
            import ssl

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                # Connect TCP first
                sock.connect((target, port))

                # Wrap with SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                ssl_sock = context.wrap_socket(sock, server_hostname=target)

                # If we get here, handshake succeeded
                ssl_sock.close()
                return {
                    "handshake_success": True,
                    "rst_after_client_hello": False,
                    "timeout": False,
                }

            except socket.timeout:
                return {
                    "timeout": True,
                    "rst_after_client_hello": False,
                    "handshake_success": False,
                }
            except (ConnectionResetError, BrokenPipeError):
                return {
                    "rst_after_client_hello": True,
                    "timeout": False,
                    "handshake_success": False,
                }
            except ssl.SSLError as e:
                # Could be DPI interference
                return {
                    "ssl_error": str(e),
                    "rst_after_client_hello": False,
                    "timeout": False,
                    "handshake_success": False,
                }
            finally:
                sock.close()

        except Exception as e:
            self.logger.debug(f"TLS probe failed: {e}")
            return {"error": str(e)}
