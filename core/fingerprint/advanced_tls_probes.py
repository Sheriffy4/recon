"""
Advanced TLS/HTTP Probes for DPI Detection - Task 23 Implementation
Implements sophisticated TLS/HTTP level probes to detect DPI behavior patterns.

This module implements advanced TLS/HTTP probing techniques:
- TLS ClientHello size sensitivity testing
- ECH (Encrypted Client Hello) reaction analysis
- HTTP/2 and HTTP/3 (QUIC) support detection
- "Dirty" HTTP traffic reaction testing
"""

import asyncio
import socket
import ssl
import time
import logging
import struct
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

try:
    from scapy.all import IP, TCP, Raw, sr1, send, sr, conf, get_if_list, get_if_addr

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import h2.connection
    import h2.events

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

LOG = logging.getLogger(__name__)


@dataclass
class AdvancedTLSProbeResult:
    """Results from advanced TLS/HTTP probing"""

    target: str
    port: int
    timestamp: float = field(default_factory=time.time)

    # TLS ClientHello Size Tests
    clienthello_size_sensitivity: Dict[str, Any] = field(default_factory=dict)
    max_clienthello_size: Optional[int] = None
    min_clienthello_size: Optional[int] = None

    # ECH (Encrypted Client Hello) Tests
    ech_support_detected: bool = False
    ech_blocking_detected: bool = False
    ech_config_available: bool = False

    # HTTP/2 and HTTP/3 Tests
    http2_support: bool = False
    http2_blocking_detected: bool = False
    http3_support: bool = False
    quic_blocking_detected: bool = False

    # "Dirty" HTTP Traffic Tests
    dirty_http_tolerance: Dict[str, str] = field(default_factory=dict)
    http_header_filtering: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class AdvancedTLSProber:
    """
    Advanced TLS/HTTP probing for sophisticated DPI detection.

    This class implements advanced probing techniques to detect DPI behavior:
    - TLS ClientHello size sensitivity testing
    - ECH (Encrypted Client Hello) reaction analysis
    - HTTP/2 and HTTP/3 (QUIC) support detection
    - "Dirty" HTTP traffic reaction testing
    """

    def __init__(self, timeout: float = 10.0, max_attempts: int = 2):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)
        self.is_available = SCAPY_AVAILABLE

        if not self.is_available:
            self.logger.warning("Scapy not available - advanced TLS probes disabled")

    async def run_advanced_tls_probes(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Run all advanced TLS/HTTP probes against the target.

        Args:
            target: Target hostname or IP
            port: Target port (default 443 for HTTPS)

        Returns:
            Dictionary with probe results
        """
        if not self.is_available:
            return {}

        self.logger.info(f"Starting advanced TLS probes for {target}:{port}")

        result = AdvancedTLSProbeResult(target=target, port=port)

        try:
            target_ip = await self._resolve_target(target)

            # Run all probe categories
            await asyncio.gather(
                self._probe_clienthello_size_sensitivity(
                    result, target, target_ip, port
                ),
                self._probe_ech_support(result, target, target_ip, port),
                self._probe_http2_support(result, target, target_ip, port),
                self._probe_dirty_http_traffic(result, target, target_ip, port),
                return_exceptions=True,
            )
            self.logger.info(
                f"Advanced TLS probes for {target}:{port} completed. ECH support detected: {result.ech_support_detected}"
            )
        except Exception as e:
            self.logger.error(
                f"Advanced TLS probes failed for {target}: {e}", exc_info=True
            )

        return result.to_dict()

    async def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(target, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {target}: {e}")
            return target  # Assume it's already an IP

    async def _probe_clienthello_size_sensitivity(
        self, result: AdvancedTLSProbeResult, target: str, target_ip: str, port: int
    ):
        """
        Test DPI sensitivity to TLS ClientHello size.

        Many DPI systems have size thresholds for TLS inspection.
        Large ClientHello messages may bypass inspection or trigger blocking.
        """

        def probe():
            try:
                # Test different ClientHello sizes
                size_results = {}

                # Test sizes: small (300), normal (500), large (1000), huge (2000), massive (4000)
                test_sizes = [300, 500, 1000, 2000, 4000]

                for size in test_sizes:
                    try:
                        # Create TLS ClientHello with specific size
                        clienthello = self._create_clienthello_with_size(target, size)

                        # Send via raw socket to control exact size
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)

                        start_time = time.perf_counter()

                        try:
                            sock.connect((target_ip, port))
                            sock.send(clienthello)

                            # Try to receive ServerHello
                            response = sock.recv(4096)
                            end_time = time.perf_counter()

                            if response:
                                # Check if it looks like a valid TLS response
                                if (
                                    len(response) >= 5 and response[0] == 0x16
                                ):  # TLS Handshake
                                    size_results[size] = {
                                        "status": "success",
                                        "response_time": (end_time - start_time) * 1000,
                                        "response_size": len(response),
                                    }
                                else:
                                    size_results[size] = {
                                        "status": "invalid_response",
                                        "response_time": (end_time - start_time) * 1000,
                                    }
                            else:
                                size_results[size] = {"status": "no_response"}

                        except socket.timeout:
                            size_results[size] = {"status": "timeout"}
                        except ConnectionResetError:
                            size_results[size] = {"status": "connection_reset"}
                        except Exception as e:
                            size_results[size] = {"status": f"error_{type(e).__name__}"}
                        finally:
                            sock.close()

                        # Small delay between tests
                        time.sleep(0.2)

                    except Exception as e:
                        self.logger.debug(f"ClientHello size {size} test failed: {e}")
                        size_results[size] = {"status": "test_error"}

                result.clienthello_size_sensitivity = size_results

                # Analyze results to find size limits
                successful_sizes = [
                    size
                    for size, res in size_results.items()
                    if res.get("status") == "success"
                ]
                failed_sizes = [
                    size
                    for size, res in size_results.items()
                    if res.get("status") in ["timeout", "connection_reset"]
                ]

                if successful_sizes:
                    result.max_clienthello_size = max(successful_sizes)
                    result.min_clienthello_size = min(successful_sizes)

                # Log findings
                if failed_sizes and successful_sizes:
                    self.logger.debug(
                        f"ClientHello size sensitivity detected: "
                        f"success up to {max(successful_sizes)}, "
                        f"failures at {failed_sizes}"
                    )
                elif not successful_sizes:
                    self.logger.debug(
                        "All ClientHello sizes failed - possible blocking"
                    )
                else:
                    self.logger.debug("No ClientHello size sensitivity detected")

            except Exception as e:
                self.logger.debug(f"ClientHello size sensitivity probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)

    def _create_clienthello_with_size(self, hostname: str, target_size: int) -> bytes:
        """Create a TLS ClientHello with approximately the target size"""

        # Basic TLS 1.2 ClientHello structure
        # We'll pad with extensions to reach target size

        # TLS Record Header (5 bytes)
        # Handshake Header (4 bytes)
        # ClientHello base (~39 bytes minimum)
        base_size = 5 + 4 + 39

        if target_size <= base_size:
            target_size = base_size + 50  # Minimum reasonable size

        padding_needed = target_size - base_size - len(hostname) - 20  # Account for SNI

        # Create extensions with padding
        extensions = b""

        # SNI Extension
        sni_data = hostname.encode("utf-8")
        sni_ext = struct.pack(">HH", 0x0000, len(sni_data) + 5)  # SNI extension
        sni_ext += struct.pack(">HHB", len(sni_data) + 3, 0x0000, len(sni_data))
        sni_ext += sni_data
        extensions += sni_ext

        # Padding extension to reach target size
        if padding_needed > 4:
            padding_ext = struct.pack(
                ">HH", 0x0015, padding_needed - 4
            )  # Padding extension
            padding_ext += b"\x00" * (padding_needed - 4)
            extensions += padding_ext

        # Build ClientHello
        clienthello = b""
        clienthello += b"\x03\x03"  # TLS 1.2
        clienthello += b"\x00" * 32  # Random
        clienthello += b"\x00"  # Session ID length
        clienthello += b"\x00\x02\x00\x35"  # Cipher suites (just one)
        clienthello += b"\x01\x00"  # Compression methods
        clienthello += struct.pack(">H", len(extensions)) + extensions

        # Handshake header
        handshake = b"\x01"  # ClientHello
        handshake += struct.pack(">I", len(clienthello))[1:]  # Length (3 bytes)
        handshake += clienthello

        # TLS Record
        record = b"\x16"  # Handshake
        record += b"\x03\x01"  # TLS 1.0 (record version)
        record += struct.pack(">H", len(handshake))
        record += handshake

        return record

    async def _probe_ech_support(
        self, result: AdvancedTLSProbeResult, target: str, target_ip: str, port: int
    ):
        """
        Test ECH (Encrypted Client Hello) support and DPI reaction.

        ECH is a new TLS extension that encrypts the ClientHello.
        DPI systems may block or have issues with ECH.
        """

        def probe():
            try:
                # First, check if ECH config is available via DNS
                result.ech_config_available = self._check_ech_dns_config(target)

                # Test basic TLS connection
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Test normal connection first
                try:
                    sock = socket.create_connection(
                        (target_ip, port), timeout=self.timeout
                    )
                    ssl_sock = context.wrap_socket(sock, server_hostname=target)
                    ssl_sock.close()
                    normal_connection_works = True
                except Exception:
                    normal_connection_works = False

                # Test with ECH-like extension (simulated)
                # Since real ECH requires complex crypto, we simulate the extension
                try:
                    clienthello_with_ech = self._create_clienthello_with_ech_extension(
                        target
                    )

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target_ip, port))
                    sock.send(clienthello_with_ech)

                    response = sock.recv(4096)
                    sock.close()

                    if response and len(response) >= 5:
                        if response[0] == 0x16:  # TLS Handshake
                            result.ech_support_detected = True
                        elif response[0] == 0x15:  # TLS Alert
                            # Check if it's an unsupported extension alert
                            if (
                                len(response) >= 7 and response[6] == 0x6E
                            ):  # unsupported_extension
                                result.ech_blocking_detected = (
                                    False  # Server doesn't support ECH
                                )
                            else:
                                result.ech_blocking_detected = (
                                    True  # DPI might be blocking
                                )

                except Exception as e:
                    if normal_connection_works:
                        # If normal works but ECH fails, might be DPI blocking
                        result.ech_blocking_detected = True
                    self.logger.debug(f"ECH test failed: {e}")

                self.logger.debug(
                    f"ECH probe results: support={result.ech_support_detected}, "
                    f"blocking={result.ech_blocking_detected}, "
                    f"config_available={result.ech_config_available}"
                )

            except Exception as e:
                self.logger.debug(f"ECH support probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)

    def _check_ech_dns_config(self, hostname: str) -> bool:
        """Check if ECH config is available via DNS HTTPS record"""
        try:
            import dns.resolver

            # Query for HTTPS record which may contain ECH config
            try:
                answers = dns.resolver.resolve(hostname, "HTTPS")
                for answer in answers:
                    # ECH config would be in the SvcParams
                    if hasattr(answer, "params") and answer.params:
                        return True
            except:
                pass

            return False
        except ImportError:
            # DNS library not available
            return False

    def _create_clienthello_with_ech_extension(self, hostname: str) -> bytes:
        """Create ClientHello with simulated ECH extension"""

        # Create base ClientHello
        base_clienthello = self._create_clienthello_with_size(hostname, 500)

        # Add ECH extension (type 0xfe0d)
        # This is a simplified simulation - real ECH is much more complex
        ech_extension = struct.pack(">HH", 0xFE0D, 32)  # ECH extension type and length
        ech_extension += b"\x00" * 32  # Dummy ECH payload

        # Insert extension into ClientHello
        # This is a simplified approach - real implementation would need proper parsing
        return base_clienthello + ech_extension

    async def _probe_http2_support(
        self, result: AdvancedTLSProbeResult, target: str, target_ip: str, port: int
    ):
        """
        Test HTTP/2 and HTTP/3 (QUIC) support and DPI blocking.

        Some DPI systems block or have issues with HTTP/2 and QUIC.
        """

        def probe():
            try:
                # Test HTTP/2 support
                if H2_AVAILABLE:
                    try:
                        # Test HTTP/2 over TLS (h2)
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        context.set_alpn_protocols(["h2", "http/1.1"])

                        sock = socket.create_connection(
                            (target_ip, port), timeout=self.timeout
                        )
                        ssl_sock = context.wrap_socket(sock, server_hostname=target)

                        # Check negotiated protocol
                        negotiated = ssl_sock.selected_alpn_protocol()
                        if negotiated == "h2":
                            result.http2_support = True

                            # Try to send HTTP/2 request
                            try:
                                conn = h2.connection.H2Connection()
                                conn.initiate_connection()
                                ssl_sock.sendall(conn.data_to_send())

                                # Send a simple request
                                headers = [
                                    (":method", "GET"),
                                    (":path", "/"),
                                    (":authority", target),
                                    (":scheme", "https"),
                                ]
                                conn.send_headers(1, headers)
                                ssl_sock.sendall(conn.data_to_send())

                                # Try to receive response
                                response_data = ssl_sock.recv(4096)
                                if response_data:
                                    result.http2_support = True

                            except Exception as e:
                                # HTTP/2 negotiated but request failed - might be DPI blocking
                                result.http2_blocking_detected = True
                                self.logger.debug(f"HTTP/2 request blocked: {e}")

                        ssl_sock.close()

                    except Exception as e:
                        self.logger.debug(f"HTTP/2 test failed: {e}")

                # Test HTTP/3 (QUIC) support
                # This is more complex and would require QUIC library
                # For now, we'll do a simple UDP probe to check if QUIC port responds
                try:
                    # QUIC typically uses UDP on same port as HTTPS
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.settimeout(2.0)

                    # Send a simple QUIC-like packet (this is very simplified)
                    quic_probe = b"\x80\x00\x00\x01"  # Simplified QUIC header
                    udp_sock.sendto(quic_probe, (target_ip, port))

                    try:
                        response, addr = udp_sock.recvfrom(1024)
                        if response:
                            result.http3_support = True
                    except socket.timeout:
                        # No response - QUIC might not be supported or blocked
                        pass

                    udp_sock.close()

                except Exception as e:
                    self.logger.debug(f"QUIC probe failed: {e}")

                self.logger.debug(
                    f"HTTP/2 support: {result.http2_support}, "
                    f"HTTP/2 blocking: {result.http2_blocking_detected}, "
                    f"HTTP/3 support: {result.http3_support}"
                )

            except Exception as e:
                self.logger.debug(f"HTTP/2 support probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)

    async def _probe_dirty_http_traffic(
        self, result: AdvancedTLSProbeResult, target: str, target_ip: str, port: int
    ):
        """
        Test DPI reaction to "dirty" HTTP traffic.

        Sends malformed or unusual HTTP requests to see how DPI reacts.
        Some DPI systems are strict about HTTP format compliance.
        """

        def probe():
            try:
                # Test various "dirty" HTTP patterns
                dirty_tests = {
                    "malformed_method": b"GETT / HTTP/1.1\r\nHost: "
                    + target.encode()
                    + b"\r\n\r\n",
                    "invalid_version": b"GET / HTTP/2.0\r\nHost: "
                    + target.encode()
                    + b"\r\n\r\n",
                    "missing_host": b"GET / HTTP/1.1\r\n\r\n",
                    "extra_spaces": b"GET  /  HTTP/1.1 \r\nHost:  "
                    + target.encode()
                    + b" \r\n\r\n",
                    "case_sensitive": b"get / http/1.1\r\nhost: "
                    + target.encode()
                    + b"\r\n\r\n",
                    "long_uri": b"GET /"
                    + b"A" * 2000
                    + b" HTTP/1.1\r\nHost: "
                    + target.encode()
                    + b"\r\n\r\n",
                    "binary_data": b"GET / HTTP/1.1\r\nHost: "
                    + target.encode()
                    + b"\r\n\x00\x01\x02\r\n\r\n",
                    "invalid_headers": b"GET / HTTP/1.1\r\nHost: "
                    + target.encode()
                    + b"\r\nInvalid Header\r\n\r\n",
                }

                for test_name, request in dirty_tests.items():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)

                        start_time = time.perf_counter()
                        sock.connect((target_ip, port))
                        sock.send(request)

                        try:
                            response = sock.recv(4096)
                            end_time = time.perf_counter()

                            if response:
                                # Analyze response
                                if b"HTTP/" in response:
                                    if b"400" in response or b"Bad Request" in response:
                                        result.dirty_http_tolerance[test_name] = (
                                            "rejected_properly"
                                        )
                                    elif (
                                        b"200" in response
                                        or b"301" in response
                                        or b"302" in response
                                    ):
                                        result.dirty_http_tolerance[test_name] = (
                                            "accepted"
                                        )
                                    else:
                                        result.dirty_http_tolerance[test_name] = (
                                            "unknown_response"
                                        )
                                else:
                                    result.dirty_http_tolerance[test_name] = (
                                        "non_http_response"
                                    )
                            else:
                                result.dirty_http_tolerance[test_name] = "no_response"

                        except socket.timeout:
                            result.dirty_http_tolerance[test_name] = "timeout"
                        except ConnectionResetError:
                            result.dirty_http_tolerance[test_name] = "connection_reset"

                        sock.close()
                        time.sleep(0.1)  # Small delay between tests

                    except Exception as e:
                        result.dirty_http_tolerance[test_name] = (
                            f"error_{type(e).__name__}"
                        )
                        self.logger.debug(f"Dirty HTTP test {test_name} failed: {e}")

                # Analyze results for filtering patterns
                rejected_tests = [
                    test
                    for test, result_str in result.dirty_http_tolerance.items()
                    if "rejected" in result_str or "reset" in result_str
                ]

                if rejected_tests:
                    result.http_header_filtering = rejected_tests

                self.logger.debug(
                    f"Dirty HTTP tolerance results: {len(result.dirty_http_tolerance)} tests, "
                    f"{len(rejected_tests)} rejected"
                )

            except Exception as e:
                self.logger.debug(f"Dirty HTTP traffic probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)
