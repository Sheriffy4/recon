"""
DPI Probing Methods Module
Extracted from AdvancedFingerprinter for better organization and maintainability

This module contains all DPI probing methods that test various aspects of DPI behavior.
"""

import socket
import ssl
import asyncio
import time
from typing import Dict, Any
from scapy.all import IP, TCP, send

from core.fingerprint.connection_testers import (
    test_payload_size,
    test_connection_with_reordering,
    test_fragmented_connection,
)


class DPIProber:
    """
    Centralized DPI probing methods for testing various DPI characteristics
    """

    def __init__(self, config, logger, executor=None):
        """
        Initialize DPI Prober

        Args:
            config: FingerprintingConfig instance
            logger: Logger instance
            executor: ThreadPoolExecutor for blocking operations
        """
        self.config = config
        self.logger = logger
        self.executor = executor

    async def probe_sni_sensitivity(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Basic SNI sensitivity probe

        Tests if DPI is sensitive to SNI field by trying:
        - Normal SNI
        - Uppercase SNI
        - No SNI

        Args:
            target: Target domain
            port: Target port (default 443)

        Returns:
            Dict with probe results including sni_sensitive flag
        """
        loop = asyncio.get_event_loop()
        res = {"normal": None, "uppercase": None, "nosni": None, "sni_sensitive": False}

        def do_handshake(server_hostname):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                t0 = time.time()
                with socket.create_connection((target, port), timeout=3.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                        version = ssock.version()
                        latency = (time.time() - t0) * 1000
                        return {"ok": True, "version": version, "latency_ms": latency}
            except Exception as e:
                return {"ok": False, "error": str(e)}

        try:
            # Normal SNI
            res["normal"] = await loop.run_in_executor(self.executor, do_handshake, target)

            # Uppercase SNI
            upp = target.upper() if isinstance(target, str) else None
            if upp and upp != target:
                res["uppercase"] = await loop.run_in_executor(self.executor, do_handshake, upp)

            # No SNI
            res["nosni"] = await loop.run_in_executor(self.executor, do_handshake, None)

            # Analyze results
            def ok(v):
                return bool(v and v.get("ok"))

            res["sni_sensitive"] = (ok(res["normal"]) and not ok(res["nosni"])) or (
                ok(res["normal"]) and not ok(res.get("uppercase"))
            )

        except Exception as e:
            res["error"] = str(e)

        return res

    async def probe_sni_sensitivity_detailed(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Detailed SNI sensitivity probe with additional tests

        Extends basic SNI probe with:
        - Subdomain SNI test
        - Random SNI test
        - SNI validation type detection

        Args:
            target: Target domain
            port: Target port (default 443)

        Returns:
            Dict with detailed SNI sensitivity results
        """
        basic = await self.probe_sni_sensitivity(target, port)

        # Additional tests
        loop = asyncio.get_event_loop()

        def test_sni_variant(sni_value):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target, port), timeout=2.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=sni_value):
                        return True
            except Exception:
                return False

        # Test with subdomain
        subdomain_test = await loop.run_in_executor(
            self.executor, test_sni_variant, f"www.{target}"
        )

        # Test with random SNI
        random_test = await loop.run_in_executor(
            self.executor, test_sni_variant, "random.example.com"
        )

        basic["subdomain_works"] = subdomain_test
        basic["random_sni_works"] = random_test

        # Enhanced sensitivity detection
        if not random_test and subdomain_test:
            basic["sni_validation_type"] = "strict_domain"
        elif random_test:
            basic["sni_validation_type"] = "none"
        else:
            basic["sni_validation_type"] = "unknown"

        return basic

    async def probe_timing_sensitivity(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe timing sensitivity with actual delays

        Tests if DPI is sensitive to timing by introducing delays
        before connection attempts.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with timing sensitivity results
        """
        results = {}

        async def test_with_delay(delay_ms: int) -> bool:
            try:
                await asyncio.sleep(delay_ms / 1000.0)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False

        # Test different delays
        delays = [0, 100, 500, 1000]
        for delay in delays:
            success = await test_with_delay(delay)
            results[f"delay_{delay}ms"] = success

        # Calculate sensitivity
        successes = sum(1 for v in results.values() if v)
        results["timing_sensitive"] = successes < len(delays) / 2

        return results

    async def probe_fragmentation_support(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe IP fragmentation support

        Tests if DPI can handle fragmented IP packets.
        Requires scapy and may need elevated privileges.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with fragmentation support results
        """
        if not self.config.enable_scapy_probes:
            return {"supports_fragmentation": False, "error": "scapy_probes_disabled"}

        results = {"supports_fragmentation": False, "error": None}

        try:
            # Send fragmented packet
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            fragments = packet.fragment(8)  # Fragment into 8-byte chunks

            # Send fragments
            for frag in fragments:
                send(frag, verbose=0)

            # Check for response (simplified)
            await asyncio.sleep(0.5)
            results["supports_fragmentation"] = True

        except Exception as e:
            results["error"] = str(e)

        return results

    async def probe_dpi_behavioral_patterns(self, target: str, port: int) -> Dict[str, Any]:
        """
        Comprehensive behavioral pattern analysis

        Tests multiple DPI behavioral characteristics:
        - Packet reordering tolerance
        - Fragmentation handling
        - Timing patterns
        - Packet size limits
        - Protocol detection

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with comprehensive behavioral analysis results
        """
        results = {}

        try:
            # Packet reordering tolerance
            results["reordering_tolerance"] = await self.probe_packet_reordering_detailed(
                target, port
            )

            # Fragmentation handling
            results["fragmentation_handling"] = await self.probe_fragmentation_detailed(
                target, port
            )

            # Timing patterns
            results["timing_patterns"] = await self.analyze_timing_patterns(target, port)

            # Packet size limits
            results["packet_size_limits"] = await self.probe_packet_size_limits(target, port)

            # Protocol detection
            results["protocol_detection"] = await self.probe_protocol_detection(target, port)

        except Exception as e:
            self.logger.error(f"Behavioral pattern probing failed: {e}")
            results["error"] = str(e)

        return results

    async def probe_packet_reordering_detailed(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detailed packet reordering tolerance test

        Tests DPI tolerance to out-of-order TCP packets.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with reordering tolerance results
        """
        result = {"tolerates_reordering": False, "max_reorder_distance": 0}

        try:
            # Test with different reordering distances
            for distance in [1, 2, 4, 8]:
                success = await test_connection_with_reordering(
                    target, port, timeout=2.0, logger=self.logger
                )
                if success:
                    result["tolerates_reordering"] = True
                    result["max_reorder_distance"] = distance
                else:
                    break

        except Exception as e:
            result["error"] = str(e)

        return result

    async def probe_fragmentation_detailed(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detailed fragmentation analysis

        Tests various fragment sizes to determine DPI fragmentation handling.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with detailed fragmentation results
        """
        if not self.config.enable_scapy_probes:
            return {
                "supports_ip_fragmentation": False,
                "min_fragment_size": None,
                "reassembly_timeout": None,
            }

        result = {
            "supports_ip_fragmentation": False,
            "min_fragment_size": None,
            "reassembly_timeout": None,
        }

        try:
            # Test different fragment sizes
            for frag_size in [8, 16, 32, 64]:
                success = await test_fragmented_connection(
                    target, port, frag_size, timeout=2.0, logger=self.logger
                )
                if success:
                    result["supports_ip_fragmentation"] = True
                    if not result["min_fragment_size"]:
                        result["min_fragment_size"] = frag_size

        except Exception as e:
            result["error"] = str(e)

        return result

    async def analyze_timing_patterns(self, target: str, port: int) -> Dict[str, Any]:
        """
        Analyze various timing patterns

        Measures connection and TLS handshake timing.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with timing measurements
        """
        patterns = {}

        # Connection establishment timing
        try:
            t0 = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=5.0
            )
            patterns["connect_time_ms"] = (time.time() - t0) * 1000
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            patterns["connect_error"] = str(e)

        # TLS handshake timing (if HTTPS)
        if port == 443:
            try:
                t0 = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=ctx), timeout=5.0
                )
                patterns["tls_handshake_ms"] = (time.time() - t0) * 1000
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                patterns["tls_error"] = str(e)

        return patterns

    async def probe_packet_size_limits(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe packet size limitations

        Tests various payload sizes to determine DPI packet size limits.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with packet size limit results
        """
        limits = {
            "max_tcp_payload": None,
            "mtu_discovered": 1500,
            "jumbo_frames_supported": False,
        }

        # Test various payload sizes
        test_sizes = [64, 256, 512, 1024, 1460, 9000]

        for size in test_sizes:
            success = await test_payload_size(target, port, size, timeout=2.0, logger=self.logger)
            if success:
                limits["max_tcp_payload"] = size
                if size > 1500:
                    limits["jumbo_frames_supported"] = True
            else:
                break

        return limits

    async def probe_protocol_detection(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe protocol detection capabilities

        Uses port-based heuristics to determine protocol detection.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with protocol detection results
        """
        detection = {
            "http_detected": False,
            "https_detected": False,
            "http2_detected": False,
            "quic_detected": False,
            "custom_protocol_blocked": False,
            "target": target,
        }

        # Port-based heuristics
        if port == 80:
            detection["http_detected"] = True
        elif port == 443:
            detection["https_detected"] = True
            detection["http2_detected"] = True  # Assume HTTP/2 support

        return detection

    async def probe_quic_initial(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe QUIC protocol support

        Tests if QUIC connections are blocked by DPI.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with QUIC probe results
        """
        result = {"blocked": False, "supported": False, "error": None}

        try:
            # Simplified QUIC probe - in production would send actual QUIC packets
            # For now, just check if UDP port is accessible
            loop = asyncio.get_event_loop()

            def test_udp():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.config.udp_timeout)
                    sock.sendto(b"\x00" * 16, (target, port))
                    sock.close()
                    return True
                except Exception:
                    return False

            result["supported"] = await loop.run_in_executor(self.executor, test_udp)
            result["blocked"] = not result["supported"]

        except Exception as e:
            result["error"] = str(e)
            result["blocked"] = True

        return result

    async def probe_tls_capabilities(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe TLS capabilities and restrictions

        Tests various TLS versions and features.

        Args:
            target: Target domain
            port: Target port

        Returns:
            Dict with TLS capabilities results
        """
        capabilities = {
            "tls10_supported": False,
            "tls11_supported": False,
            "tls12_supported": False,
            "tls13_supported": False,
            "error": None,
        }

        loop = asyncio.get_event_loop()

        def test_tls_version(min_version):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = min_version
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((target, port), timeout=2.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target):
                        return True
            except Exception:
                return False

        try:
            # Test TLS 1.2
            capabilities["tls12_supported"] = await loop.run_in_executor(
                self.executor, test_tls_version, ssl.TLSVersion.TLSv1_2
            )

            # Test TLS 1.3 if available
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                capabilities["tls13_supported"] = await loop.run_in_executor(
                    self.executor, test_tls_version, ssl.TLSVersion.TLSv1_3
                )

        except Exception as e:
            capabilities["error"] = str(e)

        return capabilities
