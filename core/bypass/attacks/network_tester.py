"""
Network Connectivity Tester

Provides real network connectivity testing for attacks to validate
if they actually work in practice, not just execute without errors.
"""

import socket
import time
import ssl
import logging
from typing import Optional, Tuple
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.domain_tester import test_domain_accessibility_sync
from core.bypass.attacks.bypass_tester import test_bypass_effectiveness_sync

LOG = logging.getLogger("NetworkTester")


class NetworkTester:
    """
    Tests real network connectivity to validate attack effectiveness.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = LOG

    def test_tcp_connection(
        self, context: AttackContext
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Test TCP connection to target.

        Args:
            context: Attack context with target information

        Returns:
            Tuple of (success, latency_ms, error_message)
        """
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((context.dst_ip, context.dst_port))
            latency_ms = (time.time() - start_time) * 1000
            if result == 0:
                sock.close()
                return (True, latency_ms, None)
            else:
                sock.close()
                return (
                    False,
                    latency_ms,
                    f"Connection failed with error code {result}",
                )
        except socket.timeout:
            return (False, self.timeout * 1000, "Connection timeout")
        except socket.gaierror as e:
            return (
                False,
                (time.time() - start_time) * 1000,
                f"DNS resolution failed: {e}",
            )
        except Exception as e:
            return (False, (time.time() - start_time) * 1000, f"Connection error: {e}")

    def test_http_request(
        self, context: AttackContext, use_ssl: bool = False
    ) -> Tuple[bool, float, Optional[str], Optional[bytes]]:
        """
        Test HTTP request to target.

        Args:
            context: Attack context with target information
            use_ssl: Whether to use HTTPS

        Returns:
            Tuple of (success, latency_ms, error_message, response_data)
        """
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((context.dst_ip, context.dst_port))
            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                sock = ssl_context.wrap_socket(sock, server_hostname=context.domain)
            if context.payload:
                request = context.payload
            else:
                host = context.domain or context.dst_ip
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
            sock.send(request)
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if len(response) > 10240:
                        break
                except socket.timeout:
                    break
            sock.close()
            latency_ms = (time.time() - start_time) * 1000
            if response and (b"HTTP/" in response[:20] or len(response) > 0):
                return (True, latency_ms, None, response)
            else:
                return (False, latency_ms, "No valid HTTP response received", response)
        except socket.timeout:
            return (False, self.timeout * 1000, "Request timeout", None)
        except Exception as e:
            return (
                False,
                (time.time() - start_time) * 1000,
                f"Request error: {e}",
                None,
            )

    def validate_attack_result(
        self,
        context: AttackContext,
        attack_result: AttackResult,
        strict_mode: bool = False,
    ) -> AttackResult:
        """
        Validate attack result by testing real network connectivity.

        Args:
            context: Attack context
            attack_result: Original attack result
            strict_mode: If True, requires successful network connection. If False, more lenient.

        Returns:
            Updated attack result with real network validation
        """
        if attack_result.status != AttackStatus.SUCCESS:
            return attack_result
        use_ssl = context.dst_port in [443, 8443] or (
            context.domain and context.domain.startswith("https://")
        )
        if context.dst_port in [80, 443, 8080, 8443] and context.domain:
            try:
                bypass_results = test_bypass_effectiveness_sync(
                    context, attack_result, timeout=self.timeout
                )
                if "error" in bypass_results:
                    success, latency_ms, error_msg = test_domain_accessibility_sync(
                        context.domain, timeout=self.timeout
                    )
                    if success:
                        attack_result.connection_established = True
                        attack_result.data_transmitted = True
                        attack_result.response_received = True
                        attack_result.latency_ms = latency_ms
                        if not isinstance(attack_result.metadata, dict):
                            attack_result.metadata = {}
                        attack_result.metadata["network_test"] = (
                            "domain_success_fallback"
                        )
                        attack_result.metadata["domain_tested"] = context.domain
                    elif not strict_mode:
                        attack_result.connection_established = False
                        attack_result.latency_ms = latency_ms
                        if not isinstance(attack_result.metadata, dict):
                            attack_result.metadata = {}
                        attack_result.metadata["network_test"] = (
                            "domain_failed_but_attack_ok"
                        )
                        attack_result.metadata["network_error"] = error_msg
                        attack_result.metadata["domain_tested"] = context.domain
                    else:
                        attack_result.status = AttackStatus.ERROR
                        attack_result.error_message = (
                            error_msg or "Domain accessibility test failed"
                        )
                        attack_result.connection_established = False
                        attack_result.data_transmitted = False
                        attack_result.latency_ms = latency_ms
                        if not isinstance(attack_result.metadata, dict):
                            attack_result.metadata = {}
                        attack_result.metadata["network_test"] = "domain_failed"
                        attack_result.metadata["domain_tested"] = context.domain
                else:
                    bypass_effective = bypass_results.get("bypass_effective", False)
                    bypass_data = bypass_results.get("bypass", {})
                    baseline_data = bypass_results.get("baseline", {})
                    if bypass_effective:
                        attack_result.connection_established = True
                        attack_result.data_transmitted = True
                        attack_result.response_received = True
                        attack_result.latency_ms = bypass_data.get("latency_ms", 0)
                        if not isinstance(attack_result.metadata, dict):
                            attack_result.metadata = {}
                        attack_result.metadata["network_test"] = "bypass_effective"
                        attack_result.metadata["bypass_results"] = bypass_results
                        attack_result.metadata["domain_tested"] = context.domain
                    elif not strict_mode:
                        attack_result.connection_established = baseline_data.get(
                            "success", False
                        )
                        attack_result.latency_ms = baseline_data.get("latency_ms", 0)
                        if not isinstance(attack_result.metadata, dict):
                            attack_result.metadata = {}
                        attack_result.metadata["network_test"] = (
                            "bypass_not_effective_but_attack_ok"
                        )
                        attack_result.metadata["bypass_results"] = bypass_results
                        attack_result.metadata["domain_tested"] = context.domain
                    else:
                        attack_result.status = AttackStatus.ERROR
                        attack_result.error_message = (
                            "Bypass strategy was not effective"
                        )
                        attack_result.connection_established = False
                        attack_result.data_transmitted = False
                        attack_result.latency_ms = bypass_data.get("latency_ms", 0)
                        if not isinstance(attack_result.metadata, dict):
                            attack_result.metadata = {}
                        attack_result.metadata["network_test"] = "bypass_not_effective"
                        attack_result.metadata["bypass_results"] = bypass_results
                        attack_result.metadata["domain_tested"] = context.domain
            except Exception:
                success, latency_ms, error_msg, response = self.test_http_request(
                    context, use_ssl
                )
                if success:
                    attack_result.connection_established = True
                    attack_result.data_transmitted = True
                    attack_result.response_received = True
                    attack_result.latency_ms = latency_ms
                    attack_result.metadata["network_test"] = "http_fallback_success"
                    attack_result.metadata["response_size"] = (
                        len(response) if response else 0
                    )
                elif not strict_mode:
                    attack_result.connection_established = False
                    attack_result.latency_ms = latency_ms
                    attack_result.metadata["network_test"] = (
                        "http_fallback_failed_but_attack_ok"
                    )
                    attack_result.metadata["network_error"] = error_msg
                else:
                    attack_result.status = AttackStatus.ERROR
                    attack_result.error_message = (
                        error_msg or "HTTP fallback test failed"
                    )
                    attack_result.connection_established = False
                    attack_result.data_transmitted = False
                    attack_result.latency_ms = latency_ms
                    attack_result.metadata["network_test"] = "http_fallback_failed"
        else:
            success, latency_ms, error_msg = self.test_tcp_connection(context)
            if success:
                attack_result.connection_established = True
                attack_result.latency_ms = latency_ms
                attack_result.metadata["network_test"] = "tcp_success"
            elif not strict_mode:
                attack_result.connection_established = False
                attack_result.latency_ms = latency_ms
                attack_result.metadata["network_test"] = "tcp_failed_but_attack_ok"
                attack_result.metadata["network_error"] = error_msg
            else:
                attack_result.status = AttackStatus.ERROR
                attack_result.error_message = (
                    error_msg or "TCP connectivity test failed"
                )
                attack_result.connection_established = False
                attack_result.latency_ms = latency_ms
                attack_result.metadata["network_test"] = "tcp_failed"
        return attack_result

    def quick_connectivity_check(
        self, ip: str, port: int, timeout: float = 2.0
    ) -> bool:
        """
        Quick connectivity check without detailed testing.

        Args:
            ip: Target IP address
            port: Target port
            timeout: Connection timeout

        Returns:
            True if connection is possible, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
