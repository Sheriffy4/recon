"""
Accessibility Testing Diagnostics

This module provides diagnostic commands and tools for troubleshooting
accessibility testing issues, helping developers identify and resolve
problems with site accessibility detection.

Requirements: 2.1, 2.3
"""

import time
import subprocess
import socket
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import sys
import json


@dataclass
class DiagnosticResult:
    """Result of a diagnostic test."""

    test_name: str
    success: bool
    message: str
    details: Dict[str, Any]
    duration_ms: float
    timestamp: float


class AccessibilityDiagnostics:
    """
    Comprehensive diagnostics for accessibility testing issues.

    Provides tools to diagnose common problems with site accessibility testing,
    including curl availability, network connectivity, DNS resolution, and
    configuration issues.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize diagnostics with optional logger."""
        self.logger = logger or logging.getLogger(__name__)

    def run_full_diagnostics(
        self, target_domain: Optional[str] = None
    ) -> Dict[str, DiagnosticResult]:
        """
        Run comprehensive accessibility testing diagnostics.

        Args:
            target_domain: Optional domain to test connectivity with

        Returns:
            Dictionary of diagnostic results keyed by test name
        """
        self.logger.info("🔍 Running full accessibility testing diagnostics...")

        results = {}

        # Core system diagnostics
        results["curl_availability"] = self.diagnose_curl_availability()
        results["curl_http2_support"] = self.diagnose_curl_http2_support()
        results["network_connectivity"] = self.diagnose_network_connectivity()
        results["dns_resolution"] = self.diagnose_dns_resolution()

        # Python environment diagnostics
        results["python_libraries"] = self.diagnose_python_libraries()
        results["socket_functionality"] = self.diagnose_socket_functionality()

        # Configuration diagnostics
        results["logging_configuration"] = self.diagnose_logging_configuration()
        results["cache_functionality"] = self.diagnose_cache_functionality()

        # Optional target-specific diagnostics
        if target_domain:
            results["target_connectivity"] = self.diagnose_target_connectivity(target_domain)
            results["target_ssl_handshake"] = self.diagnose_target_ssl_handshake(target_domain)

        # Summary
        successful_tests = sum(1 for result in results.values() if result.success)
        total_tests = len(results)

        self.logger.info(f"🔍 Diagnostics complete: {successful_tests}/{total_tests} tests passed")

        return results

    def diagnose_curl_availability(self) -> DiagnosticResult:
        """Diagnose curl executable availability."""
        start_time = time.time()

        try:
            # Check for local curl.exe first (Windows)
            if sys.platform == "win32":
                local_curl = Path(__file__).parent.parent.parent / "curl.exe"
                if local_curl.exists():
                    result = subprocess.run(
                        [str(local_curl), "--version"], capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        duration_ms = (time.time() - start_time) * 1000
                        return DiagnosticResult(
                            test_name="curl_availability",
                            success=True,
                            message=f"Local curl.exe found and working: {local_curl}",
                            details={
                                "curl_path": str(local_curl),
                                "version_output": result.stdout[:200],
                                "type": "local_executable",
                            },
                            duration_ms=duration_ms,
                            timestamp=time.time(),
                        )

            # Try system curl
            curl_executable = "curl.exe" if sys.platform == "win32" else "curl"
            result = subprocess.run(
                [curl_executable, "--version"], capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                duration_ms = (time.time() - start_time) * 1000
                return DiagnosticResult(
                    test_name="curl_availability",
                    success=True,
                    message=f"System curl found and working: {curl_executable}",
                    details={
                        "curl_path": curl_executable,
                        "version_output": result.stdout[:200],
                        "type": "system_executable",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                duration_ms = (time.time() - start_time) * 1000
                return DiagnosticResult(
                    test_name="curl_availability",
                    success=False,
                    message=f"curl executable found but failed to run (return code: {result.returncode})",
                    details={
                        "curl_path": curl_executable,
                        "return_code": result.returncode,
                        "stderr": result.stderr[:200],
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except FileNotFoundError:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="curl_availability",
                success=False,
                message="curl executable not found in system PATH",
                details={
                    "error": "FileNotFoundError",
                    "suggestion": "Install curl or place curl.exe in project directory",
                },
                duration_ms=duration_ms,
                timestamp=time.time(),
            )
        except subprocess.TimeoutExpired:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="curl_availability",
                success=False,
                message="curl executable timeout during version check",
                details={"error": "TimeoutExpired", "timeout_seconds": 5},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="curl_availability",
                success=False,
                message=f"Unexpected error checking curl: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_curl_http2_support(self) -> DiagnosticResult:
        """Diagnose curl HTTP/2 support."""
        start_time = time.time()

        try:
            # Find curl executable
            curl_executable = "curl"
            if sys.platform == "win32":
                local_curl = Path(__file__).parent.parent.parent / "curl.exe"
                if local_curl.exists():
                    curl_executable = str(local_curl)
                else:
                    curl_executable = "curl.exe"

            result = subprocess.run(
                [curl_executable, "--version"], capture_output=True, text=True, timeout=5
            )

            duration_ms = (time.time() - start_time) * 1000

            if result.returncode == 0:
                version_output = result.stdout
                has_http2 = "HTTP2" in version_output or "nghttp2" in version_output

                if has_http2:
                    return DiagnosticResult(
                        test_name="curl_http2_support",
                        success=True,
                        message="curl supports HTTP/2 (required for proper ClientHello generation)",
                        details={
                            "curl_path": curl_executable,
                            "version_output": version_output[:300],
                            "http2_indicators": [
                                indicator
                                for indicator in ["HTTP2", "nghttp2"]
                                if indicator in version_output
                            ],
                        },
                        duration_ms=duration_ms,
                        timestamp=time.time(),
                    )
                else:
                    return DiagnosticResult(
                        test_name="curl_http2_support",
                        success=False,
                        message="curl does NOT support HTTP/2 (will generate small ClientHello packets)",
                        details={
                            "curl_path": curl_executable,
                            "version_output": version_output[:300],
                            "issue": "Missing HTTP/2 support will cause false negatives in DPI bypass testing",
                            "solution": "Install curl with HTTP/2 support or use a different curl binary",
                        },
                        duration_ms=duration_ms,
                        timestamp=time.time(),
                    )
            else:
                return DiagnosticResult(
                    test_name="curl_http2_support",
                    success=False,
                    message=f"Failed to check curl version (return code: {result.returncode})",
                    details={
                        "curl_path": curl_executable,
                        "return_code": result.returncode,
                        "stderr": result.stderr[:200],
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="curl_http2_support",
                success=False,
                message=f"Error checking curl HTTP/2 support: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_network_connectivity(self) -> DiagnosticResult:
        """Diagnose basic network connectivity."""
        start_time = time.time()

        try:
            # Test connectivity to well-known servers
            test_hosts = [
                ("8.8.8.8", 53),  # Google DNS
                ("1.1.1.1", 53),  # Cloudflare DNS
                ("google.com", 443),  # Google HTTPS
                ("cloudflare.com", 443),  # Cloudflare HTTPS
            ]

            results = []
            successful_connections = 0

            for host, port in test_hosts:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect((host, port))
                    sock.close()
                    results.append(f"✅ {host}:{port}")
                    successful_connections += 1
                except Exception as e:
                    results.append(f"❌ {host}:{port} - {e}")

            duration_ms = (time.time() - start_time) * 1000

            if successful_connections >= 2:
                return DiagnosticResult(
                    test_name="network_connectivity",
                    success=True,
                    message=f"Network connectivity OK ({successful_connections}/{len(test_hosts)} hosts reachable)",
                    details={
                        "successful_connections": successful_connections,
                        "total_hosts": len(test_hosts),
                        "connection_results": results,
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                return DiagnosticResult(
                    test_name="network_connectivity",
                    success=False,
                    message=f"Poor network connectivity ({successful_connections}/{len(test_hosts)} hosts reachable)",
                    details={
                        "successful_connections": successful_connections,
                        "total_hosts": len(test_hosts),
                        "connection_results": results,
                        "issue": "Limited network connectivity may affect accessibility testing",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="network_connectivity",
                success=False,
                message=f"Error testing network connectivity: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_dns_resolution(self) -> DiagnosticResult:
        """Diagnose DNS resolution functionality."""
        start_time = time.time()

        try:
            import socket

            test_domains = ["google.com", "cloudflare.com", "github.com", "stackoverflow.com"]
            results = []
            successful_resolutions = 0

            for domain in test_domains:
                try:
                    ip = socket.gethostbyname(domain)
                    results.append(f"✅ {domain} → {ip}")
                    successful_resolutions += 1
                except Exception as e:
                    results.append(f"❌ {domain} - {e}")

            duration_ms = (time.time() - start_time) * 1000

            if successful_resolutions >= 3:
                return DiagnosticResult(
                    test_name="dns_resolution",
                    success=True,
                    message=f"DNS resolution working ({successful_resolutions}/{len(test_domains)} domains resolved)",
                    details={
                        "successful_resolutions": successful_resolutions,
                        "total_domains": len(test_domains),
                        "resolution_results": results,
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                return DiagnosticResult(
                    test_name="dns_resolution",
                    success=False,
                    message=f"DNS resolution issues ({successful_resolutions}/{len(test_domains)} domains resolved)",
                    details={
                        "successful_resolutions": successful_resolutions,
                        "total_domains": len(test_domains),
                        "resolution_results": results,
                        "issue": "DNS resolution problems will affect domain-based accessibility testing",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="dns_resolution",
                success=False,
                message=f"Error testing DNS resolution: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_python_libraries(self) -> DiagnosticResult:
        """Diagnose Python library availability for fallback testing."""
        start_time = time.time()

        libraries = {
            "requests": "HTTP fallback testing",
            "socket": "TCP connectivity testing",
            "subprocess": "curl execution",
            "threading": "concurrent operations",
            "logging": "diagnostic logging",
        }

        available_libraries = []
        missing_libraries = []

        for lib_name, description in libraries.items():
            try:
                __import__(lib_name)
                available_libraries.append(f"✅ {lib_name} - {description}")
            except ImportError:
                missing_libraries.append(f"❌ {lib_name} - {description}")

        duration_ms = (time.time() - start_time) * 1000

        # Check for critical missing libraries
        critical_missing = [
            lib
            for lib in missing_libraries
            if any(critical in lib for critical in ["socket", "subprocess", "logging"])
        ]

        if not critical_missing:
            return DiagnosticResult(
                test_name="python_libraries",
                success=True,
                message=f"All required Python libraries available ({len(available_libraries)} available)",
                details={
                    "available_libraries": available_libraries,
                    "missing_libraries": missing_libraries,
                    "total_checked": len(libraries),
                },
                duration_ms=duration_ms,
                timestamp=time.time(),
            )
        else:
            return DiagnosticResult(
                test_name="python_libraries",
                success=False,
                message=f"Critical Python libraries missing ({len(critical_missing)} critical missing)",
                details={
                    "available_libraries": available_libraries,
                    "missing_libraries": missing_libraries,
                    "critical_missing": critical_missing,
                    "total_checked": len(libraries),
                },
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_socket_functionality(self) -> DiagnosticResult:
        """Diagnose socket functionality for TCP testing."""
        start_time = time.time()

        try:
            import socket

            # Test socket creation and basic operations
            test_results = []

            # Test IPv4 socket creation
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.close()
                test_results.append("✅ IPv4 socket creation")
            except Exception as e:
                test_results.append(f"❌ IPv4 socket creation - {e}")

            # Test IPv6 socket creation (optional)
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.close()
                test_results.append("✅ IPv6 socket creation")
            except Exception as e:
                test_results.append(f"⚠️ IPv6 socket creation - {e}")

            # Test timeout setting
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.close()
                test_results.append("✅ Socket timeout setting")
            except Exception as e:
                test_results.append(f"❌ Socket timeout setting - {e}")

            duration_ms = (time.time() - start_time) * 1000

            # Check for critical failures
            critical_failures = [result for result in test_results if result.startswith("❌")]

            if not critical_failures:
                return DiagnosticResult(
                    test_name="socket_functionality",
                    success=True,
                    message="Socket functionality working correctly",
                    details={"test_results": test_results, "critical_failures": 0},
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                return DiagnosticResult(
                    test_name="socket_functionality",
                    success=False,
                    message=f"Socket functionality issues ({len(critical_failures)} critical failures)",
                    details={
                        "test_results": test_results,
                        "critical_failures": len(critical_failures),
                        "issue": "Socket problems will affect TCP fallback testing",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="socket_functionality",
                success=False,
                message=f"Error testing socket functionality: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_logging_configuration(self) -> DiagnosticResult:
        """Diagnose logging configuration and functionality."""
        start_time = time.time()

        try:
            import logging

            # Check current logging configuration
            root_logger = logging.getLogger()
            current_level = root_logger.level
            handlers_count = len(root_logger.handlers)

            # Test logging functionality
            test_logger = logging.getLogger("accessibility_diagnostics_test")

            # Capture log output to test functionality
            import io

            log_stream = io.StringIO()
            test_handler = logging.StreamHandler(log_stream)
            test_logger.addHandler(test_handler)
            test_logger.setLevel(logging.DEBUG)

            # Test different log levels
            test_logger.debug("Debug test message")
            test_logger.info("Info test message")
            test_logger.warning("Warning test message")
            test_logger.error("Error test message")

            log_output = log_stream.getvalue()
            test_logger.removeHandler(test_handler)

            duration_ms = (time.time() - start_time) * 1000

            if log_output and "test message" in log_output:
                return DiagnosticResult(
                    test_name="logging_configuration",
                    success=True,
                    message="Logging configuration working correctly",
                    details={
                        "root_level": logging.getLevelName(current_level),
                        "handlers_count": handlers_count,
                        "test_output_length": len(log_output),
                        "logging_functional": True,
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                return DiagnosticResult(
                    test_name="logging_configuration",
                    success=False,
                    message="Logging configuration issues detected",
                    details={
                        "root_level": logging.getLevelName(current_level),
                        "handlers_count": handlers_count,
                        "test_output_length": len(log_output),
                        "logging_functional": False,
                        "issue": "Logging may not be capturing diagnostic information properly",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="logging_configuration",
                success=False,
                message=f"Error testing logging configuration: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_cache_functionality(self) -> DiagnosticResult:
        """Diagnose cache functionality for accessibility testing."""
        start_time = time.time()

        try:
            # Test basic cache operations
            from collections import defaultdict
            import threading

            # Simulate cache operations
            test_cache = {}
            cache_lock = threading.Lock()

            # Test cache write
            with cache_lock:
                test_cache["test_key"] = {"value": "test_value", "timestamp": time.time()}

            # Test cache read
            with cache_lock:
                cached_value = test_cache.get("test_key")

            # Test cache cleanup simulation
            with cache_lock:
                del test_cache["test_key"]

            duration_ms = (time.time() - start_time) * 1000

            if cached_value and cached_value["value"] == "test_value":
                return DiagnosticResult(
                    test_name="cache_functionality",
                    success=True,
                    message="Cache functionality working correctly",
                    details={
                        "cache_operations": ["write", "read", "delete"],
                        "threading_support": True,
                        "test_successful": True,
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                return DiagnosticResult(
                    test_name="cache_functionality",
                    success=False,
                    message="Cache functionality issues detected",
                    details={
                        "cache_operations": ["write", "read", "delete"],
                        "threading_support": True,
                        "test_successful": False,
                        "issue": "Cache read/write operations not working as expected",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="cache_functionality",
                success=False,
                message=f"Error testing cache functionality: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_target_connectivity(self, domain: str) -> DiagnosticResult:
        """Diagnose connectivity to a specific target domain."""
        start_time = time.time()

        try:
            import socket

            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
                dns_success = True
            except Exception as e:
                ip = None
                dns_success = False
                dns_error = str(e)

            # Test TCP connectivity if DNS succeeded
            tcp_success = False
            tcp_error = None

            if dns_success and ip:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10.0)
                    sock.connect((ip, 443))
                    sock.close()
                    tcp_success = True
                except Exception as e:
                    tcp_error = str(e)

            duration_ms = (time.time() - start_time) * 1000

            if dns_success and tcp_success:
                return DiagnosticResult(
                    test_name="target_connectivity",
                    success=True,
                    message=f"Target {domain} is reachable (DNS: ✅, TCP: ✅)",
                    details={
                        "domain": domain,
                        "resolved_ip": ip,
                        "dns_success": True,
                        "tcp_success": True,
                        "port_tested": 443,
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            elif dns_success and not tcp_success:
                return DiagnosticResult(
                    test_name="target_connectivity",
                    success=False,
                    message=f"Target {domain} DNS works but TCP fails (DNS: ✅, TCP: ❌)",
                    details={
                        "domain": domain,
                        "resolved_ip": ip,
                        "dns_success": True,
                        "tcp_success": False,
                        "tcp_error": tcp_error,
                        "port_tested": 443,
                        "issue": "Domain resolves but connection fails - may be blocked or down",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )
            else:
                return DiagnosticResult(
                    test_name="target_connectivity",
                    success=False,
                    message=f"Target {domain} not reachable (DNS: ❌, TCP: N/A)",
                    details={
                        "domain": domain,
                        "resolved_ip": None,
                        "dns_success": False,
                        "dns_error": dns_error,
                        "tcp_success": False,
                        "issue": "DNS resolution failed - domain may not exist or DNS issues",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="target_connectivity",
                success=False,
                message=f"Error testing target connectivity: {e}",
                details={"domain": domain, "error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def diagnose_target_ssl_handshake(self, domain: str) -> DiagnosticResult:
        """Diagnose SSL/TLS handshake with target domain."""
        start_time = time.time()

        try:
            import socket
            import ssl

            # Resolve domain
            try:
                ip = socket.gethostbyname(domain)
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                return DiagnosticResult(
                    test_name="target_ssl_handshake",
                    success=False,
                    message=f"Cannot resolve {domain} for SSL test: {e}",
                    details={"domain": domain, "dns_error": str(e)},
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

            # Test SSL handshake
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)

                ssl_sock = context.wrap_socket(sock, server_hostname=domain)
                ssl_sock.connect((ip, 443))

                # Get certificate info
                cert = ssl_sock.getpeercert()
                cipher = ssl_sock.cipher()

                ssl_sock.close()

                duration_ms = (time.time() - start_time) * 1000

                return DiagnosticResult(
                    test_name="target_ssl_handshake",
                    success=True,
                    message=f"SSL handshake successful with {domain}",
                    details={
                        "domain": domain,
                        "resolved_ip": ip,
                        "ssl_version": cipher[1] if cipher else "unknown",
                        "cipher_suite": cipher[0] if cipher else "unknown",
                        "certificate_subject": cert.get("subject") if cert else None,
                        "handshake_successful": True,
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                return DiagnosticResult(
                    test_name="target_ssl_handshake",
                    success=False,
                    message=f"SSL handshake failed with {domain}: {e}",
                    details={
                        "domain": domain,
                        "resolved_ip": ip,
                        "ssl_error": str(e),
                        "handshake_successful": False,
                        "issue": "SSL handshake failure may indicate blocking or server issues",
                    },
                    duration_ms=duration_ms,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return DiagnosticResult(
                test_name="target_ssl_handshake",
                success=False,
                message=f"Error testing SSL handshake: {e}",
                details={"domain": domain, "error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                timestamp=time.time(),
            )

    def generate_diagnostic_report(self, results: Dict[str, DiagnosticResult]) -> str:
        """
        Generate a comprehensive diagnostic report.

        Args:
            results: Dictionary of diagnostic results

        Returns:
            Formatted diagnostic report as string
        """
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("ACCESSIBILITY TESTING DIAGNOSTICS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        # Summary
        successful_tests = sum(1 for result in results.values() if result.success)
        total_tests = len(results)
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0

        report_lines.append("SUMMARY")
        report_lines.append("-" * 40)
        report_lines.append(f"Total Tests: {total_tests}")
        report_lines.append(f"Successful: {successful_tests}")
        report_lines.append(f"Failed: {total_tests - successful_tests}")
        report_lines.append(f"Success Rate: {success_rate:.1f}%")
        report_lines.append("")

        # Detailed results
        report_lines.append("DETAILED RESULTS")
        report_lines.append("-" * 40)

        for test_name, result in results.items():
            status = "✅ PASS" if result.success else "❌ FAIL"
            report_lines.append(f"{status} {test_name.upper()}")
            report_lines.append(f"    Message: {result.message}")
            report_lines.append(f"    Duration: {result.duration_ms:.1f}ms")

            if not result.success and "issue" in result.details:
                report_lines.append(f"    Issue: {result.details['issue']}")

            if not result.success and "solution" in result.details:
                report_lines.append(f"    Solution: {result.details['solution']}")

            report_lines.append("")

        # Recommendations
        failed_tests = [name for name, result in results.items() if not result.success]
        if failed_tests:
            report_lines.append("RECOMMENDATIONS")
            report_lines.append("-" * 40)

            if "curl_availability" in failed_tests:
                report_lines.append("• Install curl or place curl.exe in project directory")

            if "curl_http2_support" in failed_tests:
                report_lines.append("• Install curl with HTTP/2 support for accurate DPI testing")

            if "network_connectivity" in failed_tests:
                report_lines.append("• Check network connection and firewall settings")

            if "dns_resolution" in failed_tests:
                report_lines.append("• Check DNS configuration and network settings")

            report_lines.append("")

        report_lines.append("=" * 80)

        return "\n".join(report_lines)
