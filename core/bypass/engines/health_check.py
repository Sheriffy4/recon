# recon/core/bypass/engines/health_check.py
"""
Engine Health Check System

Provides comprehensive health checking for packet processing engines,
including PyDivert availability, Scapy functionality, and system permissions.
"""

import logging
import sys
import os
import socket
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    pydivert = None  # Создаем заглушку, чтобы остальной код не падал
    PYDIVERT_AVAILABLE = False

LOG = logging.getLogger("EngineHealthCheck")


class HealthStatus(Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""

    component: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_healthy(self) -> bool:
        """Check if component is healthy."""
        return self.status == HealthStatus.HEALTHY

    @property
    def needs_attention(self) -> bool:
        """Check if component needs attention."""
        return self.status in [HealthStatus.WARNING, HealthStatus.CRITICAL]


@dataclass
class SystemHealthReport:
    """Comprehensive system health report."""

    overall_status: HealthStatus
    component_results: List[HealthCheckResult] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    fallback_options: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def healthy_components(self) -> List[HealthCheckResult]:
        """Get list of healthy components."""
        return [r for r in self.component_results if r.is_healthy]

    @property
    def problematic_components(self) -> List[HealthCheckResult]:
        """Get list of components with issues."""
        return [r for r in self.component_results if r.needs_attention]

    @property
    def can_use_pydivert(self) -> bool:
        """Check if PyDivert can be used."""
        pydivert_result = next(
            (r for r in self.component_results if r.component == "pydivert"), None
        )
        return pydivert_result and pydivert_result.is_healthy

    @property
    def can_use_scapy(self) -> bool:
        """Check if Scapy can be used."""
        scapy_result = next(
            (r for r in self.component_results if r.component == "scapy"), None
        )
        return scapy_result and scapy_result.is_healthy


class EngineHealthCheck:
    """
    Comprehensive health checking system for packet processing engines.

    Checks:
    - PyDivert availability and permissions
    - Scapy functionality
    - Network interface access
    - System permissions
    - Driver status
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = LOG
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def perform_full_health_check(self) -> SystemHealthReport:
        """
        Perform comprehensive health check of all engine components.

        Returns:
            SystemHealthReport with detailed results and recommendations
        """
        self.logger.info("🏥 Starting comprehensive engine health check...")

        results = []

        # Check PyDivert
        results.append(self._check_pydivert())

        # Check Scapy
        results.append(self._check_scapy())

        # Check system permissions
        results.append(self._check_system_permissions())

        # Check network interfaces
        results.append(self._check_network_interfaces())

        # Check WinDivert driver (Windows specific)
        if sys.platform.startswith("win"):
            results.append(self._check_windivert_driver())

        # Determine overall status
        overall_status = self._determine_overall_status(results)

        # Generate recommendations
        recommendations = self._generate_recommendations(results)

        # Generate fallback options
        fallback_options = self._generate_fallback_options(results)

        report = SystemHealthReport(
            overall_status=overall_status,
            component_results=results,
            recommendations=recommendations,
            fallback_options=fallback_options,
        )

        self.logger.info(
            f"🏥 Health check completed. Overall status: {overall_status.value}"
        )
        return report

    def _check_pydivert(self) -> HealthCheckResult:
        self.logger.debug("Checking PyDivert...")

        try:
            import pydivert

            # --- УЛУЧШЕНИЕ: Проверяем, можем ли мы создать хендл ---
            try:
                # Пытаемся создать простой фильтр, который ничего не будет ловить
                with pydivert.WinDivert("false") as w:
                    pass  # Если это выполнилось, драйвер и права в порядке

                return HealthCheckResult(
                    component="pydivert",
                    status=HealthStatus.HEALTHY,
                    message="PyDivert is available and functional",
                    details={
                        "version": getattr(pydivert, "__version__", "unknown"),
                        "can_create_handle": True,
                        "driver_loaded": True,
                    },
                )

            except OSError as e:
                if e.winerror == 5:  # Access denied
                    return HealthCheckResult(
                        component="pydivert",
                        status=HealthStatus.CRITICAL,
                        message="PyDivert requires administrator privileges",
                        details={"error_code": e.winerror, "error_message": str(e)},
                    )
                elif e.winerror == 2:  # Driver not found
                    return HealthCheckResult(
                        component="pydivert",
                        status=HealthStatus.CRITICAL,
                        message="WinDivert driver not found or not loaded",
                        details={"error_code": e.winerror, "error_message": str(e)},
                    )
                else:
                    return HealthCheckResult(
                        component="pydivert",
                        status=HealthStatus.CRITICAL,
                        message=f"PyDivert initialization failed: {e}",
                        details={
                            "error_code": getattr(e, "winerror", None),
                            "error_message": str(e),
                        },
                    )

        except ImportError:
            return HealthCheckResult(
                component="pydivert",
                status=HealthStatus.CRITICAL,
                message="PyDivert is not installed",
                details={"import_error": True},
            )
        except Exception as e:
            return HealthCheckResult(
                component="pydivert",
                status=HealthStatus.CRITICAL,
                message=f"Unexpected PyDivert error: {e}",
                details={"unexpected_error": str(e)},
            )

    def _check_scapy(self) -> HealthCheckResult:
        """Check Scapy availability and functionality."""
        self.logger.debug("Checking Scapy...")

        try:
            from scapy.all import IP, TCP, Raw

            # Try to create a simple packet
            try:
                packet = IP(dst="127.0.0.1") / TCP(dport=80) / Raw(b"test")
                packet_bytes = bytes(packet)

                return HealthCheckResult(
                    component="scapy",
                    status=HealthStatus.HEALTHY,
                    message="Scapy is available and functional",
                    details={
                        "can_create_packets": True,
                        "packet_size": len(packet_bytes),
                        "layers_available": ["IP", "TCP", "Raw"],
                    },
                )

            except Exception as e:
                return HealthCheckResult(
                    component="scapy",
                    status=HealthStatus.WARNING,
                    message=f"Scapy packet creation failed: {e}",
                    details={
                        "packet_creation_error": str(e),
                        "may_affect_functionality": True,
                    },
                )

        except ImportError as e:
            return HealthCheckResult(
                component="scapy",
                status=HealthStatus.WARNING,
                message="Scapy is not available",
                details={
                    "import_error": str(e),
                    "fallback_available": True,
                    "note": "System can work without Scapy using raw packet building",
                },
            )
        except Exception as e:
            return HealthCheckResult(
                component="scapy",
                status=HealthStatus.WARNING,
                message=f"Unexpected Scapy error: {e}",
                details={"unexpected_error": str(e)},
            )

    def _check_system_permissions(self) -> HealthCheckResult:
        """Check system permissions required for packet processing."""
        self.logger.debug("Checking system permissions...")

        try:
            if sys.platform.startswith("win"):
                # Check if running as administrator on Windows
                import ctypes

                is_admin = ctypes.windll.shell32.IsUserAnAdmin()

                if is_admin:
                    return HealthCheckResult(
                        component="permissions",
                        status=HealthStatus.HEALTHY,
                        message="Running with administrator privileges",
                        details={
                            "is_admin": True,
                            "platform": "windows",
                            "can_access_raw_sockets": True,
                        },
                    )
                else:
                    return HealthCheckResult(
                        component="permissions",
                        status=HealthStatus.CRITICAL,
                        message="Administrator privileges required",
                        details={
                            "is_admin": False,
                            "platform": "windows",
                            "elevation_required": True,
                        },
                    )
            else:
                # Check if running as root on Unix-like systems
                is_root = os.geteuid() == 0

                if is_root:
                    return HealthCheckResult(
                        component="permissions",
                        status=HealthStatus.HEALTHY,
                        message="Running with root privileges",
                        details={
                            "is_root": True,
                            "platform": "unix",
                            "can_access_raw_sockets": True,
                        },
                    )
                else:
                    return HealthCheckResult(
                        component="permissions",
                        status=HealthStatus.WARNING,
                        message="Not running as root - some features may be limited",
                        details={
                            "is_root": False,
                            "platform": "unix",
                            "may_need_sudo": True,
                        },
                    )

        except Exception as e:
            return HealthCheckResult(
                component="permissions",
                status=HealthStatus.UNKNOWN,
                message=f"Could not determine permissions: {e}",
                details={"error": str(e)},
            )

    def _check_network_interfaces(self) -> HealthCheckResult:
        """Check network interface accessibility."""
        self.logger.debug("Checking network interfaces...")

        try:
            # Try to create a raw socket to test network access
            try:
                if sys.platform.startswith("win"):
                    # On Windows, try to create a socket
                    sock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                    )
                    sock.close()

                    return HealthCheckResult(
                        component="network_interfaces",
                        status=HealthStatus.HEALTHY,
                        message="Network interfaces accessible",
                        details={"raw_socket_access": True, "platform": "windows"},
                    )
                else:
                    # On Unix-like systems
                    sock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                    )
                    sock.close()

                    return HealthCheckResult(
                        component="network_interfaces",
                        status=HealthStatus.HEALTHY,
                        message="Network interfaces accessible",
                        details={"raw_socket_access": True, "platform": "unix"},
                    )

            except PermissionError:
                return HealthCheckResult(
                    component="network_interfaces",
                    status=HealthStatus.WARNING,
                    message="Limited network interface access",
                    details={
                        "raw_socket_access": False,
                        "permission_error": True,
                        "may_need_elevation": True,
                    },
                )
            except OSError as e:
                return HealthCheckResult(
                    component="network_interfaces",
                    status=HealthStatus.WARNING,
                    message=f"Network interface access issue: {e}",
                    details={
                        "os_error": str(e),
                        "error_code": getattr(e, "errno", None),
                    },
                )

        except Exception as e:
            return HealthCheckResult(
                component="network_interfaces",
                status=HealthStatus.UNKNOWN,
                message=f"Could not check network interfaces: {e}",
                details={"error": str(e)},
            )

    def _check_windivert_driver(self) -> HealthCheckResult:
        """Check WinDivert driver status (Windows only)."""
        self.logger.debug("Checking WinDivert driver...")

        try:
            # IMPROVED: Use actual PyDivert functionality test instead of service status
            # WinDivert doesn't run as a Windows service - it loads on demand

            # First, test if PyDivert can actually work
            try:
                import pydivert

                # Try to create a simple handle that won't capture anything
                with pydivert.WinDivert("false") as w:
                    pass

                return HealthCheckResult(
                    component="windivert_driver",
                    status=HealthStatus.HEALTHY,
                    message="WinDivert driver is functional and can create handles",
                    details={
                        "driver_status": "functional",
                        "can_create_handle": True,
                        "pydivert_available": True,
                    },
                )

            except OSError as e:
                if e.winerror == 5:  # Access denied
                    return HealthCheckResult(
                        component="windivert_driver",
                        status=HealthStatus.CRITICAL,
                        message="WinDivert driver requires administrator privileges",
                        details={
                            "driver_status": "access_denied",
                            "error_code": e.winerror,
                            "needs_admin": True,
                        },
                    )
                elif e.winerror == 2:  # Driver not found
                    return HealthCheckResult(
                        component="windivert_driver",
                        status=HealthStatus.CRITICAL,
                        message="WinDivert driver files not found - reinstall PyDivert",
                        details={
                            "driver_status": "files_missing",
                            "error_code": e.winerror,
                            "needs_reinstall": True,
                        },
                    )
                elif e.winerror == 87:  # Invalid parameter
                    return HealthCheckResult(
                        component="windivert_driver",
                        status=HealthStatus.CRITICAL,
                        message="WinDivert driver corrupted - reinstall PyDivert",
                        details={
                            "driver_status": "corrupted",
                            "error_code": e.winerror,
                            "needs_reinstall": True,
                        },
                    )
                else:
                    return HealthCheckResult(
                        component="windivert_driver",
                        status=HealthStatus.CRITICAL,
                        message=f"WinDivert driver error: {e}",
                        details={
                            "driver_status": "error",
                            "error_code": getattr(e, "winerror", None),
                            "error_message": str(e),
                        },
                    )

            except ImportError:
                return HealthCheckResult(
                    component="windivert_driver",
                    status=HealthStatus.CRITICAL,
                    message="PyDivert not installed - install with: pip install pydivert",
                    details={
                        "driver_status": "pydivert_missing",
                        "needs_install": True,
                    },
                )

        except Exception as e:
            return HealthCheckResult(
                component="windivert_driver",
                status=HealthStatus.UNKNOWN,
                message=f"Could not check WinDivert driver: {e}",
                details={"error": str(e)},
            )

    def _determine_overall_status(
        self, results: List[HealthCheckResult]
    ) -> HealthStatus:
        """Determine overall system health status."""
        if not results:
            return HealthStatus.UNKNOWN

        # If any critical issues, overall is critical
        if any(r.status == HealthStatus.CRITICAL for r in results):
            return HealthStatus.CRITICAL

        # If any warnings, overall is warning
        if any(r.status == HealthStatus.WARNING for r in results):
            return HealthStatus.WARNING

        # If any unknown, overall is warning
        if any(r.status == HealthStatus.UNKNOWN for r in results):
            return HealthStatus.WARNING

        # All healthy
        return HealthStatus.HEALTHY

    def _generate_recommendations(self, results: List[HealthCheckResult]) -> List[str]:
        """Generate recommendations based on health check results."""
        recommendations = []

        for result in results:
            if (
                result.component == "pydivert"
                and result.status == HealthStatus.CRITICAL
            ):
                if result.details.get("requires_admin"):
                    recommendations.append(
                        "Run the application as Administrator to enable PyDivert"
                    )
                elif result.details.get("installation_required"):
                    recommendations.append("Install PyDivert: pip install pydivert")
                elif result.details.get("driver_missing"):
                    recommendations.append(
                        "Ensure WinDivert driver files are present in the application directory"
                    )

            elif result.component == "scapy" and result.status == HealthStatus.WARNING:
                if result.details.get("import_error"):
                    recommendations.append(
                        "Install Scapy for enhanced packet building: pip install scapy"
                    )

            elif (
                result.component == "permissions"
                and result.status == HealthStatus.CRITICAL
            ):
                if result.details.get("elevation_required"):
                    recommendations.append(
                        "Run the application as Administrator (Windows) or with sudo (Linux)"
                    )

            elif (
                result.component == "windivert_driver"
                and result.status == HealthStatus.CRITICAL
            ):
                if result.details.get("needs_admin"):
                    recommendations.append(
                        "Run the application as Administrator to enable WinDivert driver"
                    )
                elif result.details.get("needs_install"):
                    recommendations.append(
                        "Install PyDivert with driver: pip install pydivert"
                    )
                elif result.details.get("needs_reinstall"):
                    recommendations.append(
                        "Reinstall PyDivert: pip uninstall pydivert && pip install pydivert"
                    )
                elif result.details.get("files_missing"):
                    recommendations.append(
                        "WinDivert driver files missing - reinstall PyDivert"
                    )
                    recommendations.append(
                        "Check if antivirus software is blocking WinDivert files"
                    )

        return recommendations

    def _generate_fallback_options(self, results: List[HealthCheckResult]) -> List[str]:
        """Generate fallback options when primary engines are unavailable."""
        fallback_options = []

        pydivert_available = any(
            r.component == "pydivert" and r.is_healthy for r in results
        )
        scapy_available = any(r.component == "scapy" and r.is_healthy for r in results)

        if not pydivert_available:
            fallback_options.append(
                "Use simulation mode for testing (no real packet processing)"
            )
            fallback_options.append(
                "Use external tools like zapret for packet manipulation"
            )

            if scapy_available:
                fallback_options.append(
                    "Use Scapy-based packet building with external sending"
                )

        if not scapy_available:
            fallback_options.append("Use raw packet building instead of Scapy")

        return fallback_options

    def log_health_report(self, report: SystemHealthReport) -> None:
        """Log comprehensive health report."""
        self.logger.info("=" * 60)
        self.logger.info("🏥 ENGINE HEALTH CHECK REPORT")
        self.logger.info("=" * 60)

        # Overall status
        status_emoji = {
            HealthStatus.HEALTHY: "🟢",
            HealthStatus.WARNING: "🟡",
            HealthStatus.CRITICAL: "🔴",
            HealthStatus.UNKNOWN: "⚪",
        }

        self.logger.info(
            f"Overall Status: {status_emoji[report.overall_status]} {report.overall_status.value.upper()}"
        )
        self.logger.info("")

        # Component details
        self.logger.info("Component Status:")
        for result in report.component_results:
            emoji = status_emoji[result.status]
            self.logger.info(f"  {emoji} {result.component}: {result.message}")

            if self.debug and result.details:
                for key, value in result.details.items():
                    self.logger.debug(f"    {key}: {value}")

        self.logger.info("")

        # Recommendations
        if report.recommendations:
            self.logger.info("Recommendations:")
            for i, rec in enumerate(report.recommendations, 1):
                self.logger.info(f"  {i}. {rec}")
            self.logger.info("")

        # Fallback options
        if report.fallback_options:
            self.logger.info("Fallback Options:")
            for i, option in enumerate(report.fallback_options, 1):
                self.logger.info(f"  {i}. {option}")
            self.logger.info("")

        # Summary
        healthy_count = len(report.healthy_components)
        problem_count = len(report.problematic_components)

        self.logger.info(
            f"Summary: {healthy_count} healthy, {problem_count} with issues"
        )

        if report.can_use_pydivert:
            self.logger.info("✅ PyDivert engine can be used")
        else:
            self.logger.warning("❌ PyDivert engine cannot be used")

        if report.can_use_scapy:
            self.logger.info("✅ Scapy packet building available")
        else:
            self.logger.info("ℹ️ Using raw packet building (Scapy not available)")

        self.logger.info("=" * 60)

    def evaluate_strategy_health(
        self, stats: Dict[str, Any], thresholds: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # Ожидается, что stats содержит ключи: success_count, fail_count, avg_latency_ms
        success = int(stats.get("success_count", 0))
        fail = int(stats.get("fail_count", 0))
        total = success + fail if (success + fail) > 0 else 1
        success_rate = success / total
        avg_latency_ms = float(stats.get("avg_latency_ms", 0.0) or 0.0)

        # Пороговые значения (переопределяются конфигом при наличии)
        failing_sr = float((thresholds or {}).get("failing_success_rate", 0.4))
        degrading_sr = float((thresholds or {}).get("degrading_success_rate", 0.7))
        degrading_latency = float(
            (thresholds or {}).get("degrading_latency_ms", 1500.0)
        )

        status = "healthy"
        reason = None
        recommendation = None

        if success_rate < failing_sr:
            status = "failing"
            reason = "low success rate"
            recommendation = "disable strategy or switch to fallback"
        elif success_rate < degrading_sr or avg_latency_ms > degrading_latency:
            status = "degrading"
            reason = "moderate success or high latency"
            recommendation = "tune parameters or try alternative technique"

        return {
            "status": status,
            "success_rate": success_rate,
            "avg_latency_ms": avg_latency_ms,
            "reason": reason,
            "recommendation": recommendation,
        }


def perform_startup_health_check(debug: bool = False) -> SystemHealthReport:
    """
    Convenience function to perform health check at application startup.

    Args:
        debug: Enable debug logging

    Returns:
        SystemHealthReport with results
    """
    health_checker = EngineHealthCheck(debug=debug)
    report = health_checker.perform_full_health_check()
    health_checker.log_health_report(report)
    return report


if __name__ == "__main__":
    # Run health check when executed directly
    import argparse

    parser = argparse.ArgumentParser(description="Engine Health Check")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    report = perform_startup_health_check(debug=args.debug)

    # Exit with appropriate code
    if report.overall_status == HealthStatus.CRITICAL:
        sys.exit(1)
    elif report.overall_status == HealthStatus.WARNING:
        sys.exit(2)
    else:
        sys.exit(0)
