"""
Capability detection for different operation modes.
"""

import logging
import platform
import sys
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

try:
    from core.bypass.modes.exceptions import CapabilityDetectionError
except ImportError:
    pass
LOG = logging.getLogger(__name__)


class CapabilityLevel(Enum):
    """Levels of capability support."""

    FULL = "full"
    PARTIAL = "partial"
    EMULATED = "emulated"
    UNAVAILABLE = "unavailable"


@dataclass
class CapabilityInfo:
    """Information about a specific capability."""

    level: CapabilityLevel
    reason: str
    details: Dict[str, Any]
    requirements_met: bool = False
    fallback_available: bool = False


class CapabilityDetector:
    """
    Detects system capabilities for different operation modes.

    This class determines what bypass engine modes are available on the current
    system and provides detailed information about their capabilities.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._capabilities_cache: Optional[Dict[str, CapabilityInfo]] = None
        self._system_info = self._gather_system_info()

    def detect_all_capabilities(self) -> Dict[str, CapabilityInfo]:
        """
        Detect all available capabilities.

        Returns:
            Dictionary mapping capability names to CapabilityInfo objects
        """
        if self._capabilities_cache is not None:
            return self._capabilities_cache
        self.logger.info("Starting comprehensive capability detection...")
        capabilities = {
            "pydivert": self._detect_pydivert_capability(),
            "scapy": self._detect_scapy_capability(),
            "netfilter": self._detect_netfilter_capability(),
            "raw_sockets": self._detect_raw_sockets_capability(),
            "admin_privileges": self._detect_admin_privileges(),
            "windivert_driver": self._detect_windivert_driver(),
        }
        self._capabilities_cache = capabilities
        self.logger.info(
            f"Capability detection complete. Found {len(capabilities)} capabilities."
        )
        return capabilities

    def is_native_mode_available(self) -> bool:
        """
        Check if native mode is available.

        Returns:
            True if native mode can be used
        """
        capabilities = self.detect_all_capabilities()
        if self._system_info["platform"] == "Windows":
            pydivert_cap = capabilities.get("pydivert")
            admin_cap = capabilities.get("admin_privileges")
            driver_cap = capabilities.get("windivert_driver")
            return (
                pydivert_cap
                and pydivert_cap.level
                in [CapabilityLevel.FULL, CapabilityLevel.PARTIAL]
                and admin_cap
                and admin_cap.requirements_met
                and driver_cap
                and (driver_cap.level != CapabilityLevel.UNAVAILABLE)
            )
        elif self._system_info["platform"] == "Linux":
            netfilter_cap = capabilities.get("netfilter")
            raw_sockets_cap = capabilities.get("raw_sockets")
            admin_cap = capabilities.get("admin_privileges")
            return (
                admin_cap
                and admin_cap.requirements_met
                and (
                    netfilter_cap
                    and netfilter_cap.level != CapabilityLevel.UNAVAILABLE
                    or (
                        raw_sockets_cap
                        and raw_sockets_cap.level != CapabilityLevel.UNAVAILABLE
                    )
                )
            )
        return False

    def is_emulated_mode_available(self) -> bool:
        """
        Check if emulated mode is available.

        Returns:
            True if emulated mode can be used
        """
        capabilities = self.detect_all_capabilities()
        scapy_cap = capabilities.get("scapy")
        return scapy_cap and scapy_cap.level != CapabilityLevel.UNAVAILABLE

    def get_recommended_mode(self) -> str:
        """
        Get the recommended operation mode based on capabilities.

        Returns:
            Recommended mode name
        """
        if self.is_native_mode_available():
            return "native"
        elif self.is_emulated_mode_available():
            return "emulated"
        else:
            return "compatibility"

    def _gather_system_info(self) -> Dict[str, Any]:
        """Gather basic system information."""
        return {
            "platform": platform.system(),
            "architecture": platform.architecture()[0],
            "python_version": sys.version_info,
            "is_admin": self._check_admin_privileges(),
        }

    def _detect_pydivert_capability(self) -> CapabilityInfo:
        """Detect PyDivert capability."""
        try:
            import pydivert

            try:
                test_handle = pydivert.WinDivert("false")
                test_handle.close()
                return CapabilityInfo(
                    level=CapabilityLevel.FULL,
                    reason="PyDivert available with full functionality",
                    details={
                        "version": getattr(pydivert, "__version__", "unknown"),
                        "driver_loaded": True,
                    },
                    requirements_met=True,
                    fallback_available=True,
                )
            except Exception as e:
                return CapabilityInfo(
                    level=CapabilityLevel.PARTIAL,
                    reason=f"PyDivert available but cannot create handle: {e}",
                    details={
                        "version": getattr(pydivert, "__version__", "unknown"),
                        "driver_loaded": False,
                        "error": str(e),
                    },
                    requirements_met=False,
                    fallback_available=True,
                )
        except ImportError as e:
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason=f"PyDivert not installed: {e}",
                details={"import_error": str(e)},
                requirements_met=False,
                fallback_available=True,
            )

    def _detect_scapy_capability(self) -> CapabilityInfo:
        """Detect Scapy capability."""
        try:
            import scapy
            from scapy.all import conf

            try:
                iface = conf.iface
                return CapabilityInfo(
                    level=CapabilityLevel.FULL,
                    reason="Scapy available with full functionality",
                    details={
                        "version": getattr(scapy, "__version__", "unknown"),
                        "default_interface": iface,
                        "can_sniff": True,
                    },
                    requirements_met=True,
                    fallback_available=False,
                )
            except Exception as e:
                return CapabilityInfo(
                    level=CapabilityLevel.PARTIAL,
                    reason=f"Scapy available but limited functionality: {e}",
                    details={
                        "version": getattr(scapy, "__version__", "unknown"),
                        "error": str(e),
                    },
                    requirements_met=False,
                    fallback_available=False,
                )
        except ImportError as e:
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason=f"Scapy not installed: {e}",
                details={"import_error": str(e)},
                requirements_met=False,
                fallback_available=False,
            )

    def _detect_netfilter_capability(self) -> CapabilityInfo:
        """Detect Linux netfilter capability."""
        if self._system_info["platform"] != "Linux":
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason="Netfilter only available on Linux",
                details={"platform": self._system_info["platform"]},
                requirements_met=False,
                fallback_available=True,
            )
        try:
            import netfilterqueue

            return CapabilityInfo(
                level=CapabilityLevel.FULL,
                reason="Netfilter available",
                details={"netfilterqueue_available": True, "requires_root": True},
                requirements_met=self._system_info["is_admin"],
                fallback_available=True,
            )
        except ImportError:
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason="netfilterqueue not installed",
                details={"requires_install": "python3-netfilterqueue"},
                requirements_met=False,
                fallback_available=True,
            )

    def _detect_raw_sockets_capability(self) -> CapabilityInfo:
        """Detect raw sockets capability."""
        try:
            import socket

            try:
                if self._system_info["platform"] == "Windows":
                    sock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                    )
                    sock.close()
                    return CapabilityInfo(
                        level=CapabilityLevel.PARTIAL,
                        reason="Raw sockets available with Windows limitations",
                        details={"platform_limitations": True, "requires_admin": True},
                        requirements_met=self._system_info["is_admin"],
                        fallback_available=True,
                    )
                else:
                    sock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                    )
                    sock.close()
                    return CapabilityInfo(
                        level=CapabilityLevel.FULL,
                        reason="Raw sockets fully available",
                        details={"requires_root": True},
                        requirements_met=self._system_info["is_admin"],
                        fallback_available=True,
                    )
            except (OSError, PermissionError) as e:
                return CapabilityInfo(
                    level=CapabilityLevel.UNAVAILABLE,
                    reason=f"Cannot create raw socket: {e}",
                    details={"error": str(e), "requires_admin": True},
                    requirements_met=False,
                    fallback_available=True,
                )
        except Exception as e:
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason=f"Raw sockets not available: {e}",
                details={"error": str(e)},
                requirements_met=False,
                fallback_available=True,
            )

    def _detect_admin_privileges(self) -> CapabilityInfo:
        """Detect administrative privileges."""
        is_admin = self._check_admin_privileges()
        return CapabilityInfo(
            level=CapabilityLevel.FULL if is_admin else CapabilityLevel.UNAVAILABLE,
            reason=(
                "Administrator privileges detected"
                if is_admin
                else "Administrator privileges required"
            ),
            details={"is_admin": is_admin, "platform": self._system_info["platform"]},
            requirements_met=is_admin,
            fallback_available=False,
        )

    def _detect_windivert_driver(self) -> CapabilityInfo:
        """Detect WinDivert driver availability."""
        if self._system_info["platform"] != "Windows":
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason="WinDivert only available on Windows",
                details={"platform": self._system_info["platform"]},
                requirements_met=False,
                fallback_available=True,
            )
        try:
            import os

            possible_paths = [
                "WinDivert.dll",
                "WinDivert64.sys",
                "./WinDivert.dll",
                "./WinDivert64.sys",
            ]
            found_files = []
            for path in possible_paths:
                if os.path.exists(path):
                    found_files.append(path)
            if found_files:
                return CapabilityInfo(
                    level=CapabilityLevel.FULL,
                    reason="WinDivert driver files found",
                    details={"found_files": found_files, "driver_loadable": True},
                    requirements_met=True,
                    fallback_available=True,
                )
            else:
                return CapabilityInfo(
                    level=CapabilityLevel.UNAVAILABLE,
                    reason="WinDivert driver files not found",
                    details={
                        "searched_paths": possible_paths,
                        "found_files": found_files,
                    },
                    requirements_met=False,
                    fallback_available=True,
                )
        except Exception as e:
            return CapabilityInfo(
                level=CapabilityLevel.UNAVAILABLE,
                reason=f"Error checking WinDivert driver: {e}",
                details={"error": str(e)},
                requirements_met=False,
                fallback_available=True,
            )

    def _check_admin_privileges(self) -> bool:
        """Check if running with administrative privileges."""
        try:
            if self._system_info["platform"] == "Windows":
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                import os

                return os.geteuid() == 0
        except Exception:
            return False

    def get_capability_report(self) -> str:
        """
        Generate a human-readable capability report.

        Returns:
            Formatted capability report
        """
        capabilities = self.detect_all_capabilities()
        report = ["=== Bypass Engine Capability Report ===\n"]
        report.append(
            f"Platform: {self._system_info['platform']} ({self._system_info['architecture']})"
        )
        report.append(
            f"Python: {'.'.join(map(str, self._system_info['python_version'][:3]))}"
        )
        report.append(
            f"Admin Privileges: {('Yes' if self._system_info['is_admin'] else 'No')}"
        )
        report.append("")
        report.append("Capabilities:")
        for name, info in capabilities.items():
            status = info.level.value.upper()
            report.append(f"  {name:20} [{status:12}] {info.reason}")
            if info.details:
                for key, value in info.details.items():
                    report.append(f"    {key}: {value}")
        report.append("")
        report.append("Recommended Modes:")
        report.append(
            f"  Native Mode:    {('Available' if self.is_native_mode_available() else 'Not Available')}"
        )
        report.append(
            f"  Emulated Mode:  {('Available' if self.is_emulated_mode_available() else 'Not Available')}"
        )
        report.append(f"  Recommended:    {self.get_recommended_mode()}")
        return "\n".join(report)
