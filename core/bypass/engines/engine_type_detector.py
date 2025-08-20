# recon/core/bypass/engines/engine_type_detector.py
"""
Engine Type Detection Service for automatic engine type detection and validation.
"""

from typing import List, Dict, Optional
import platform
import logging
import subprocess
import sys
import os
from dataclasses import dataclass, field

from .base import EngineType


LOG = logging.getLogger("EngineTypeDetector")


@dataclass
class SystemCapabilities:
    """System capabilities assessment result."""

    platform: str
    is_windows: bool
    is_linux: bool
    is_admin: bool
    python_version: str
    available_packages: Dict[str, bool] = field(default_factory=dict)
    network_interfaces: List[str] = field(default_factory=list)
    permissions: Dict[str, bool] = field(default_factory=dict)


@dataclass
class EngineDetectionResult:
    """Result of engine detection and validation."""

    engine_type: EngineType
    available: bool
    score: int  # Higher score = better choice
    dependencies_met: bool
    missing_dependencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    installation_hints: List[str] = field(default_factory=list)


class EngineTypeDetector:
    """
    Service for automatic engine type detection and system capability assessment.

    This service provides:
    - Automatic detection of available engine types
    - Dependency checking for each engine type
    - System capability assessment
    - Recommendation of best engine type
    - Installation hints for missing dependencies
    """

    def __init__(self):
        self.logger = LOG
        self._system_capabilities: Optional[SystemCapabilities] = None
        self._detection_cache: Dict[EngineType, EngineDetectionResult] = {}

    def detect_available_engines(self) -> List[EngineType]:
        """
        Detect all available engine types on the current system.

        Returns:
            List of available engine types, sorted by preference
        """
        available_engines = []

        for engine_type in EngineType:
            if self.check_engine_dependencies(engine_type):
                available_engines.append(engine_type)

        # Sort by preference (score)
        detection_results = [self._get_detection_result(et) for et in available_engines]
        detection_results.sort(key=lambda x: x.score, reverse=True)

        return [result.engine_type for result in detection_results]

    def check_engine_dependencies(self, engine_type: EngineType) -> bool:
        """
        Check if all dependencies for a specific engine type are met.

        Args:
            engine_type: Engine type to check

        Returns:
            True if all dependencies are met
        """
        result = self._get_detection_result(engine_type)
        return result.dependencies_met

    def get_recommended_engine(self) -> EngineType:
        """
        Get the recommended engine type for the current system.

        Returns:
            Best available engine type
        """
        available = self.detect_available_engines()

        if not available:
            # Fallback to external tool as it has the least requirements
            self.logger.warning(
                "No engines with all dependencies available, falling back to EXTERNAL_TOOL"
            )
            return EngineType.EXTERNAL_TOOL

        recommended = available[0]
        self.logger.info(f"Recommended engine: {recommended.value}")
        return recommended

    def check_system_capabilities(self) -> SystemCapabilities:
        """
        Perform comprehensive system capability assessment.

        Returns:
            System capabilities information
        """
        if self._system_capabilities is None:
            self._system_capabilities = self._assess_system_capabilities()

        return self._system_capabilities

    def get_detection_details(self, engine_type: EngineType) -> EngineDetectionResult:
        """
        Get detailed detection results for a specific engine type.

        Args:
            engine_type: Engine type to analyze

        Returns:
            Detailed detection result
        """
        return self._get_detection_result(engine_type)

    def get_all_detection_results(self) -> Dict[EngineType, EngineDetectionResult]:
        """
        Get detection results for all engine types.

        Returns:
            Dictionary mapping engine types to detection results
        """
        results = {}
        for engine_type in EngineType:
            results[engine_type] = self._get_detection_result(engine_type)

        return results

    def get_installation_recommendations(self) -> Dict[EngineType, List[str]]:
        """
        Get installation recommendations for engines with missing dependencies.

        Returns:
            Dictionary mapping engine types to installation hints
        """
        recommendations = {}

        for engine_type in EngineType:
            result = self._get_detection_result(engine_type)
            if not result.dependencies_met and result.installation_hints:
                recommendations[engine_type] = result.installation_hints

        return recommendations

    def _get_detection_result(self, engine_type: EngineType) -> EngineDetectionResult:
        """Get or compute detection result for an engine type."""
        if engine_type not in self._detection_cache:
            self._detection_cache[engine_type] = self._detect_engine_type(engine_type)

        return self._detection_cache[engine_type]

    def _detect_engine_type(self, engine_type: EngineType) -> EngineDetectionResult:
        """Detect and validate a specific engine type."""
        if engine_type == EngineType.NATIVE_PYDIVERT:
            return self._detect_pydivert_engine()
        elif engine_type == EngineType.EXTERNAL_TOOL:
            return self._detect_external_tool_engine()
        elif engine_type == EngineType.NATIVE_NETFILTER:
            return self._detect_netfilter_engine()
        else:
            return EngineDetectionResult(
                engine_type=engine_type,
                available=False,
                score=0,
                dependencies_met=False,
                missing_dependencies=["Unknown engine type"],
                warnings=["Unknown engine type"],
            )

    def _detect_pydivert_engine(self) -> EngineDetectionResult:
        """Detect PyDivert engine availability."""
        result = EngineDetectionResult(
            engine_type=EngineType.NATIVE_PYDIVERT,
            available=False,
            score=100,  # Highest score for best performance
            dependencies_met=False,
        )

        # Check platform
        if not platform.system() == "Windows":
            result.missing_dependencies.append("Windows platform")
            result.warnings.append("PyDivert only works on Windows")
            result.installation_hints.append(
                "PyDivert requires Windows operating system"
            )
            return result

        # Check PyDivert availability
        try:
            import pydivert

            result.missing_dependencies = []
            self.logger.debug("PyDivert package is available")
        except ImportError:
            result.missing_dependencies.append("pydivert package")
            result.installation_hints.append("Install PyDivert: pip install pydivert")
            result.warnings.append("PyDivert package not installed")

        # Check administrator privileges
        capabilities = self.check_system_capabilities()
        if not capabilities.is_admin:
            result.missing_dependencies.append("administrator privileges")
            result.warnings.append("PyDivert requires administrator privileges")
            result.installation_hints.append(
                "Run as administrator or with elevated privileges"
            )

        # Check WinDivert driver (basic check)
        if self._check_windivert_driver():
            self.logger.debug("WinDivert driver appears to be available")
        else:
            result.warnings.append("WinDivert driver status unclear")
            result.installation_hints.append(
                "Ensure WinDivert driver is properly installed"
            )

        result.dependencies_met = len(result.missing_dependencies) == 0
        result.available = result.dependencies_met

        return result

    def _detect_external_tool_engine(self) -> EngineDetectionResult:
        """Detect external tool engine availability."""
        result = EngineDetectionResult(
            engine_type=EngineType.EXTERNAL_TOOL,
            available=True,  # Generally available
            score=50,  # Medium score
            dependencies_met=True,
            missing_dependencies=[],
        )

        # Check for common external tools
        tools_found = []

        # Check for zapret (common DPI bypass tool)
        if self._check_external_tool("zapret"):
            tools_found.append("zapret")

        # Check for other tools if needed
        # This can be extended to check for other external tools

        if not tools_found:
            result.warnings.append(
                "No specific external tools detected, but engine should work with any compatible tool"
            )
            result.installation_hints.append(
                "Consider installing zapret or other DPI bypass tools"
            )
        else:
            result.warnings.append(f"Found external tools: {', '.join(tools_found)}")

        return result

    def _detect_netfilter_engine(self) -> EngineDetectionResult:
        """Detect Netfilter engine availability."""
        result = EngineDetectionResult(
            engine_type=EngineType.NATIVE_NETFILTER,
            available=False,
            score=80,  # High score for Linux
            dependencies_met=False,
        )

        # Check platform
        if not platform.system() == "Linux":
            result.missing_dependencies.append("Linux platform")
            result.warnings.append("Netfilter only works on Linux")
            result.installation_hints.append(
                "Netfilter requires Linux operating system"
            )
            return result

        # Check for netfilter support (basic check)
        if self._check_netfilter_support():
            result.warnings.append(
                "Netfilter support detected but engine not implemented yet"
            )
            result.missing_dependencies.append("netfilter engine implementation")
            result.installation_hints.append("Netfilter engine is not yet implemented")
        else:
            result.missing_dependencies.extend(
                ["netfilter support", "netfilter engine implementation"]
            )
            result.warnings.append("Netfilter support not detected")
            result.installation_hints.extend(
                [
                    "Ensure netfilter is available on your Linux system",
                    "Netfilter engine is not yet implemented",
                ]
            )

        return result

    def _assess_system_capabilities(self) -> SystemCapabilities:
        """Assess comprehensive system capabilities."""
        capabilities = SystemCapabilities(
            platform=platform.system(),
            is_windows=platform.system() == "Windows",
            is_linux=platform.system() == "Linux",
            is_admin=self._check_admin_privileges(),
            python_version=sys.version,
        )

        # Check available packages
        capabilities.available_packages = {
            "pydivert": self._check_package_availability("pydivert"),
            "scapy": self._check_package_availability("scapy"),
            "netfilterqueue": self._check_package_availability("netfilterqueue"),
        }

        # Check network interfaces (basic check)
        capabilities.network_interfaces = self._get_network_interfaces()

        # Check permissions - avoid recursion by using direct admin check
        capabilities.permissions = {
            "admin": capabilities.is_admin,
            "network": capabilities.is_admin,  # Simplified to avoid recursion
        }

        return capabilities

    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            if platform.system() == "Windows":
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def _check_package_availability(self, package_name: str) -> bool:
        """Check if a Python package is available."""
        try:
            __import__(package_name)
            return True
        except ImportError:
            return False

    def _check_windivert_driver(self) -> bool:
        """Check if WinDivert driver is available (basic check)."""
        if not platform.system() == "Windows":
            return False

        try:
            # Try to import and do a basic check

            # This is a basic check - actual driver status would need more detailed testing
            return True
        except Exception:
            return False

    def _check_external_tool(self, tool_name: str) -> bool:
        """Check if an external tool is available."""
        try:
            # Try to find the tool in PATH
            result = subprocess.run(
                ["where" if platform.system() == "Windows" else "which", tool_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_netfilter_support(self) -> bool:
        """Check if netfilter support is available on Linux."""
        if not platform.system() == "Linux":
            return False

        try:
            # Check for netfilter kernel modules
            with open("/proc/modules", "r") as f:
                modules = f.read()
                return "netfilter" in modules or "iptables" in modules
        except Exception:
            return False

    def _get_network_interfaces(self) -> List[str]:
        """Get list of network interfaces (basic implementation)."""
        interfaces = []

        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    # Basic parsing - could be improved
                    lines = result.stdout.split("\n")
                    for line in lines:
                        if "adapter" in line.lower():
                            interfaces.append(line.strip())
            else:
                result = subprocess.run(
                    ["ip", "link", "show"], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    # Basic parsing - could be improved
                    lines = result.stdout.split("\n")
                    for line in lines:
                        if ": " in line and "state" in line.lower():
                            interface = line.split(":")[1].strip().split("@")[0]
                            interfaces.append(interface)
        except Exception as e:
            self.logger.debug(f"Failed to get network interfaces: {e}")

        return interfaces

    def _check_network_permissions(self) -> bool:
        """Check if we have network-level permissions."""
        # This is a basic check - could be more sophisticated
        return self._check_admin_privileges()

    def clear_cache(self):
        """Clear the detection cache to force re-detection."""
        self._detection_cache.clear()
        self._system_capabilities = None
        self.logger.debug("Detection cache cleared")


# Global instance for easy access
_detector = EngineTypeDetector()


def get_engine_type_detector() -> EngineTypeDetector:
    """Get the global engine type detector instance."""
    return _detector


def detect_available_engines() -> List[EngineType]:
    """Convenience function to detect available engines."""
    return _detector.detect_available_engines()


def get_recommended_engine() -> EngineType:
    """Convenience function to get recommended engine."""
    return _detector.get_recommended_engine()


def check_engine_dependencies(engine_type: EngineType) -> bool:
    """Convenience function to check engine dependencies."""
    return _detector.check_engine_dependencies(engine_type)
