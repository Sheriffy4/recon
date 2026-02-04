"""
Main mode controller for managing operation modes.
"""

import logging
import time
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum

try:
    from core.bypass.modes.capability_detector import (
        CapabilityDetector,
        CapabilityLevel,
    )
    from core.bypass.modes.mode_transition import ModeTransitionManager
    from core.bypass.modes.exceptions import (
        ModeError,
        ModeTransitionError,
        UnsupportedModeError,
    )
except ImportError:
    from capability_detector import CapabilityDetector, CapabilityLevel
    from mode_transition import ModeTransitionManager
    from exceptions import ModeTransitionError, UnsupportedModeError
LOG = logging.getLogger(__name__)


class OperationMode(Enum):
    """Available operation modes for the bypass engine."""

    NATIVE = "native"
    EMULATED = "emulated"
    HYBRID = "hybrid"
    COMPATIBILITY = "compat"
    AUTO = "auto"


@dataclass
class ModeInfo:
    """Information about an operation mode."""

    mode: OperationMode
    available: bool
    description: str
    capabilities: Dict[str, Any]
    performance_level: str
    stability_level: str
    requirements: Dict[str, Any]


class ModeController:
    """
    Central controller for managing bypass engine operation modes.

    This class provides the main interface for:
    - Detecting available modes
    - Switching between modes safely
    - Handling mode failures with automatic fallback
    - Monitoring mode health and performance
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capability_detector = CapabilityDetector()
        self.transition_manager = ModeTransitionManager(self.capability_detector)
        self.current_mode = OperationMode.AUTO
        self.fallback_mode = OperationMode.COMPATIBILITY
        self.mode_capabilities: Dict[OperationMode, ModeInfo] = {}
        self.mode_health_checks: Dict[OperationMode, Callable] = {}
        self.mode_failure_counts: Dict[OperationMode, int] = {}
        self.last_health_check: Dict[OperationMode, float] = {}
        self._initialize_mode_info()
        self._register_default_handlers()
        self.logger.info("ModeController initialized")

    def get_current_mode(self) -> OperationMode:
        """
        Get the current operation mode.

        Returns:
            Current operation mode
        """
        return self.current_mode

    def get_available_modes(self) -> Dict[OperationMode, ModeInfo]:
        """
        Get information about all available modes.

        Returns:
            Dictionary mapping modes to their information
        """
        return {mode: info for mode, info in self.mode_capabilities.items() if info.available}

    def is_mode_available(self, mode: OperationMode) -> bool:
        """
        Check if a specific mode is available.

        Args:
            mode: Mode to check

        Returns:
            True if mode is available
        """
        mode_info = self.mode_capabilities.get(mode)
        return mode_info is not None and mode_info.available

    def switch_mode(
        self,
        target_mode: OperationMode,
        reason: str = "Manual switch",
        force: bool = False,
    ) -> bool:
        """
        Switch to a different operation mode.

        Args:
            target_mode: Mode to switch to
            reason: Reason for the switch
            force: Force switch even if mode appears unavailable

        Returns:
            True if switch was successful

        Raises:
            UnsupportedModeError: If target mode is not supported
            ModeTransitionError: If transition fails
        """
        if target_mode == OperationMode.AUTO:
            return self._auto_select_mode(reason)
        if not force and (not self.is_mode_available(target_mode)):
            raise UnsupportedModeError(f"Mode {target_mode.value} is not available")
        if target_mode == self.current_mode:
            self.logger.info(f"Already in {target_mode.value} mode")
            return True
        self.logger.info(
            f"Switching from {self.current_mode.value} to {target_mode.value}: {reason}"
        )
        try:
            success = self.transition_manager.transition_to_mode(
                target_mode.value, self.current_mode.value, reason
            )
            if success:
                old_mode = self.current_mode
                self.current_mode = target_mode
                self.logger.info(f"Successfully switched to {target_mode.value} mode")
                self.mode_failure_counts[target_mode] = 0
                return True
            else:
                self.logger.error(f"Failed to switch to {target_mode.value} mode")
                return False
        except Exception as e:
            self.logger.error(f"Mode switch failed: {e}")
            raise ModeTransitionError(self.current_mode.value, target_mode.value, str(e))

    def auto_fallback(self, error: Exception) -> bool:
        """
        Automatically fallback to a working mode when current mode fails.

        Args:
            error: Error that triggered the fallback

        Returns:
            True if fallback was successful
        """
        self.logger.warning(f"Auto-fallback triggered from {self.current_mode.value}: {error}")
        self.mode_failure_counts[self.current_mode] = (
            self.mode_failure_counts.get(self.current_mode, 0) + 1
        )
        new_mode = self.transition_manager.auto_fallback(
            self.current_mode.value,
            error,
            {"failure_count": self.mode_failure_counts[self.current_mode]},
        )
        if new_mode:
            try:
                self.current_mode = OperationMode(new_mode)
                self.logger.info(f"Auto-fallback successful, now in {new_mode} mode")
                return True
            except ValueError:
                self.logger.error(f"Invalid mode returned from fallback: {new_mode}")
                return False
        else:
            self.logger.error("Auto-fallback failed, no suitable mode available")
            return False

    def get_mode_info(self, mode: Optional[OperationMode] = None) -> Dict[str, Any]:
        """
        Get detailed information about a mode or current mode.

        Args:
            mode: Mode to get info for, or None for current mode

        Returns:
            Mode information dictionary
        """
        target_mode = mode or self.current_mode
        mode_info = self.mode_capabilities.get(target_mode)
        if not mode_info:
            return {"error": f"Mode {target_mode.value} not found"}
        return {
            "mode": target_mode.value,
            "available": mode_info.available,
            "description": mode_info.description,
            "capabilities": mode_info.capabilities,
            "performance_level": mode_info.performance_level,
            "stability_level": mode_info.stability_level,
            "requirements": mode_info.requirements,
            "failure_count": self.mode_failure_counts.get(target_mode, 0),
            "last_health_check": self.last_health_check.get(target_mode),
            "is_current": target_mode == self.current_mode,
        }

    def check_mode_health(self, mode: Optional[OperationMode] = None) -> bool:
        """
        Check the health of a specific mode or current mode.

        Args:
            mode: Mode to check, or None for current mode

        Returns:
            True if mode is healthy
        """
        target_mode = mode or self.current_mode
        health_checker = self.mode_health_checks.get(target_mode)
        if not health_checker:
            return True
        try:
            is_healthy = health_checker()
            self.last_health_check[target_mode] = time.time()
            if not is_healthy:
                self.logger.warning(f"Mode {target_mode.value} failed health check")
            return is_healthy
        except Exception as e:
            self.logger.error(f"Health check failed for {target_mode.value}: {e}")
            return False

    def register_health_check(self, mode: OperationMode, checker: Callable[[], bool]) -> None:
        """
        Register a health check function for a mode.

        Args:
            mode: Mode to register checker for
            checker: Function that returns True if mode is healthy
        """
        self.mode_health_checks[mode] = checker
        self.logger.debug(f"Registered health check for {mode.value} mode")

    def get_capability_report(self) -> str:
        """
        Get a comprehensive capability and mode report.

        Returns:
            Formatted report string
        """
        report = [self.capability_detector.get_capability_report()]
        report.append("\n=== Mode Information ===")
        for mode, info in self.mode_capabilities.items():
            status = "AVAILABLE" if info.available else "UNAVAILABLE"
            current = " (CURRENT)" if mode == self.current_mode else ""
            report.append(f"\n{mode.value.upper()}{current}:")
            report.append(f"  Status: {status}")
            report.append(f"  Description: {info.description}")
            report.append(f"  Performance: {info.performance_level}")
            report.append(f"  Stability: {info.stability_level}")
            if info.requirements:
                report.append("  Requirements:")
                for req, value in info.requirements.items():
                    report.append(f"    {req}: {value}")
            failure_count = self.mode_failure_counts.get(mode, 0)
            if failure_count > 0:
                report.append(f"  Failures: {failure_count}")
        return "\n".join(report)

    def _initialize_mode_info(self) -> None:
        """Initialize information about all operation modes."""
        capabilities = self.capability_detector.detect_all_capabilities()
        native_available = self.capability_detector.is_native_mode_available()
        self.mode_capabilities[OperationMode.NATIVE] = ModeInfo(
            mode=OperationMode.NATIVE,
            available=native_available,
            description="Direct packet interception using native OS capabilities",
            capabilities={
                "packet_modification": True,
                "real_time_processing": True,
                "low_latency": True,
                "requires_admin": True,
            },
            performance_level="high",
            stability_level="stable",
            requirements={
                "admin_privileges": True,
                "native_driver": True,
                "platform_specific": True,
            },
        )
        emulated_available = self.capability_detector.is_emulated_mode_available()
        self.mode_capabilities[OperationMode.EMULATED] = ModeInfo(
            mode=OperationMode.EMULATED,
            available=emulated_available,
            description="Packet processing using Scapy emulation",
            capabilities={
                "packet_modification": True,
                "real_time_processing": False,
                "low_latency": False,
                "requires_admin": False,
            },
            performance_level="medium",
            stability_level="stable",
            requirements={"scapy_library": True, "python_environment": True},
        )
        hybrid_available = native_available and emulated_available
        self.mode_capabilities[OperationMode.HYBRID] = ModeInfo(
            mode=OperationMode.HYBRID,
            available=hybrid_available,
            description="Combination of native and emulated processing",
            capabilities={
                "packet_modification": True,
                "real_time_processing": True,
                "low_latency": True,
                "fallback_support": True,
                "requires_admin": True,
            },
            performance_level="high",
            stability_level="beta",
            requirements={"native_and_emulated": True, "admin_privileges": True},
        )
        self.mode_capabilities[OperationMode.COMPATIBILITY] = ModeInfo(
            mode=OperationMode.COMPATIBILITY,
            available=True,
            description="Maximum compatibility mode with limited functionality",
            capabilities={
                "packet_modification": False,
                "real_time_processing": False,
                "low_latency": False,
                "basic_functionality": True,
            },
            performance_level="low",
            stability_level="stable",
            requirements={},
        )
        self.mode_capabilities[OperationMode.AUTO] = ModeInfo(
            mode=OperationMode.AUTO,
            available=True,
            description="Automatic mode selection based on capabilities",
            capabilities={"adaptive_selection": True, "automatic_fallback": True},
            performance_level="variable",
            stability_level="stable",
            requirements={},
        )

    def _auto_select_mode(self, reason: str = "Auto-selection") -> bool:
        """Automatically select the best available mode."""
        recommended_mode = self.capability_detector.get_recommended_mode()
        try:
            target_mode = OperationMode(recommended_mode)
            return self.switch_mode(target_mode, f"Auto-selected: {reason}")
        except ValueError:
            self.logger.error(f"Invalid recommended mode: {recommended_mode}")
            return self.switch_mode(OperationMode.COMPATIBILITY, "Fallback to compatibility")

    def _register_default_handlers(self) -> None:
        """Register default transition and validation handlers."""
        self.transition_manager.register_rollback_handler("native", self._rollback_native_mode)
        self.transition_manager.register_rollback_handler("emulated", self._rollback_emulated_mode)
        self.transition_manager.register_validation_handler("native", self._validate_native_mode)
        self.transition_manager.register_validation_handler(
            "emulated", self._validate_emulated_mode
        )

    def _rollback_native_mode(self, rollback_data: Optional[Dict[str, Any]] = None) -> None:
        """Rollback handler for native mode."""
        self.logger.info("Rolling back native mode")

    def _rollback_emulated_mode(self, rollback_data: Optional[Dict[str, Any]] = None) -> None:
        """Rollback handler for emulated mode."""
        self.logger.info("Rolling back emulated mode")

    def _validate_native_mode(self) -> bool:
        """Validation handler for native mode."""
        try:
            capabilities = self.capability_detector.detect_all_capabilities()
            pydivert_cap = capabilities.get("pydivert")
            return pydivert_cap and pydivert_cap.level in [
                CapabilityLevel.FULL,
                CapabilityLevel.PARTIAL,
            ]
        except Exception as e:
            self.logger.error(f"Native mode validation failed: {e}")
            return False

    def _validate_emulated_mode(self) -> bool:
        """Validation handler for emulated mode."""
        try:
            capabilities = self.capability_detector.detect_all_capabilities()
            scapy_cap = capabilities.get("scapy")
            return scapy_cap and scapy_cap.level in [
                CapabilityLevel.FULL,
                CapabilityLevel.PARTIAL,
            ]
        except Exception as e:
            self.logger.error(f"Emulated mode validation failed: {e}")
            return False
