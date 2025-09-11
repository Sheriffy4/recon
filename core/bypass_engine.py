import platform
import logging
import threading
from typing import Set, Dict, Any, Optional

# This is the primary, refactored engine implementation
from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.engine.base_engine import EngineConfig

# For backward compatibility, some components might still import these from here
from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.packet.types import TCPSegmentSpec, UDPDatagramSpec
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.sender import PacketSender
from core.bypass.flow.manager import FlowManager
from core.bypass.telemetry.manager import TelemetryManager
from core.bypass.techniques.registry import TechniqueRegistry


class BypassEngine:
    """
    Backward-compatible wrapper for the new WindowsBypassEngine.

    This class maintains the public API of the original BypassEngine for any
    legacy components or tests that might still use it. It delegates all core
    functionality to the new, refactored WindowsBypassEngine.
    """

    def __init__(self, debug=True, *args, **kwargs):
        """
        Initializes the wrapper and the underlying WindowsBypassEngine.

        All arguments are passed directly to the new engine's constructor.
        """
        if platform.system() != "Windows":
            self.logger = logging.getLogger("BypassEngine")
            self.logger.warning(
                "Pydivert is not supported on this platform. BypassEngine is disabled."
            )
            self._engine = None
            return

        # Instantiate the real engine and store it in a private attribute.
        # The tests rely on this attribute being named `_engine`.
        config = EngineConfig(debug=debug)
        self._engine = WindowsBypassEngine(config=config)

        # Expose the logger for convenience, as the old engine did.
        self.logger = self._engine.logger
        self.logger.info("BypassEngine wrapper initialized, using WindowsBypassEngine.")

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None):
        """Delegates the start call to the underlying engine."""
        if not self._engine:
            self.logger.warning("BypassEngine is disabled, cannot start.")
            return None
        # The new engine doesn't accept *args, **kwargs in start, so we are explicit
        return self._engine.start(
            target_ips=target_ips,
            strategy_map=strategy_map,
            reset_telemetry=reset_telemetry,
            strategy_override=strategy_override
        )

    def stop(self):
        """Delegates the stop call to the underlying engine."""
        if self._engine:
            self._engine.stop()

    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        """Delegates the strategy override call to the underlying engine."""
        if self._engine:
            self._engine.set_strategy_override(strategy_task)

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """Delegates the telemetry snapshot call to the underlying engine."""
        if self._engine:
            return self._engine.get_telemetry_snapshot()
        return {}

    # --- Backward Compatibility Properties ---
    # These properties expose internal state from the new components
    # to match the structure of the old, monolithic BypassEngine.

    @property
    def running(self) -> bool:
        """Exposes the running state from the engine."""
        return self._engine.running if self._engine else False

    @running.setter
    def running(self, value: bool):
        """Allows setting the running state, primarily for stopping."""
        if self._engine:
            self._engine.running = value
            if not value:
                self._engine.stop()

    @property
    def stats(self) -> Dict[str, int]:
        """
        Exposes high-level stats from the WindowsBypassEngine.
        This attribute is maintained for backward compatibility.
        """
        if self._engine:
            return self._engine.stats
        return {}

    @property
    def _exec_handlers(self) -> Dict:
        """
        Exposes execution handlers from the TechniqueRegistry.
        This was a private attribute accessed by some tests.
        """
        if self._engine:
            return self._engine.technique_registry._exec_handlers
        return {}

    @property
    def current_params(self) -> Dict[str, Any]:
        """Exposes current_params from the underlying engine for tests."""
        if self._engine:
            return self._engine.current_params
        return {}

    @property
    def _telemetry(self) -> Dict[str, Any]:
        """Exposes the internal _data dictionary from the TelemetryManager for tests."""
        if self._engine and hasattr(self._engine, 'telemetry') and hasattr(self._engine.telemetry, '_data'):
            return self._engine.telemetry._data
        return {}

    @property
    def _tlock(self) -> Optional[threading.Lock]:
        """Exposes the internal lock from the TelemetryManager for tests."""
        if self._engine and hasattr(self._engine, 'telemetry') and hasattr(self._engine.telemetry, '_lock'):
            return self._engine.telemetry._lock
        return None

    @property
    def flow_table(self) -> Dict:
        """Exposes the internal _flows dictionary from the FlowManager for tests."""
        if self._engine and hasattr(self._engine, 'flow_manager') and hasattr(self._engine.flow_manager, '_flows'):
            return self._engine.flow_manager._flows
        return {}
