import platform
import logging
from typing import Set, Dict, Any, Optional

from core.bypass.engine.factory import BypassEngineFactory
from core.bypass.engine.base_engine import EngineConfig
from core.bypass.techniques.primitives import BypassTechniques

class BypassEngine:
    """
    Backward-compatible wrapper that uses the BypassEngineFactory to create
    a platform-specific engine.
    """

    def __init__(self, debug=True, *args, **kwargs):
        """
        Initializes the wrapper and the underlying engine.
        """
        config = EngineConfig(debug=debug)
        self._engine = BypassEngineFactory.create_engine(config)

        if self._engine:
            self.logger = self._engine.logger
            self.logger.info("BypassEngine wrapper initialized.")
        else:
            self.logger = logging.getLogger("BypassEngine")
            self.logger.warning(
                "Pydivert is not supported on this platform or engine creation failed. BypassEngine is disabled."
            )

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None):
        """Delegates the start call to the underlying engine."""
        if not self._engine:
            self.logger.warning("BypassEngine is disabled, cannot start.")
            return None
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

    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict):
        """Delegates the apply_bypass call to the underlying engine."""
        if self._engine:
            self._engine.apply_bypass(packet, w, strategy_task)

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
