import platform
import logging
import threading
from typing import Dict, Any, Optional, Set

# Import new components
from core.bypass.telemetry.manager import TelemetryManager
from core.bypass.flow.manager import FlowManager
from core.bypass.techniques.registry import TechniqueRegistry
from core.bypass.engine.windows_engine import WindowsBypassEngine

# Keep original imports for compatibility shims if needed
from core.bypass.techniques.primitives import BypassTechniques

if platform.system() == "Windows":

    class BypassEngine:
        """
        Backward-compatible wrapper around WindowsBypassEngine.
        Maintains all original public APIs while using new components internally.
        """

        def __init__(self, debug=True, *args, **kwargs):
            self._engine = WindowsBypassEngine(debug=debug)

            # Expose components for backward compatibility
            self.debug = debug
            self.logger = self._engine.logger
            self.running = self._engine.running

            # Legacy attributes that are now managed by components
            self.stats = self._engine.stats
            self.current_params = self._engine.current_params

            # Direct access to component internals for deep compatibility
            self._telemetry = self._engine.telemetry._data
            self._tlock = self._engine.telemetry._lock

            # Shims for flow management attributes
            self.flow_table = self._engine.flow_manager._flows
            self._active_flows = self._engine.flow_manager._active_flows
            self._inbound_events = self._engine.flow_manager._events
            self._inbound_results = self._engine.flow_manager._results

            # Keep original techniques reference
            self.techniques = BypassTechniques()

            # Controllers and strategy
            self.controller = None # Controller logic should be attached to the new engine
            self._strategy_manager = None
            self.strategy_override = None
            self._forced_strategy_active = False

            # Packet handling components from Phase 1, now owned by the new engine
            self._packet_builder = self._engine._packet_builder
            self._packet_sender = self._engine._packet_sender

            # Constants and semaphores
            self._INJECT_MARK = 0xC0DE # Should be consistent with PacketSender
            self._inject_sema = threading.Semaphore(12) # Compatibility

        def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict],
                 reset_telemetry: bool = False,
                 strategy_override: Optional[Dict[str, Any]] = None):
            """Start the engine (backward compatible)."""
            result = self._engine.start(target_ips, strategy_map,
                                       reset_telemetry, strategy_override)
            self.running = self._engine.running
            return result

        def stop(self):
            """Stop the engine (backward compatible)."""
            self._engine.stop()
            self.running = self._engine.running

        def start_with_config(self, config: dict,
                            strategy_override: Optional[Dict[str, Any]] = None):
            """Start with configuration (backward compatible)."""
            # This logic should ideally be in the new engine, but kept for compatibility
            strategy_task = self._config_to_strategy_task(config)
            target_ips = set()
            strategy_map = {"default": strategy_task}
            return self.start(target_ips, strategy_map, strategy_override=strategy_override)

        def set_strategy_override(self, strategy_task: Dict[str, Any]):
            """Set strategy override (backward compatible)."""
            self._engine.set_strategy_override(strategy_task)
            self.strategy_override = self._engine.strategy_override
            self._forced_strategy_active = self._engine._forced_strategy_active

        def attach_controller(self, *args, **kwargs):
            """Attach adaptive controller (backward compatible)."""
            if hasattr(self._engine, 'attach_controller'):
                return self._engine.attach_controller(*args, **kwargs)
            # For compatibility, we might need to set self.controller as well
            self.controller = self._engine.controller
            return self.controller is not None

        def get_telemetry_snapshot(self) -> Dict[str, Any]:
            """Get telemetry snapshot (backward compatible)."""
            return self._engine.get_telemetry_snapshot()

        def _config_to_strategy_task(self, config: dict) -> dict:
            """(Legacy) Convert configuration to strategy task."""
            desync_method = config.get("desync_method", "fake")
            if desync_method == "multisplit":
                return {"type": "multisplit", "params": config}
            return {"type": "fakeddisorder", "params": config}

else:
    # Non-Windows stub remains the same
    class BypassEngine:
        def __init__(self, debug=True):
            self.logger = logging.getLogger("BypassEngine")
            self.logger.warning(
                "Pydivert is not supported on this platform. BypassEngine is disabled."
            )

        def start(self, *args, **kwargs):
            self.logger.warning("BypassEngine is disabled.")
            return None

        def stop(self, *args, **kwargs):
            pass

        def start_with_config(self, *args, **kwargs):
            self.logger.warning("BypassEngine is disabled.")
            return None

        def get_telemetry_snapshot(self) -> Dict[str, Any]:
            return {}
