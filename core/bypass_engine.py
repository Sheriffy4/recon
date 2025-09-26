import platform
import logging
from typing import Set, Dict, Any, Optional, Union, List, Tuple

from core.bypass.engine.factory import BypassEngineFactory
from core.bypass.engine.base_engine import EngineConfig
from core.bypass.techniques.primitives import BypassTechniques
from core.fingerprint.advanced_models import DPIFingerprint # Corrected import for DPIFingerprint

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

    def _strategy_to_map(self, strategy: Union[str, Dict[str, Any]], target_ips: Set[str]) -> Dict[str, Dict]:
        """Converts a single strategy or strategy dict to a strategy_map."""
        if isinstance(strategy, str):
            # Apply the same strategy string to all target IPs
            return {ip: {"strategy": strategy} for ip in target_ips}
        elif isinstance(strategy, dict):
            # Assume it's already a strategy_map or a single strategy dict for all IPs
            # If it's a single strategy dict, wrap it for all IPs
            if "strategy" in strategy or "fooling_methods" in strategy: # Check for common strategy keys
                return {ip: strategy for ip in target_ips}
            return strategy # Assume it's already a strategy_map
        return {}

    def start_with_strategy(
        self,
        target_ips: Set[str],
        dns_cache: Optional[Dict[str, str]],  # игнорируем, но оставляем для совместимости вызова
        engine_task: Dict[str, Any],
        reset_telemetry: bool = False
    ):
        """
        Запускает движок строго с переданной стратегией.
        dns_cache не используется движком, оставлен для совместимости вызова из HybridEngine.
        """
        if not self._engine:
            self.logger.warning("BypassEngine is disabled, cannot start.")
            return None

        # Принудительно фиксируем стратегию для всех подходящих потоков
        try:
            if hasattr(self._engine, "set_strategy_override") and callable(getattr(self._engine, "set_strategy_override")):
                self._engine.set_strategy_override(engine_task)
        except Exception:
            pass

        strategy_map = {"default": engine_task}
        try:
            # Передаем strategy_override, чтобы движок шёл по simple/forced пути
            return self._engine.start(
                target_ips=target_ips,
                strategy_map=strategy_map,
                reset_telemetry=reset_telemetry,
                strategy_override=engine_task
            )
        except TypeError:
            # На случай, если сигнатура start другая — fallback без reset_telemetry/override
            return self._engine.start(target_ips=target_ips, strategy_map=strategy_map)

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

    def report_high_level_outcome(self, target_ip: str, success: bool):
        """Delegates the high-level outcome report to the underlying engine."""
        if self._engine and hasattr(self._engine, 'report_high_level_outcome'):
            self._engine.report_high_level_outcome(target_ip, success)

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
