# path: core/bypass/engine/base_engine.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Set, Dict, Any, Optional

@dataclass
class EngineConfig:
    """Configuration for the bypass engine."""
    debug: bool = True

class IBypassEngine(ABC):
    """
    Abstract Base Class (Interface) for all platform-specific bypass engines.
    Defines the contract that concrete engine implementations must follow.
    """

    @abstractmethod
    def __init__(self, config: EngineConfig):
        """Initializes the engine with the given configuration."""
        ...

    @abstractmethod
    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None):
        """Starts the packet interception and bypass loop in a separate thread."""
        ...

    @abstractmethod
    def stop(self):
        """Stops the bypass engine."""
        ...

    @abstractmethod
    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        """
        Sets a strategy that will be forcibly applied to all matching traffic,
        bypassing any adaptive logic.
        """
        ...

    @abstractmethod
    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Returns a snapshot of the current telemetry data collected by the engine.
        """
        ...

    @abstractmethod
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict):
        """
        Applies a specific bypass strategy to an intercepted packet.
        This is the core method where bypass techniques are executed.
        """
        ...

    @abstractmethod
    def report_high_level_outcome(self, target_ip: str, success: bool):
        """
        Reports the high-level outcome of a connection attempt (e.g., from an HTTP client)
        to improve the accuracy of success metrics.
        """
        ...