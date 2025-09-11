"""Abstract base class for bypass engines."""

import abc
import logging
from typing import Dict, Any, Optional, Set, List
from dataclasses import dataclass


@dataclass
class EngineConfig:
    """Configuration for bypass engine."""
    debug: bool = False
    max_injections: int = 12
    flow_ttl_sec: float = 3.0
    telemetry_max_targets: int = 1000
    inject_mark: int = 0xC0DE


class IBypassEngine(abc.ABC):
    """Abstract base class for bypass engines."""

    def __init__(self, config: EngineConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = False

        if config.debug:
            self.logger.setLevel(logging.DEBUG)

    @abc.abstractmethod
    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict],
             reset_telemetry: bool = False,
             strategy_override: Optional[Dict[str, Any]] = None) -> Any:
        """Start the bypass engine."""
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop the bypass engine."""
        pass

    @abc.abstractmethod
    def apply_bypass(self, packet: Any, handler: Any, strategy_task: Dict) -> bool:
        """Apply bypass strategy to packet."""
        pass

    @abc.abstractmethod
    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """Get telemetry snapshot."""
        pass

    @abc.abstractmethod
    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        """Set strategy override."""
        pass
