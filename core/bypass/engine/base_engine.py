from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Set, Dict, Any, Optional

@dataclass
class EngineConfig:
    debug: bool = True

class IBypassEngine(ABC):
    @abstractmethod
    def __init__(self, config: EngineConfig):
        ...

    @abstractmethod
    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None):
        ...

    @abstractmethod
    def stop(self):
        ...

    @abstractmethod
    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        ...

    @abstractmethod
    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        ...

    @abstractmethod
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict):
        ...
