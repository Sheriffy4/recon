# recon/core/bypass/engines/base.py
"""
Base interface for all bypass engines.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Set, Optional
from dataclasses import dataclass
from enum import Enum
import logging  # <-- Добавляем отсутствующий импорт


class EngineType(Enum):
    """Types of bypass engines."""

    EXTERNAL_TOOL = "external_tool"
    NATIVE_PYDIVERT = "native_pydivert"
    NATIVE_NETFILTER = "native_netfilter"


@dataclass
class EngineConfig:
    """Configuration for bypass engines."""

    debug: bool = False
    timeout: float = 30.0
    base_path: Optional[str] = None
    tool_name: Optional[str] = None  # For external tools

    # Advanced options
    packet_buffer_size: int = 65535
    max_concurrent_connections: int = 1000
    log_packets: bool = False


class EngineStats:
    """Statistics collected by engines."""

    def __init__(self):
        self.packets_processed: int = 0
        self.packets_modified: int = 0
        self.packets_sent: int = 0
        self.modified_packets: int = 0
        self.bytes_processed: int = 0
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self.errors: int = 0
        self.metadata: Dict[str, Any] = {}
        
    def to_dict(self) -> Dict[str, Any]:
        """Возвращает статистику в виде словаря."""
        return {
            "packets_processed": self.packets_processed,
            "packets_modified": self.packets_modified,
            "packets_sent": self.packets_sent,
            "modified_packets": self.modified_packets,
            "bytes_processed": self.bytes_processed,
            "start_time": self.start_time,
            "stop_time": self.stop_time,
            "errors": self.errors,
            "metadata": self.metadata
        }


class BaseBypassEngine(ABC):
    """
    Abstract base class for all bypass engines.

    Engines are responsible for intercepting and modifying network traffic
    according to provided strategies.
    """

    def __init__(self, config: EngineConfig):
        self.config = config or EngineConfig()  # <-- Защита от None
        self.stats = EngineStats()
        self.is_running = False
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def start(
        self, target_ips: Set[str], strategy_map: Dict[str, Dict[str, Any]]
    ) -> bool:
        """
        Start the bypass engine.

        Args:
            target_ips: Set of target IP addresses to intercept
            strategy_map: Map of IP -> strategy dict

        Returns:
            True if started successfully
        """
        pass

    @abstractmethod
    def stop(self) -> bool:
        """
        Stop the bypass engine.

        Returns:
            True if stopped successfully
        """
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]: # Возвращаемый тип теперь dict
        """Get current engine statistics."""
        return self.stats.to_dict()

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if engine is running properly."""
        pass
