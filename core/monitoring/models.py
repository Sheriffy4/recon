"""Data models for monitoring system.

This module contains shared data models to avoid circular dependencies.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


@dataclass
class ConnectionHealth:
    """Состояние здоровья соединения."""

    domain: str
    ip: str
    port: int
    is_accessible: bool
    response_time_ms: float
    last_check: datetime
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    bypass_active: bool = False
    current_strategy: Optional[str] = None

    def to_dict(self) -> dict:
        return {**asdict(self), "last_check": self.last_check.isoformat()}


@dataclass
class MonitoringConfig:
    """Конфигурация системы мониторинга."""

    check_interval_seconds: int = 30
    failure_threshold: int = 3
    recovery_timeout_seconds: int = 300
    max_concurrent_checks: int = 10
    enable_auto_recovery: bool = True
    enable_adaptive_strategies: bool = True
    web_interface_port: int = 8080
    log_level: str = "INFO"
