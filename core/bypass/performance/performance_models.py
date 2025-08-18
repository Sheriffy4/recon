"""
Performance optimization data models.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class OptimizationLevel(Enum):
    """Performance optimization levels."""
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class PerformanceMetrics:
    """Performance metrics for bypass operations."""
    attack_execution_time: float
    strategy_selection_time: float
    validation_time: float
    memory_usage: float
    cpu_usage: float
    success_rate: float
    throughput: float
    latency: float
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class OptimizationResult:
    """Result of performance optimization."""
    original_metrics: PerformanceMetrics
    optimized_metrics: PerformanceMetrics
    improvement_percentage: float
    optimization_actions: List[str]
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class StrategyPerformance:
    """Performance data for a specific strategy."""
    strategy_id: str
    execution_count: int
    average_execution_time: float
    success_rate: float
    resource_usage: Dict[str, float]
    effectiveness_score: float
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class SystemHealth:
    """Overall system health metrics."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_latency: float
    active_attacks: int
    failed_attacks: int
    system_load: float
    uptime: float
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Alert:
    """System alert."""
    id: str
    severity: AlertSeverity
    title: str
    message: str
    component: str
    metrics: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class ProductionConfig:
    """Production deployment configuration."""
    optimization_level: OptimizationLevel
    max_concurrent_attacks: int
    resource_limits: Dict[str, float]
    monitoring_interval: int
    alert_thresholds: Dict[str, float]
    auto_scaling_enabled: bool
    backup_enabled: bool
    logging_level: str
    performance_targets: Dict[str, float]


@dataclass
class DeploymentChecklist:
    """Production deployment checklist."""
    system_requirements_met: bool
    dependencies_installed: bool
    configuration_validated: bool
    security_checks_passed: bool
    performance_tests_passed: bool
    monitoring_configured: bool
    backup_configured: bool
    documentation_complete: bool
    rollback_plan_ready: bool
    team_trained: bool