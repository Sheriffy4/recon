"""
Data models for the refactored Adaptive Engine components.

These models define the core data structures used throughout the system.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from enum import Enum


class CacheType(Enum):
    """Types of caches used in the system."""

    FINGERPRINT = "fingerprint"
    STRATEGY = "strategy"
    DOMAIN_ACCESSIBILITY = "domain_accessibility"
    PROTOCOL_PREFERENCE = "protocol_preference"
    METRICS = "metrics"
    FAILURE_ANALYSIS = "failure_analysis"


class TestMode(Enum):
    """Different modes for testing strategies."""

    DISCOVERY = "discovery"
    SERVICE = "service"
    INLINE = "inline"
    VALIDATION = "validation"


class StrategyType(Enum):
    """Types of bypass strategies."""

    TCP_FRAGMENTATION = "tcp_fragmentation"
    TLS_FRAGMENTATION = "tls_fragmentation"
    HTTP_FRAGMENTATION = "http_fragmentation"
    FAKE_PACKETS = "fake_packets"
    DOMAIN_FRONTING = "domain_fronting"
    SNI_MODIFICATION = "sni_modification"
    MIXED_CASE = "mixed_case"
    COMBINATION = "combination"


@dataclass
class Strategy:
    """Represents a DPI bypass strategy."""

    name: str
    attack_combination: List[str]
    parameters: Dict[str, Any]
    strategy_type: StrategyType = StrategyType.COMBINATION
    success_rate: float = 0.0
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_tested: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert strategy to dictionary."""
        return {
            "name": self.name,
            "attack_combination": self.attack_combination,
            "parameters": self.parameters,
            "strategy_type": self.strategy_type.value,
            "success_rate": self.success_rate,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at.isoformat(),
            "last_tested": self.last_tested.isoformat() if self.last_tested else None,
            "metadata": self.metadata,
        }


@dataclass
class TestArtifacts:
    """Artifacts generated during strategy testing."""

    pcap_path: Optional[str] = None
    pcap_file: Optional[str] = None  # Added for backward compatibility
    log_entries: List[str] = field(default_factory=list)
    log_file: Optional[str] = None  # Added for backward compatibility
    network_traces: List[Dict[str, Any]] = field(default_factory=list)
    performance_data: Dict[str, float] = field(default_factory=dict)
    debug_info: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)  # Added for backward compatibility

    def __post_init__(self):
        """Handle backward compatibility for field names."""
        # If pcap_file was provided but pcap_path wasn't, use pcap_file
        if self.pcap_file and not self.pcap_path:
            self.pcap_path = self.pcap_file


@dataclass
class TestResult:
    """Result of testing a strategy against a domain."""

    success: bool
    strategy: Strategy
    domain: str
    execution_time: float
    test_mode: TestMode = TestMode.DISCOVERY
    error: Optional[str] = None
    artifacts: Optional[TestArtifacts] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        return {
            "success": self.success,
            "strategy": self.strategy.to_dict(),
            "domain": self.domain,
            "execution_time": self.execution_time,
            "test_mode": self.test_mode.value,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class DPIFingerprint:
    """Represents characteristics of a DPI system."""

    domain: str
    detection_methods: List[str] = field(default_factory=list)
    blocking_patterns: List[str] = field(default_factory=list)
    protocol_analysis: Dict[str, Any] = field(default_factory=dict)
    timing_characteristics: Dict[str, float] = field(default_factory=dict)
    characteristics: Dict[str, Any] = field(default_factory=dict)  # Added for test compatibility
    confidence_level: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureReport:
    """Report of a strategy failure with analysis."""

    domain: str
    strategy: Optional[Strategy] = None  # Made optional for backward compatibility
    strategy_name: Optional[str] = None  # Added for test compatibility
    error_message: str = ""
    failure_type: str = ""
    failure_category: Optional[str] = None  # Added for test compatibility
    root_cause: Optional[str] = None
    suggested_fixes: List[str] = field(default_factory=list)
    failure_patterns: List[str] = field(default_factory=list)
    timestamp: datetime = field(
        default_factory=datetime.now
    )  # Changed back to datetime with default
    artifacts: Optional["TestArtifacts"] = None  # Added for test compatibility
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Handle backward compatibility for timestamp field."""
        # If timestamp was passed as float, convert to datetime
        if isinstance(self.timestamp, (int, float)):
            self.timestamp = datetime.fromtimestamp(self.timestamp)


@dataclass
class TestVerdict:
    """Final verdict from a test session."""

    session_id: str
    success: bool
    confidence: float
    evidence: List[str]
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PerformanceMetrics:
    """Performance metrics for the system."""

    cache_hit_rate: float = 0.0
    average_test_time: float = 0.0
    strategy_generation_time: float = 0.0
    fingerprint_creation_time: float = 0.0
    total_domains_processed: int = 0
    total_strategies_found: int = 0
    total_tests_executed: int = 0
    success_rate: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    uptime_seconds: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "cache_hit_rate": self.cache_hit_rate,
            "average_test_time": self.average_test_time,
            "strategy_generation_time": self.strategy_generation_time,
            "fingerprint_creation_time": self.fingerprint_creation_time,
            "total_domains_processed": self.total_domains_processed,
            "total_strategies_found": self.total_strategies_found,
            "total_tests_executed": self.total_tests_executed,
            "success_rate": self.success_rate,
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_usage_percent": self.cpu_usage_percent,
            "uptime_seconds": self.uptime_seconds,
            "last_updated": self.last_updated.isoformat(),
        }


@dataclass
class ValidationError:
    """Represents a configuration validation error."""

    field: str
    message: str
    severity: str = "error"  # error, warning, info
    suggested_fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation error to dictionary."""
        return {
            "field": self.field,
            "message": self.message,
            "severity": self.severity,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class CacheEntry:
    """Represents an entry in the cache."""

    key: str
    value: Any
    cache_type: CacheType
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: Optional[int] = None
    access_count: int = 0
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.ttl_seconds is None:
            return False

        elapsed = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds

    def touch(self) -> None:
        """Update last accessed time and increment access count."""
        self.last_accessed = datetime.now(timezone.utc)
        self.access_count += 1


@dataclass
class ComponentHealth:
    """Health status of a system component."""

    component_name: str
    is_healthy: bool
    status_message: str
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_count: int = 0
    uptime_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemStatus:
    """Overall system status."""

    is_operational: bool
    component_health: List[ComponentHealth]
    performance_metrics: PerformanceMetrics
    active_sessions: int = 0
    pending_operations: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
